#!/usr/bin/env python3
"""
Analyze decompressed swkbd.elf and nsyskbd.elf to map AppearArg struct fields.
"""

import struct
import sys
import zlib
import capstone

# ─────────────────────────── ELF helpers ────────────────────────────────────

def u32be(data, off):
    return struct.unpack_from('>I', data, off)[0]

def u16be(data, off):
    return struct.unpack_from('>H', data, off)[0]


class ELF:
    def __init__(self, path):
        with open(path, 'rb') as f:
            self.data = f.read()
        assert self.data[:4] == b'\x7fELF'
        self.e_shoff     = u32be(self.data, 0x20)
        self.e_shnum     = u16be(self.data, 0x30)
        self.e_shentsize = u16be(self.data, 0x2e)
        self.e_shstrndx  = u16be(self.data, 0x32)
        self._load_sections()

    def _sh(self, idx):
        off = self.e_shoff + idx * self.e_shentsize
        return {
            'name_idx': u32be(self.data, off + 0),
            'type':     u32be(self.data, off + 4),
            'flags':    u32be(self.data, off + 8),
            'addr':     u32be(self.data, off + 12),
            'offset':   u32be(self.data, off + 16),
            'size':     u32be(self.data, off + 20),
        }

    def _section_body(self, sh):
        off  = sh['offset']
        size = sh['size']
        if size == 0:
            return b''
        raw = self.data[off:off+size]
        if sh['flags'] & 0x08000000:          # SHF_RPL_ZLIB
            usize = u32be(raw, 0)
            return zlib.decompress(raw[4:], 15, usize)
        return raw

    def _load_sections(self):
        # shstrtab
        shstr_sh = self._sh(self.e_shstrndx)
        shstr    = self._section_body(shstr_sh)

        def cstr(data, off):
            end = data.index(b'\x00', off)
            return data[off:end].decode('latin-1')

        self.sections = {}
        for i in range(self.e_shnum):
            sh = self._sh(i)
            name = cstr(shstr, sh['name_idx']) if sh['name_idx'] < len(shstr) else ''
            sh['name'] = name
            sh['body'] = self._section_body(sh)
            self.sections[name] = sh
            if not name:
                pass  # unnamed sections kept by index only

    def get(self, name):
        return self.sections.get(name)


# ─────────────────────────── exports parser ─────────────────────────────────

def parse_fexports(sh):
    body = sh['body']
    if len(body) < 8:
        return []
    count = u32be(body, 0)
    # sig   = u32be(body, 4)   # 0x10b9dc15
    exports = []
    for i in range(count):
        off = 8 + i * 8
        va   = u32be(body, off)
        noff = u32be(body, off + 4)
        end  = body.index(b'\x00', noff)
        name = body[noff:end].decode('latin-1')
        exports.append((va, name))
    return exports


# ─────────────────────────── symtab ─────────────────────────────────────────

def parse_symtab(elf):
    symsh  = elf.get('.symtab')
    strsh  = elf.get('.strtab')
    if symsh is None or strsh is None:
        return []
    sym_body = symsh['body']
    str_body = strsh['body']
    syms = []
    n    = len(sym_body) // 16
    for i in range(n):
        off   = i * 16
        nidx  = u32be(sym_body, off + 0)
        value = u32be(sym_body, off + 4)
        size  = u32be(sym_body, off + 8)
        bind  = sym_body[off + 12] >> 4
        stype = sym_body[off + 12] & 0xF
        end   = str_body.index(b'\x00', nidx)
        name  = str_body[nidx:end].decode('latin-1')
        syms.append({'name': name, 'value': value, 'size': size,
                     'bind': bind, 'type': stype})
    return syms


# ─────────────────────────── disassembler ───────────────────────────────────

def disasm_func(text_body, text_va, func_va, max_insns=400, stop_on_blr=True):
    """Disassemble from func_va until BLR or max_insns."""
    md = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN)
    md.detail = True
    offset = func_va - text_va
    if offset < 0 or offset >= len(text_body):
        return []
    chunk = text_body[offset:offset + max_insns * 4]
    insns = []
    for insn in md.disasm(chunk, func_va):
        insns.append(insn)
        if stop_on_blr and insn.mnemonic == 'blr':
            break
        if len(insns) >= max_insns:
            break
    return insns


# ─────────────────────────── analysis helpers ────────────────────────────────

def rodata_strings(sh):
    """Yield (offset, string) from rodata."""
    body = sh['body']
    i = 0
    while i < len(body):
        if body[i] >= 0x20:
            j = i
            while j < len(body) and body[j] != 0:
                j += 1
            s = body[i:j].decode('latin-1', errors='replace')
            if len(s) >= 3:
                yield (i, s)
            i = j + 1
        else:
            i += 1


def find_field_accesses(insns, arg_reg='r3', max_offset=0x200):
    """
    Walk disassembly; track loads/stores from a base pointer held in a register.
    Returns list of (insn_va, mnemonic, reg, offset_hex, insn_str).
    """
    # Track which register holds the AppearArg pointer.
    # r3 on function entry is arg0.
    base_regs = {arg_reg}
    results = []

    for insn in insns:
        ops = insn.op_str
        mn  = insn.mnemonic

        # Detect copy: mr rX, rY  where rY is a base_reg
        if mn in ('mr', 'ori') and ',' in ops:
            parts = [p.strip() for p in ops.split(',')]
            if mn == 'mr' and len(parts) == 2 and parts[1] in base_regs:
                base_regs.add(parts[0])

        # Detect load: lwz / lhz / lbz / lwzu / lha rX, N(rY)
        if mn in ('lwz', 'lhz', 'lbz', 'lwzu', 'lha', 'lbzu', 'lwzx',
                  'stw', 'sth', 'stb', 'stwu'):
            if '(' in ops:
                left, right = ops.split('(', 1)
                base_part = right.rstrip(')')
                offset_part = left.split(',')[-1].strip() if ',' in left else left.strip()
                dst_part    = left.split(',')[0].strip() if ',' in left else ''
                if base_part in base_regs:
                    try:
                        off = int(offset_part, 0)
                        if 0 <= off <= max_offset:
                            results.append((insn.address, mn, dst_part, off, insn.op_str))
                    except ValueError:
                        pass
    return results


def branch_context(insns, va):
    """Return the 3 insns before a given va (for context around a branch)."""
    for i, insn in enumerate(insns):
        if insn.address == va:
            start = max(0, i - 3)
            return insns[start:i+4]
    return []


# ─────────────────────────── MAIN ───────────────────────────────────────────

def analyze(elf_path, label):
    print(f"\n{'='*70}")
    print(f"  {label}: {elf_path}")
    print(f"{'='*70}")

    elf = ELF(elf_path)

    # ── Exports ──
    fexp_sh = elf.get('.fexports')
    exports = []
    if fexp_sh:
        exports = parse_fexports(fexp_sh)
        print(f"\n[Exports] ({len(exports)} total)")
        for va, name in exports:
            print(f"  0x{va:08x}  {name}")

    # ── Symbols ──
    syms = parse_symtab(elf)
    if syms:
        print(f"\n[Symbols] ({len(syms)} total, showing non-empty names)")
        for s in syms:
            if s['name']:
                print(f"  0x{s['value']:08x}  sz={s['size']:5d}  {s['name']}")

    # ── Rodata strings ──
    ro_sh = elf.get('.rodata')
    if ro_sh:
        print(f"\n[.rodata strings]")
        for off, s in rodata_strings(ro_sh):
            print(f"  +0x{off:04x}  {repr(s)}")

    # ── Disassemble key functions ──
    text_sh = elf.get('.text')
    if text_sh is None or not exports:
        return

    text_body = text_sh['body']
    text_va   = text_sh['addr']

    interest = [
        'AppearInputForm', 'AppearKeyboard', 'Create', 'Calc',
        'AppearWithDimCursor', 'Appear', 'IsAppearInputForm',
        'GetInputFormString', 'GetKeyboardString',
    ]

    # Sort exports by VA so we can bound each function
    sorted_exp = sorted(exports, key=lambda x: x[0])
    exp_vas    = [va for va, _ in sorted_exp]

    for func_va, func_name in sorted_exp:
        if not any(k in func_name for k in interest):
            continue

        # Find next export VA to bound the function
        idx = exp_vas.index(func_va)
        if idx + 1 < len(exp_vas):
            max_insns = min(400, (exp_vas[idx+1] - func_va) // 4 + 4)
        else:
            max_insns = 400

        insns = disasm_func(text_body, text_va, func_va, max_insns=max_insns)

        print(f"\n{'─'*60}")
        print(f"  Function: {func_name}  @ 0x{func_va:08x}  ({len(insns)} insns)")
        print(f"{'─'*60}")

        # Full disassembly
        for insn in insns:
            print(f"  0x{insn.address:08x}:  {insn.mnemonic:<10} {insn.op_str}")

        # Field accesses from first arg (r3)
        accesses = find_field_accesses(insns, arg_reg='r3')
        if accesses:
            print(f"\n  [AppearArg field accesses from r3]")
            # Show unique offsets
            seen = {}
            for va, mn, reg, off, ops in accesses:
                if off not in seen:
                    seen[off] = (va, mn, reg, ops)
            for off in sorted(seen):
                va, mn, reg, ops = seen[off]
                print(f"    +0x{off:03x}  {mn:<6} -> {reg}   (0x{va:08x}: {ops})")

            # Show branch context for conditional branches
            cmp_offsets = set()
            for i, insn in enumerate(insns):
                if insn.mnemonic in ('cmpwi', 'cmplwi', 'cmpw', 'cmplw',
                                     'cmpdi', 'cmpldi'):
                    cmp_offsets.add(i)
            if cmp_offsets:
                print(f"\n  [Comparisons / conditional branches]")
                for i in sorted(cmp_offsets):
                    start = max(0, i-2)
                    end   = min(len(insns), i+3)
                    for insn in insns[start:end]:
                        print(f"    0x{insn.address:08x}:  {insn.mnemonic:<10} {insn.op_str}")
                    print()


if __name__ == '__main__':
    swkbd   = r'C:\Users\Nikolaj\source\repos\Cemu\tools\swkbd_decomp.elf'
    nsyskbd = r'C:\Users\Nikolaj\source\repos\Cemu\tools\nsyskbd_decomp.elf'
    analyze(swkbd,   'swkbd')
    analyze(nsyskbd, 'nsyskbd')
