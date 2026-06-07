#!/usr/bin/env python3
"""
Comprehensive AppearArg field mapping for swkbd.rpl / nsyskbd.rpl.

Strategy:
1. Parse exports + symtab from both ELFs.
2. For each focus function in swkbd, build a 2-level-deep call graph.
3. For every function in that graph, do a dataflow scan:
   - Track which registers hold the AppearArg base (initially r3 or r4
     depending on calling convention), propagating through 'mr'.
   - Record every lwz/lhz/lbz/lha load from a tracked reg,
     noting: offset, size, destination reg, address.
   - Record every stw/sth/stb store into a tracked reg.
   - Record the instruction after the load (cmpwi/cmplwi/beq/bne/bl)
     for semantic evidence.
4. For nsyskbd, do same for all exports + track AppearArg arg position.
5. Print consolidated table.
"""

import struct, zlib, re, sys
import capstone

# ──────────────── ELF loader ────────────────────────────────────────────────

def u32be(d, o): return struct.unpack_from('>I', d, o)[0]
def u16be(d, o): return struct.unpack_from('>H', d, o)[0]
def u8(d, o):    return d[o]

class ELF:
    def __init__(self, path):
        with open(path, 'rb') as f:
            self.data = f.read()
        self.e_shoff     = u32be(self.data, 0x20)
        self.e_shnum     = u16be(self.data, 0x30)
        self.e_shentsize = u16be(self.data, 0x2e)
        self.e_shstrndx  = u16be(self.data, 0x32)
        self._load()

    def _sh(self, i):
        o = self.e_shoff + i * self.e_shentsize
        return dict(ni=u32be(self.data,o),    type=u32be(self.data,o+4),
                    flags=u32be(self.data,o+8), addr=u32be(self.data,o+12),
                    offset=u32be(self.data,o+16), size=u32be(self.data,o+20))

    def _body(self, sh):
        if sh['size'] == 0: return b''
        raw = self.data[sh['offset']:sh['offset']+sh['size']]
        if sh['flags'] & 0x08000000:
            us = u32be(raw, 0)
            return zlib.decompress(raw[4:], 15, us)
        return raw

    def _load(self):
        ss = self._sh(self.e_shstrndx)
        sb = self._body(ss)
        def cs(d, o):
            e = d.index(b'\x00', o)
            return d[o:e].decode('latin-1')
        self.sec = {}
        for i in range(self.e_shnum):
            sh = self._sh(i)
            sh['name']  = cs(sb, sh['ni']) if sh['ni'] < len(sb) else ''
            sh['body']  = self._body(sh)
            self.sec[sh['name']] = sh

    def get(self, n): return self.sec.get(n)

def parse_fexports(sh):
    if sh is None: return []
    b = sh['body']
    if len(b) < 8: return []
    cnt = u32be(b, 0)
    out = []
    for i in range(cnt):
        o = 8 + i*8
        va  = u32be(b, o)
        no  = u32be(b, o+4)
        e   = b.index(b'\x00', no)
        name = b[no:e].decode('latin-1')
        out.append((va, name))
    return out

def parse_symtab(elf):
    ss = elf.get('.symtab')
    st = elf.get('.strtab')
    if not ss or not st: return {}
    sb  = ss['body']; stb = st['body']
    out = {}
    for i in range(len(sb)//16):
        o  = i*16
        ni = u32be(sb, o)
        va = u32be(sb, o+4)
        sz = u32be(sb, o+8)
        e  = stb.index(b'\x00', ni) if ni < len(stb) else ni
        name = stb[ni:e].decode('latin-1') if ni < len(stb) else ''
        if va and name:
            out[va] = (name, sz)
    return out

# ──────────────── Disassembly ────────────────────────────────────────────────

def make_disassembler():
    md = capstone.Cs(capstone.CS_ARCH_PPC,
                     capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN)
    md.detail = True
    return md

MD = make_disassembler()

def disasm_range(text_body, text_va, start_va, end_va, max_insns=2000):
    off = start_va - text_va
    size = min(end_va - start_va, len(text_body) - off, max_insns * 4)
    if off < 0 or size <= 0: return []
    return list(MD.disasm(text_body[off:off+size], start_va))

def func_insns(text_body, text_va, func_va, next_va, max_size=0x2000):
    """Disassemble one function, stopping at blr or next export VA."""
    end_va = min(func_va + max_size, next_va)
    insns  = disasm_range(text_body, text_va, func_va, end_va)
    # Stop at blr
    for i, insn in enumerate(insns):
        if insn.mnemonic == 'blr':
            return insns[:i+1]
    return insns

# ──────────────── Load-size helper ──────────────────────────────────────────

LOAD_SIZE = {
    'lwz': 4, 'lwzu': 4, 'lwzx': 4,
    'lhz': 2, 'lha': 2, 'lhzu': 2, 'lhax': 2,
    'lbz': 1, 'lbzu': 1, 'lbzx': 1,
}
STORE_MN = {'stw', 'stwu', 'sth', 'stb', 'stwx'}

# ──────────────── Dataflow field-access tracker ──────────────────────────────

def track_loads(insns, arg_reg):
    """
    Linear dataflow: track which regs hold the AppearArg pointer
    (initially arg_reg). Collect every load from tracked regs.

    Returns list of:
        (va, mnemonic, dst_reg, offset, op_str, next_insn_str)
    """
    tracked = {arg_reg}
    results = []

    for idx, insn in enumerate(insns):
        mn  = insn.mnemonic
        ops = insn.op_str

        # ── Register copy propagation ─────────────────────────────────────────
        # mr rDst, rSrc
        if mn == 'mr' and ',' in ops:
            parts = [p.strip() for p in ops.split(',')]
            if len(parts) == 2 and parts[1] in tracked:
                tracked.add(parts[0])
            # mr to a tracked reg from non-tracked: we don't clear it here
            # (conservative: don't clear; the real tracking would need CFG)

        # addi rDst, rSrc, 0 (effectively mr)
        # not common but handle:
        if mn == 'addi' and ',' in ops:
            parts = [p.strip() for p in ops.split(',')]
            if len(parts) == 3 and parts[1] in tracked and parts[2] == '0':
                tracked.add(parts[0])

        # ── Load from tracked pointer ──────────────────────────────────────────
        if mn in LOAD_SIZE and '(' in ops:
            left, right = ops.split('(', 1)
            base = right.rstrip(')')
            parts_left = left.split(',')
            dst_reg    = parts_left[0].strip()
            off_str    = parts_left[-1].strip() if len(parts_left) > 1 else '0'
            if base in tracked:
                try:
                    off = int(off_str, 0)
                    next_str = ''
                    if idx + 1 < len(insns):
                        ni = insns[idx+1]
                        next_str = f"{ni.mnemonic} {ni.op_str}"
                    results.append((insn.address, mn, dst_reg, off, ops, next_str))
                except ValueError:
                    pass

    return results


def collect_calls(insns, text_va, text_size):
    """Return list of bl targets that are within the text section."""
    calls = []
    for insn in insns:
        if insn.mnemonic == 'bl':
            try:
                tgt = int(insn.op_str, 16)
                if text_va <= tgt < text_va + text_size:
                    calls.append(tgt)
            except ValueError:
                pass
    return calls


# ──────────────── Per-function analysis ──────────────────────────────────────

def analyze_func(text_body, text_va, func_va, next_va,
                 arg_reg, depth, visited, sym_map, exp_map,
                 field_hits, func_label=''):
    """
    Analyze func_va, collect field hits.
    depth=0 means top-level; depth=1 means first callee; etc.
    """
    if func_va in visited or depth < 0:
        return
    visited.add(func_va)

    insns = func_insns(text_body, text_va, func_va, next_va)
    if not insns:
        return

    hits = track_loads(insns, arg_reg)
    for h in hits:
        va, mn, dst, off, ops, nxt = h
        size = LOAD_SIZE.get(mn, 4)
        key  = (off, size)
        if key not in field_hits:
            field_hits[key] = []
        name = exp_map.get(func_va) or (sym_map.get(func_va, ('??', 0))[0])
        field_hits[key].append({
            'func': name or func_label or f'sub_{func_va:08x}',
            'va':   va,
            'mn':   mn,
            'dst':  dst,
            'ops':  ops,
            'next': nxt,
            'depth': depth,
        })

    if depth > 0:
        # Go one level deeper: for each bl callee, figure out which arg carries AppearArg
        # If the current func_va's arg_reg is still live and passed to a bl, track it.
        # We need to figure out which argument register the callee receives.
        # Heuristic: look for "mr r3,<tracked>" or "mr r4,<tracked>" just before the bl.
        tracked = {arg_reg}
        for idx, insn in enumerate(insns):
            mn2 = insn.mnemonic
            ops2 = insn.op_str
            # propagate copies
            if mn2 == 'mr' and ',' in ops2:
                parts = [p.strip() for p in ops2.split(',')]
                if len(parts) == 2 and parts[1] in tracked:
                    tracked.add(parts[0])
            # on a bl, figure out which arg reg holds the AppearArg pointer
            if mn2 == 'bl':
                try:
                    tgt = int(ops2, 16)
                    if not (text_va <= tgt < text_va + len(text_body)):
                        continue
                    # Which of r3..r10 was set to a tracked reg in the 6 insns before?
                    callee_arg = None
                    for prev in insns[max(0,idx-8):idx]:
                        if prev.mnemonic == 'mr' and ',' in prev.op_str:
                            pp = [p.strip() for p in prev.op_str.split(',')]
                            if len(pp)==2 and pp[0] in ('r3','r4','r5','r6') and pp[1] in tracked:
                                callee_arg = pp[0]
                        # addi rX, tracked, 0
                        if prev.mnemonic == 'addi' and ',' in prev.op_str:
                            pp = [p.strip() for p in prev.op_str.split(',')]
                            if len(pp)==3 and pp[1] in tracked and pp[2]=='0':
                                callee_arg = pp[0]
                    # Also: if arg_reg itself is r3/r4 and never overwritten, it's passed
                    if callee_arg is None and arg_reg in ('r3','r4'):
                        callee_arg = arg_reg  # assume still live

                    if callee_arg:
                        # find next export/sym for bounding
                        next_tgt = tgt + 0x800  # fallback
                        for v2, _ in sorted(exp_map.items()):
                            if v2 > tgt:
                                next_tgt = v2
                                break
                        analyze_func(text_body, text_va, tgt, next_tgt,
                                     callee_arg, depth-1, visited,
                                     sym_map, exp_map, field_hits)
                except ValueError:
                    pass


# ──────────────── Main analysis ──────────────────────────────────────────────

SWKBD_PATH   = r'C:\Users\Nikolaj\source\repos\Cemu\tools\swkbd_decomp.elf'
NSYSKBD_PATH = r'C:\Users\Nikolaj\source\repos\Cemu\tools\nsyskbd_decomp.elf'

# Focus functions from swkbd
SWKBD_FOCUS = [
    'SwkbdAppearInputForm',
    'SwkbdAppearKeyboard',
    'SwkbdCreate',
    'SwkbdSetReceiver',
]

def run_swkbd():
    elf       = ELF(SWKBD_PATH)
    text_sh   = elf.get('.text')
    text_va   = text_sh['addr']
    text_body = text_sh['body']
    exports   = parse_fexports(elf.get('.fexports'))
    sym_map   = parse_symtab(elf)

    sorted_exp = sorted(exports, key=lambda x: x[0])
    exp_va_map = {va: nm for va, nm in sorted_exp}
    exp_nm_map = {nm: va for va, nm in sorted_exp}

    # For bounding functions, build va->next_va map
    exp_vas = [va for va, _ in sorted_exp] + [text_va + len(text_body)]

    def next_va(va):
        for v2 in exp_vas:
            if v2 > va: return v2
        return va + 0x800

    print("=" * 70)
    print("  swkbd exports")
    print("=" * 70)
    for va, nm in sorted_exp:
        print(f"  0x{va:08x}  {nm}")

    # ── Per-focus function ────────────────────────────────────────────────────
    global_field_hits = {}  # (offset, size) -> list of hit dicts

    for focus_name in SWKBD_FOCUS:
        # Find matching export (may have mangled suffix)
        func_va = None
        for va, nm in sorted_exp:
            if nm.startswith(focus_name):
                func_va = va
                break
        if func_va is None:
            print(f"\n[WARN] {focus_name} not found in exports")
            continue

        print(f"\n{'=' * 70}")
        print(f"  Analyzing: {focus_name} @ 0x{func_va:08x}  (depth=2)")
        print(f"{'=' * 70}")

        visited = set()
        field_hits = {}

        # Determine which register holds AppearArg on entry.
        # SwkbdAppearInputForm(instance, const AppearArg*) → r4
        # SwkbdAppearKeyboard(instance, const AppearArg*) → r4
        # SwkbdCreate(instance, const CreateArg*) → r4  (different struct, skip field tracking)
        # SwkbdSetReceiver(instance, const ReceiveArg*) → skip
        if 'Appear' in focus_name:
            arg_reg = 'r4'
        elif 'Create' in focus_name:
            # CreateArg is a different struct; we include it to see what offset-0 fields look like
            arg_reg = 'r4'
        else:
            arg_reg = 'r4'

        analyze_func(text_body, text_va, func_va, next_va(func_va),
                     arg_reg, depth=2, visited=visited,
                     sym_map=sym_map, exp_map=exp_va_map,
                     field_hits=field_hits,
                     func_label=focus_name)

        # Print per-function hits
        print(f"  Field accesses found ({len(field_hits)} unique offset/size combos):")
        for key in sorted(field_hits.keys()):
            off, sz = key
            hits = field_hits[key]
            print(f"\n    AppearArg+0x{off:03x}  ({sz}B):")
            for h in hits:
                print(f"      [{h['depth']}d] {h['func']}+? @ 0x{h['va']:08x}:  {h['mn']} {h['ops']}")
                if h['next']:
                    print(f"             next:  {h['next']}")

        # Accumulate into global
        for key, hits in field_hits.items():
            if key not in global_field_hits:
                global_field_hits[key] = []
            global_field_hits[key].extend(hits)

    return global_field_hits, text_va, text_body, sorted_exp, sym_map


def run_nsyskbd(swkbd_field_hits):
    elf       = ELF(NSYSKBD_PATH)
    text_sh   = elf.get('.text')
    text_va   = text_sh['addr']
    text_body = text_sh['body']
    exports   = parse_fexports(elf.get('.fexports'))
    sym_map   = parse_symtab(elf)

    sorted_exp = sorted(exports, key=lambda x: x[0])
    exp_va_map = {va: nm for va, nm in sorted_exp}

    exp_vas = [va for va, _ in sorted_exp] + [text_va + len(text_body)]
    def next_va(va):
        for v2 in exp_vas:
            if v2 > va: return v2
        return va + 0x800

    print("\n\n" + "=" * 70)
    print("  nsyskbd exports")
    print("=" * 70)
    for va, nm in sorted_exp:
        print(f"  0x{va:08x}  {nm}")

    ns_field_hits = {}
    for func_va, func_name in sorted_exp:
        visited = set()
        field_hits = {}
        # Most nsyskbd functions wrap swkbd; AppearArg is typically r3 (only arg)
        # or r4 (second arg after instance pointer).
        # Try both and report what we find.
        for arg_reg in ('r3', 'r4'):
            analyze_func(text_body, text_va, func_va, next_va(func_va),
                         arg_reg, depth=1, visited=set(),
                         sym_map=sym_map, exp_map=exp_va_map,
                         field_hits=field_hits,
                         func_label=func_name)

        if field_hits:
            print(f"\n  {func_name} @ 0x{func_va:08x}")
            for key in sorted(field_hits.keys()):
                off, sz = key
                hits = field_hits[key]
                print(f"    +0x{off:03x} ({sz}B):", end='')
                for h in hits:
                    print(f"  {h['mn']} @ 0x{h['va']:08x}", end='')
                    if h['next']:
                        print(f"  [=> {h['next']}]", end='')
                print()

            for key, hits in field_hits.items():
                if key not in ns_field_hits:
                    ns_field_hits[key] = []
                ns_field_hits[key].extend(hits)

    return ns_field_hits


def print_full_table(swkbd_hits, ns_hits):
    """Print a combined offset table with all evidence."""
    # Known fields
    KNOWN = {
        0x00: ('inputType',      4, 'keyboard layout enum 0-12'),
        0x04: ('passwordMode',   4, '0-4; 4=swap dim panel to DRC'),
        0x1C: ('okButtonLabel',  4, 'MEMPTR<uint16> to OK button string'),
        0x9C: ('languageType',   4, '0/negative=auto'),
        0xC0: ('inputFormType',  4, '0=keyboard-only, 1=with input form'),
        0xC4: ('cursorIndex',    4, 'initial cursor position'),
        0xC8: ('initialText',    4, 'MEMPTR<uint16be>, NULL=empty'),
        0xCC: ('infoText',       4, 'MEMPTR<uint16be>, NULL=no hint'),
        0xD0: ('maxTextLength',  4, '0=default(40)'),
        0xD4: ('ukn_D4',         4, 'stored to instance+0x278'),
        0xD8: ('ukn_D8',         4, 'stored to instance+0x254'),
        0xDC: ('ukn_DC',         1, 'xori r9,r10,1 then stored to instance+0x25c'),
    }

    all_offsets = set()
    for (off, sz) in swkbd_hits.keys():
        all_offsets.add(off)
    for (off, sz) in ns_hits.keys():
        all_offsets.add(off)
    for off in KNOWN.keys():
        all_offsets.add(off)

    print("\n\n" + "=" * 90)
    print("  CONSOLIDATED AppearArg FIELD TABLE")
    print("=" * 90)
    print(f"  {'Offset':<8} {'Size':<6} {'Name':<25} {'Evidence / Notes'}")
    print(f"  {'-'*8} {'-'*6} {'-'*25} {'-'*48}")

    for off in sorted(all_offsets):
        # Find size: prefer known, else from hits
        sz = 4
        name = ''
        notes = ''

        if off in KNOWN:
            name, sz, notes = KNOWN[off]

        # Collect evidence from swkbd
        sw_ev = []
        for (o2, s2), hits in swkbd_hits.items():
            if o2 == off:
                sz = s2
                for h in hits:
                    sw_ev.append(f"{h['mn']}@{h['func']} [{h['next'][:40]}]")

        # Collect evidence from nsyskbd
        ns_ev = []
        for (o2, s2), hits in ns_hits.items():
            if o2 == off:
                for h in hits:
                    ns_ev.append(f"ns:{h['mn']}@{h['func']}")

        all_ev = sw_ev + ns_ev

        if not name:
            if not all_ev:
                name = 'UNUSED_IN_DISASM'
                notes = 'no load found'
            else:
                name = f'unk_{off:03X}'

        if not notes and all_ev:
            notes = '; '.join(all_ev[:3])

        print(f"  +0x{off:03X}    {sz:<6} {name:<25} {notes}")

    print("=" * 90)


def main():
    print("Running swkbd analysis...")
    swkbd_hits, text_va, text_body, sorted_exp, sym_map = run_swkbd()

    print("\n\nRunning nsyskbd analysis...")
    ns_hits = run_nsyskbd(swkbd_hits)

    print_full_table(swkbd_hits, ns_hits)


if __name__ == '__main__':
    main()
