#!/usr/bin/env python3
"""
Focused disassembly of SwkbdAppearInputForm and SwkbdAppearKeyboard.
Traces which AppearArg fields are read and how they're used.
"""

import struct, zlib
import capstone

# ─── ELF helpers ──────────────────────────────────────────────────────────────

def u32be(data, off): return struct.unpack_from('>I', data, off)[0]
def u16be(data, off): return struct.unpack_from('>H', data, off)[0]

class ELF:
    def __init__(self, path):
        with open(path,'rb') as f: self.data=f.read()
        assert self.data[:4]==b'\x7fELF'
        self.e_shoff=u32be(self.data,0x20)
        self.e_shnum=u16be(self.data,0x30)
        self.e_shentsize=u16be(self.data,0x2e)
        self.e_shstrndx=u16be(self.data,0x32)
        self._load()
    def _sh(self,i):
        o=self.e_shoff+i*self.e_shentsize
        return dict(ni=u32be(self.data,o),type=u32be(self.data,o+4),
                    flags=u32be(self.data,o+8),addr=u32be(self.data,o+12),
                    offset=u32be(self.data,o+16),size=u32be(self.data,o+20))
    def _body(self,sh):
        if sh['size']==0: return b''
        raw=self.data[sh['offset']:sh['offset']+sh['size']]
        if sh['flags']&0x08000000:
            us=u32be(raw,0); return zlib.decompress(raw[4:],15,us)
        return raw
    def _load(self):
        ss=self._sh(self.e_shstrndx); sb=self._body(ss)
        def cs(d,o):
            e=d.index(b'\x00',o); return d[o:e].decode('latin-1')
        self.sec={}
        for i in range(self.e_shnum):
            sh=self._sh(i); sh['name']=cs(sb,sh['ni']); sh['body']=self._body(sh)
            self.sec[sh['name']]=sh
    def get(self,n): return self.sec.get(n)

def parse_fexports(sh):
    b=sh['body']
    if len(b)<8: return []
    cnt=u32be(b,0); exp=[]
    for i in range(cnt):
        o=8+i*8; va=u32be(b,o); no=u32be(b,o+4)
        e=b.index(b'\x00',no); exp.append((va,b[no:e].decode('latin-1')))
    return exp

def parse_symtab(elf):
    ss=elf.get('.symtab'); st=elf.get('.strtab')
    if not ss or not st: return []
    sb=ss['body']; stb=st['body']; syms=[]
    for i in range(len(sb)//16):
        o=i*16; ni=u32be(sb,o); va=u32be(sb,o+4); sz=u32be(sb,o+8)
        e=stb.index(b'\x00',ni); name=stb[ni:e].decode('latin-1')
        syms.append((name,va,sz))
    return syms

# ─── Disassembly ──────────────────────────────────────────────────────────────

def disasm_range(text_body, text_va, start_va, end_va):
    md=capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32|capstone.CS_MODE_BIG_ENDIAN)
    md.detail=True
    off=start_va-text_va
    size=min(end_va-start_va+16, len(text_body)-off)
    chunk=text_body[off:off+size]
    return list(md.disasm(chunk, start_va))

# ─── Main ─────────────────────────────────────────────────────────────────────

SWKBD = r'C:\Users\Nikolaj\source\repos\Cemu\tools\swkbd_decomp.elf'

elf      = ELF(SWKBD)
text_sh  = elf.get('.text')
text_va  = text_sh['addr']
text_body= text_sh['body']
exports  = parse_fexports(elf.get('.fexports'))
syms     = parse_symtab(elf)

# Build symbol map va→size
sym_sizes = {va:sz for name,va,sz in syms if sz>0}

print("=== Exports ===")
for va,nm in sorted(exports):
    print(f"  0x{va:08x}  {nm}")

# Focus functions
FOCUS = [
    'SwkbdAppearInputForm',
    'SwkbdAppearKeyboard',
    'SwkbdCreate',
]

exp_map = {nm:va for va,nm in exports}
sorted_exp = sorted(exports)

def next_func_va(va):
    for v2,_ in sorted_exp:
        if v2 > va: return v2
    return va + 0x400

for func_va, func_name in sorted_exp:
    short = func_name.split('__')[0]  # demangle prefix
    if not any(f==short for f in FOCUS):
        continue

    end_va = next_func_va(func_va)
    insns  = disasm_range(text_body, text_va, func_va, end_va)

    print(f"\n{'='*70}")
    print(f"  {func_name}")
    print(f"  VA=0x{func_va:08x}  size~{end_va-func_va} bytes  ({len(insns)} insns)")
    print(f"{'='*70}")
    for insn in insns:
        print(f"  0x{insn.address:08x}:  {insn.mnemonic:<10} {insn.op_str}")

# ─── Also dump the internal functions called by AppearInputForm ───────────────
# Find calls (bl instructions) in AppearInputForm and disassemble them too.

print("\n\n=== Callees of SwkbdAppearInputForm ===")
appear_va  = None
for va, nm in exports:
    if 'AppearInputForm' in nm:
        appear_va = va; break

if appear_va:
    end_va = next_func_va(appear_va)
    insns  = disasm_range(text_body, text_va, appear_va, end_va)
    callees = []
    for insn in insns:
        if insn.mnemonic == 'bl':
            try:
                target = int(insn.op_str, 16)
                if text_va <= target < text_va+len(text_body):
                    callees.append(target)
            except: pass

    print(f"  BL targets from AppearInputForm: {[hex(t) for t in callees]}")

    for callee_va in callees:
        end_va = next_func_va(callee_va)
        # if no next export is closer, bound by sym_sizes
        sz = sym_sizes.get(callee_va, 0)
        if sz > 0:
            end_va = callee_va + sz

        insns = disasm_range(text_body, text_va, callee_va, end_va)
        # Find name
        name = next((nm for va,nm in exports if va==callee_va), '??')
        if name=='??':
            name = next((nm for nm,va,sz in syms if va==callee_va), f'sub_{callee_va:08x}')

        print(f"\n--- Callee: {name} @ 0x{callee_va:08x} ---")
        for insn in insns:
            print(f"  0x{insn.address:08x}:  {insn.mnemonic:<10} {insn.op_str}")
