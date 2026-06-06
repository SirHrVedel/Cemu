#!/usr/bin/env python3
"""
Deep trace of the InputForm appear logic.
Focus on sub_02080cd4 and its callees that take inputFormType at +0xC0.
"""

import struct, zlib
import capstone

def u32be(data, off): return struct.unpack_from('>I', data, off)[0]
def u16be(data, off): return struct.unpack_from('>H', data, off)[0]

class ELF:
    def __init__(self, path):
        with open(path,'rb') as f: self.data=f.read()
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

SWKBD = r'C:\Users\Nikolaj\source\repos\Cemu\tools\swkbd_decomp.elf'
elf = ELF(SWKBD)
text_sh = elf.get('.text')
text_va  = text_sh['addr']
text_body= text_sh['body']

def disasm(start_va, max_bytes=0x200, stop_blr=True):
    md=capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32|capstone.CS_MODE_BIG_ENDIAN)
    md.detail=True
    off=start_va-text_va
    if off<0 or off>=len(text_body): return []
    chunk=text_body[off:off+max_bytes]
    insns=[]
    for i in md.disasm(chunk, start_va):
        insns.append(i)
        if stop_blr and i.mnemonic=='blr': break
        if len(insns)>=max_bytes//4: break
    return insns

def show(insns, label=''):
    if label: print(f"\n{'='*60}\n  {label}\n{'='*60}")
    for i in insns:
        print(f"  0x{i.address:08x}:  {i.mnemonic:<10} {i.op_str}")

# ─── 1. AppearInputForm itself (already seen, just the key parts) ────────────
# r31 = AppearArg pointer
# 0x02064030: lwz r30, 0xcc(r31)  <- infoText pointer
# 0x02064034: cmpwi r30, 0
# 0x02064038: beq -> 0x20640a0   (skip string copy if infoText==NULL)
# ... string copy loop ...
# 0x020640dc: cmpwi r3, 0        <- test if global swkbd instance is valid
# 0x020640e0: beq -> 0x2064110   (return 0 if no instance)
# 0x020640e8: bl 0x2080cd4       <- actual "appear" implementation
#   r3=instance, r4=AppearArg

# ─── 2. sub_02080cd4: the real AppearInputForm impl ─────────────────────────
print("\n### sub_02080cd4 (AppearInputForm implementation) ###")
insns = disasm(0x02080cd4, max_bytes=0x200)
show(insns)

# Key observations:
# 0x02080d24: lwz r4, 0(r31)      <- AppearArg+0x00
# 0x02080d28: bl 0x2080b88        <- SetTextOrSomething(instance, arg+0x00)
# 0x02080d30: lwz r3, 0x9c(r31)   <- AppearArg+0x9c
# 0x02080d34: bl 0x20b5f14        <- some function with +0x9c value
# 0x02080d48: lwz r3, 0xc0(r31)   <- AppearArg+0xc0 = inputFormType
# 0x02080d4c: bl 0x20b5f34        <- convert/validate inputFormType
# 0x02080d50: cmplwi r3, 1        <- compare result to 1
# 0x02080d54: stwu r3, 0x6010(r29) <- store the result
# 0x02080d58: blt -> 0x2080d74    <- <1 (i.e. ==0) -> branch A
# 0x02080d5c: beq -> 0x2080da8    <- ==1           -> branch B
# else (>1)                        -> branch C

# Branch A (inputFormType result==0):
# 0x2080d74: different scene setup
# Branch B (inputFormType result==1):
# 0x2080da8: different scene setup
# Branch C (>1):
# 0x2080d60: li r3, 0xff; bl...; stb r3, 8; b 0x2080de0

print("\n\n### 0x2080b88 (called with AppearArg+0x00) ###")
insns = disasm(0x2080b88, max_bytes=0x300)
show(insns)

print("\n\n### 0x20b5f14 (called with AppearArg+0x9c = LanguageType) ###")
insns = disasm(0x20b5f14, max_bytes=0x100)
show(insns)

print("\n\n### 0x20b5f34 (called with AppearArg+0xc0 = inputFormType, converts it) ###")
insns = disasm(0x20b5f34, max_bytes=0x100)
show(insns)

# Branch A: inputFormType==0 path
print("\n\n### 0x2072430 (Branch A: inputFormType==0 path) ###")
insns = disasm(0x2072430, max_bytes=0x500)
show(insns)

# Branch B: inputFormType==1 path
print("\n\n### 0x2072810 (Branch B: inputFormType==1 path) ###")
insns = disasm(0x2072810, max_bytes=0x500)
show(insns)
