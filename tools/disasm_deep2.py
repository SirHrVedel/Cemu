#!/usr/bin/env python3
"""
Trace deeper: sub_02080cd4 (full), and the scene dispatch functions.
r31 = AppearArg* throughout sub_02080cd4
"""
import struct, zlib, capstone

def u32be(d,o): return struct.unpack_from('>I',d,o)[0]
def u16be(d,o): return struct.unpack_from('>H',d,o)[0]

class ELF:
    def __init__(self,path):
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
elf=ELF(SWKBD)
text_sh=elf.get('.text')
text_va=text_sh['addr']
text_body=text_sh['body']

def disasm_bytes(start_va, nbytes, stop_blr=True):
    md=capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32|capstone.CS_MODE_BIG_ENDIAN)
    md.detail=True
    off=start_va-text_va
    if off<0 or off>=len(text_body): return []
    chunk=text_body[off:off+nbytes]
    insns=[]
    for i in md.disasm(chunk, start_va):
        insns.append(i)
        if stop_blr and i.mnemonic=='blr': break
        if len(insns)>=nbytes//4: break
    return insns

def show(insns, label=''):
    if label: print(f"\n{'='*60}\n  {label}\n{'='*60}")
    for i in insns:
        print(f"  0x{i.address:08x}:  {i.mnemonic:<10} {i.op_str}")

# The full sub_02080cd4 — note that the function body was NOT complete before.
# From context we know the function DOESN'T end at 0x2080d20; it has the beq at
# 0x2080d00 -> 0x2080d24 which means the blr at 0x2080d20 is the EARLY EXIT path.
# The function continues at 0x2080d24.
# Let's just dump a big window (no stop_blr):

print("### sub_02080cd4 FULL (no stop-at-blr) ###")
# From 0x2080cd4 to ~ 0x2080e00
insns = disasm_bytes(0x2080cd4, 0x240, stop_blr=False)
show(insns)

# The branch structure:
# 0x2080cfc: cmpwi r3, 0
# 0x2080d00: beq  0x2080d24  -- if NOT in "animating" state, skip to real work
# 0x2080d04..0x2080d20: early exit (return 0) -- still busy
# 0x2080d24: real work begins:
#   lwz r4, 0(r31)      -- AppearArg+0x00
#   bl  0x2080b88       -- SetLocaleOrRegion(instance, arg[0])
#   lwz r3, 0x9c(r31)   -- AppearArg+0x9c
#   bl  0x20b5f14       -- normalize language (0 -> 1)
#   addis r29, r30, 7   -- r29 = instance + 0x70000
#   stw r3, 0x6014(r29) -- store normalized language into instance
#   stb r0, 0x6018(r29) -- ...
#   lwz r3, 0xc0(r31)   -- AppearArg+0xc0 = inputFormType
#   bl  0x20b5f34       -- clamp: if >= 2 return 1, else return as-is
#   cmplwi r3, 1        -- compare clamped result to 1
#   stwu r3, 0x6010(r29)-- store to instance (offset from r29)
#   blt  0x2080d74      -- clamped < 1 (i.e. ==0) -> path A (inputFormType==0: "no input form" / keyboard only)
#   beq  0x2080da8      -- clamped == 1            -> path B (inputFormType==1: input form + keyboard)
#   -- fall-through: clamped > 1 (shouldn't happen after clamp, but >=2 raw -> clamped=1)

# After seeing 0x20b5f34:
#   cmplwi r3, 2 / bltlr / li r3,1 / blr
# This means: if inputFormType < 2, return it unchanged; if >= 2, return 1.
# So valid values are 0 and 1. Value 2+ is clamped to 1.

# Path A (inputFormType==0): calls sub_0x2072430(scene_mgr, appArg, &appArg->inputFormType_copy)
# Path B (inputFormType==1): calls sub_0x2072810(scene_mgr, appArg, &appArg->inputFormType_copy)

print("\n\n### 0x2072430 full -- inputFormType==0 path ###")
insns2 = disasm_bytes(0x2072430, 0x400, stop_blr=False)
show(insns2)

print("\n\n### 0x2072810 full -- inputFormType==1 path ###")
insns3 = disasm_bytes(0x2072810, 0x400, stop_blr=False)
show(insns3)

# These functions call into scene-setup. Let's find what they do with AppearArg
# (r30=appArg, r31=&appArg->inputFormType region, r29=scene_mgr)
# They call: 0x20ac920 (inputFormType==0) vs 0x20ad24c (inputFormType==1)
print("\n\n### 0x20ac920 (scene enter for inputFormType==0) ###")
insns4 = disasm_bytes(0x20ac920, 0x300, stop_blr=False)
show(insns4)

print("\n\n### 0x20ad24c (scene enter for inputFormType==1) ###")
insns5 = disasm_bytes(0x20ad24c, 0x300, stop_blr=False)
show(insns5)
