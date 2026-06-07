#!/usr/bin/env python3
"""
Trace the full "appear" path to find dim/background/inputForm field usage.
Focus on:
  1. What field is AppearArg+0x00 (passed to sub_02080b88)?
  2. What does sub_02080b88 compare it against (0xd)?
  3. The scene "enter" function that actually sets up the UI - what does it read
     from the AppearArg (r30/r31 in those functions)?
  4. Look at 0x20ac6cc (the final setup call for inputFormType==0 after state checks pass).
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

def disasm(start_va, nbytes=0x200, stop_blr=True):
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
    for i in insns: print(f"  0x{i.address:08x}:  {i.mnemonic:<10} {i.op_str}")

# ─── sub_02080b88: SetInputMode/InputType ─────────────────────────────────────
# Called with: r3=instance, r4=AppearArg[0x00]
# cmplwi r31, 0xd  => if arg[0x00] >= 13 -> log error and return 0
# So arg[0x00] is an enum 0..12 -> this is "InputType" (keyboard type)

print("### sub_02080b88 full (r4=AppearArg[0x00]) ###")
insns = disasm(0x2080b88, 0x300, stop_blr=False)
show(insns)

# ─── The "real" scene enter for inputFormType==0 ─────────────────────────────
# sub_02072430:
#   r3 = scene_mgr_ptr (r30 from outer = instance offset+X)
#   r4 = AppearArg (r31 from outer)
#   r5 = &AppearArg->inputFormType_copy
# -> calls 0x20ac920 (is_scene_a_ok?), 0x20ac970 (is_scene_b_ok?), 0x20ac6cc (enter)

print("\n\n### 0x20ac6cc (scene enter with appArg: inputFormType==0 success path) ###")
insns = disasm(0x20ac6cc, 0x400, stop_blr=False)
show(insns)

# ─── inputFormType==1 path entry ─────────────────────────────────────────────
print("\n\n### 0x20ad04c (scene enter with appArg: inputFormType==1 success path) ###")
insns = disasm(0x20ad04c, 0x800, stop_blr=False)
show(insns)

# ─── Look for all AppearArg field reads in the big scene-apply function ───────
# The function at 0x20ac6cc (or 0x20ad04c for ==1) likely distributes AppearArg
# fields to UI components. Let's also check what nsyskbd does.

# nsyskbd analysis
print("\n\n=== nsyskbd analysis ===")
NSYSKBD = r'C:\Users\Nikolaj\source\repos\Cemu\tools\nsyskbd_decomp.elf'
nelf=ELF(NSYSKBD)
ntext_sh=nelf.get('.text')
ntext_va=ntext_sh['addr']
ntext_body=ntext_sh['body']

def parse_fexports(sh):
    b=sh['body']
    if len(b)<8: return []
    cnt=u32be(b,0); exp=[]
    for i in range(cnt):
        o=8+i*8; va=u32be(b,o); no=u32be(b,o+4)
        e=b.index(b'\x00',no); exp.append((va,b[no:e].decode('latin-1')))
    return exp

nexp = parse_fexports(nelf.get('.fexports'))
print("[nsyskbd exports]")
for va,nm in sorted(nexp): print(f"  0x{va:08x}  {nm}")

def ndisasm(start_va, nbytes=0x200, stop_blr=True):
    md=capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32|capstone.CS_MODE_BIG_ENDIAN)
    md.detail=True
    off=start_va-ntext_va
    if off<0 or off>=len(ntext_body): return []
    chunk=ntext_body[off:off+nbytes]
    insns=[]
    for i in md.disasm(chunk, start_va):
        insns.append(i)
        if stop_blr and i.mnemonic=='blr': break
        if len(insns)>=nbytes//4: break
    return insns

sorted_nexp = sorted(nexp)
for func_va, func_name in sorted_nexp:
    idx = sorted_nexp.index((func_va, func_name))
    end_va = sorted_nexp[idx+1][0] if idx+1 < len(sorted_nexp) else func_va+0x200
    insns = ndisasm(func_va, end_va-func_va+16, stop_blr=True)
    print(f"\n{'='*60}\n  nsyskbd: {func_name}\n{'='*60}")
    for i in insns: print(f"  0x{i.address:08x}:  {i.mnemonic:<10} {i.op_str}")
