#!/usr/bin/env python3
"""
Full trace: find every AppearArg field access across the entire scene-appear path.
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

def disasm_range(start_va, end_va):
    md=capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32|capstone.CS_MODE_BIG_ENDIAN)
    md.detail=True
    off=start_va-text_va
    size=min(end_va-start_va, len(text_body)-off)
    if size<=0 or off<0: return []
    chunk=text_body[off:off+size]
    return list(md.disasm(chunk, start_va))

def show(insns, label=''):
    if label: print(f"\n{'='*60}\n  {label}\n{'='*60}")
    for i in insns: print(f"  0x{i.address:08x}:  {i.mnemonic:<10} {i.op_str}")

# ─── 0x20a18d0: the function that gets (scene_instance.+0x44, AppearArg, &inputFormType)
# In 0x20ac6cc at 0x20ac8b4:
#   lwz r3, 0x44(r27)   -> r3 = scene_obj+0x44 (some sub-object of scene)
#   mr  r5, r29         -> r5 = &appArg->inputFormType (was r29=r5 from outer)
#   mr  r4, r28         -> r4 = AppearArg
#   bl  0x20a18d0
# So 0x20a18d0: r3=some_scene_obj, r4=AppearArg, r5=&inputFormType_copy

print("### 0x20a18d0 (scene_obj, AppearArg r4, &inputFormType r5) ###")
insns = disasm_range(0x20a18d0, 0x20a1d00)
show(insns, '0x20a18d0')

# Look for the actual "does dimming" function
# Possible: look at what happens to AppearArg+0x04 specifically
# In 0x20ac6cc:  lwz r31, 4(r28)  -> gets AppearArg+0x04
# Then: xori r8, r31, 4  -> XOR with 4 (bit 2)
#       addic r9, r8, -1
#       subfe r26, r9, r8  -> r26 = (r31 & 4) != 0 ? 1 : 0
#                              i.e. r26 = (AppearArg[4] has bit 2 set)
# This bit-2 check: in C:  bool has_dim = (arg->ukn04 & 4) != 0
# or equivalently: r26 = (arg->ukn04 == 4 or 5 or 6 or 7, ...) (bit 2)
# Actually xori x,y,4 then the addic/subfe pattern is computing x=(val^4), then borrow=(val^4)-1
# subfe rd, ra, rb => rd = rb - ra - 1 + borrow = rb - ra - 1 + (borrow from addic)
# addic sets carry/borrow: C = (val^4) + 0xFFFFFFFF overflowed
# subfe rd, ra, rb: rd = rb - ra + CA - 1
# so: rd = (r31^4) - (r31^4) - 1 + 1 = 0 when CA=1
#   CA is set by addic (r8, -1) when r8 + 0xFFFFFFFF >= 2^32 i.e. r8 != 0
# r26 = r8 != 0 ? 1 : 0 where r8 = r31 ^ 4
# i.e. r26 = (r31 != 4) ... no wait:
# Actually: addic r0, r8, -1 => r0 = r8 - 1, carry if r8 != 0
# subfe r26, r0, r8 => r26 = r8 - r0 - 1 + CA = r8 - (r8-1) - 1 + CA = CA
# So r26 = (r8 != 0) where r8 = r31 ^ 4
# r26 = 1 if (AppearArg+0x04) != 4
# r26 = 0 if (AppearArg+0x04) == 4
# Hmm. The cmpwi after sets up the beq/bne.
# Let me recheck from the actual bytes...

# Actually the sequence in 0x20ac6cc:
#  lwz r31, 4(r28)      <- r31 = AppearArg[4]
#  xori r8, r31, 4      <- r8 = AppearArg[4] ^ 4
#  addic r9, r8, -1     <- r9 = r8-1, set carry if r8!=0
#  subfe r26, r9, r8    <- r26 = r8 - r9 - 1 + CA = r8-(r8-1)-1+CA = CA = (r8!=0)
# So r26 = (AppearArg[4] ^ 4) != 0 = AppearArg[4] != 4
# Then: cmpwi r26, 0 at 0x20ac788 -> beq = AppearArg[4]==4 -> skip inner block
# The inner block (0x20ac7f8..0x20ac870) handles SOME scene config when AppearArg[4]!=4
# and branches to 0x20ac878 when ==4.
# This means the field at +0x04 has a special meaning when value==4.

# But wait - we should look at what NintendoSDK documentation says about the struct.
# The SDK header for nn::swkbd::AppearArg is:
#   word at +0x00 = InputFormType (but Cemu puts InputFormType at +0xC0!)
#   Actually, from looking at the 0x2080b88 call pattern:
#     AppearArg+0x00 is passed to sub_02080b88 which does cmplwi r31, 0xd -> max 12
#     -> this is "InputType" (keyboard layout type), NOT inputFormType!

# So Cemu's struct may have the first fields wrong. Let me re-examine the struct layout:
# From the callee that processes AppearArg:
#   +0x00: InputType (0..12, keyboard layout) - confirmed from 0x2080b88
#   +0x9c: LanguageType - confirmed
#   +0xc0: inputFormType (0=keyboard-only/no-text-box, 1=with-text-box) - confirmed
#   +0x04: some flag word, bit 2 (value 4) has special meaning
#   +0xcc: infoText pointer (used in SwkbdAppearInputForm itself)

# Let's also check 0x20a18d0 to find more field accesses

print("\n\nFull 0x20a18d0 with tracked AppearArg fields (r4 on entry):")
insns_a18 = disasm_range(0x20a18d0, 0x20a2000)

# Track loads from r4 (AppearArg) with register propagation
tracked = {'r4'}
print("Tracking register set: starts with r4")
field_hits = {}
for insn in insns_a18:
    mn = insn.mnemonic
    ops = insn.op_str

    # mr copies
    if mn == 'mr' and ',' in ops:
        parts = [p.strip() for p in ops.split(',')]
        if len(parts)==2 and parts[1] in tracked and parts[0] not in tracked:
            tracked.add(parts[0])
            print(f"  [track] {parts[0]} <- {parts[1]} at 0x{insn.address:08x}")

    # loads from tracked
    if mn in ('lwz','lhz','lbz','lwzu','lha'):
        if '(' in ops:
            p = ops.split('(')
            base = p[1].rstrip(')')
            left = p[0].split(',')
            dst = left[0].strip()
            off_str = left[-1].strip()
            if base in tracked:
                try:
                    off = int(off_str, 0)
                    if off not in field_hits:
                        field_hits[off] = []
                    field_hits[off].append((insn.address, mn, dst, ops))
                except: pass

print("\n[Field accesses from AppearArg in 0x20a18d0 and callees (linear scan)]")
for off in sorted(field_hits.keys()):
    for va, mn, dst, ops in field_hits[off]:
        print(f"  AppearArg+0x{off:03x}  {mn}  {dst}  @ 0x{va:08x}:  {ops}")
