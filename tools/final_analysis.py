#!/usr/bin/env python3
"""Final targeted analysis of background dim and AppearArg field layout."""
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

# Check 0x2070cb0 - called in scene enter when the input form object exists
print("=== 0x2070cb0 (input form enter helper) ===")
insns = disasm_range(0x2070cb0, 0x2070d40)
for i in insns[:40]:
    print(f"  0x{i.address:08x}:  {i.mnemonic:<10} {i.op_str}")

# Look at whether ANY code path can suppress the dim based on an AppearArg field
# Let's examine what happens in 0x20ac6cc around the dim panel skip
print("\n\n=== 0x20ac6cc main body: what r26=0 vs r26!=0 controls ===")
insns = disasm_range(0x20ac6cc, 0x20ac8d0)
# Highlight the key divergence
for i in insns:
    addr = i.address
    highlight = addr in (0x20ac788, 0x20ac7e4, 0x20ac7ec, 0x20ac7f4)
    prefix = ">>>" if highlight else "   "
    print(f"  {prefix} 0x{addr:08x}:  {i.mnemonic:<10} {i.op_str}")

print("\n\n=== AppearArg+0x08 through +0x20: looking for size ===")
# In the struct, AppearArg+0x00 = InputType (uint32)
# AppearArg+0x04 = PasswordMode (uint32)
# What's at +0x08? Let's look at the large setup function 0x20a18d0
# to find if it reads other fields from r28=AppearArg

# Already found:
# r28+0x00: lhz at 0x20a1bc0 -> but this is from a LOCAL var, not AppearArg directly
# r28+0x04: lwz at 0x20a1b8c -> PasswordMode
# r28+0x24: lbz at 0x20a1f7c -> byte field

# Let's check if any fields between +0x08 and +0x23 are read
print("Scanning 0x20a18d0 body for r28 accesses (+0x08 to +0x23):")
insns = disasm_range(0x20a18d0, 0x20a2400)
tracked = {'r28'}
for insn in insns:
    mn = insn.mnemonic
    ops = insn.op_str
    # track mr
    if mn == 'mr' and ',' in ops:
        parts = [p.strip() for p in ops.split(',')]
        if len(parts)==2 and parts[1] in tracked and parts[0] not in tracked:
            tracked.add(parts[0])
    # loads from tracked
    if mn in ('lwz','lhz','lbz','lwzu','lha') and '(' in ops:
        p = ops.split('(')
        base = p[1].rstrip(')')
        if base in tracked:
            left = p[0].split(',')
            try:
                off = int(left[-1].strip(), 0)
                if 0 <= off < 0x100:
                    print(f"  AppearArg+0x{off:03x}  {mn}  @ 0x{insn.address:08x}: {ops}")
            except:
                pass
