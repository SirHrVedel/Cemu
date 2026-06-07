#!/usr/bin/env python3
"""Check remaining unknown fields: +0x08, +0x10, +0x14, +0x18, +0x1C and the large blocks."""
import struct, zlib, capstone

def u32be(d,o): return struct.unpack_from('>I',d,o)[0]
def u16be(d,o): return struct.unpack_from('>H',d,o)[0]

class ELF:
    def __init__(self,path):
        with open(path,'rb') as f: self.data=f.read()
        self.e_shoff=u32be(self.data,0x20); self.e_shnum=u16be(self.data,0x30)
        self.e_shentsize=u16be(self.data,0x2e); self.e_shstrndx=u16be(self.data,0x32)
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
    cnt=u32be(b,0); out=[]
    for i in range(cnt):
        o=8+i*8; va=u32be(b,o); no=u32be(b,o+4)
        e=b.index(b'\x00',no); out.append((va,b[no:e].decode('latin-1')))
    return out

elf = ELF(r'C:\Users\Nikolaj\source\repos\Cemu\tools\swkbd_decomp.elf')
text_sh = elf.get('.text')
text_va = text_sh['addr']
text_body = text_sh['body']
exports = parse_fexports(elf.get('.fexports'))

md = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32|capstone.CS_MODE_BIG_ENDIAN)
md.detail = True

def disasm_range(start, end):
    off=start-text_va; sz=min(end-start, len(text_body)-off)
    if off<0 or sz<=0: return []
    return list(md.disasm(text_body[off:off+sz], start))

load_mnems = ('lwz','lhz','lbz','lha','lwzu')

def scan_for_offset(insns, target_off, base_regs=None):
    """Find all loads of target_off from ANY register (if base_regs=None) or specific regs."""
    hits = []
    for idx, i in enumerate(insns):
        if i.mnemonic not in load_mnems: continue
        if '(' not in i.op_str: continue
        left, right = i.op_str.split('(', 1)
        base = right.rstrip(')')
        lp = left.split(',')
        off_s = lp[-1].strip() if len(lp)>1 else '0'
        try:
            off = int(off_s, 0)
            if off == target_off:
                if base_regs is None or base in base_regs:
                    ctx = ''
                    if idx+1 < len(insns): ctx = f" | {insns[idx+1].mnemonic} {insns[idx+1].op_str}"
                    hits.append((i.address, i.mnemonic, base, off, i.op_str, ctx))
        except: pass
    return hits

# Now look at the FULL 0x2081680 function for any offset in 0x00..0x30 range
# This function reads AppearArg (internal copy) extensively for specialKeyOptions
# r27 = internal_appear_arg_copy in 0x2081680
print("=== Full scan of 0x2081680 for all individual field accesses ===")
insns_full = disasm_range(0x2081680, 0x2081680+0x2000)
# Find blr to stop
blr_idx = next((i for i, insn in enumerate(insns_full) if insn.mnemonic == 'blr' and insn.address > 0x2082000), len(insns_full))
insns_full = insns_full[:blr_idx+1]
print(f"  Function spans {len(insns_full)} instructions")

# Find where r27 = AppearArg copy (established from 0x020816a8: mr r27, r4)
# Then scan all loads from r27
hits = []
for idx, i in enumerate(insns_full):
    if i.mnemonic not in load_mnems: continue
    if '(' not in i.op_str: continue
    left, right = i.op_str.split('(', 1)
    base = right.rstrip(')')
    if base != 'r27': continue
    lp = left.split(',')
    off_s = lp[-1].strip() if len(lp)>1 else '0'
    try:
        off = int(off_s, 0)
        if off < 0x200:
            ctx = ''
            if idx+1 < len(insns_full): ctx = f" | {insns_full[idx+1].mnemonic} {insns_full[idx+1].op_str}"
            hits.append((i.address, i.mnemonic, off, i.op_str, ctx))
    except: pass

print(f"\n  Loads from r27 (AppearArg internal copy) in 0x2081680:")
seen_offs = set()
for h in hits:
    if h[2] not in seen_offs:
        print(f"  +0x{h[2]:03x}  {h[1]}  @ 0x{h[0]:08x}: {h[3]}{h[4]}")
        seen_offs.add(h[2])

# Now check ALL SwkbdSet* functions for AppearArg arg access
print("\n\n=== SwkbdSet* functions that take AppearArg ===")
sorted_exp = sorted(exports, key=lambda x: x[0])
exp_vas = [va for va,_ in sorted_exp]
for func_va, func_name in sorted_exp:
    if 'Set' not in func_name: continue
    # find next export
    idx = exp_vas.index(func_va)
    next_va = exp_vas[idx+1] if idx+1 < len(exp_vas) else func_va+0x400
    insns = disasm_range(func_va, next_va)
    print(f"\n  {func_name} @ 0x{func_va:08x}:")
    for i in insns:
        print(f"    0x{i.address:08x}: {i.mnemonic} {i.op_str}")

# Now scan SwkbdCreate for CreateArg
print("\n\n=== SwkbdCreate to understand CreateArg layout ===")
create_va = next(va for va,nm in exports if 'Create' in nm)
create_end = next((va for va in exp_vas if va > create_va), create_va+0x400)
insns_create = disasm_range(create_va, create_end)
print(f"  SwkbdCreate @ 0x{create_va:08x}")
for i in insns_create:
    print(f"  0x{i.address:08x}: {i.mnemonic} {i.op_str}")

# Also: sub_20b5f14 for languageType - what values map to what?
# cmplwi r3, 0 -> bgt -> li r3,1 -> blr
# This means: if languageType <= 0: return 1 (=auto?), else return as-is
# So languageType: 0 or negative = auto (becomes 1 internally); positive = explicit

# For sub_20b5eec (AppearArg+8 validation): cmplwi r3, 4; blt -> return r3; else return 0
# So enum 0..3 valid; >=4 clamped to 0

# For sub_20b5edc (PasswordMode): cmplwi r3, 5; blt -> return r3; else return 0
# So 0..4 valid; >=5 clamped to 0

# What is the enum 0..3 at +0x08? Let's search for where it's read back and used in a branch
print("\n\n=== Search for use of +0x08 value post-copy (looking for switch/branch) ===")
# After 0x20837e8 validates +0x08 via 0x20b5eec and stores back to internal[8],
# let's find where internal[8] is read next
insns_837 = disasm_range(0x20838b0, 0x2083a40)
print("  0x20837e8 continued from 0x20838b0:")
# Look for cmpwi/cmplwi after 0x20838b0 that uses a reg
for idx, i in enumerate(insns_837):
    if i.mnemonic in ('cmpwi','cmplwi','cmpw','cmplw','beq','bne','blt','bgt','ble','bge'):
        # show 2 instructions before
        for j in range(max(0,idx-2), min(len(insns_837), idx+3)):
            print(f"    0x{insns_837[j].address:08x}: {insns_837[j].mnemonic} {insns_837[j].op_str}")
        print()
    if i.mnemonic == 'blr': break
