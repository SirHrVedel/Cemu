#!/usr/bin/env python3
"""Final targeted scan for offsets we haven't found yet."""
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

elf = ELF(r'C:\Users\Nikolaj\source\repos\Cemu\tools\swkbd_decomp.elf')
text_sh = elf.get('.text')
text_va = text_sh['addr']
text_body = text_sh['body']

md = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32|capstone.CS_MODE_BIG_ENDIAN)
md.detail = True

def disasm_range(start, end):
    off=start-text_va; sz=min(end-start, len(text_body)-off)
    if off<0 or sz<=0: return []
    return list(md.disasm(text_body[off:off+sz], start))

load_mnems = ('lwz','lhz','lbz','lha','lwzu')

# Scan large block 0x20815b4 for ALL offsets in range 0..0xBF
# r30=r4=AppearArg copy
print("=== 0x20815b4: all field accesses from r30 in 0..0xFF range ===")
insns = disasm_range(0x20815b4, 0x20815b4+0x200)
for idx, i in enumerate(insns):
    if i.mnemonic not in load_mnems: continue
    if '(' not in i.op_str: continue
    left, right = i.op_str.split('(', 1)
    base = right.rstrip(')')
    if base != 'r30': continue
    lp = left.split(',')
    off_s = lp[-1].strip() if len(lp)>1 else '0'
    try:
        off = int(off_s, 0)
        ctx = ''
        if idx+1 < len(insns): ctx = f" | {insns[idx+1].mnemonic} {insns[idx+1].op_str}"
        print(f"  +0x{off:03x}  {i.mnemonic}  @ 0x{i.address:08x}: {i.op_str}{ctx}")
    except: pass
    if i.mnemonic == 'blr': break

# The big question: does 0x20815b4 use r30+0x0C (AppearArg+0x0C) alone or along with +0x04?
# From previous: lwz r31, 0xc(r30) -> then bitmask operations based on display_mode
# Then: lwz r10, 4(r30) -> cmpwi r10, 4 (passwordMode check)
# This confirms: 0x0C = some bitmask, 0x04 = passwordMode (already known)

# Look at sub_20837a4 (called from SwkbdSetReceiver) to understand ReceiverArg
print("\n\n=== sub_20837a4 (SwkbdSetReceiver callee) ===")
insns_37a4 = disasm_range(0x20837a4, 0x20837a4+0x80)
for i in insns_37a4:
    print(f"  0x{i.address:08x}: {i.mnemonic} {i.op_str}")
    if i.mnemonic == 'blr': break

# Search specifically for +0x08 being used with a switch-like cmplwi/cmpwi pattern
# in all the functions we've visited
# From 0x20837e8 (AppearArg+8 = enum 0..3), r3=result of 0x20b5eec(AppearArg+8)
# After 0x20838b0: stw r3, 8(r27)
# Then continues with setting up key-list operations (not reading +8 again by name)
# The enum 0..3 value from +8 is stored back to internal copy and used indirectly

# Let's check what 0x20b5f14 does for languageType and whether +0x9C is the actual field
# 0x20b5f14: cmpwi r3,0; bgt; li r3,1; blr
# So: languageType <= 0 -> return 1; else return r3 (pass through)
# This means internal representation: 1=auto/default, >1=explicit language

# Now let's check AppearArg+0x9C usage in nsyskbd to confirm it's LanguageType
print("\n\n=== nsyskbd analysis for AppearArg fields ===")
nelf = ELF(r'C:\Users\Nikolaj\source\repos\Cemu\tools\nsyskbd_decomp.elf')
ntext_sh = nelf.get('.text')
ntext_va = ntext_sh['addr']
ntext_body = ntext_sh['body']

def parse_fexports(sh):
    b=sh['body']
    if len(b)<8: return []
    cnt=u32be(b,0); out=[]
    for i in range(cnt):
        o=8+i*8; va=u32be(b,o); no=u32be(b,o+4)
        e=b.index(b'\x00',no); out.append((va,b[no:e].decode('latin-1')))
    return out

nexp = parse_fexports(nelf.get('.fexports'))
sorted_nexp = sorted(nexp)

print("[nsyskbd exports]")
for va,nm in sorted_nexp:
    print(f"  0x{va:08x}  {nm}")

# nsyskbd doesn't directly deal with swkbd AppearArg - it's a physical keyboard lib
# KBD/SKBD functions
# The only functions that might be relevant: SKBDSetup, SKBDGetKey, etc.

# Let's look at what fields a ControllerInfo struct has (for SwkbdCalc)
print("\n\n=== SwkbdCalc reading ControllerInfo ===")
insns_calc = disasm_range(0x2063e50, 0x2063edc)
for i in insns_calc:
    print(f"  0x{i.address:08x}: {i.mnemonic} {i.op_str}")

# Summary of confirmed AppearArg layout:
print("\n\n" + "="*70)
print("CONFIRMED FIELD ACCESSES IN AppearArg/KeyboardArg (shared layout 0x00..0xBF):")
print("="*70)
CONFIRMED = [
    (0x00, 4, 'inputType', 'enum 0..12, lwz r4,0(r31) -> bl 0x2080b88 (cmplwi r31,0xd)'),
    (0x04, 4, 'passwordMode', 'enum 0..4 (>=5->0), lwz r3,4(r28) -> bl 0x20b5edc'),
    (0x08, 4, 'unknown_enum_0_3', 'enum 0..3 (>=4->0), lwz r3,8(r27) -> bl 0x20b5eec'),
    (0x0C, 4, 'disableKeyGroup_or_keyMask', 'bitmask, lwz r31,0xc(r30) -> rlwinm/and operations per display mode'),
    (0x24, 1, 'unknown_byte', 'lbz r0,0x24(r28) checked after cmpwi r9,2 (font mode 2?)'),
    (0x28, 4, 'specialKeyOption', 'bitmask, lwz r0,0x28(r27) -> rlwinm. per bit for special chars (@=%/\\etc)'),
    (0x9C, 4, 'languageType', 'int32, <=0->1(auto), lwz r3,0x9c(r31) -> bl 0x20b5f14'),
    (0xC0, 4, 'inputFormType', 'enum 0..1, lwz r3,0xc0(r31) -> bl 0x20b5f34 (cmplwi r3,2)'),
    (0xC4, 4, 'cursorIndex', 'lwz r29,4(r30) where r30=&arg->inputFormType'),
    (0xC8, 4, 'initialText', 'MEMPTR<uint16be>, lwz r6,8(r30) -> copy loop'),
    (0xCC, 4, 'infoText', 'MEMPTR<uint16be>, lwz r31,0xcc(r31) (SwkbdAppearInputForm reads this)'),
    (0xD0, 4, 'maxTextLength', 'lwz r12,0x10(r30); clamped to 0x28 if >0x28, error if ==0x28'),
    (0xD4, 4, 'ukn_D4', 'lwz r8,0x14(r30) -> stw r8,0x278(r27) (cursor pos or mask)'),
    (0xD8, 4, 'ukn_D8', 'lwz r7,0x18(r30) -> stw r7,0x254(r27)'),
    (0xDC, 1, 'ukn_DC', 'lbz r10,0x1c(r30) -> xori r9,r10,1 -> stb r9,0x25c(r27)'),
]
NOT_FOUND = [
    (0x10, 4, 'ukn10', 'In block copy 0x00..0xBF but no individual named access found'),
    (0x14, 4, 'ukn14', 'In block copy 0x00..0xBF but no individual named access found'),
    (0x18, 4, 'ukn18', 'In block copy 0x00..0xBF but no individual named access found'),
    (0x1C, 4, 'ukn1C', 'Previously noted as OK button label ptr -- not directly confirmed in disasm; in block copy'),
    (0x20, 4, 'ukn20[0]', 'In block copy 0x00..0xBF; no individual named access'),
    (0x2C, 4, 'ukn2C', 'In block copy 0x00..0xBF; specialKeyOption is at 0x28'),
    (0x30, 4, 'ukn30...', 'In block copy 0x00..0xBF; range 0x2C..0x9B = block copy padding'),
    (0xA0, 4, 'uknA0...', 'In block copy 0x00..0xBF; range 0xA0..0xBF = block copy padding'),
]

for off, sz, name, ev in CONFIRMED:
    print(f"  +0x{off:03X}  {sz}B  {name}")
    print(f"         {ev}")
print()
for off, sz, name, ev in NOT_FOUND:
    print(f"  +0x{off:03X}  {sz}B  {name} [UNUSED in named access]")
    print(f"         {ev}")
