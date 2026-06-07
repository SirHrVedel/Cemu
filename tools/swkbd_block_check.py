#!/usr/bin/env python3
"""Check the block copy loop and remaining fields in AppearArg / KeyboardArg."""
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

# Verify: block copy at 0x20a26a4 in 0x20a18d0
print("=== Block copy at 0x20a26a4 in 0x20a18d0 ===")
insns2 = disasm_range(0x20a2694, 0x20a2750)
for i in insns2:
    print(f"  0x{i.address:08x}: {i.mnemonic} {i.op_str}")

# The block copy loop:
# addi r9, r28, -4 means r9 starts 4 bytes before AppearArg
# The loop reads 4(r9), 8(r9), 0xc(r9), lwzu r6, 0x10(r9)
# = AppearArg+0, AppearArg+4, AppearArg+8, AppearArg+12 (then r9 advances)
# 12 iterations of 4 words = 48 words = 192 bytes total
# So AppearArg[0..0xBF] is block-copied to stack buffer

# Then: addi r4, r27, 0x590; copies another set from stack to instance+0x590
# And: bl 0x2080f70 with the copied data as arg

# After the block copy, sub_2080f70 processes it:
# r30=r4=stack_copy; reads 0(r30)=inputType, 0x9c(r30)=languageType
# Confirms same layout for all bytes 0x00..0x9F at least

# CONCLUSION: AppearArg and KeyboardArg have the SAME layout for bytes 0x00..0xBF
# KeyboardArg is just AppearArg extended with more keyboard-specific state (not in first 0xBF bytes)
# All fields found in SwkbdAppearKeyboard path apply to the shared beginning of both structs

# Check sub_20815b4's return value usage after 0x20837e8 calls it
print("\n\n=== After sub_20815b4 call in sub_20837e8 ===")
insns3 = disasm_range(0x2083904, 0x2083940)
for i in insns3:
    print(f"  0x{i.address:08x}: {i.mnemonic} {i.op_str}")

# Check: what bitmasks does 0x20815b4 use for AppearArg+0x0C?
# At r11=0 (display_mode=TV?):   mask = 0xFFFAE001 (inverted = 0x00051FFE)
# -> bits 1..12 (0x1FFE) and bit 16 (0x10000) and bit 18 (0x40000) enabled
# At r11=1 (DRC): mask = 0xFFFE001E (inverted = 0x0001FFE1)
# -> bits 0,5..12 enabled
# At r11=2 (both): mask = 0xFFFE1FE0 (inverted 0x0001E01F)
# These correspond to "key group" bits in nn::swkbd::KeyGroup

# Let's also look at what comes after the copy to understand AppearArg+0x1C
# Previously found: AppearArg+0x1C = ptr to OK button label
# The SwkbdAppearInputForm reads 0xCC(r31) = infoText (initialText copy)
# And earlier comment in the code says: "r31+0xCC" which is instance+0xCC, not AppearArg+0xCC

# Wait! Let me re-examine SwkbdAppearInputForm:
# mr r31, r3 (r3=AppearArg? or r3=instance?)
# The export is: SwkbdAppearInputForm__3RplFRCQ3_2nn5swkbd9AppearArg
# This is a STATIC free function taking (const AppearArg&) as r3
# But then later: lwz r30, 0xCC(r31) which would be AppearArg+0xCC = infoText!
# And lhz r0, 0(r30) -> reads first uint16 of the infoText string
# So r31 IS AppearArg, and 0xCC is infoText within AppearArg

# BUT that contradicts the overall struct layout from sub_2080cd4:
# sub_2080cd4: r31=r4=AppearArg; reads 0xC0(r31)=inputFormType
# AND sub_2080cd4 is called from SwkbdAppearInputForm via bl 0x2080cd4; mr r4,r31
# So r31=AppearArg in both, and:
# - 0xC0 = inputFormType (from sub_2080cd4)
# - 0xCC = infoText (from SwkbdAppearInputForm itself)

# But the struct has infoText at +0xCC AND +0xCC in the "sub-struct starting at +0xC0":
# If r30=inputFormType_ptr = &AppearArg+0xC0, then:
# 0xC(r30) = AppearArg+0xCC = infoText -- consistent!

# Now let me understand the 0x20 block copy: addi r10, r1, 0x44 (stack buffer)
# Then bl 0x2080f70; with addi r4, r1, 0x44 as arg
# 0x2080f70 is called with KEYBOARD ARG COPY, not AppearArg!
# It's the keyboard setup function

# RECONCILIATION:
# The "block" 0x20..0xBF is all relevant! Every dword in it is potentially meaningful.
# Functions that read the whole block will use whichever bits matter.
# We've identified:
# +0x08: enum 0..3 -- might be "panelType" or "appearance mode"? confirmed validated
# +0x0C: keyGroupDisableMask (bitmask)
# +0x24: bool byte (0=use full width chars, 1=use half-width?)
# +0x28: specialKeyOption bitmask

# Cross-check what AppearArg+0x20, +0x24 are
# From 0x20a18d0: lbz r0, 0x24(r28) -> byte at AppearArg+0x24
# The context shows: it's checked after computing r9=0x260(r27) value vs 2
# If r9 (fontScale mode?) == 2 AND AppearArg+0x24 != 0: r11 = 1 (some flag)
# Then r10 (text alignment?) and r12 (another flag) computed and combined

# Let's look at what 0x20b5228 does (called with addi r3, r1, 0x3c; li r4, 0xa)
# This might relate to AppearArg processing
print("\n\n=== sub_20b5228 (called with string ptr, max_len=0xa) ===")
insns4 = disasm_range(0x20b5228, 0x20b5228+0x100)
for i in insns4:
    print(f"  0x{i.address:08x}: {i.mnemonic} {i.op_str}")
    if i.mnemonic == 'blr': break

# Understanding AppearArg+0x1C:
# Previously established: "pointer to OK button label string"
# But from SwkbdAppearInputForm: lwz r30, 0xCC(r31) -- and this is AppearArg+0xCC = infoText
# The "OK button label" at +0x1C might be part of KeyboardArg or AppearArg main data

# SwkbdAppearInputForm reads 0xCC(r31) which is AppearArg+0xCC
# from the known layout: AppearArg+0xCC = infoText
# So the AppearArg+0xCC read was done BEFORE the function determined there was an infoText string to copy

# Now: the lhz/sthu at 0x2064030-0x206409c:
# This is copying the infoText (UTF-16 wchar) string from AppearArg+0xCC ptr
# to some static buffer (0x1005:0xFFFD2D40 or similar - that's the lis+addi pattern)
# So 0xCC is infoText pointer - confirmed.

# Look at AppearArg+0x1C in any path:
# In the original trace, "+0x1C" was called "pointer to OK button label string"
# Let's search for any lwz/lhz of 0x1C(r31) in relevant functions

# From SwkbdAppearInputForm (r31=AppearArg):
# The only field explicitly read is 0xCC(r31) = infoText
# Then it calls sub_2080cd4 which reads 0x00, 0x9C, 0xC0

# AppearArg+0x1C: let's do a brute-force search for it in the scene functions
print("\n\n=== Searching for accesses to offset 0x1C from any relevant reg ===")
# Since the whole struct is block-copied, 0x1C access would be inside a copy
# The INDIVIDUAL 0x1C read would happen in the function using the internal copy
# after the copy, at internal_copy+0x1C

# After 0x20837e8 copies AppearArg[0..0xBF] to internal buffer (r27):
# the internal buffer is called with 0x2081680(scene, r27) -- uses r27=internal buf
# in 0x2081680, only 0x28(r27) is accessed individually
# What about 0x1C(r27) = AppearArg+0x1C?

# Check for 0x1C accesses in 0x2081680
print("Scanning 0x2081680 for +0x1C accesses:")
insns5 = disasm_range(0x2081680, 0x2081680+0x2000)
found = False
for idx, i in enumerate(insns5):
    if i.mnemonic in ('lwz','lhz','lbz') and '0x1c(' in i.op_str.lower():
        print(f"  0x{i.address:08x}: {i.mnemonic} {i.op_str}")
        found = True
    if i.mnemonic == 'blr' and i.address > 0x2082000:
        break
if not found:
    print("  (none found)")

# Also check 0x20815b4 for 0x1C
print("\nScanning 0x20815b4 for +0x1C accesses:")
insns6 = disasm_range(0x20815b4, 0x20815b4+0x100)
found2 = False
for i in insns6:
    if i.mnemonic in ('lwz','lhz','lbz') and '0x1c(' in i.op_str.lower():
        print(f"  0x{i.address:08x}: {i.mnemonic} {i.op_str}")
        found2 = True
    if i.mnemonic == 'blr': break
if not found2:
    print("  (none found)")
