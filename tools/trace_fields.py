#!/usr/bin/env python3
"""
Exhaustive scan of every field in AppearArg that is accessed.
For the key scene-setup functions, trace all lwz/lhz/lbz from the AppearArg pointer.

Strategy: for each function of interest, detect which register holds the AppearArg
pointer at each point and collect all loads from it.
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

def track_arg_loads(insns, initial_arg_regs):
    """
    Walk instructions tracking which regs hold the AppearArg pointer.
    Return list of (va, mnemonic, dst_reg, offset, op_str) for loads from tracked regs.
    """
    tracked = set(initial_arg_regs)
    results = []

    for insn in insns:
        mn = insn.mnemonic
        ops = insn.op_str

        # mr rDst, rSrc -> track copy
        if mn == 'mr' and ',' in ops:
            parts = [p.strip() for p in ops.split(',')]
            if len(parts)==2 and parts[1] in tracked:
                tracked.add(parts[0])

        # addi rDst, rSrc, imm -> if imm==0 this is effectively mr (shouldn't happen)
        # we track addi only when offset is 0 (pure copy via addi rDst,rSrc,0)
        # skip for now

        # load/store from tracked pointer
        if mn in ('lwz','lhz','lbz','lwzu','lha','lbzu','stw','sth','stb'):
            if '(' in ops:
                parts = ops.split('(')
                base_part = parts[1].rstrip(')')
                left_parts = parts[0].split(',')
                dst_reg = left_parts[0].strip() if len(left_parts)>0 else ''
                offset_str = left_parts[-1].strip() if len(left_parts)>1 else left_parts[0].strip()
                if base_part in tracked:
                    try:
                        off = int(offset_str, 0)
                        results.append((insn.address, mn, dst_reg, off, ops))
                    except ValueError:
                        pass

        # A branch clears tracking in the branch target (conservative: keep tracking)
        # For simplicity we don't do full CFG; just linear scan

    return results


# ─── AppearInputForm wrapper: r31 = AppearArg ────────────────────────────────
# We know:
#   sub_02080cd4: r31 = AppearArg
#     - reads: AppearArg+0x00 (inputType), +0x9c (language), +0xc0 (inputFormType)
#   sub_02072430: r30 = AppearArg (passed as r4)
#   sub_02072810: r30 = AppearArg (passed as r4)
#   sub_0x20ac6cc: r28 = AppearArg (r4 on entry)
#                  reads r28+4 = AppearArg+0x04

# Let's trace sub_02080cd4 more carefully
print("=== sub_02080cd4: AppearArg field accesses (r31=AppearArg) ===")
insns = disasm_range(0x02080cd4, 0x02080dfc)
results = track_arg_loads(insns, {'r31'})
seen = {}
for va, mn, reg, off, ops in results:
    if off not in seen:
        seen[off] = []
    seen[off].append((va, mn, reg, ops))
for off in sorted(seen.keys()):
    for va, mn, reg, ops in seen[off]:
        print(f"  AppearArg+0x{off:03x}  {mn:<6}  r={reg}  @ 0x{va:08x}:  {ops}")

# ─── sub_02072430: r30=AppearArg ─────────────────────────────────────────────
print("\n=== sub_02072430: AppearArg field accesses (r30=AppearArg, r5=&arg->inputFormType) ===")
insns = disasm_range(0x02072430, 0x020724d8)  # first function in this group
results = track_arg_loads(insns, {'r30'})
seen = {}
for va, mn, reg, off, ops in results:
    if off not in seen: seen[off] = []
    seen[off].append((va, mn, reg, ops))
for off in sorted(seen.keys()):
    for va, mn, reg, ops in seen[off]:
        print(f"  AppearArg+0x{off:03x}  {mn:<6}  r={reg}  @ 0x{va:08x}:  {ops}")

# ─── sub_0x20ac6cc: r28=AppearArg ────────────────────────────────────────────
print("\n=== 0x20ac6cc: AppearArg field accesses (r28=AppearArg) ===")
insns = disasm_range(0x020ac6cc, 0x020ac8d0)
results = track_arg_loads(insns, {'r28'})
seen = {}
for va, mn, reg, off, ops in results:
    if off not in seen: seen[off] = []
    seen[off].append((va, mn, reg, ops))
for off in sorted(seen.keys()):
    for va, mn, reg, ops in seen[off]:
        print(f"  AppearArg+0x{off:03x}  {mn:<6}  r={reg}  @ 0x{va:08x}:  {ops}")

# ─── sub_0x20ad04c: r? = AppearArg ───────────────────────────────────────────
# in sub_02072810, it calls 0x20ad04c(scene_mgr, appArg, &appArg->inputFormType)
# so r4=AppearArg on entry to 0x20ad04c
print("\n=== 0x20ad04c: AppearArg field accesses (figure out arg reg) ===")
insns = disasm_range(0x020ad04c, 0x020ad200)
# On entry: r3=scene_instance, r4=AppearArg, r5=&arg->inputFormType
# first insns establish which reg holds what
for i in insns[:20]:
    print(f"  0x{i.address:08x}:  {i.mnemonic:<10} {i.op_str}")
print("  ---tracking from r4=AppearArg---")
results = track_arg_loads(insns, {'r4'})
# But r4 gets overwritten by mr rX, r4 style at entry
# let's also check what r3 becomes
seen = {}
for va, mn, reg, off, ops in results:
    if off not in seen: seen[off] = []
    seen[off].append((va, mn, reg, ops))
for off in sorted(seen.keys()):
    for va, mn, reg, ops in seen[off]:
        print(f"  AppearArg+0x{off:03x}  {mn:<6}  r={reg}  @ 0x{va:08x}:  {ops}")

# Let's also look at the full 0x20ac8b4 region which seems to call an enter with r28
print("\n=== Scanning 0x20ac870..0x20ac8d0 for AppearArg refs ===")
insns2 = disasm_range(0x020ac870, 0x020ac8d0)
for i in insns2:
    print(f"  0x{i.address:08x}:  {i.mnemonic:<10} {i.op_str}")
