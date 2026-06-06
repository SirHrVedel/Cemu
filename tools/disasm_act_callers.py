"""
Improved xref analysis for the nn.act IOSU module:
- Properly bound functions by finding *next* push prologue after the LDR.
- Disassemble all helpers used by the common.dat open path (0xE30E15C0):
    - 0xE30E27B8  open()/IOS_Open wrapper
    - 0xE30E14D8  cleanup/close
"""
import struct, sys, io, json
from pathlib import Path
import capstone

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DEC   = r"C:\Users\Nikolaj\source\repos\Cemu\tools\fw_decrypted.bin"
PHDRS = json.loads(Path(r"C:\Users\Nikolaj\source\repos\Cemu\tools\fw_phdrs.json").read_text())
data  = Path(DEC).read_bytes()

TEXT  = next(p for p in PHDRS["phdrs"] if p["type"]==1 and p["vaddr"]==0xE3000000)
text_lo = TEXT["abs_file_off"]
text_va = TEXT["vaddr"]
text    = data[text_lo:text_lo + TEXT["filesz"]]

md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | capstone.CS_MODE_BIG_ENDIAN)
md.detail = False

# Locate all function starts (PUSH {…, lr}) — gives function boundary list
prologues = []
for k in range(0, len(text) - 4, 4):
    w, = struct.unpack_from(">I", text, k)
    if (w & 0xFFFF0000) == 0xE92D0000 and (w & 0x00004000):
        prologues.append(k)
prologues.sort()
print(f"[*] Detected {len(prologues)} function prologues in nn.act .text")

def function_bounds(file_off_in_text):
    """Return (start, end_exclusive) of the function containing this offset."""
    import bisect
    idx = bisect.bisect_right(prologues, file_off_in_text) - 1
    if idx < 0:
        return 0, prologues[0] if prologues else len(text)
    start = prologues[idx]
    end = prologues[idx+1] if idx+1 < len(prologues) else len(text)
    return start, end

def disasm_range(off, end, va_base):
    out = []
    pos = off
    while pos < end and pos + 4 <= len(text):
        chunk = text[pos:pos+4]
        ins = list(md.disasm(chunk, va_base + pos))
        if not ins:
            v, = struct.unpack(">I", chunk)
            out.append((va_base+pos, ".word", f"{v:#010x}"))
        else:
            ins = ins[0]
            out.append((ins.address, ins.mnemonic, ins.op_str))
        pos += 4
    return out

# 1) Find ALL LDR PC-rel insns loading common.dat string VAs
TARGETS = {
    0xE3195500: '/vol/storage_mlc01/usr/save/system/act/common.dat',
    0xE31956F4: '/vol/sys/proc_ram/fpd/act/common.dat',
}
# First, find the literal-pool offsets
pools_for = {va: [] for va in TARGETS}
for va in TARGETS:
    needle = struct.pack(">I", va)
    i = 0
    while True:
        p = text.find(needle, i)
        if p == -1: break
        if p % 4 == 0: pools_for[va].append(p)
        i = p + 1

# Then find ALL LDR PC-rel insns that target any of those pools, anywhere in .text
def find_ldr_pc_rel():
    refs = []  # (ldr_off, rd, pool_off, str_va)
    for ioff in range(0, len(text) - 4, 4):
        w, = struct.unpack_from(">I", text, ioff)
        if (w & 0xFF7F0000) != 0xE51F0000:
            continue
        rd    = (w >> 12) & 0xF
        imm12 = w & 0xFFF
        u_bit = (w >> 23) & 1
        pc    = (text_va + ioff) + 8
        tgt   = pc + imm12 if u_bit else pc - imm12
        # is tgt one of our pool VAs?
        for str_va, pool_offs in pools_for.items():
            for po in pool_offs:
                if tgt == text_va + po:
                    refs.append((ioff, rd, po, str_va))
    return refs

refs = find_ldr_pc_rel()
print(f"\n[*] LDR PC-rel insns loading common.dat string VAs: {len(refs)}")
for ldr_off, rd, po, str_va in refs:
    print(f"    LDR R{rd} at {text_va+ldr_off:#010x} -> pool {text_va+po:#010x} = '{TARGETS[str_va]}'")

# Disassemble each containing function
print("\n" + "="*80)
print("FUNCTIONS that load common.dat strings (real, bounded by next prologue)")
print("="*80)
seen_funcs = set()
for ldr_off, rd, po, str_va in refs:
    fn_start, fn_end = function_bounds(ldr_off)
    if fn_start in seen_funcs: continue
    seen_funcs.add(fn_start)
    print(f"\n--- Function {text_va+fn_start:#010x} .. {text_va+fn_end:#010x}  ({fn_end-fn_start:#x} bytes) ---")
    for addr, mn, op in disasm_range(fn_start, fn_end, text_va):
        tag = ""
        for lo, rd2, p2, sv in refs:
            if addr == text_va + lo and sv == str_va:
                tag = f"   ◄── &\"{TARGETS[sv][-40:]}\""
                break
        # tag pool entries
        for sv, pool_offs in pools_for.items():
            for po2 in pool_offs:
                if addr == text_va + po2:
                    tag = f"   ◄ pool: addr of '{TARGETS[sv][-40:]}'"
        print(f"    {addr:#010x}:  {mn:<10} {op}{tag}")

# Disassemble helper functions called from 0xE30E15C0
HELPERS = [0xE30E27B8, 0xE30E14D8]
print("\n" + "="*80)
print("HELPER FUNCTIONS called from 0xE30E15C0")
print("="*80)
for va in HELPERS:
    fo = va - text_va
    if not (0 <= fo < len(text)):
        print(f"\n  {va:#010x} not in .text range")
        continue
    fn_start, fn_end = function_bounds(fo)
    print(f"\n--- Function {text_va+fn_start:#010x} .. {text_va+fn_end:#010x} ---")
    for addr, mn, op in disasm_range(fn_start, fn_end, text_va):
        # tag pool entries that lie inside this function
        tag = ""
        if mn == ".word":
            v = int(op, 16)
            # try resolve to a string in seg53 (.rodata)
            if 0xE3180000 <= v < 0xE3180000 + 0x2C78C:
                # read string from data
                file_off_str = v - 0xE3180000 + next(p for p in PHDRS["phdrs"]
                                                     if p["vaddr"]==0xE3180000)["abs_file_off"]
                end = data.find(b"\x00", file_off_str)
                if end > file_off_str and end - file_off_str < 200:
                    s = data[file_off_str:end].decode('ascii','replace')
                    tag = f"   ◄ &'{s}'"
        print(f"    {addr:#010x}:  {mn:<10} {op}{tag}")
