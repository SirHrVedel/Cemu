"""
ARMv5TE xref search for 'common.dat' in fw_decrypted.bin.

Discovery so far:
  - String 1: '/vol/storage_mlc01/usr/save/system/act/common.dat' at file offset 0xD8BC64
  - Right before, bytes at file offset 0xD8BC50:  E3 0E 10 84  (BE u32 = 0xE30E1084)
  - 'AccountManager' string is at file offset 0xD8BC54
  - Inference: relocations applied; pointer 0xE30E1084 -> string at file offset 0xD8BC54
  - => data section base VA = 0xE30E0000;  data section file offset = 0xD8BC54 - 0x1084 = 0xD8ABD0

So predicted string VAs:
  String "AccountManager"  -> 0xE30E1084  (file 0xD8BC54)
  String "/vol/storage_mlc01/.../common.dat" -> 0xE30E0000 + (0xD8BC64 - 0xD8ABD0) = 0xE30E1094
"""
import struct, sys, io
from pathlib import Path
import capstone

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DEC = r"C:\Users\Nikolaj\source\repos\Cemu\tools\fw_decrypted.bin"
data = Path(DEC).read_bytes()

DATA_SECTION_FILE_OFF = 0x00D8ABD0
DATA_SECTION_VA       = 0xE30E0000

def file_to_va(fo):  return DATA_SECTION_VA + (fo - DATA_SECTION_FILE_OFF)
def va_to_file(va):  return DATA_SECTION_FILE_OFF + (va - DATA_SECTION_VA)

# ── locate ALL occurrences of 'common.dat' and reconstruct full paths ─────────
print("[*] Locating 'common.dat' strings (proper null-terminated extraction)…")
hits = []
i = 0
while True:
    p = data.find(b"common.dat", i)
    if p == -1: break
    # walk back to previous null (proper string start)
    s = p
    while s > 0 and 0x20 <= data[s-1] < 0x7F:
        s -= 1
    e = p + len(b"common.dat")
    while e < len(data) and data[e] != 0 and 0x20 <= data[e] < 0x7F:
        e += 1
    full = data[s:e].decode('ascii','replace')
    va   = file_to_va(s)
    hits.append((s, full, va))
    i = p + 1

for s, full, va in hits:
    print(f"  file {s:#010x}  va {va:#010x}  '{full}'")

# ── For each string, find literal-pool entries (BE 4-byte = its VA) ───────────
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | capstone.CS_MODE_BIG_ENDIAN)
md.detail = False

def find_be_u32(data, value, aligned=True):
    needle = struct.pack(">I", value & 0xFFFFFFFF)
    out, i = [], 0
    while True:
        p = data.find(needle, i)
        if p == -1: break
        if (not aligned) or (p % 4 == 0):
            out.append(p)
        i = p + 1
    return out

def find_function_start(data, ioff, max_back=0x4000):
    """Walk back to function prologue (PUSH {..., lr} or STMFD sp!, {..., lr})."""
    off = ioff & ~3
    limit = max(0, off - max_back)
    for k in range(off, limit, -4):
        w, = struct.unpack_from(">I", data, k)
        # E92D ?4?? (push with LR), or E92D ?F?? (push with PC), or
        # STMFD sp!, {…, lr}
        if (w & 0xFFFF0000) == 0xE92D0000 and (w & 0x00004000):
            return k
        # MOV ip, sp prologue used by some ARMv5 compilers (e.g. GHS)
        if w == 0xE1A0C00D and k+4 < len(data):
            return k
    return max(0, ioff - 256)

def disasm_function(off, code_base, limit=120):
    out = []
    pos = off
    for _ in range(limit):
        if pos+4 > len(data): break
        chunk = data[pos:pos+4]
        ins = list(md.disasm(chunk, code_base + pos))
        if not ins:
            v, = struct.unpack(">I", chunk)
            out.append((code_base+pos, ".word", f"{v:#010x}"))
            pos += 4
            continue
        ins = ins[0]
        out.append((ins.address, ins.mnemonic, ins.op_str))
        pos += 4
        if ins.mnemonic == "bx" and ins.op_str == "lr": break
        if ins.mnemonic in ("pop","ldm","ldmia","ldmfd","ldmea") and "pc" in ins.op_str: break
    return out

# Find ALL `LDR Rd, [PC, #imm]` instructions and resolve their pool targets.
# Encoding (BE):  E5 9F XYYY (U=1)  or  E5 1F XYYY (U=0)
# Rd = X[upper4], imm12 = (X[lower4] << 8) | YY  -- wait, simpler: imm12 = word & 0xFFF
print("\n[*] Scanning for LDR Rd, [PC, #imm] instructions that load string VAs …")

# Build code-base detection: assume CODE section sits before DATA section,
# load-contiguous. So instruction at file offset F has VA (DATA_VA - DATA_FILE_OFF) + F
CODE_BASE = DATA_SECTION_VA - DATA_SECTION_FILE_OFF
print(f"    Assuming linear mapping: instruction at file F -> VA F + {CODE_BASE:#010x}")
print(f"    (TEXT and DATA may not actually be contiguous, but try anyway.)\n")

for str_file, full, str_va in hits:
    print(f"{'='*72}")
    print(f"STRING: '{full}'")
    print(f"  file {str_file:#010x}  va {str_va:#010x}")

    pool_offs = find_be_u32(data, str_va)
    print(f"  Literal pool entries (4-byte BE u32 = {str_va:#010x}): {len(pool_offs)}")
    for po in pool_offs[:10]:
        print(f"    pool entry at file {po:#010x}  (va {CODE_BASE+po:#010x})")

    if not pool_offs:
        # Try ±1 byte offset (in case there are slightly different VAs nearby
        # due to my section-base estimate being slightly off).
        for delta in (-4, -2, -1, 1, 2, 4):
            alt = find_be_u32(data, str_va + delta)
            if alt:
                print(f"    [hint] {len(alt)} hits at VA={str_va+delta:#x} (delta={delta:+d})")
        continue

    # For each pool entry, find LDR PC-relative loads pointing to it
    for po in pool_offs[:5]:
        pool_va = CODE_BASE + po
        print(f"\n  ── Pool entry @ file {po:#010x}  va {pool_va:#010x} ──")
        ldr_hits = []
        # Window of 4096 bytes back from pool
        for ioff in range(max(0, po - 0x1000), po, 4):
            w, = struct.unpack_from(">I", data, ioff)
            # LDR Rd, [PC, #imm12] BE: E5 9F XYYY (U=1) or E5 1F XYYY (U=0)
            if (w & 0xFF7F0000) == 0xE51F0000:
                rd       = (w >> 12) & 0xF
                imm12    = w & 0xFFF
                u_bit    = (w >> 23) & 1
                pc       = (CODE_BASE + ioff) + 8
                target_va = pc + imm12 if u_bit else pc - imm12
                if target_va == pool_va:
                    ldr_hits.append((ioff, rd))

        print(f"     LDR instructions referencing this pool: {len(ldr_hits)}")
        for ldr_off, rd in ldr_hits[:3]:
            fn_start = find_function_start(data, ldr_off)
            print(f"\n     LDR R{rd} at file {ldr_off:#010x}  va {CODE_BASE+ldr_off:#010x}")
            print(f"     Function starts ~file {fn_start:#010x}  va {CODE_BASE+fn_start:#010x}")
            print(f"     Disassembly:")
            for addr, mn, op in disasm_function(fn_start, CODE_BASE, 80):
                tag = ""
                if addr == CODE_BASE + ldr_off:
                    tag = f"   ◄── loads &\"{full[:40]}…\""
                print(f"        {addr:#010x}:  {mn:<10} {op}{tag}")
