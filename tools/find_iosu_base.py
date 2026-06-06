"""
Find the IOSU ARM load base address and locate common.dat xrefs.

Strategy:
1. Find ARM exception vector table (7-8 consecutive B instructions: 0x??_??_??_EA)
   near the start of the file to determine load base.
2. Find all occurrences of the string VA as a 4-byte LE literal in the code.
3. Disassemble the function that contains each LDR.
"""
import struct, sys, io, hashlib
from pathlib import Path

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DEC_PATH = r"C:\Users\Nikolaj\source\repos\Cemu\tools\fw_decrypted.bin"
data = Path(DEC_PATH).read_bytes()
print(f"[*] Decrypted firmware: {len(data):#x} bytes")

# ── Step 1: find ARM exception vector table ────────────────────────────────────
# ARM B instruction (unconditional): 0xEA?????? in big-endian = ?????? EA in LE memory
# So in file bytes (LE): last byte is 0xEA
# The exception vector has 7-8 of these in a row at 4-byte intervals

def find_vector_table(data, min_branches=5):
    """Find offset of ARM exception vector table."""
    candidates = []
    for i in range(0, len(data) - 32, 4):
        count = 0
        for j in range(8):
            if i + j*4 + 3 >= len(data):
                break
            w = data[i + j*4 + 3]  # last byte of LE word
            if w in (0xEA, 0xEB):   # B or BL
                count += 1
            else:
                break
        if count >= min_branches:
            candidates.append((i, count))
    return candidates

print("[*] Scanning for ARM exception vector table …")
vtables = find_vector_table(data)
for off, cnt in vtables[:10]:
    print(f"  Candidate vector table at file offset {off:#010x}  ({cnt} branch instructions)")

# ── Step 2: determine load base ───────────────────────────────────────────────
# The vector table branches to specific addresses.
# If the vector table is at file offset F, and the load base is B,
# then VA of the vector = B + F.
# A branch target B instruction: 0xEA?????? where ?????? is signed 24-bit offset
# branch target VA = (PC + 8) + (signext(imm24) << 2)
# PC = VA of the B instruction = B + F + j*4

# From the first vector table candidate, decode branches and find self-consistent base
def decode_arm_branch(word_le):
    """Decode ARM B instruction, return 24-bit signed immediate (not yet added to PC)."""
    w, = struct.unpack("<I", word_le)
    imm24 = w & 0xFFFFFF
    # Sign extend 24-bit
    if imm24 & 0x800000:
        imm24 -= 0x1000000
    return imm24

if vtables:
    best_off, _ = vtables[0]
    print(f"\n[*] Using vector table candidate at file offset {best_off:#010x}")
    print(f"    Branch targets (assuming base=0):")
    for j in range(8):
        off = best_off + j*4
        if off + 4 > len(data):
            break
        word = data[off:off+4]
        w, = struct.unpack("<I", word)
        op = (w >> 24) & 0xFF
        if op not in (0xEA, 0xEB):
            break
        imm = decode_arm_branch(word)
        # target_va = pc + 8 + imm*4 where pc = base + off
        # If base = 0: target_va = off + 8 + imm*4
        target_no_base = off + 8 + imm * 4
        print(f"    Vector[{j}] at offset {off:#010x}: B {target_no_base:#010x}")

# ── Step 3: find load base by cross-referencing string address ────────────────
# For each candidate base B, compute string_va = B + string_file_offset
# Then search for 4-byte LE encoding of string_va in the data.

STRING_OFFSETS = [0x00d8bc8b, 0x00d8be72]

print(f"\n[*] Brute-forcing load base using string literal pool search …")
print(f"    Scanning 0x0000_0000 to 0x1000_0000 in steps of 0x1000 …")

best_base = None
best_hits = 0

for base in range(0x00000000, 0x10000000, 0x1000):
    total_hits = 0
    for str_off in STRING_OFFSETS:
        va = base + str_off
        needle = struct.pack("<I", va)
        idx = 0
        while True:
            p = data.find(needle, idx)
            if p == -1:
                break
            if p % 4 == 0:
                total_hits += 1
            idx = p + 1
    if total_hits > best_hits:
        best_hits = total_hits
        best_base = base
        if total_hits >= len(STRING_OFFSETS) * 2:
            print(f"  Found base candidate {base:#010x} with {total_hits} hits")

print(f"\n  Best base: {best_base:#010x}  ({best_hits} hits)")

if best_base is None or best_hits == 0:
    print("[!] Could not determine base. Trying known IOSU bases explicitly:")
    for base in [0x00000000, 0x01000000, 0x05000000, 0x08000000,
                 0x0C000000, 0x10000000, 0xE0000000, 0xFF000000]:
        for str_off in STRING_OFFSETS:
            va = base + str_off
            needle = struct.pack("<I", va)
            hits = []
            idx = 0
            while True:
                p = data.find(needle, idx)
                if p == -1:
                    break
                if p % 4 == 0:
                    hits.append(p)
                idx = p + 1
            if hits:
                print(f"  base={base:#010x}  string_va={va:#010x}  literal pool refs: {hits}")
    sys.exit(0)

# ── Step 4: with best_base, find xrefs and disassemble ────────────────────────

def find_function_start_arm(data, offset, max_back=0x2000):
    off = offset & ~3
    limit = max(0, off - max_back)
    for i in range(off, limit, -4):
        if i + 3 >= len(data):
            continue
        w, = struct.unpack_from("<I", data, i)
        # PUSH {???, lr}: E92D???? with bit 14 set
        if (w & 0xFFFF0000) == 0xE92D0000 and (w & 0x4000):
            return i
    return max(0, offset - 512)

def disasm_at(data, file_offset, length=512, base_va=0):
    if not HAS_CAPSTONE:
        return ["(capstone unavailable)"]
    va_start = base_va + file_offset
    chunk    = data[file_offset : file_offset + length]
    out = []
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    md.detail = False
    lines = list(md.disasm(chunk, va_start))
    if not lines:
        md2 = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        md2.detail = False
        lines = list(md2.disasm(chunk, va_start))
    for insn in lines[:100]:
        out.append(f"  {insn.address:#010x}:  {insn.mnemonic:<10} {insn.op_str}")
    return out

print(f"\n[*] Cross-reference analysis with base={best_base:#010x}")

for str_off in STRING_OFFSETS:
    str_va = best_base + str_off
    # Extract full path string
    s = str_off
    while s > 0 and data[s-1] not in (0,):
        s -= 1
    e = str_off + len(b"common.dat")
    while e < len(data) and data[e] != 0:
        e += 1
    try:
        full_str = data[s:e].decode('ascii', 'replace')
    except Exception:
        full_str = repr(data[s:e])

    print(f"\n{'='*72}")
    print(f"  String: '{full_str}'")
    print(f"  File offset: {str_off:#010x}  VA: {str_va:#010x}")

    # Find literal pool entries containing str_va
    needle = struct.pack("<I", str_va)
    pool_offsets = []
    idx = 0
    while True:
        p = data.find(needle, idx)
        if p == -1:
            break
        if p % 4 == 0:
            pool_offsets.append(p)
        idx = p + 1

    print(f"  Literal pool entries: {len(pool_offsets)}")
    for pool_off in pool_offsets[:5]:
        pool_va = best_base + pool_off
        print(f"\n  Pool entry at file offset {pool_off:#010x}  VA={pool_va:#010x}")

        # Find LDR PC-relative instructions pointing here
        refs = []
        search_start = max(0, pool_off - 8192)
        search_end   = min(len(data) - 4, pool_off + 8192)
        for ioff in range(search_start, search_end, 4):
            w, = struct.unpack_from("<I", data, ioff)
            # ARM LDR Rd, [PC, #+/-N]  — E59F???? or E51F????
            if (w & 0xFF700000) in (0xE5100000, 0xE5900000) and ((w >> 16) & 0xF) == 15:
                u_bit    = (w >> 23) & 1
                offset12 = w & 0xFFF
                pc_val   = ioff + 8
                computed = pc_val + offset12 if u_bit else pc_val - offset12
                if computed == pool_off:
                    refs.append(ioff)
            # Thumb LDR Rd, [PC, #N]  — 0x48XX (1-word), or 0xF8DF (2-word)
            # Also check 2-byte aligned for THUMB
            if ioff % 2 == 0 and ioff + 1 < len(data):
                hw = (data[ioff+1] << 8) | data[ioff]  # LE halfword
                if (hw >> 11) == 0b01001:  # THUMB LDR Rd, [PC, #imm8*4]
                    rd  = (hw >> 8) & 7
                    imm = (hw & 0xFF) * 4
                    pc_val = (ioff + 4) & ~2  # THUMB PC alignment
                    if pc_val + imm == pool_off:
                        refs.append(ioff)

        if not refs:
            print(f"    [!] No LDR instructions found pointing to pool entry")
            continue

        for ioff in refs[:3]:
            fn_start = find_function_start_arm(data, ioff)
            fn_va    = best_base + fn_start
            print(f"\n    LDR instruction at file offset {ioff:#010x}  VA={best_base+ioff:#010x}")
            print(f"    Function estimated start: {fn_va:#010x}")
            print(f"    Disassembly:")
            for line in disasm_at(data, fn_start, 768, best_base):
                print(line)
