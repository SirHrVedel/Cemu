"""
Locate functions in fw.img that reference 'common.dat' file paths.
Big-endian ARMv7 (Starbuck IOSU runs in BE mode).
"""
import struct, sys, io
from pathlib import Path
import capstone

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DEC_PATH = r"C:\Users\Nikolaj\source\repos\Cemu\tools\fw_decrypted.bin"
data = Path(DEC_PATH).read_bytes()
print(f"[*] Decrypted firmware: {len(data):#x} bytes  (BE ARMv7)")

# ── Locate strings (extract full paths) ────────────────────────────────────────
TARGET = b"common.dat"
hits = []
i = 0
while True:
    p = data.find(TARGET, i)
    if p == -1: break
    s = p
    while s > 0 and data[s-1] != 0:
        s -= 1
    e = p + len(TARGET)
    while e < len(data) and data[e] != 0:
        e += 1
    full = data[s:e].decode('ascii','replace')
    hits.append((s, e, full))  # s = file offset of string start
    i = p + 1

print(f"[*] Found {len(hits)} 'common.dat' string(s):")
for s, e, full in hits:
    print(f"    offset {s:#010x}: '{full}'")

# ── Determine load base ───────────────────────────────────────────────────────
# From BE disassembly at 0x6CF0 we saw:
#   bl #0x173a4  → target = pc + 8 + (imm * 4) where pc = absolute_va_of_instr
# The branch landed at 0x173A4 with no base offset — strongly suggests base = 0.
# Let's verify by trying base=0 with BE string pointers.

BASE_CANDIDATES = [0x00000000, 0x05100000, 0x08000000, 0x10000000,
                   0x20000000, 0xFFFF0000, 0xFFFFFFFE]

def find_be_uint32(data, value):
    needle = struct.pack(">I", value & 0xFFFFFFFF)
    found = []
    i = 0
    while True:
        p = data.find(needle, i)
        if p == -1: break
        if p % 4 == 0:
            found.append(p)
        i = p + 1
    return found

print("\n[*] Searching for string VAs (BE 4-byte pointers) at each candidate base …")
best_base = None
best_total = -1
for base in BASE_CANDIDATES:
    total = 0
    detail = []
    for s, _, _ in hits:
        va = (base + s) & 0xFFFFFFFF
        refs = find_be_uint32(data, va)
        total += len(refs)
        detail.append((s, va, len(refs)))
    print(f"  base={base:#010x}: total_refs={total}  details={detail}")
    if total > best_total:
        best_total = total
        best_base = base

# Also search broadly for BE pointers into the strings area to find the right base
print("\n[*] Broad scan: look for any BE 4-byte value in [0xD8B000..0xD8C000] range …")
range_lo, range_hi = 0x00D8B000, 0x00D8C000
candidate_pointers = {}
for ioff in range(0, len(data) - 4, 4):
    v, = struct.unpack_from(">I", data, ioff)
    # Strip possible load base offsets
    for try_base in (0, 0x05100000, 0x08000000, 0x10000000, 0x20000000):
        off_in_file = (v - try_base) & 0xFFFFFFFF
        if range_lo <= off_in_file < range_hi:
            candidate_pointers.setdefault(try_base, []).append((ioff, v, off_in_file))
            break
for tb, lst in candidate_pointers.items():
    print(f"  base={tb:#010x}: {len(lst)} candidate pointers — first 5: {lst[:5]}")

if best_total == 0 and candidate_pointers:
    # Pick the base with the most pointers into the string range
    best_base = max(candidate_pointers, key=lambda k: len(candidate_pointers[k]))
    print(f"\n[*] Choosing base={best_base:#010x} based on broad pointer scan")

# ── For each string, find xrefs and disassemble ───────────────────────────────
print(f"\n[*] Using load base: {best_base:#010x}")

def find_function_start_be(data, ioff, max_back=0x2000):
    """Walk back from ioff to find an ARM function prologue (BE)."""
    off = ioff & ~3
    limit = max(0, off - max_back)
    for k in range(off, limit, -4):
        if k + 3 >= len(data): continue
        w, = struct.unpack_from(">I", data, k)
        # PUSH {…, lr}: E92D??F? or E92D?4?? (bit14 of register list = LR)
        if (w & 0xFFFF0000) == 0xE92D0000 and (w & 0x00004000):
            return k
    return max(0, ioff - 256)

md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | capstone.CS_MODE_BIG_ENDIAN)
md.detail = False

def disasm_at(off, length=768, base=0):
    chunk = data[off:off+length]
    out = []
    for insn in md.disasm(chunk, base + off):
        out.append((insn.address, insn.mnemonic, insn.op_str))
    return out

for s, _, full in hits:
    va = (best_base + s) & 0xFFFFFFFF
    print(f"\n{'='*72}")
    print(f"STRING: '{full}'")
    print(f"  File offset: {s:#010x}   VA: {va:#010x}")
    pool_refs = find_be_uint32(data, va)
    print(f"  Literal pool entries pointing to it: {len(pool_refs)}")
    for pref in pool_refs[:5]:
        print(f"    pool entry at {pref:#010x}  (VA {best_base+pref:#010x})")

    if not pool_refs:
        # Show raw hex near string start
        print("  No xrefs found. Hex dump near pool candidate (next 64 bytes):")
        # Try to also see if the address is encoded differently
        # (e.g. ADR-style splits)
        continue

    for pref in pool_refs[:3]:
        # Find LDR Rd, [PC, #N] instructions that load this pool entry
        # BE ARM word: E5{1,9}F???? with rn=15 (PC)
        ldr_refs = []
        for ioff in range(max(0, pref - 0x2000), min(len(data)-4, pref + 0x2000), 4):
            w, = struct.unpack_from(">I", data, ioff)
            if (w & 0xFFFF0000) in (0xE59F0000, 0xE59F1000, 0xE59F2000, 0xE59F3000,
                                    0xE59F4000, 0xE59F5000, 0xE59F6000, 0xE59F7000,
                                    0xE59F8000, 0xE59F9000, 0xE59FA000, 0xE59FB000,
                                    0xE59FC000) \
               or (w & 0xFF7F0000) == 0xE51F0000:
                u_bit    = (w >> 23) & 1
                offset12 = w & 0xFFF
                pc_val   = (best_base + ioff) + 8
                computed = pc_val + offset12 if u_bit else pc_val - offset12
                if computed == best_base + pref:
                    ldr_refs.append(ioff)

        print(f"\n  Pool {pref:#010x}: {len(ldr_refs)} LDR instruction(s) load this address")
        for ldr_off in ldr_refs[:2]:
            fn_start = find_function_start_be(data, ldr_off)
            print(f"\n    LDR at {best_base+ldr_off:#010x}  Function ~{best_base+fn_start:#010x}")
            print(f"    Disassembly:")
            insns = disasm_at(fn_start, 1024, best_base)
            shown = 0
            for addr, mn, op in insns:
                marker = ""
                if addr == best_base + ldr_off:
                    marker = "   ◄── loads &\"" + full + "\""
                print(f"      {addr:#010x}:  {mn:<10} {op}{marker}")
                shown += 1
                # Stop at next function (BX LR) + one or two extra instructions
                if (mn == "bx" and op == "lr") or mn == "pop":
                    if "pc" in op:
                        print(f"      --- end of function ---")
                        break
                if shown > 60:
                    break
