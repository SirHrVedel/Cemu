"""
Analyze decrypted fw.img:
- Find all 'common.dat' strings
- Find ARM code that references them (literal pool scan)
- Disassemble surrounding functions
"""
import struct, sys, io
from pathlib import Path

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

# Force UTF-8 output
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DEC_PATH = r"C:\Users\Nikolaj\source\repos\Cemu\tools\fw_decrypted.bin"
TARGET   = b"common.dat"

# ── Known IOSU base addresses to try ─────────────────────────────────────────
# IOSU typically loads at 0x00000000 for the kernel code
CANDIDATE_BASES = [0x00000000, 0x01000000, 0xE0000000, 0x08000000]

data = Path(DEC_PATH).read_bytes()
print(f"[*] Loaded {DEC_PATH}  ({len(data):#x} bytes)")

# ── Find all strings containing 'common.dat' ─────────────────────────────────

def extract_cstring(buf, pos):
    s = pos
    while s > 0 and buf[s-1] not in (0, 0x0A, 0x0D):
        s -= 1
    e = pos + len(TARGET)
    while e < len(buf) and buf[e] not in (0, 0x0A, 0x0D):
        e += 1
    try:
        return buf[s:e].decode('ascii', 'replace')
    except Exception:
        return repr(buf[s:e])

string_hits = []
idx = 0
while True:
    p = data.find(TARGET, idx)
    if p == -1:
        break
    full = extract_cstring(data, p)
    string_hits.append((p, full))
    idx = p + 1

print(f"[*] Found {len(string_hits)} 'common.dat' string(s):")
for off, s in string_hits:
    print(f"    offset {off:#010x}  '{s}'")

if not string_hits:
    sys.exit(1)

# ── Find code cross-references ────────────────────────────────────────────────

def find_xrefs_to_offset(data, str_offset, bases):
    """
    For each base, the string's virtual address = base + str_offset.
    Scan data for 4-byte little-endian values equal to that VA.
    Hits in code regions (where preceding/following bytes look like ARM instructions)
    are returned as (data_offset, va, base).
    """
    hits = []
    for base in bases:
        va = base + str_offset
        needle = struct.pack("<I", va)
        i = 0
        while True:
            p = data.find(needle, i)
            if p == -1:
                break
            # Only care about 4-byte aligned offsets (literal pools are aligned)
            if p % 4 == 0:
                hits.append((p, va, base))
            i = p + 1
    return hits

def find_function_start_arm(data, offset, max_back=0x2000):
    """Walk back to find ARM function prologue: PUSH {…, lr} = E92D?0?? where bit14 is set."""
    off = offset & ~3
    limit = max(0, off - max_back)
    best = off
    for i in range(off, limit, -4):
        if i + 3 >= len(data):
            continue
        w, = struct.unpack_from("<I", data, i)
        # PUSH with LR bit (bit 14 = 0x4000) — standard ARM function prologue
        if (w & 0xFFFF0000) == 0xE92D0000 and (w & 0x4000):
            return i
        # Also: STMFD sp! with LR
        if (w & 0xFFFF4000) == 0xE92D4000:
            return i
    return best

def disasm(data, start, length=512, base_va=0):
    if not HAS_CAPSTONE:
        return ["(capstone unavailable)"]
    out = []
    # Try ARM32 first
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    md.detail = False
    chunk = data[start:start+length]
    lines_arm = list(md.disasm(chunk, base_va + start))
    # Try THUMB
    md2 = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md2.detail = False
    lines_thumb = list(md2.disasm(chunk, base_va + start))
    # Use whichever got more instructions
    lines = lines_arm if len(lines_arm) >= len(lines_thumb) else lines_thumb
    for insn in lines[:80]:  # cap at 80 instructions
        out.append(f"  {insn.address:#010x}:  {insn.mnemonic:<10} {insn.op_str}")
    if not out:
        # Raw hex fallback
        for i in range(0, min(length, 64), 4):
            if start + i + 3 < len(data):
                w, = struct.unpack_from("<I", data, start + i)
                out.append(f"  {base_va+start+i:#010x}:  .word  {w:#010x}")
    return out

# ── Main analysis loop ────────────────────────────────────────────────────────

for str_offset, full_str in string_hits:
    print(f"\n{'='*72}")
    print(f"STRING: '{full_str}'")
    print(f"        file offset {str_offset:#010x}")

    xrefs = find_xrefs_to_offset(data, str_offset, CANDIDATE_BASES)
    if not xrefs:
        print("  [!] No literal pool references found for any candidate base.")
        print("      Context around the string (±64 bytes):")
        ctx_start = max(0, str_offset - 64)
        ctx = data[ctx_start : str_offset + 128]
        for r in range(0, len(ctx), 16):
            chunk = ctx[r:r+16]
            addr = ctx_start + r
            hx = " ".join(f"{b:02x}" for b in chunk)
            ac = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
            print(f"    {addr:#010x}: {hx:<48}  {ac}")
        continue

    for (pool_off, va, base) in xrefs[:5]:
        print(f"\n  Literal pool ref at file offset {pool_off:#010x}  (VA={va:#010x}, base={base:#010x})")

        # Find ARM LDR instructions that load from this literal pool entry
        # LDR Rd, [PC, #+N] = 0xE59F????  (U=1)
        # LDR Rd, [PC, #-N] = 0xE51F????  (U=0)
        ref_instrs = []
        search_start = max(0, pool_off - 8192)
        search_end   = min(len(data) - 4, pool_off + 8192)
        for ioff in range(search_start, search_end, 4):
            w, = struct.unpack_from("<I", data, ioff)
            # ARM LDR PC-relative: E51F/E59F with any reg, 12-bit offset
            if (w & 0xFF700000) == 0xE5100000 and ((w >> 16) & 0xF) == 15:
                # rn = 15 (PC), check if computed address = pool_off
                u_bit   = (w >> 23) & 1
                offset12 = w & 0xFFF
                pc_val   = ioff + 8
                computed = pc_val + offset12 if u_bit else pc_val - offset12
                if computed == pool_off:
                    ref_instrs.append(ioff)

        if not ref_instrs:
            print(f"    [!] No LDR PC-relative found pointing to {pool_off:#010x}")
            # Show code around pool entry
            ctx_start = max(0, pool_off - 32)
            ctx_end   = min(len(data), pool_off + 32)
            print(f"    Code around pool entry:")
            for line in disasm(data, ctx_start, ctx_end - ctx_start, base):
                print(f"  {line}")
            continue

        for ioff in ref_instrs[:3]:
            fn_start = find_function_start_arm(data, ioff)
            print(f"\n    LDR at file offset {ioff:#010x}  function starts ~{fn_start:#010x}")
            print(f"    Disassembly (from function start):")
            for line in disasm(data, fn_start, 512, base):
                print(line)

# ── Also: hex dump first 64 bytes of decrypted to verify ARM code ─────────────
print(f"\n{'='*72}")
print("First 64 bytes of decrypted firmware (sanity check):")
for r in range(0, 64, 16):
    chunk = data[r:r+16]
    hx = " ".join(f"{b:02x}" for b in chunk)
    ac = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
    print(f"  {r:#06x}: {hx:<48}  {ac}")

if HAS_CAPSTONE:
    print("\nDisassembly of first 64 bytes:")
    for line in disasm(data, 0, 64, 0):
        print(line)
