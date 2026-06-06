"""
Fast approach: IOSU ARM firmware may be big-endian.
Also try specific known IOSU load bases rather than a full scan.
Look for function signatures near the strings context area.
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

STRING_OFFSETS = [0x00d8bc8b, 0x00d8be72]

# ── 1. Determine endianness by scanning for vector table ──────────────────────
print("[*] Scanning for ARM exception vector table …")
# Big-endian ARM:  branch = 0xEA?????? → first byte EA
# Little-endian:   branch = ????EA → last byte EA
le_vtable_candidates = []
be_vtable_candidates = []

for i in range(0, min(0x100000, len(data) - 32), 4):
    # Little-endian scan
    le_count = sum(1 for j in range(8)
                   if (i+j*4+3 < len(data)) and data[i+j*4+3] in (0xEA, 0xEB))
    if le_count >= 5:
        le_vtable_candidates.append((i, le_count))
    # Big-endian scan
    be_count = sum(1 for j in range(8)
                   if (i+j*4 < len(data)) and data[i+j*4] in (0xEA, 0xEB))
    if be_count >= 5:
        be_vtable_candidates.append((i, be_count))

print(f"  LE vector table candidates: {le_vtable_candidates[:5]}")
print(f"  BE vector table candidates: {be_vtable_candidates[:5]}")

# ── 2. Try specific IOSU load bases (from Wii U research) ─────────────────────
# IOSU kernel: 0x08000000 (ARM secure world)
# IOSU kernel alt: 0x00000000, 0x00800000, 0x01000000
KNOWN_BASES = [
    0x00000000, 0x00800000, 0x01000000, 0x02000000,
    0x05000000, 0x08000000, 0x0C000000, 0x10000000,
    0x20000000, 0xE0000000,
]

print("\n[*] Testing known IOSU load bases (both LE and BE encoding) …")
results = []
for base in KNOWN_BASES:
    for str_off in STRING_OFFSETS:
        va = base + str_off
        for endian, fmt in [("LE", "<I"), ("BE", ">I")]:
            needle = struct.pack(fmt, va)
            count = 0
            i = 0
            positions = []
            while True:
                p = data.find(needle, i)
                if p == -1:
                    break
                if p % 4 == 0:
                    count += 1
                    positions.append(p)
                i = p + 1
            if count > 0:
                results.append((base, str_off, va, endian, count, positions[:3]))
                print(f"  base={base:#010x}  str_off={str_off:#010x}  VA={va:#010x}  [{endian}]  hits={count}  at={[f'{p:#010x}' for p in positions[:3]]}")

if not results:
    print("  [!] No hits with known bases – trying wider scan with step 0x10000 …")
    for base in range(0, 0x20000000, 0x10000):
        for endian, fmt in [("LE", "<I"), ("BE", ">I")]:
            total = 0
            for str_off in STRING_OFFSETS:
                va = base + str_off
                needle = struct.pack(fmt, va)
                p = data.find(needle)
                if p != -1 and p % 4 == 0:
                    total += 1
            if total >= 2:
                print(f"  HIT: base={base:#010x}  [{endian}]  total={total}")
                results.append((base, 0, 0, endian, total, []))

# ── 3. Context analysis: what's NEAR the strings? ────────────────────────────
print("\n[*] Context around strings – looking for nearby code patterns …")
for str_off in STRING_OFFSETS:
    # Extract full string
    s = str_off
    while s > 0 and data[s-1] not in (0,):
        s -= 1
    e = str_off + 10
    while e < len(data) and data[e] != 0:
        e += 1
    try:
        full = data[s:e].decode('ascii', 'replace')
    except:
        full = "?"

    print(f"\n  String '{full}' @ {str_off:#010x}")

    # Scan backwards from string for nearest code (PUSH instruction)
    print(f"  Scanning backwards for ARM function prologues …")
    for look_back in range(4, 0x10000, 4):
        off = str_off - look_back
        if off < 0:
            break
        w_le, = struct.unpack_from("<I", data, off)
        w_be, = struct.unpack_from(">I", data, off)
        # LE ARM PUSH {r?, lr}: E92D???? with bit 14
        if (w_le & 0xFFFF0000) == 0xE92D0000 and (w_le & 0x4000):
            print(f"  Found LE ARM PUSH at offset {off:#010x} (d={look_back:#x} before string)")
            break
        # BE ARM PUSH: same value but in big-endian storage
        if (w_be & 0xFFFF0000) == 0xE92D0000 and (w_be & 0x4000):
            print(f"  Found BE ARM PUSH at offset {off:#010x} (d={look_back:#x} before string)")
            break

# ── 4. Disassemble surrounding area using both LE/BE ARM ─────────────────────
if HAS_CAPSTONE and results:
    best = sorted(results, key=lambda x: -x[4])[0]
    base, _, _, endian, _, _ = best
    print(f"\n[*] Best base: {base:#010x}  endian: {endian}")

    # Find all literal pool entries and disassemble their referencing functions
    for str_off in STRING_OFFSETS:
        va = base + str_off
        fmt = "<I" if endian == "LE" else ">I"
        needle = struct.pack(fmt, va)

        s = str_off
        while s > 0 and data[s-1] != 0:
            s -= 1
        e = str_off + 10
        while e < len(data) and data[e] != 0:
            e += 1
        full = data[s:e].decode('ascii','replace')

        print(f"\n{'='*72}")
        print(f"String: '{full}'  file_off={str_off:#010x}  VA={va:#010x}")

        pool_offsets = []
        i = 0
        while True:
            p = data.find(needle, i)
            if p == -1:
                break
            if p % 4 == 0:
                pool_offsets.append(p)
            i = p + 1

        cs_mode = capstone.CS_MODE_ARM
        if endian == "BE":
            cs_mode |= capstone.CS_MODE_BIG_ENDIAN
        else:
            cs_mode |= capstone.CS_MODE_LITTLE_ENDIAN

        for pool_off in pool_offsets[:3]:
            pool_va = base + pool_off
            print(f"\n  Literal pool at file_off={pool_off:#010x}  VA={pool_va:#010x}")

            # Find LDR instructions referencing this pool entry
            # In ARM32 (both LE and BE): LDR Rd, [PC, #+/-N] = E59F / E51F
            # Search in nearby code
            refs = []
            for ioff in range(max(0, pool_off - 8192), min(len(data)-4, pool_off+8192), 4):
                if endian == "LE":
                    w, = struct.unpack_from("<I", data, ioff)
                else:
                    w, = struct.unpack_from(">I", data, ioff)
                if (w & 0xFF700000) in (0xE5100000, 0xE5900000) and ((w >> 16) & 0xF) == 15:
                    u_bit    = (w >> 23) & 1
                    offset12 = w & 0xFFF
                    pc_val   = (base + ioff) + 8
                    computed_va = pc_val + offset12 if u_bit else pc_val - offset12
                    if computed_va == pool_va:
                        refs.append(ioff)

            for ioff in refs[:2]:
                # Find function start (backwards scan for PUSH {??, lr})
                fn_off = ioff
                for k in range(ioff, max(0, ioff - 0x2000), -4):
                    if endian == "LE":
                        fw, = struct.unpack_from("<I", data, k)
                    else:
                        fw, = struct.unpack_from(">I", data, k)
                    if (fw & 0xFFFF0000) == 0xE92D0000 and (fw & 0x4000):
                        fn_off = k
                        break

                fn_va = base + fn_off
                print(f"\n  LDR at {base+ioff:#010x}  Function starts at {fn_va:#010x}")

                md = capstone.Cs(capstone.CS_ARCH_ARM, cs_mode)
                md.detail = False
                chunk = data[fn_off:fn_off+512]
                for insn in list(md.disasm(chunk, fn_va))[:80]:
                    marker = " ◄── loads common.dat ptr" if insn.address == base + ioff else ""
                    print(f"  {insn.address:#010x}:  {insn.mnemonic:<10} {insn.op_str}{marker}")
