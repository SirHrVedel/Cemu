"""
Decrypt fw.img (Wii U Ancast/Starbuck ARM firmware) and find common.dat references.

Ancast header layout (0x200 bytes):
  0x000-0x003: magic 0xEFA282D9
  0x004-0x007: flags/version
  0x008-0x00B: inner header offset? (0x20)
  0x020-0x11F: RSA-2048 signature (256 bytes)
  0x1A0-0x1A7: ?
  0x1A8-0x1AB: target type (0x02 = Starbuck ARM)
  0x1AC-0x1AF: payload size
  0x1B0-0x1BF: AES-128-CBC IV
  0x200+:       encrypted payload
"""

import struct, hashlib, sys
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError:
    from Cryptodome.Cipher import AES

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    print("[WARN] capstone not available – disassembly skipped")

FW_PATH  = r"D:\Games\Console\Cafe\storage_slc\sys\title\00050010\1000400a\code\fw.img"
OTP_PATH = r"C:\Users\Nikolaj\AppData\Roaming\Cemu\otp.bin"
OUT_PATH = r"C:\Users\Nikolaj\source\repos\Cemu\tools\fw_decrypted.bin"
TARGET   = b"common.dat"

# ── Key extraction ────────────────────────────────────────────────────────────

otp = Path(OTP_PATH).read_bytes()
STARBUCK_KEY = otp[0x090:0x090 + 16]
print(f"[*] Starbuck ancast key: {STARBUCK_KEY.hex()}")

# ── Parse Ancast header ───────────────────────────────────────────────────────

fw_raw = Path(FW_PATH).read_bytes()
print(f"[*] fw.img size: {len(fw_raw):#x} bytes")

magic, = struct.unpack_from(">I", fw_raw, 0)
assert magic == 0xEFA282D9, f"Bad magic: {magic:#010x}"

# Try candidate IV positions in the header
iv_candidates = {
    "0x010": fw_raw[0x010:0x020],
    "0x1B0": fw_raw[0x1B0:0x1C0],
    "0x030": fw_raw[0x030:0x040],
    "0x040": fw_raw[0x040:0x050],
    "zero":  bytes(16),
}

# Payload size from header offset 0x1AC
payload_size_field, = struct.unpack_from(">I", fw_raw, 0x1AC)
header_size = 0x200
print(f"[*] Payload size from header: {payload_size_field:#x}")
print(f"[*] Actual data after header: {len(fw_raw) - header_size:#x}")
payload_size = min(payload_size_field, len(fw_raw) - header_size)
# Align to 16 bytes for AES
payload_size = (payload_size // 16) * 16
encrypted_payload = fw_raw[header_size : header_size + payload_size]
print(f"[*] Using payload: {len(encrypted_payload):#x} bytes  ({len(encrypted_payload)} bytes)")

# ── Try each IV candidate ─────────────────────────────────────────────────────

def looks_like_arm(data):
    """Heuristic: first 256 bytes of decrypted data should look like ARM code
    (many 4-byte aligned words with ARM instruction patterns)."""
    if len(data) < 256:
        return False
    # ARM exception vector table check: first 8 words should be
    #   b/ldr pc, instructions (0xEA... or 0xE5... patterns)
    count = 0
    for i in range(0, 64, 4):
        w, = struct.unpack_from("<I", data, i)
        # Common ARM branch: 0xEA??????
        if (w >> 24) in (0xEA, 0xE5, 0xEB, 0xE3, 0xE2, 0xE1, 0xE0, 0xE9, 0xE8):
            count += 1
    return count >= 3

decrypted = None
winning_iv_name = None

print("\n[*] Trying IV candidates …")
for iv_name, iv in iv_candidates.items():
    try:
        cipher = AES.new(STARBUCK_KEY, AES.MODE_CBC, iv=iv)
        dec = cipher.decrypt(encrypted_payload[:4096])  # Just first 4K for test
        arm_score = sum(1 for i in range(0, 64, 4)
                        if (struct.unpack_from("<I", dec, i)[0] >> 24) in
                        (0xEA, 0xE5, 0xEB, 0xE3, 0xE2, 0xE1, 0xE0, 0xE9, 0xE8, 0xE6, 0xE7))
        print(f"  IV[{iv_name}] = {iv.hex()}  ARM score: {arm_score}")
        if arm_score >= 3 and decrypted is None:
            print(f"  → Selected IV: {iv_name}")
            winning_iv_name = iv_name
            # Decrypt full payload
            cipher2 = AES.new(STARBUCK_KEY, AES.MODE_CBC, iv=iv)
            decrypted = cipher2.decrypt(encrypted_payload)
    except Exception as e:
        print(f"  IV[{iv_name}] error: {e}")

# Fallback: try all 16-byte aligned windows in header
if decrypted is None:
    print("\n[*] No obvious ARM match – brute-forcing IV from header …")
    best_score = 0
    for off in range(0, header_size - 16, 4):
        iv = fw_raw[off:off+16]
        if iv == bytes(16):
            continue
        try:
            cipher = AES.new(STARBUCK_KEY, AES.MODE_CBC, iv=iv)
            dec = cipher.decrypt(encrypted_payload[:256])
            score = sum(1 for i in range(0, 64, 4)
                       if (struct.unpack_from("<I", dec, i)[0] >> 24) in
                       (0xEA, 0xE5, 0xEB, 0xE3, 0xE2, 0xE1, 0xE0, 0xE9, 0xE8))
            if score > best_score:
                best_score = score
                best_iv = iv
                best_off = off
        except Exception:
            pass
    print(f"  Best IV at header offset {best_off:#05x}: {best_iv.hex()}  score={best_score}")
    if best_score >= 2:
        winning_iv_name = f"header+{best_off:#05x}"
        cipher2 = AES.new(STARBUCK_KEY, AES.MODE_CBC, iv=best_iv)
        decrypted = cipher2.decrypt(encrypted_payload)

if decrypted is None:
    print("[!] Could not find a working IV – trying zero IV with full decrypt check")
    cipher2 = AES.new(STARBUCK_KEY, AES.MODE_CBC, iv=bytes(16))
    decrypted = cipher2.decrypt(encrypted_payload)
    winning_iv_name = "zero (fallback)"

print(f"\n[*] Decrypted {len(decrypted):#x} bytes (IV: {winning_iv_name})")
print(f"[*] First 32 bytes of decrypted: {decrypted[:32].hex()}")

# ── Save decrypted binary ─────────────────────────────────────────────────────

Path(OUT_PATH).write_bytes(decrypted)
print(f"[*] Saved decrypted binary to: {OUT_PATH}")

# ── Search for 'common.dat' and extract function context ──────────────────────

print(f"\n[*] Searching for b'{TARGET.decode()}' in decrypted firmware …")

string_offsets = []
idx = 0
while True:
    pos = decrypted.find(TARGET, idx)
    if pos == -1:
        break
    # Extract surrounding null-terminated string
    str_start = pos
    while str_start > 0 and decrypted[str_start-1] != 0:
        str_start -= 1
    str_end = pos + len(TARGET)
    while str_end < len(decrypted) and decrypted[str_end] != 0:
        str_end += 1
    full_str = decrypted[str_start:str_end]
    print(f"\n  [STRING] offset={pos:#010x}  '{full_str.decode('ascii','replace')}'")
    string_offsets.append((pos, full_str.decode('ascii', 'replace')))
    idx = pos + 1

if not string_offsets:
    print("  [!] 'common.dat' not found in decrypted firmware")
    print("       Searching for 'common' and '.dat' separately …")
    for kw in (b"common", b"/vol/", b"act/", b"account"):
        i = 0
        while True:
            p = decrypted.find(kw, i)
            if p == -1:
                break
            ctx = decrypted[max(0,p-4):p+32]
            print(f"  kw={kw!r}  offset={p:#010x}  ctx={ctx!r}")
            i = p + 1
            if i - decrypted.find(kw, 0) > 200:
                break
    sys.exit(0)

# ── Cross-reference scan (ARM32/THUMB load-literal patterns) ──────────────────

def find_arm_xrefs(data, string_offset, search_radius=0x200000):
    """
    Find ARM/Thumb instructions that reference string_offset.
    ARM uses PC-relative LDR (ldr rX, [pc, #offset]) or ADR.
    We scan backwards from the string to find code that loads its address.

    In IOSU code:
    - LDR rX, [PC, #N]:  E51F???? or E59F???? (ARM32)
    - The loaded value must equal the absolute address of string_offset.

    Since we don't know the load address, we look for references to
    (string_offset + likely_base) where likely_base is typically 0x00000000,
    0x01000000, or read from the header.
    """
    hits = []
    # Common IOSU base addresses
    bases = [0x00000000, 0x01000000, 0x08000000, 0x10000000, 0xE0000000]

    for base in bases:
        target_va = base + string_offset
        target_bytes = struct.pack("<I", target_va)
        # Search for target_va as a literal pool value
        i = 0
        while True:
            p = data.find(target_bytes, i)
            if p == -1:
                break
            # Check if this might be a literal pool (aligned to 4 bytes)
            if p % 4 == 0:
                hits.append((p, target_va, base))
            i = p + 1
    return hits

def find_function_start_arm(data, code_offset, max_back=0x1000):
    """
    Walk back from code_offset to find ARM function prologue.
    Common ARM prologue: PUSH {rX, ..., lr} = 0xE92D????
    or STMFD sp!, {rX-rY, lr} = 0xE92D????
    """
    off = code_offset & ~3
    limit = max(0, off - max_back)
    for i in range(off, limit, -4):
        if i + 3 >= len(data):
            continue
        w, = struct.unpack_from("<I", data, i)
        # PUSH {r?, lr}: E92D???? (bit 14 = lr set, stmfd pattern)
        if (w & 0xFFFF0000) == 0xE92D0000 and (w & 0x4000):
            return i
        # also: E1A0000? (mov r0, rX) - common epilogue pattern before next fn
    return max(0, code_offset - 256)

def disassemble_arm(data, start_offset, length=512):
    if not HAS_CAPSTONE:
        return ["(capstone not available)"]
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    md.detail = False
    chunk = data[start_offset : start_offset + length]
    lines = []
    for insn in md.disasm(chunk, start_offset):
        lines.append(f"  {insn.address:#010x}:  {insn.mnemonic:<10} {insn.op_str}")
    if not lines:
        # Try THUMB mode
        md2 = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        md2.detail = False
        for insn in md2.disasm(chunk, start_offset):
            lines.append(f"  {insn.address:#010x}:  {insn.mnemonic:<10} {insn.op_str}")
    return lines

print("\n[*] Scanning for cross-references to 'common.dat' strings …")
for str_offset, full_str in string_offsets:
    print(f"\n{'='*70}")
    print(f"  String: '{full_str}'  @ offset {str_offset:#010x}")
    xrefs = find_arm_xrefs(decrypted, str_offset)
    if xrefs:
        for (pool_off, target_va, base) in xrefs[:10]:
            print(f"\n  Literal pool at offset {pool_off:#010x}  (target_va={target_va:#010x}, base={base:#010x})")
            # Find code that references this pool entry (within ±4KB)
            # LDR Rd, [PC, #N]: E51F????  E59F????
            # where PC = instruction + 8, and N = pool_off - (instr_off + 8)
            for instr_off in range(max(0, pool_off - 4096), min(len(decrypted)-4, pool_off + 4096), 4):
                w, = struct.unpack_from("<I", decrypted, instr_off)
                # LDR Rd, [PC, #+N] = E59F???? (positive offset)
                # LDR Rd, [PC, #-N] = E51F????
                if (w & 0xFFF0F000) in (0xE59F0000, 0xE51F0000):
                    offset_field = w & 0xFFF
                    is_add = (w & 0x00800000) != 0
                    pc_val = instr_off + 8
                    computed = (pc_val + offset_field) if is_add else (pc_val - offset_field)
                    if computed == pool_off:
                        fn_start = find_function_start_arm(decrypted, instr_off)
                        print(f"\n    → LDR at offset {instr_off:#010x}  (fn starts ~{fn_start:#010x})")
                        print(f"    Disassembly:")
                        for line in disassemble_arm(decrypted, fn_start, 512):
                            print(line)
                        break
    else:
        print(f"  [!] No literal pool references found for base addresses tried")
        print(f"      Try loading fw_decrypted.bin in Ghidra/radare2 for full analysis")

# ── Summary table ─────────────────────────────────────────────────────────────
print(f"\n{'='*70}")
print("SUMMARY")
print(f"  Starbuck key:       {STARBUCK_KEY.hex()}")
print(f"  IV used:            {winning_iv_name}")
print(f"  Decrypted size:     {len(decrypted):#x} bytes")
print(f"  'common.dat' hits:  {len(string_offsets)}")
for off, s in string_offsets:
    print(f"    offset {off:#010x}  '{s}'")
print(f"  Decrypted saved to: {OUT_PATH}")
