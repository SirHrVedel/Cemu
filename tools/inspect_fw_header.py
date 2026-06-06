"""
Inspect the raw fw.img header and OTP.bin to understand the Ancast format
and locate the Starbuck key.
"""
import struct, hashlib
from pathlib import Path

FW_PATH  = r"D:\Games\Console\Cafe\storage_slc\sys\title\00050010\1000400a\code\fw.img"
OTP_PATH = r"C:\Users\Nikolaj\AppData\Roaming\Cemu\otp.bin"

# Known SHA-1 hashes from the key sheet (hex → bytes)
KNOWN_KEY_HASHES = {
    bytes.fromhex("3d331b3165f9638c6cd6221702b2f736f7fcf931"): "Wii-U BootROM Key",
    bytes.fromhex("ee28d0be718055423ee79d89889ebe386e5b0c2d"): "Wii-U boot0 Key",
    bytes.fromhex("6a0b87fc98b306ae3366f0e0a88d0b06a2813313"): "Wii-U Common Key",
    bytes.fromhex("2b30b703c6676c8124c7347b30c7972ffeae2b39"): "vWii Common key",
    bytes.fromhex("d8b4970a7ed12e1002a0c4bf89bee171740d268b"): "Starbuck Wii-U Ancast Key",
    bytes.fromhex("2ba6f692ddbf0b3cd267e9374fa7dd849e80f8ab"): "Wii-U Espresso ancast Key",
    bytes.fromhex("ce3641b2660253f5a7e789db297be2c1585b3054"): "vWii Espresso ancast Key",
}

# ── fw.img header ─────────────────────────────────────────────────────────────
fw = Path(FW_PATH).read_bytes()
print(f"[fw.img]  size = {len(fw):#x} bytes  ({len(fw)} bytes)")
print(f"  First 32 bytes: {fw[:32].hex()}")
print(f"  Magic (BE u32): {struct.unpack_from('>I', fw, 0)[0]:#010x}")
print()

# Dump first 0x200 bytes of header
print("=== fw.img first 0x200 bytes (hex dump) ===")
for row in range(0, min(0x200, len(fw)), 16):
    chunk = fw[row:row+16]
    hex_part = " ".join(f"{b:02x}" for b in chunk)
    asc_part = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
    print(f"  {row:04x}: {hex_part:<48}  {asc_part}")

# ── OTP.bin ────────────────────────────────────────────────────────────────────
otp = Path(OTP_PATH).read_bytes()
print(f"\n[otp.bin] size = {len(otp)} bytes")
print()

# Dump OTP in 16-byte rows (word-index annotations)
print("=== OTP dump (first 0x100 bytes) ===")
for row in range(0, min(0x100, len(otp)), 16):
    chunk = otp[row:row+16]
    word_idx = row // 4
    hex_part = " ".join(f"{b:02x}" for b in chunk)
    asc_part = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
    print(f"  byte {row:#04x} / word {word_idx:#04x}: {hex_part}  {asc_part}")

# ── Search OTP for key candidates by SHA-1 ────────────────────────────────────
print("\n=== Searching OTP for known key hashes (SHA-1 of 16-byte windows) ===")
found_keys = {}
for key_size in (16, 20):
    for offset in range(0, len(otp) - key_size + 1, 1):
        candidate = otp[offset:offset + key_size]
        h = hashlib.sha1(candidate).digest()
        if h in KNOWN_KEY_HASHES:
            name = KNOWN_KEY_HASHES[h]
            print(f"  MATCH: {name}")
            print(f"    OTP byte offset: {offset:#05x}  word index: {offset//4:#04x}  key_size: {key_size}")
            print(f"    Key bytes: {candidate.hex()}")
            found_keys[name] = (offset, candidate)

# Also try byte-swapped 4-byte words (OTP might be big-endian words in little-endian storage)
print("\n=== Searching OTP with word byte-swap for known key hashes ===")
# Swap every 4 bytes
otp_swapped = bytearray(len(otp))
for i in range(0, len(otp), 4):
    w = otp[i:i+4]
    if len(w) == 4:
        otp_swapped[i:i+4] = w[::-1]
    else:
        otp_swapped[i:i+len(w)] = w

for key_size in (16, 20):
    for offset in range(0, len(otp_swapped) - key_size + 1, 4):
        candidate = bytes(otp_swapped[offset:offset + key_size])
        h = hashlib.sha1(candidate).digest()
        if h in KNOWN_KEY_HASHES:
            name = KNOWN_KEY_HASHES[h]
            print(f"  MATCH (byte-swapped): {name}")
            print(f"    OTP byte offset: {offset:#05x}  word index: {offset//4:#04x}  key_size: {key_size}")
            print(f"    Key bytes (after swap): {candidate.hex()}")
            found_keys[name + " (swapped)"] = (offset, candidate)

if not found_keys:
    print("  [!] No matches found – keys might be stored differently")
    print("      Trying XOR or other transforms …")
    # Try SHA-1 of each 16-byte block XOR'd with 0xFF
    for offset in range(0, len(otp) - 16 + 1, 4):
        candidate = bytes(b ^ 0xFF for b in otp[offset:offset+16])
        h = hashlib.sha1(candidate).digest()
        if h in KNOWN_KEY_HASHES:
            name = KNOWN_KEY_HASHES[h]
            print(f"  MATCH (XOR 0xFF): {name} at offset {offset:#05x}")
            found_keys[name] = (offset, candidate)

print(f"\n  Found {len(found_keys)} key(s) in OTP.")
