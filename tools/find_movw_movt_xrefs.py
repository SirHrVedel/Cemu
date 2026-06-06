"""
ARMv7 commonly loads 32-bit constants via MOVW + MOVT pairs instead of literal pools.
Search for code that builds the address of 'common.dat' strings.

BE ARM MOVW encoding:
  E3 0X XYYY  →  cond=AL, opcode=MOVW, imm4=X[upper], Rd=X[lower].high,
                  imm12 = (X[lower].low << 8) | Y... Actually:
  Word = E3 0i RdII  where:
     E3 0i  →  cond/op + imm4=i (high 4 bits of imm16)
     Rd[15:12] + imm12[11:0]  →  packed as high-nibble.Rd  low-12.imm12

BE ARM MOVT encoding:
  E3 4X XYYY  →  cond=AL, opcode=MOVT, same layout, imm16 = high half of address.
"""
import struct, sys, io
from pathlib import Path
import capstone

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DEC_PATH = r"C:\Users\Nikolaj\source\repos\Cemu\tools\fw_decrypted.bin"
data = Path(DEC_PATH).read_bytes()

# String addresses (assuming load base 0)
STRINGS = []
TARGET = b"common.dat"
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
    STRINGS.append((s, full))
    i = p + 1

def encode_movw_be(rd, imm16):
    """Encode MOVW Rd, #imm16 as 4-byte BE pattern."""
    imm4  = (imm16 >> 12) & 0xF
    imm12 = imm16 & 0xFFF
    word  = (0xE << 28) | (0x30 << 20) | (imm4 << 16) | (rd << 12) | imm12
    return struct.pack(">I", word)

def encode_movt_be(rd, imm16):
    imm4  = (imm16 >> 12) & 0xF
    imm12 = imm16 & 0xFFF
    word  = (0xE << 28) | (0x34 << 20) | (imm4 << 16) | (rd << 12) | imm12
    return struct.pack(">I", word)

print(f"[*] Searching for MOVW/MOVT loading 'common.dat' string addresses …")
print(f"    (assuming load base = 0x00000000, so VA == file offset)\n")

md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | capstone.CS_MODE_BIG_ENDIAN)
md.detail = False

def find_function_start_be(data, ioff, max_back=0x4000):
    off = ioff & ~3
    limit = max(0, off - max_back)
    for k in range(off, limit, -4):
        if k + 3 >= len(data): continue
        w, = struct.unpack_from(">I", data, k)
        # PUSH {…, lr}
        if (w & 0xFFFF0000) == 0xE92D0000 and (w & 0x4000):
            return k
    return max(0, ioff - 256)

def disasm_function(off, limit=600):
    """Disassemble from off until BX LR, POP {…, pc}, or limit insns."""
    out = []
    pos = off
    for _ in range(limit):
        if pos + 4 > len(data): break
        chunk = data[pos:pos+4]
        ins = list(md.disasm(chunk, pos))
        if not ins:
            out.append((pos, ".word", f"{struct.unpack('>I', chunk)[0]:#010x}"))
            pos += 4
            continue
        ins = ins[0]
        out.append((ins.address, ins.mnemonic, ins.op_str))
        pos += 4
        # Stop conditions
        if ins.mnemonic == "bx" and "lr" in ins.op_str:
            break
        if ins.mnemonic in ("pop","ldm","ldmia","ldmfd") and "pc" in ins.op_str:
            break
    return out

found_any = False
for str_off, full in STRINGS:
    print(f"{'='*72}")
    print(f"STRING: '{full}'")
    print(f"  File offset / VA: {str_off:#010x}")
    lo16 = str_off & 0xFFFF
    hi16 = (str_off >> 16) & 0xFFFF

    # Search for MOVW with this lo16 for each Rd 0..14
    movw_locations = []
    for rd in range(15):
        pat = encode_movw_be(rd, lo16)
        i = 0
        while True:
            p = data.find(pat, i)
            if p == -1: break
            if p % 4 == 0:
                movw_locations.append((p, rd))
            i = p + 1

    print(f"  MOVW Rd, #{lo16:#06x} candidates: {len(movw_locations)}")

    # For each MOVW, look for a MOVT Rd, #hi16 within next 4 instructions
    real_refs = []
    for movw_off, rd in movw_locations:
        movt_pat = encode_movt_be(rd, hi16)
        # Look in the next 16 instructions (64 bytes)
        window = data[movw_off + 4 : movw_off + 4 + 64]
        for j in range(0, len(window) - 3, 4):
            if window[j:j+4] == movt_pat:
                real_refs.append((movw_off, movw_off + 4 + j, rd))
                break

    print(f"  Matching MOVT pairs: {len(real_refs)}")
    for movw_off, movt_off, rd in real_refs[:5]:
        found_any = True
        fn_start = find_function_start_be(data, movw_off)
        print(f"\n  ── Reference at MOVW {movw_off:#010x} / MOVT {movt_off:#010x}  (R{rd}) ──")
        print(f"     Function starts at ~{fn_start:#010x}")
        print(f"     Disassembly:")
        for addr, mn, op in disasm_function(fn_start, 80):
            marker = ""
            if addr == movw_off:
                marker = f"   ◄── MOVW R{rd}, #lo16(common.dat str)"
            elif addr == movt_off:
                marker = f"   ◄── MOVT R{rd}, #hi16(common.dat str)"
            print(f"        {addr:#010x}:  {mn:<10} {op}{marker}")

if not found_any:
    print("\n[!] No MOVW/MOVT pairs found.  Code may use a different addressing.")
    print("    Trying alternative: MOV.W with ldr-immediate followed by add pc-rel …")
