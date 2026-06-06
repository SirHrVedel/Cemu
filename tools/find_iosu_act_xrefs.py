"""
Find IOSU /dev/act code that references common.dat strings.

ELF segment 52: VA 0xE3000000, R-X, size 0x16BA14   <-- nn.act .text
ELF segment 53: VA 0xE3180000, R--, size 0x2C78C    <-- nn.act .rodata (strings)
ELF segment 54: VA 0xE31AD000, RW-, size 0x150
ELF segment 55: VA 0xE31AE000, RW-, size 0x9D0
ELF segment 56: VA 0xE31AF000, RW- BSS

String VAs:
  /vol/storage_mlc01/usr/save/system/act/common.dat  -> 0xE3195500
  /vol/sys/proc_ram/fpd/act/common.dat                -> 0xE31956F4
"""
import struct, sys, io, json
from pathlib import Path
import capstone

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DEC = r"C:\Users\Nikolaj\source\repos\Cemu\tools\fw_decrypted.bin"
PHDRS = json.loads(Path(r"C:\Users\Nikolaj\source\repos\Cemu\tools\fw_phdrs.json").read_text())
data = Path(DEC).read_bytes()

# Build segment table
PT_LOAD = 1
loads = [p for p in PHDRS["phdrs"] if p["type"] == PT_LOAD]

def file_to_va(off):
    for p in loads:
        lo = p["abs_file_off"]; hi = lo + p["filesz"]
        if lo <= off < hi:
            return p["vaddr"] + (off - lo), p
    return None, None

def va_to_file(va):
    for p in loads:
        if p["vaddr"] <= va < p["vaddr"] + p["filesz"]:
            return p["abs_file_off"] + (va - p["vaddr"]), p
    return None, None

# Re-extract strings (correct boundaries)
print("[*] Locating both common.dat strings (proper boundaries)…")
hits = []
i = 0
while True:
    p = data.find(b"common.dat", i)
    if p == -1: break
    s = p
    while s > 0 and 0x20 <= data[s-1] < 0x7F:
        s -= 1
    # If first char isn't '/', advance until it is
    if s < p and data[s] != ord('/'):
        slash = data.find(b'/', s, p)
        if slash != -1: s = slash
    e = p + len(b"common.dat")
    full = data[s:e].decode('ascii','replace')
    va_s, _ = file_to_va(s)
    hits.append((s, va_s, full))
    i = p + 1

print("    string  file_off    VA          path")
for s, va, full in hits:
    print(f"           {s:#010x}  {va:#010x}  '{full}'")

# Find nn.act .text segment
TEXT = next(p for p in loads if p["vaddr"] == 0xE3000000)
text_lo, text_hi = TEXT["abs_file_off"], TEXT["abs_file_off"] + TEXT["filesz"]
text_va_base = TEXT["vaddr"]
text = data[text_lo:text_hi]
print(f"\n[*] nn.act .text: file [{text_lo:#x}..{text_hi:#x}]  VA base {text_va_base:#010x}  size {TEXT['filesz']:#x}")

# Search literal pool for BE 4-byte u32 == each string VA
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | capstone.CS_MODE_BIG_ENDIAN)
md.detail = False

def find_be_u32_in_text(value):
    needle = struct.pack(">I", value & 0xFFFFFFFF)
    out, i = [], 0
    while True:
        p = text.find(needle, i)
        if p == -1: break
        if p % 4 == 0:
            out.append(p)        # offset within text segment
        i = p + 1
    return out

def find_function_start(text, ioff, max_back=0x4000):
    off = ioff & ~3
    limit = max(0, off - max_back)
    for k in range(off, limit, -4):
        w, = struct.unpack_from(">I", text, k)
        # E92D ??F? / E92D ??4? : PUSH {…, lr/pc}
        if (w & 0xFFFF0000) == 0xE92D0000 and (w & 0x00004000):
            return k
    return max(0, ioff - 256)

def disasm_function(text_off, va_base, max_insns=200):
    out = []
    pos = text_off
    for _ in range(max_insns):
        if pos + 4 > len(text): break
        chunk = text[pos:pos+4]
        ins = list(md.disasm(chunk, va_base + pos))
        if not ins:
            v, = struct.unpack(">I", chunk)
            out.append((va_base + pos, ".word", f"{v:#010x}"))
            pos += 4
            continue
        ins = ins[0]
        out.append((ins.address, ins.mnemonic, ins.op_str))
        pos += 4
        if ins.mnemonic == "bx" and ins.op_str == "lr": break
        if ins.mnemonic in ("pop","ldm","ldmia","ldmfd","ldmea") and "pc" in ins.op_str: break
    return out

for s_file, s_va, full in hits:
    print(f"\n{'='*78}")
    print(f"STRING: '{full}'")
    print(f"  file {s_file:#010x}  va {s_va:#010x}")
    pool_offs = find_be_u32_in_text(s_va)
    print(f"  Literal-pool hits in nn.act .text: {len(pool_offs)}")

    if not pool_offs:
        # Try slightly different VAs (in case of off-by-N)
        for delta in (-4,-1,1,4):
            alt = find_be_u32_in_text(s_va + delta)
            if alt:
                print(f"   [hint] {len(alt)} hits at VA={s_va+delta:#x} (delta={delta:+d})")
        continue

    for po in pool_offs[:5]:
        pool_va = text_va_base + po
        print(f"\n  ── Pool entry @ {pool_va:#010x} (file {text_lo+po:#010x}) ──")

        # Find LDR Rd, [PC, #imm12] (BE: E5 9F xRR YYY / E5 1F …)
        ldr_hits = []
        for ioff in range(max(0, po - 0x1000), po, 4):
            w, = struct.unpack_from(">I", text, ioff)
            if (w & 0xFF7F0000) == 0xE51F0000:
                rd       = (w >> 12) & 0xF
                imm12    = w & 0xFFF
                u_bit    = (w >> 23) & 1
                pc       = (text_va_base + ioff) + 8
                tgt      = pc + imm12 if u_bit else pc - imm12
                if tgt == pool_va:
                    ldr_hits.append((ioff, rd))
        print(f"     LDR PC-rel insns -> this pool: {len(ldr_hits)}")

        for ldr_off, rd in ldr_hits[:3]:
            fn_start = find_function_start(text, ldr_off)
            print(f"\n     LDR R{rd} at {text_va_base+ldr_off:#010x}  Func starts ~{text_va_base+fn_start:#010x}")
            print(f"     Disassembly:")
            for addr, mn, op in disasm_function(fn_start, text_va_base, 120):
                tag = ""
                if addr == text_va_base + ldr_off:
                    tag = f"   ◄── loads &\"…{full[-32:]}\""
                print(f"        {addr:#010x}:  {mn:<10} {op}{tag}")
