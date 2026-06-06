"""Disassemble the three friends-process functions that reference record.bin.

For each ARMv5TE BE instruction, annotate:
  - LDR Rd, [PC, #imm12]  -> resolve literal pool target and pool value
  - BL <target>            -> compute branch target VA
  - PUSH/POP register lists
Strings referenced from the literal pool are looked up against the FPD/ACT
.rodata segment range (0xE3180000..0xE31AC78C).
"""
import bisect
import json
import struct
import capstone

FW = r"C:\Users\Nikolaj\source\repos\Cemu\tools\fw_decrypted.bin"
PHDRS = r"C:\Users\Nikolaj\source\repos\Cemu\tools\fw_phdrs.json"

with open(FW, "rb") as f:
    data = f.read()
with open(PHDRS, "r") as f:
    phdrs = json.load(f)["phdrs"]

# We'll need VA->bytes mapping over the whole image for literal-pool reads.
def va_to_file(va):
    for ph in phdrs:
        if ph["type"] != 1:
            continue
        if ph["vaddr"] <= va < ph["vaddr"] + ph["filesz"]:
            return ph["abs_file_off"] + (va - ph["vaddr"])
    return None

def read_u32_va(va):
    off = va_to_file(va)
    if off is None:
        return None
    return struct.unpack(">I", data[off:off+4])[0]

def read_cstr_va(va, maxlen=128):
    off = va_to_file(va)
    if off is None:
        return None
    end = off
    while end < len(data) and data[end] != 0 and end - off < maxlen:
        end += 1
    s = data[off:end]
    # accept only printable ASCII
    if all(0x20 <= b < 0x7f or b in (9, 10, 13) for b in s):
        return s.decode("ascii", errors="replace")
    return None

# Find .text segment (segment 52)
text_seg = next(p for p in phdrs if p["type"] == 1 and p["vaddr"] == 0xE3000000)
text_off = text_seg["abs_file_off"]
text_va = text_seg["vaddr"]
text_size = text_seg["filesz"]

# Build prologue table for "what function are we in"
text_words = struct.unpack(f">{text_size//4}I", data[text_off:text_off+text_size])
prologue_offs = []
for i, w in enumerate(text_words):
    if (w >> 16) == 0xE92D and (w & 0x4000):
        prologue_offs.append(i*4)
prologue_offs.sort()
prologue_vas = [text_va + o for o in prologue_offs]

def func_label(va):
    """Return 'sub_VVVVVVVV' for a function VA that begins with a prologue."""
    idx = bisect.bisect_right(prologue_vas, va) - 1
    if idx >= 0 and prologue_vas[idx] == va:
        return f"sub_{va:08x}"
    return f"sub_{va:08x}"

functions_to_dump = [
    (0xE301140C, 0xE3011620),
    (0xE3011620, 0xE30116AC),
    (0xE30117EC, 0xE3011914),
]

md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | capstone.CS_MODE_BIG_ENDIAN)
md.detail = True

for func_start, func_end in functions_to_dump:
    func_size = func_end - func_start
    off = func_start - text_va
    fb = data[text_off + off : text_off + off + func_size]
    print(f"\n# ==== Function 0x{func_start:08x}..0x{func_end:08x}  (len 0x{func_size:x}) ====\n")
    for ins in md.disasm(fb, func_start):
        w = struct.unpack(">I", ins.bytes)[0]
        comment = ""
        # LDR Rd, [PC, #imm12]
        if (w & 0x0F7F0000) == 0x051F0000:  # ldr (PC-relative, imm12, U bit toggles)
            u_bit = (w >> 23) & 1
            imm12 = w & 0xFFF
            rd = (w >> 12) & 0xF
            addr = (ins.address + 8 + imm12) if u_bit else (ins.address + 8 - imm12)
            pool_value = read_u32_va(addr)
            if pool_value is not None:
                comment = f"  ; -> [0x{addr:08x}] = 0x{pool_value:08x}"
                # if pool value is in rodata, dereference as string
                s = read_cstr_va(pool_value)
                if s and len(s) >= 2:
                    comment += f"  '{s}'"
        # BL <target>
        elif (w & 0x0F000000) == 0x0B000000:
            offset = w & 0x00FFFFFF
            if offset & 0x00800000:
                offset -= 0x01000000
            target = (ins.address + 8 + (offset << 2)) & 0xFFFFFFFF
            comment = f"  ; -> {func_label(target)}"
        # MOV  (imm)
        elif (w & 0x0FE00000) == 0x03A00000:
            rd = (w >> 12) & 0xF
            imm8 = w & 0xFF
            rot = ((w >> 8) & 0xF) * 2
            value = ((imm8 >> rot) | (imm8 << (32 - rot))) & 0xFFFFFFFF if rot else imm8
            if value != 0:
                comment = f"  ; r{rd} = 0x{value:x}  ({value})"
        # SVC / SWI = syscall (interesting for FSA calls)
        elif (w & 0x0F000000) == 0x0F000000:
            svc_num = w & 0x00FFFFFF
            comment = f"  ; SVC #0x{svc_num:x}"

        print(f"  0x{ins.address:08x}: {ins.bytes.hex():8s} {ins.mnemonic:8s} {ins.op_str}{comment}")
