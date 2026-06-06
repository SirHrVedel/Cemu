"""Find every LDR PC-relative reference to record.bin in the friends process
.text segment, then identify the enclosing functions.

The friends process IOSU binary owns both /dev/act and /dev/fpd:
  segment 52  R-X  0xE3000000..0xE316BA14  (.text)
  segment 53  R--  0xE3180000..0xE31AC78C  (.rodata + lit pools shared)

ARMv5TE BE PC-relative LDR encodings:
  E5 9F X YYY   LDR Rd, [PC, #+imm12]
  E5 1F X YYY   LDR Rd, [PC, #-imm12]

The literal pool at the LDR target holds a 32-bit address that we want to
match against 0xE3180B6C (= "record.bin").
"""
import bisect
import json
import struct

FW = r"C:\Users\Nikolaj\source\repos\Cemu\tools\fw_decrypted.bin"
PHDRS = r"C:\Users\Nikolaj\source\repos\Cemu\tools\fw_phdrs.json"

RECORD_BIN_VA = 0xE3180B6C  # from earlier string scan

with open(FW, "rb") as f:
    data = f.read()
with open(PHDRS, "r") as f:
    phdrs = json.load(f)["phdrs"]

# Find the .text segment for the friends process (segment 52).
text_seg = None
for ph in phdrs:
    if ph["type"] == 1 and ph["vaddr"] == 0xE3000000:
        text_seg = ph
        break
assert text_seg, "segment 52 not found"

text_off = text_seg["abs_file_off"]
text_va = text_seg["vaddr"]
text_size = text_seg["filesz"]
text_words = struct.unpack(f">{text_size//4}I", data[text_off:text_off+text_size])

print(f"# .text segment: VA 0x{text_va:08x}-0x{text_va+text_size:08x}  ({text_size//4} insns)\n")

# Pass 1: find every word in .text whose value equals the string VA
# (this is the literal pool entry the LDR will read).
pool_word_offs = []  # offsets within .text (in bytes, multiples of 4)
for i, w in enumerate(text_words):
    if w == RECORD_BIN_VA:
        pool_word_offs.append(i * 4)

print(f"# literal pool entries holding 0x{RECORD_BIN_VA:08x}: {len(pool_word_offs)}")
for off in pool_word_offs:
    print(f"    pool word at VA 0x{text_va + off:08x}")
print()

# Pass 2: find every PC-relative LDR that targets one of these pool words.
# LDR Rd, [PC, #imm12]: encoding masks:
#   high byte 0xE5, second byte 0x9F (U=1) or 0x1F (U=0), third byte is RD<<4 | 0
#   bottom 12 bits = imm12
# The effective address loaded from = (pc + 8) +/- imm12, with pc rounded down to 4
ldr_refs = []  # list of (ldr_va, pool_va, rd, value_loaded_from_pool=RECORD_BIN_VA)
for i, w in enumerate(text_words):
    high = (w >> 24) & 0xFF
    if high != 0xE5:
        continue
    mid = (w >> 20) & 0xFF
    # cccc 0101 0001 (LDR -) or 0101 1001 (LDR +)
    # We want PC-relative -> rn == 0xF -> middle nibble in (w>>16)&0xF == 0xF
    rn = (w >> 16) & 0xF
    if rn != 0xF:
        continue
    u_bit = (w >> 23) & 1  # 1 = positive offset
    # We also want the LDR form, not STR; bit 20 (L) must be 1
    l_bit = (w >> 20) & 1
    if l_bit != 1:
        continue
    imm12 = w & 0xFFF
    rd = (w >> 12) & 0xF
    pc = text_va + i*4
    addr = (pc + 8 + imm12) if u_bit else (pc + 8 - imm12)
    # Is this LDR targeting any of our pool words?
    if addr in [text_va + off for off in pool_word_offs]:
        ldr_refs.append((pc, addr, rd))

print(f"# LDR PC-relative refs that load 0x{RECORD_BIN_VA:08x}: {len(ldr_refs)}\n")
for ldr_va, pool_va, rd in ldr_refs:
    print(f"    LDR r{rd}, [PC, #...]  @ VA 0x{ldr_va:08x}  -> pool 0x{pool_va:08x}")

# Pass 3: find the containing function for each LDR by walking back to the
# nearest preceding PUSH-with-LR prologue (E92D???? with bit 14 set).
print("\n# Function prologues containing each ref:\n")
prologue_offs = []
for i, w in enumerate(text_words):
    if (w >> 16) == 0xE92D and (w & 0x4000):  # STMFD SP!,{..,LR,..}
        prologue_offs.append(i*4)

# also include simpler prologues "STR LR, [SP, #-imm]!" -> E52DE???
for i, w in enumerate(text_words):
    if (w & 0xFFFFF000) == 0xE52DE000:
        prologue_offs.append(i*4)
prologue_offs.sort()
prologue_vas = [text_va + o for o in prologue_offs]

print(f"  ({len(prologue_offs)} prologues catalogued)\n")
for ldr_va, pool_va, rd in ldr_refs:
    # bisect: the function containing ldr_va starts at the largest prologue <= ldr_va
    idx = bisect.bisect_right(prologue_vas, ldr_va) - 1
    if idx < 0:
        print(f"    LDR @ 0x{ldr_va:08x}  no preceding prologue?")
        continue
    func_start = prologue_vas[idx]
    func_end = prologue_vas[idx+1] if idx+1 < len(prologue_vas) else text_va + text_size
    print(f"    LDR @ 0x{ldr_va:08x}  inside function 0x{func_start:08x}..0x{func_end:08x}  (len 0x{func_end-func_start:x})")
