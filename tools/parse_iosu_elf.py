"""
Parse the IOSU ELF embedded in fw_decrypted.bin.
Layout (per wiiubrew): Ancast metadata + ELF loader + IOSU ELF (magic ~0x804).
Goal: find which LOAD segment contains 'common.dat' strings and what their VAs are.
"""
import struct, sys, io
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DEC = r"C:\Users\Nikolaj\source\repos\Cemu\tools\fw_decrypted.bin"
data = Path(DEC).read_bytes()

# Locate ELF magic
elf_offsets = []
i = 0
while True:
    p = data.find(b"\x7FELF", i)
    if p == -1: break
    elf_offsets.append(p)
    i = p + 1
print(f"[*] ELF magics found in fw_decrypted.bin: {[hex(x) for x in elf_offsets[:20]]}")

if not elf_offsets:
    sys.exit("No ELF magic found.")

# Take the first one — that should be the IOSU image
elf_off = elf_offsets[0]
elf = data[elf_off:]
print(f"\n[*] Parsing ELF at file offset {elf_off:#010x}")

# ELF32 header
ei = elf[:16]
print(f"    e_ident: {ei.hex()}  class={ei[4]} data={ei[5]} (1=LE,2=BE)")
e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, \
e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx \
  = struct.unpack(">HHIIIIIHHHHHH", elf[16:52])
print(f"    e_type={e_type:#x} e_machine={e_machine:#x} (40=ARM)")
print(f"    e_entry={e_entry:#010x}")
print(f"    e_phoff={e_phoff:#x} e_phnum={e_phnum} e_phentsize={e_phentsize}")
print(f"    e_shoff={e_shoff:#x} e_shnum={e_shnum}  shstrndx={e_shstrndx}")

# Parse program headers
PT_LOAD = 1
phdrs = []
print(f"\n[*] Program headers ({e_phnum}):")
print(f"    {'#':>3} {'type':>8}  {'offset':>10} {'vaddr':>10} {'paddr':>10} {'filesz':>10} {'memsz':>10}  flags")
for i in range(e_phnum):
    o = e_phoff + i*e_phentsize
    p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
        struct.unpack(">IIIIIIII", elf[o:o+32])
    phdrs.append({"type":p_type,"offset":p_offset,"vaddr":p_vaddr,"paddr":p_paddr,
                  "filesz":p_filesz,"memsz":p_memsz,"flags":p_flags,"align":p_align,
                  "abs_file_off": elf_off + p_offset})
    flag_s = ("R" if p_flags&4 else "-") + ("W" if p_flags&2 else "-") + ("X" if p_flags&1 else "-")
    print(f"    {i:>3} {p_type:>8x}  {p_offset:>#10x} {p_vaddr:>#10x} {p_paddr:>#10x} {p_filesz:>#10x} {p_memsz:>#10x}  {flag_s}")

# Map a fw_decrypted.bin file offset to a VA via the LOAD segments
def file_to_va(file_off):
    for ph in phdrs:
        if ph["type"] != PT_LOAD: continue
        seg_file_lo = ph["abs_file_off"]
        seg_file_hi = seg_file_lo + ph["filesz"]
        if seg_file_lo <= file_off < seg_file_hi:
            return ph["vaddr"] + (file_off - seg_file_lo), ph
    return None, None

# Now check our common.dat strings
print("\n[*] Resolving common.dat string offsets to ELF VAs:")
for s_off in [0xD8BC64, 0xD8BE57]:
    va, ph = file_to_va(s_off)
    if va is None:
        print(f"    file {s_off:#010x}: NOT IN ANY LOAD SEGMENT")
    else:
        print(f"    file {s_off:#010x}  ->  VA {va:#010x}  (seg vaddr={ph['vaddr']:#010x} flags={'X' if ph['flags']&1 else '-'}{'W' if ph['flags']&2 else '-'}{'R' if ph['flags']&4 else '-'})")

# Save phdrs to a JSON for reuse
import json
out = {"elf_file_offset": elf_off, "phdrs": phdrs}
Path(r"C:\Users\Nikolaj\source\repos\Cemu\tools\fw_phdrs.json").write_text(json.dumps(out, indent=2))
print(f"\n[*] Saved {len(phdrs)} program headers to tools/fw_phdrs.json")
