"""Show the PT_LOAD segments surrounding segment 53 (FPD rodata) so we can
identify FPD's .text / .data / .bss quartet."""
import json

with open(r"C:\Users\Nikolaj\source\repos\Cemu\tools\fw_phdrs.json", "r") as f:
    phdrs = json.load(f)["phdrs"]

# Number all PT_LOAD segments
load_phdrs = []
for i, ph in enumerate(phdrs):
    if ph["type"] == 1:
        load_phdrs.append((i, ph))

# Print contiguous neighbourhood of segment 53
for idx, (i, ph) in enumerate(load_phdrs):
    if 49 <= i <= 58:
        perms = "".join([
            "R" if ph["flags"] & 4 else "-",
            "W" if ph["flags"] & 2 else "-",
            "X" if ph["flags"] & 1 else "-",
        ])
        marker = " <-- FPD rodata (string match)" if i == 53 else ""
        print(f"  seg {i:2d}  VA 0x{ph['vaddr']:08x}-0x{ph['vaddr']+ph['memsz']:08x}  "
              f"file 0x{ph['abs_file_off']:08x}  filesz 0x{ph['filesz']:08x}  {perms}{marker}")
