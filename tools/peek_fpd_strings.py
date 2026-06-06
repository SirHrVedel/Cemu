"""Quick check of a few VAs in fpd .rodata."""
import json, struct
FW = r"C:\Users\Nikolaj\source\repos\Cemu\tools\fw_decrypted.bin"
with open(FW, "rb") as f: data = f.read()
with open(r"C:\Users\Nikolaj\source\repos\Cemu\tools\fw_phdrs.json", "r") as f:
    phdrs = json.load(f)["phdrs"]
def va_to_off(va):
    for ph in phdrs:
        if ph["type"]!=1: continue
        if ph["vaddr"]<=va<ph["vaddr"]+ph["filesz"]:
            return ph["abs_file_off"]+(va-ph["vaddr"])
    return None
for va in [0xe31aaaac, 0xe3180394, 0xe3180b80, 0xe31a4900, 0xe3180b6c]:
    off = va_to_off(va)
    end = off
    while end < off+128 and data[end] != 0:
        end += 1
    print(f"  VA 0x{va:08x}  file 0x{off:08x}  -> {data[off:end]!r}")
