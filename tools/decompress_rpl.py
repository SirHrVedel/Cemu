"""
Decompress a Wii U RPL/RPX file into a standard ELF.

RPL format = ELF32 BE PowerPC with two custom bits:
  - e_machine = 0x14 (EM_PPC)
  - Section header flag SHF_RPL_ZLIB = 0x08000000 marks zlib-compressed sections.
    First 4 bytes of such a section = BE uint32 uncompressed size, then zlib data.

Output: a flat ELF with all sections decompressed and section headers updated.
"""
import struct, sys, io, zlib
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

if len(sys.argv) < 3:
    print("Usage: decompress_rpl.py <in.rpl> <out.elf>")
    sys.exit(1)

src = Path(sys.argv[1]).read_bytes()
print(f"[*] Loaded {len(src)} bytes from {sys.argv[1]}")

# ── ELF32 BE header ──────────────────────────────────────────────────────────
assert src[:4] == b"\x7fELF", "Not an ELF"
assert src[4] == 1 and src[5] == 2, f"Not ELF32 BE (class={src[4]}, data={src[5]})"

e_type, e_machine = struct.unpack(">HH", src[16:20])
e_entry, e_phoff, e_shoff = struct.unpack(">III", src[24:36])
e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = \
    struct.unpack(">IHHHHHH", src[36:52])
print(f"    e_type={e_type:#x} e_machine={e_machine:#x} (0x14=PPC) entry={e_entry:#010x}")
print(f"    e_shoff={e_shoff:#x} e_shnum={e_shnum} e_shentsize={e_shentsize}")
print(f"    e_phoff={e_phoff:#x} e_phnum={e_phnum} e_phentsize={e_phentsize}")
print(f"    e_shstrndx={e_shstrndx}")

# ── Section headers ──────────────────────────────────────────────────────────
SHF_RPL_ZLIB = 0x08000000
sections = []
for i in range(e_shnum):
    o = e_shoff + i*e_shentsize
    sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, \
    sh_link, sh_info, sh_addralign, sh_entsize = \
        struct.unpack(">IIIIIIIIII", src[o:o+40])
    sections.append({"idx":i,"name":sh_name,"type":sh_type,"flags":sh_flags,
                     "addr":sh_addr,"offset":sh_offset,"size":sh_size,
                     "link":sh_link,"info":sh_info,"addralign":sh_addralign,
                     "entsize":sh_entsize})

# Pull section name strings from .shstrtab
strtab = b""
if e_shstrndx < e_shnum:
    s = sections[e_shstrndx]
    raw = src[s["offset"]:s["offset"]+s["size"]]
    if s["flags"] & SHF_RPL_ZLIB:
        uncomp_size = struct.unpack(">I", raw[:4])[0]
        try:
            strtab = zlib.decompress(raw[4:])
        except Exception as ex:
            print(f"[!] shstrtab decompress failed: {ex}")
            strtab = raw
    else:
        strtab = raw

def name_of(idx):
    n = sections[idx]["name"]
    end = strtab.find(b"\x00", n)
    return strtab[n:end].decode("ascii","replace") if end >= 0 else f"sec{idx}"

print(f"\n[*] {e_shnum} sections:")
print(f"    {'idx':>3} {'name':<24} {'type':>6} {'flags':>10} {'addr':>10} {'offset':>10} {'size':>10} {'zlib?'}")
for s in sections:
    nm = name_of(s["idx"])
    z  = "yes" if s["flags"] & SHF_RPL_ZLIB else ""
    print(f"    {s['idx']:>3} {nm[:24]:<24} {s['type']:>#6x} {s['flags']:>#10x} {s['addr']:>#10x} {s['offset']:>#10x} {s['size']:>#10x}  {z}")

# ── Decompress sections; rebuild a flat ELF ──────────────────────────────────
# We'll build: ELF header (unchanged) + new section bodies appended + new shdr table at end.
out_body = bytearray()
new_secs = []
# Reserve room for ELF header (52 bytes) and (later) for shdr table at end
# First copy original ELF header; we'll patch e_shoff after building bodies.
out = bytearray(src[:52])
# Pad to align e_phoff if needed (preserve original phdrs verbatim too if present)
if e_phnum > 0:
    if e_phoff < len(out):
        # phdr table sits at fixed offset (usually 0x40)
        pass
    needed = e_phoff + e_phnum*e_phentsize - len(out)
    if needed > 0: out.extend(b"\x00" * needed)
    out[e_phoff:e_phoff + e_phnum*e_phentsize] = src[e_phoff:e_phoff + e_phnum*e_phentsize]

# Cursor for placing section bodies
cursor = max(len(out), 0x80)
if cursor % 8: cursor += 8 - (cursor % 8)
if len(out) < cursor: out.extend(b"\x00" * (cursor - len(out)))

for s in sections:
    nm = name_of(s["idx"])
    raw = src[s["offset"]:s["offset"]+s["size"]] if s["size"] else b""
    if s["flags"] & SHF_RPL_ZLIB and s["size"] >= 4:
        uncomp_size = struct.unpack(">I", raw[:4])[0]
        try:
            dec = zlib.decompress(raw[4:])
            if len(dec) != uncomp_size:
                print(f"[!] section {nm}: header says {uncomp_size}, decompressed {len(dec)}")
        except Exception as ex:
            print(f"[!] section {nm}: zlib failed: {ex}; keeping raw")
            dec = raw
        new_size = len(dec)
        new_data = dec
        new_flags = s["flags"] & ~SHF_RPL_ZLIB
    else:
        new_data = raw
        new_size = s["size"]
        new_flags = s["flags"]

    if s["type"] == 8 or new_size == 0:  # SHT_NOBITS
        new_offset = 0
    else:
        # align body
        if s["addralign"] > 1:
            pad = (-cursor) % s["addralign"]
            if pad:
                out.extend(b"\x00" * pad)
                cursor += pad
        new_offset = cursor
        out.extend(new_data)
        cursor += len(new_data)

    new_secs.append({**s, "offset":new_offset, "size":new_size, "flags":new_flags})

# Write new shdr table
pad = (-cursor) % 8
if pad:
    out.extend(b"\x00" * pad)
    cursor += pad
new_shoff = cursor
for s in new_secs:
    out.extend(struct.pack(">IIIIIIIIII",
        s["name"], s["type"], s["flags"], s["addr"], s["offset"],
        s["size"], s["link"], s["info"], s["addralign"], s["entsize"]))

# Patch e_shoff
out[32:36] = struct.pack(">I", new_shoff)
# Clear e_phoff if we didn't carry phdrs (keep as-is if we did)
# Already copied phdrs above, leave e_phoff as original.

dst = Path(sys.argv[2])
dst.write_bytes(bytes(out))
print(f"\n[*] Wrote {len(out)} bytes -> {dst}")
print(f"    new e_shoff = {new_shoff:#x}")
