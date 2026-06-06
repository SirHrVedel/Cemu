"""
Analyze the decompressed nn_act.elf for any 'common.dat' refs and disassemble PPC.
"""
import struct, sys, io
from pathlib import Path
import capstone

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

ELF_PATH = r"C:\Users\Nikolaj\source\repos\Cemu\tools\nn_act.elf"
data = Path(ELF_PATH).read_bytes()
print(f"[*] Loaded {len(data)} bytes from nn_act.elf")

# Parse section headers
e_shoff = struct.unpack(">I", data[32:36])[0]
e_shnum = struct.unpack(">H", data[48:50])[0]
e_shstrndx = struct.unpack(">H", data[50:52])[0]
sections = []
for i in range(e_shnum):
    o = e_shoff + i*40
    sh = struct.unpack(">IIIIIIIIII", data[o:o+40])
    sections.append({"name":sh[0],"type":sh[1],"flags":sh[2],"addr":sh[3],
                     "offset":sh[4],"size":sh[5]})

strtab = data[sections[e_shstrndx]["offset"]:
              sections[e_shstrndx]["offset"]+sections[e_shstrndx]["size"]]
def name_of(s):
    n = s["name"]; e = strtab.find(b"\x00", n)
    return strtab[n:e].decode("ascii","replace") if e >= 0 else "?"

# Find .text, .rodata
text = rodata = None
for s in sections:
    nm = name_of(s)
    if nm == ".text":   text = s
    if nm == ".rodata": rodata = s
    if nm == ".data":   ddata = s

print(f"    .text   addr={text['addr']:#x} size={text['size']:#x} offset={text['offset']:#x}")
print(f"    .rodata addr={rodata['addr']:#x} size={rodata['size']:#x} offset={rodata['offset']:#x}")

# Dump all strings from .rodata
rod = data[rodata["offset"]:rodata["offset"]+rodata["size"]]
print(f"\n[*] .rodata strings:")
i = 0
strings = []
while i < len(rod):
    if 0x20 <= rod[i] < 0x7F:
        j = i
        while j < len(rod) and 0x20 <= rod[j] < 0x7F:
            j += 1
        if j - i >= 4:
            s = rod[i:j].decode('ascii','replace')
            va = rodata["addr"] + i
            strings.append((va, s))
            print(f"    {va:#010x}: '{s}'")
        i = j + 1
    else:
        i += 1

# Search for 'common.dat' anywhere in the file
for tgt in (b"common.dat", b"act/", b"/vol/", b"persistentid", b"PersistentId",
            b"account.dat", b"AccountManager"):
    p = data.find(tgt)
    if p != -1:
        print(f"\n[*] FOUND '{tgt.decode()}' at file offset {p:#x}")
    else:
        print(f"[ ] '{tgt.decode()}' NOT in nn_act.elf")

# Disassemble .text (PPC BE)
text_bytes = data[text["offset"]:text["offset"]+text["size"]]
text_va    = text["addr"]
print(f"\n[*] Disassembling .text (PPC BE) — first 30 instructions:")
md = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN)
md.detail = False
n = 0
for ins in md.disasm(text_bytes, text_va):
    print(f"    {ins.address:#010x}: {ins.mnemonic:<10} {ins.op_str}")
    n += 1
    if n >= 30: break

# Find functions that call coreinit IPC / __OSDynLoad stubs
# .fimport_coreinit is a list of imported names; look for IOS_Open or FSOpenFile
import_sections = []
for s in sections:
    nm = name_of(s)
    if nm.startswith(".fimport") or nm.startswith(".dimport"):
        import_sections.append((nm, s))

print("\n[*] Imports referenced (coreinit functions):")
for nm, s in import_sections:
    body = data[s["offset"]:s["offset"]+s["size"]]
    if not body: continue
    # Library name is at offset 8 (NUL-terminated). After that, table of imports.
    lib_end = body.find(b"\x00", 8)
    libname = body[8:lib_end].decode("ascii","replace") if lib_end > 0 else "?"
    print(f"\n    {nm} (lib={libname}):")
    # Just dump strings from this section
    i = 0; cnt = 0
    while i < len(body):
        if 0x20 <= body[i] < 0x7F:
            j = i
            while j < len(body) and 0x20 <= body[j] < 0x7F:
                j += 1
            if j - i >= 3:
                print(f"        '{body[i:j].decode(errors='replace')}'")
                cnt += 1
                if cnt > 30: break
            i = j + 1
        else:
            i += 1
