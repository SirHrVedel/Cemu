"""Find and disassemble Cancel__Q2_2nn3actFv (and any other Cancel exports)."""
import struct, sys, io
from pathlib import Path
import capstone

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

ELF = r"C:\Users\Nikolaj\source\repos\Cemu\tools\nn_act.elf"
data = Path(ELF).read_bytes()

e_shoff = struct.unpack(">I", data[32:36])[0]
e_shnum = struct.unpack(">H", data[48:50])[0]
e_shstrndx = struct.unpack(">H", data[50:52])[0]
sections = []
for i in range(e_shnum):
    o = e_shoff + i*40
    sh = struct.unpack(">IIIIIIIIII", data[o:o+40])
    sections.append({"idx":i,"name":sh[0],"addr":sh[3],"offset":sh[4],"size":sh[5]})
shstr = data[sections[e_shstrndx]["offset"]:sections[e_shstrndx]["offset"]+sections[e_shstrndx]["size"]]
def sname(i):
    n = sections[i]["name"]; e = shstr.find(b"\x00", n)
    return shstr[n:e].decode("ascii","replace") if e >= 0 else "?"
by_name = {sname(s["idx"]): s for s in sections}

text   = by_name[".text"]
fexp   = by_name[".fexports"]
body   = data[fexp["offset"]:fexp["offset"]+fexp["size"]]
cnt    = struct.unpack(">I", body[:4])[0]

# Walk export table
cancels = []
print("[*] Searching all exports for 'Cancel' / 'Finalize':")
for i in range(cnt):
    o = 8 + i*8
    va, no = struct.unpack(">II", body[o:o+8])
    end = body.find(b"\x00", no)
    nm  = body[no:end].decode("ascii","replace") if end >= 0 else "?"
    if "ancel" in nm or "inalize" in nm:
        print(f"    {va:#010x}  {nm}")
        cancels.append((va, nm))

# Read all symtab entries for size info
sym   = by_name[".symtab"]
strt  = by_name[".strtab"]
strtab = data[strt["offset"]:strt["offset"]+strt["size"]]
symd   = data[sym["offset"]:sym["offset"]+sym["size"]]
sym_size = {}
for o in range(0, len(symd), 16):
    n, v, sz, info, other, shndx = struct.unpack(">IIIBBH", symd[o:o+16])
    sym_size[v] = sz

md = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN)
md.detail = False

for va, nm in cancels:
    sz = sym_size.get(va, 0x200)
    fo = text["offset"] + (va - text["addr"])
    print(f"\n{'='*78}\n{nm}  @ {va:#010x}   size={sz:#x}\n{'='*78}")
    for ins in md.disasm(data[fo:fo+sz], va):
        print(f"    {ins.address:#010x}: {ins.mnemonic:<10} {ins.op_str}")
