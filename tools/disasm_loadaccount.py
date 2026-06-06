"""
Locate and disassemble LoadAccount (and friends) in the decompressed nn_act.elf.
"""
import struct, sys, io
from pathlib import Path
import capstone

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

ELF = r"C:\Users\Nikolaj\source\repos\Cemu\tools\nn_act.elf"
data = Path(ELF).read_bytes()

# Parse section headers
e_shoff = struct.unpack(">I", data[32:36])[0]
e_shnum = struct.unpack(">H", data[48:50])[0]
e_shstrndx = struct.unpack(">H", data[50:52])[0]
sections = []
for i in range(e_shnum):
    o = e_shoff + i*40
    sh = struct.unpack(">IIIIIIIIII", data[o:o+40])
    sections.append({"idx":i,"name":sh[0],"type":sh[1],"flags":sh[2],"addr":sh[3],
                     "offset":sh[4],"size":sh[5],"link":sh[6],"info":sh[7],
                     "addralign":sh[8],"entsize":sh[9]})
shstr = data[sections[e_shstrndx]["offset"]:
             sections[e_shstrndx]["offset"]+sections[e_shstrndx]["size"]]
def sname(i):
    n = sections[i]["name"]; e = shstr.find(b"\x00", n)
    return shstr[n:e].decode("ascii","replace") if e >= 0 else "?"

# Index by name
by_name = {sname(s["idx"]): s for s in sections}

text = by_name[".text"]
text_bytes = data[text["offset"]:text["offset"]+text["size"]]
text_va    = text["addr"]

# Parse .symtab + .strtab
sym = by_name[".symtab"]
strt = by_name[".strtab"]
strtab = data[strt["offset"]:strt["offset"]+strt["size"]]
sym_data = data[sym["offset"]:sym["offset"]+sym["size"]]

# ELF32 Sym: name(4) value(4) size(4) info(1) other(1) shndx(2)
syms = []
for o in range(0, len(sym_data), 16):
    if o+16 > len(sym_data): break
    n, v, sz, info, other, shndx = struct.unpack(">IIIBBH", sym_data[o:o+16])
    end = strtab.find(b"\x00", n)
    nm = strtab[n:end].decode("ascii","replace") if end >= 0 else "?"
    syms.append({"name":nm,"value":v,"size":sz,"info":info,"shndx":shndx})

# Find LoadAccount-related symbols
print("[*] All symbols mentioning 'oad' (Load/load) in nn_act .symtab:")
local_hits = [s for s in syms if "oad" in s["name"] and s["value"]]
for s in local_hits[:60]:
    print(f"    {s['value']:#010x}  size={s['size']:#x}  {s['name']}")
print(f"    ... total {len(local_hits)} matches")
hits = []  # filled from exports below

# Also dump all exported function names from .fexports
fexp = by_name.get(".fexports")
if fexp:
    body = data[fexp["offset"]:fexp["offset"]+fexp["size"]]
    # RPL export table format: u32 count, u32 sig, then count * (u32 vaddr, u32 name_off)
    # name_off is relative to start of this section
    if len(body) >= 8:
        cnt, sig = struct.unpack(">II", body[:8])
        print(f"\n[*] .fexports: count={cnt} sig={sig:#x}")
        for i in range(cnt):
            o = 8 + i*8
            if o+8 > len(body): break
            va, no = struct.unpack(">II", body[o:o+8])
            # name lives at offset `no` from start of section
            if 0 <= no < len(body):
                end = body.find(b"\x00", no)
                nm = body[no:end].decode("ascii","replace") if end >= 0 else "?"
            else:
                nm = "?"
            if "oad" in nm:
                print(f"    {va:#010x}  {nm}")
                if nm.startswith("LoadConsoleAccount"):
                    hits.append({"name":nm,"value":va,"size":0})

md = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN)
md.detail = False

def disasm_range(va_start, size):
    fo = text["offset"] + (va_start - text_va)
    end_fo = fo + size
    out = []
    pos = fo
    while pos < end_fo and pos + 4 <= text["offset"] + text["size"]:
        chunk = data[pos:pos+4]
        ins = list(md.disasm(chunk, text_va + (pos - text["offset"])))
        if not ins:
            v, = struct.unpack(">I", chunk)
            out.append((text_va + (pos - text["offset"]), ".word", f"{v:#010x}"))
        else:
            ins = ins[0]
            out.append((ins.address, ins.mnemonic, ins.op_str))
        pos += 4
    return out

# Build VA -> symbol name map for branch annotation
addr_to_sym = {s["value"]: s["name"] for s in syms if s["value"] and s["shndx"] != 0}

# Disassemble each LoadAccount-y function
for s in hits:
    va = s["value"]
    # If size unknown, run until next exported symbol
    size = s["size"]
    if not size:
        next_addrs = sorted(x["value"] for x in syms if x["value"] > va) + \
                     sorted(x["value"] for x in (hits + [{"value":text_va+text["size"]}]) if x["value"] > va)
        size = (min(next_addrs) - va) if next_addrs else 0x400
        size = min(size, 0x800)
    print(f"\n{'='*78}\n{s['name']}  @ {va:#010x}   size={size:#x}\n{'='*78}")
    for addr, mn, op in disasm_range(va, size):
        annot = ""
        # Try to resolve branch targets to symbols
        if mn.startswith("b") and "0x" in op:
            try:
                tgt = int(op.split("0x")[-1].split(",")[0], 16)
                if tgt in addr_to_sym:
                    annot = f"   ; -> {addr_to_sym[tgt]}"
            except: pass
        print(f"    {addr:#010x}: {mn:<10} {op}{annot}")
