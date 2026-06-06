"""Disassemble IsRecentPlayRecordCorrupted to see what it returns."""
import struct, capstone
ELF = r"C:\Users\Nikolaj\source\repos\Cemu\tools_tmp\nn_fp.elf"
with open(ELF, "rb") as f: data = f.read()
e_shoff = struct.unpack(">I", data[0x20:0x24])[0]
e_shentsz = struct.unpack(">H", data[0x2E:0x30])[0]
e_shnum = struct.unpack(">H", data[0x30:0x32])[0]
e_shstrnd = struct.unpack(">H", data[0x32:0x34])[0]
sh = []
for i in range(e_shnum):
    off = e_shoff + i*e_shentsz
    n,t,f,a,o,s,l,i_,al,e_ = struct.unpack(">IIIIIIIIII", data[off:off+40])
    sh.append(dict(name=n,off=o,size=s,addr=a))
strs = data[sh[e_shstrnd]["off"]:sh[e_shstrnd]["off"]+sh[e_shstrnd]["size"]]
for s in sh:
    end = strs.find(b"\x00", s["name"])
    s["nm"] = strs[s["name"]:end].decode("ascii","replace")
by_name = {s["nm"]: s for s in sh}

TARGET = 0x0200529c
sym_size = 0
if ".symtab" in by_name:
    st = by_name[".symtab"]
    stb = data[st["off"]:st["off"]+st["size"]]
    for i in range(st["size"] // 16):
        n,v,sz,info,oth,shndx = struct.unpack(">IIIBBH", stb[i*16:(i+1)*16])
        if v == TARGET:
            sym_size = sz

text = by_name[".text"]
base = text["addr"]
tb = data[text["off"]:text["off"]+text["size"]]
off = TARGET - base
fb = tb[off:off+max(sym_size, 0x80)]
print(f"IsRecentPlayRecordCorrupted @ 0x{TARGET:08x} size=0x{sym_size:x}")

md = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN)
for ins in md.disasm(fb, TARGET):
    print(f"  0x{ins.address:08x}: {ins.bytes.hex():8s} {ins.mnemonic:8s} {ins.op_str}")
