"""Disassemble a function at a given VA in nn_boss.elf with bl resolution."""
import struct, sys, capstone, bisect

ELF = r"C:\Users\Nikolaj\source\repos\Cemu\tools_tmp\nn_boss.elf"
TARGET = int(sys.argv[1], 0)
MAX_LEN = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x400

with open(ELF, "rb") as f:
    data = f.read()

e_shoff = struct.unpack(">I", data[0x20:0x24])[0]
e_shentsz = struct.unpack(">H", data[0x2E:0x30])[0]
e_shnum = struct.unpack(">H", data[0x30:0x32])[0]
e_shstrnd = struct.unpack(">H", data[0x32:0x34])[0]
sh = []
for i in range(e_shnum):
    off = e_shoff + i*e_shentsz
    n,t,f,a,o,s,l,i_,al,e_ = struct.unpack(">IIIIIIIIII", data[off:off+40])
    sh.append(dict(idx=i,name=n,type=t,flags=f,addr=a,off=o,size=s))
strs = data[sh[e_shstrnd]["off"]:sh[e_shstrnd]["off"]+sh[e_shstrnd]["size"]]
for s in sh:
    end = strs.find(b"\x00", s["name"])
    s["nm"] = strs[s["name"]:end].decode("ascii", "replace")
by_name = {s["nm"]: s for s in sh}

# Build a symbol map (symtab + .fimport_*)
sym_map = {}
if ".symtab" in by_name and ".strtab" in by_name:
    st = by_name[".symtab"]; strtab = by_name[".strtab"]
    stb = data[st["off"]:st["off"]+st["size"]]
    sb  = data[strtab["off"]:strtab["off"]+strtab["size"]]
    for i in range(st["size"] // 16):
        n,v,sz,info,oth,shndx = struct.unpack(">IIIBBH", stb[i*16:(i+1)*16])
        end = sb.find(b"\x00", n)
        nm = sb[n:end].decode("ascii","replace")
        if nm:
            sym_map.setdefault(v, nm)
for s in sh:
    if s["nm"].startswith(".fimport_"):
        ib = data[s["off"]:s["off"]+s["size"]]
        cnt = struct.unpack(">I", ib[:4])[0]
        for i in range(cnt):
            va, no = struct.unpack(">II", ib[8+i*8:16+i*8])
            end = ib.find(b"\x00", no)
            sym_map.setdefault(va, s["nm"][len(".fimport_"):] + "::" + ib[no:end].decode("ascii","replace"))

# function bounds
sym_size = 0
if ".symtab" in by_name:
    st = by_name[".symtab"]
    stb = data[st["off"]:st["off"]+st["size"]]
    for i in range(st["size"] // 16):
        n,v,sz,info,oth,shndx = struct.unpack(">IIIBBH", stb[i*16:(i+1)*16])
        if v == TARGET and sz > 0:
            sym_size = sz
            break

text = by_name[".text"]
base = text["addr"]
tb = data[text["off"]:text["off"]+text["size"]]
off = TARGET - base
size = sym_size if sym_size else MAX_LEN
fb = tb[off:off+size]
print(f"Disasm 0x{TARGET:08x} size=0x{size:x} (sym_size=0x{sym_size:x})")
print(f"Label: {sym_map.get(TARGET,'?')}\n")

md = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN)
md.detail = True

# rodata
rodata = by_name.get(".rodata")
rd = data[rodata["off"]:rodata["off"]+rodata["size"]] if rodata else b""
rd_base = rodata["addr"] if rodata else 0

# track register loads for lis/addi & lwz comments
regs = {}
words = struct.unpack(f">{len(fb)//4}I", fb[:(len(fb)//4)*4])
for i, ins in enumerate(md.disasm(fb, TARGET)):
    w = struct.unpack(">I", ins.bytes)[0]
    opcd = (w >> 26) & 0x3F
    comment = ""
    if opcd == 15:  # addis = lis when rA=0
        rD = (w >> 21) & 0x1F
        rA = (w >> 16) & 0x1F
        imm = w & 0xFFFF
        if rA == 0:
            regs[rD] = imm << 16
    elif opcd == 14:  # addi
        rD = (w >> 21) & 0x1F
        rA = (w >> 16) & 0x1F
        simm = w & 0xFFFF
        if simm & 0x8000: simm -= 0x10000
        if rA in regs:
            val = (regs[rA] + simm) & 0xFFFFFFFF
            regs[rD] = val
            if rodata and rodata["addr"] <= val < rodata["addr"]+rodata["size"]:
                e = rd.find(b"\x00", val-rd_base)
                s = rd[val-rd_base:e].decode("ascii", "replace")
                comment = f"  ; -> 0x{val:08x} {s!r}"
            else:
                comment = f"  ; -> 0x{val:08x}"
    elif opcd == 32:  # lwz
        # not modeling load-of-pointer through small-data here
        pass
    # bl?
    if (w & 0xFC000003) == 0x48000001:
        li = w & 0x03FFFFFC
        if li & 0x02000000: li -= 0x04000000
        target = (ins.address + li) & 0xFFFFFFFF
        lbl = sym_map.get(target, f"sub_{target:08x}")
        comment = f"  ; -> {lbl}"
    print(f"  0x{ins.address:08x}: {ins.bytes.hex():8s} {ins.mnemonic:8s} {ins.op_str}{comment}")
