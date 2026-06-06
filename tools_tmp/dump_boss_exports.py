"""Dump all nn_boss.rpl .fexports."""
import struct
ELF = r"C:\Users\Nikolaj\source\repos\Cemu\tools_tmp\nn_boss.elf"
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
fexp = next(s for s in sh if s["nm"] == ".fexports")
body = data[fexp["off"]:fexp["off"]+fexp["size"]]
count = struct.unpack(">I", body[:4])[0]
print(f"# {count} exports")
for i in range(count):
    va, no = struct.unpack(">II", body[8+i*8:16+i*8])
    end = body.find(b"\x00", no)
    nm = body[no:end].decode("ascii","replace")
    print(f"{va:08x}\t{nm}")
