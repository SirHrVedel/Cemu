"""Diff nn_boss.rpl exports vs Cemu registered exports."""
import re, struct

# 1. Parse RPL exports
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
rpl_exports = set()
for i in range(count):
    va, no = struct.unpack(">II", body[8+i*8:16+i*8])
    end = body.find(b"\x00", no)
    nm = body[no:end].decode("ascii","replace")
    rpl_exports.add(nm)

# 2. Parse Cemu nn_boss.cpp registered names
with open(r"C:\Users\Nikolaj\source\repos\Cemu\src\Cafe\OS\libs\nn_boss\nn_boss.cpp", "r") as f:
    src = f.read()
cemu_regs = set(re.findall(r'cafeExportRegisterFunc\([^,]+,\s*"nn_boss",\s*"([^"]+)"', src))

# 3. Diff
missing = sorted(rpl_exports - cemu_regs)
extra = sorted(cemu_regs - rpl_exports)
overlap = sorted(rpl_exports & cemu_regs)

print(f"RPL exports: {len(rpl_exports)}")
print(f"Cemu registrations: {len(cemu_regs)}")
print(f"Overlap: {len(overlap)}")
print(f"Missing from Cemu ({len(missing)}):")
for m in missing:
    print(f"  {m}")
print(f"\nIn Cemu but NOT in RPL ({len(extra)}):")
for m in extra:
    print(f"  {m}")
