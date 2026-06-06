"""Look up bytes at given VAs in nn_boss.elf data/rodata."""
import struct, sys
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
    sh.append(dict(name=n,type=t,flags=f,addr=a,off=o,size=s))
strs = data[sh[e_shstrnd]["off"]:sh[e_shstrnd]["off"]+sh[e_shstrnd]["size"]]
for s in sh:
    end = strs.find(b"\x00", s["name"])
    s["nm"] = strs[s["name"]:end].decode("ascii","replace")

vas = [int(x,0) for x in sys.argv[1:]]
for va in vas:
    for s in sh:
        if s["addr"] <= va < s["addr"]+s["size"]:
            o = s["off"] + (va - s["addr"])
            blob = data[o:o+64]
            ascii_ = "".join(chr(b) if 32<=b<127 else "." for b in blob)
            print(f"VA 0x{va:08x} in {s['nm']} (+0x{va-s['addr']:x}):")
            print(f"  hex:   {blob.hex()}")
            print(f"  ascii: {ascii_}")
            # Also try reading as 4-byte BE int
            if len(blob) >= 4:
                print(f"  u32 BE: 0x{struct.unpack('>I', blob[:4])[0]:08x}")
            break
    else:
        print(f"VA 0x{va:08x}: not in any section")

# Also list fimports
print("\nAll .fimport sections:")
for s in sh:
    if s["nm"].startswith(".fimport_") or s["nm"].startswith(".dimport_"):
        body = data[s["off"]:s["off"]+s["size"]]
        if len(body) < 8: continue
        cnt = struct.unpack(">I", body[:4])[0]
        print(f"  {s['nm']} cnt={cnt}")
