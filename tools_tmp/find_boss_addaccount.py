"""Locate and disassemble nn::boss::Account::Add(uint32) in nn_boss.elf."""
import struct
import sys
import capstone

ELF = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\Nikolaj\source\repos\Cemu\tools_tmp\nn_boss.elf"
TARGET_MANGLED = "AddAccount__Q3_2nn4boss7AccountSFUi"


def load_sections(data):
    e_shoff = struct.unpack(">I", data[0x20:0x24])[0]
    e_shentsz = struct.unpack(">H", data[0x2E:0x30])[0]
    e_shnum = struct.unpack(">H", data[0x30:0x32])[0]
    e_shstrnd = struct.unpack(">H", data[0x32:0x34])[0]
    sh = []
    for i in range(e_shnum):
        off = e_shoff + i*e_shentsz
        n,t,f,a,o,s,l,i_,al,e_ = struct.unpack(">IIIIIIIIII", data[off:off+40])
        sh.append(dict(idx=i,name=n,type=t,flags=f,addr=a,off=o,size=s,link=l,info=i_,align=al,ent=e_))
    # shstrtab
    strs = data[sh[e_shstrnd]["off"]:sh[e_shstrnd]["off"]+sh[e_shstrnd]["size"]]
    for s in sh:
        end = strs.find(b"\x00", s["name"])
        s["nm"] = strs[s["name"]:end].decode("ascii", "replace")
    return sh


def main():
    with open(ELF, "rb") as f:
        data = f.read()
    sh = load_sections(data)
    by_name = {s["nm"]: s for s in sh}

    # Find target VA via .fexports
    fexp = by_name[".fexports"]
    body = data[fexp["off"]:fexp["off"]+fexp["size"]]
    count = struct.unpack(">I", body[:4])[0]
    sig = struct.unpack(">I", body[4:8])[0]
    print(f".fexports: count={count} sig=0x{sig:08x}")
    target_va = None
    for i in range(count):
        va, name_off = struct.unpack(">II", body[8+i*8:16+i*8])
        end = body.find(b"\x00", name_off)
        nm = body[name_off:end].decode("ascii", "replace")
        if TARGET_MANGLED in nm:
            target_va = va
            print(f"  -> {nm} @ VA 0x{va:08x}")
    if target_va is None:
        print("Target not in .fexports — scan .symtab?")
        # also try .symtab
        if ".symtab" in by_name and ".strtab" in by_name:
            st = by_name[".symtab"]; strtab = by_name[".strtab"]
            stb = data[st["off"]:st["off"]+st["size"]]
            sb  = data[strtab["off"]:strtab["off"]+strtab["size"]]
            ent_count = st["size"] // 16
            for i in range(ent_count):
                n,v,sz,info,oth,shndx = struct.unpack(">IIIBBH", stb[i*16:(i+1)*16])
                end = sb.find(b"\x00", n)
                nm = sb[n:end].decode("ascii","replace")
                if TARGET_MANGLED in nm:
                    target_va = v
                    sym_size = sz
                    print(f"  symtab: {nm} @ 0x{v:08x} size=0x{sz:x}")
        if target_va is None:
            sys.exit(1)

    # .text section
    text = by_name[".text"]
    base = text["addr"]
    text_bytes = data[text["off"]:text["off"]+text["size"]]
    print(f".text VA=0x{base:08x} size=0x{text['size']:x}")

    # Determine function end: try symtab size; else find next prologue
    sym_size = 0
    if ".symtab" in by_name and ".strtab" in by_name:
        st = by_name[".symtab"]; strtab = by_name[".strtab"]
        stb = data[st["off"]:st["off"]+st["size"]]
        sb  = data[strtab["off"]:strtab["off"]+strtab["size"]]
        for i in range(st["size"] // 16):
            n,v,sz,info,oth,shndx = struct.unpack(">IIIBBH", stb[i*16:(i+1)*16])
            if v == target_va and sz > 0:
                sym_size = sz
                break

    off = target_va - base
    if sym_size == 0:
        # naive: find next 'mflr r0' (0x7C0802A6) after a 'blr' (0x4E800020)
        end = off + 0x800
    else:
        end = off + sym_size
    func_bytes = text_bytes[off:end]
    print(f"function bytes: off=0x{off:x} size=0x{len(func_bytes):x}\n")

    md = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN)
    md.detail = True
    addr = target_va
    for ins in md.disasm(func_bytes, addr):
        print(f"  0x{ins.address:08x}: {ins.bytes.hex():8s} {ins.mnemonic:8s} {ins.op_str}")

    # Resolve .rodata strings near it (small-data via r2/r13 plus literal pool refs)
    # Print rodata strings that any 'lis/addi' or 'lwz' pair appears to load.

    rodata = by_name.get(".rodata")
    if rodata:
        rd = data[rodata["off"]:rodata["off"]+rodata["size"]]
        rd_base = rodata["addr"]
        # Build (hi, lo) pairs from lis/addi sequences
        words = struct.unpack(f">{len(func_bytes)//4}I", func_bytes[:(len(func_bytes)//4)*4])
        # quick scan: lis r?,imm  followed by addi r?,r?,imm  produce 32-bit const
        print("\nPossible string constants:")
        regs = {}
        for i, w in enumerate(words):
            opcd = (w >> 26) & 0x3F
            if opcd == 15:  # addis (lis)
                rD = (w >> 21) & 0x1F
                imm = w & 0xFFFF
                regs[rD] = (imm << 16, "lis")
            elif opcd == 14:  # addi
                rD = (w >> 21) & 0x1F
                rA = (w >> 16) & 0x1F
                simm = w & 0xFFFF
                if simm & 0x8000: simm -= 0x10000
                if rA in regs and regs[rA][1] == "lis":
                    val = (regs[rA][0] + simm) & 0xFFFFFFFF
                    if rodata["addr"] <= val < rodata["addr"]+rodata["size"]:
                        end = rd.find(b"\x00", val-rd_base)
                        s = rd[val-rd_base:end].decode("ascii", "replace")
                        if s and all(0x20 <= ord(c) < 0x7f or c in "\r\n\t" for c in s):
                            print(f"  pc=0x{target_va + i*4:08x} -> 0x{val:08x}: {s!r}")
                    regs[rD] = (val, "const")
        # .data references too
        ddata = by_name.get(".data")
        if ddata:
            print(f"\n.data covers 0x{ddata['addr']:08x}..0x{ddata['addr']+ddata['size']:08x}")
        bss = by_name.get(".bss")
        if bss:
            print(f".bss covers 0x{bss['addr']:08x}..0x{bss['addr']+bss['size']:08x}")

    # Resolve bl targets via symtab + fimport sections
    bls = []
    for i, w in enumerate(struct.unpack(f">{len(func_bytes)//4}I", func_bytes[:(len(func_bytes)//4)*4])):
        if (w & 0xFC000003) == 0x48000001:  # bl
            li = w & 0x03FFFFFC
            if li & 0x02000000: li -= 0x04000000
            target = (target_va + i*4 + li) & 0xFFFFFFFF
            bls.append((target_va + i*4, target))
    if bls:
        # use symtab to label
        sym_map = {}
        if ".symtab" in by_name and ".strtab" in by_name:
            st = by_name[".symtab"]; strtab = by_name[".strtab"]
            stb = data[st["off"]:st["off"]+st["size"]]
            sb  = data[strtab["off"]:strtab["off"]+strtab["size"]]
            for i in range(st["size"] // 16):
                n,v,sz,info,oth,shndx = struct.unpack(">IIIBBH", stb[i*16:(i+1)*16])
                end = sb.find(b"\x00", n)
                sym_map[v] = sb[n:end].decode("ascii","replace")
        # fimport sections too
        for s in sh:
            if s["nm"].startswith(".fimport_"):
                ib = data[s["off"]:s["off"]+s["size"]]
                cnt = struct.unpack(">I", ib[:4])[0]
                for i in range(cnt):
                    va, no = struct.unpack(">II", ib[8+i*8:16+i*8])
                    end = ib.find(b"\x00", no)
                    sym_map.setdefault(va, s["nm"][len(".fimport_"):] + "::" + ib[no:end].decode("ascii","replace"))
        print("\nbl targets:")
        for src, tgt in bls:
            lbl = sym_map.get(tgt, "?")
            print(f"  0x{src:08x} -> 0x{tgt:08x}  {lbl}")


if __name__ == "__main__":
    main()
