"""Locate GetRecentPlayRecord in nn_fp.elf, disassemble, and find the IPC request ID."""
import struct, sys, capstone

ELF = r"C:\Users\Nikolaj\source\repos\Cemu\tools_tmp\nn_fp.elf"
TARGET = "GetRecentPlayRecord__Q2_2nn2fpFPQ3_2nn2fp18RecentPlayRecordExPUiUiT3"

with open(ELF, "rb") as f:
    data = f.read()
e_shoff = struct.unpack(">I", data[0x20:0x24])[0]
e_shentsz = struct.unpack(">H", data[0x2E:0x30])[0]
e_shnum = struct.unpack(">H", data[0x30:0x32])[0]
e_shstrnd = struct.unpack(">H", data[0x32:0x34])[0]
sh = []
for i in range(e_shnum):
    off = e_shoff + i * e_shentsz
    n,t,f,a,o,s,l,i_,al,e_ = struct.unpack(">IIIIIIIIII", data[off:off+40])
    sh.append(dict(name=n,type=t,flags=f,addr=a,off=o,size=s,link=l,info=i_,align=al,ent=e_))
strs = data[sh[e_shstrnd]["off"]:sh[e_shstrnd]["off"]+sh[e_shstrnd]["size"]]
for s in sh:
    end = strs.find(b"\x00", s["name"])
    s["nm"] = strs[s["name"]:end].decode("ascii","replace")
by_name = {s["nm"]: s for s in sh}

# Find target VA via .fexports
fexp = by_name[".fexports"]
body = data[fexp["off"]:fexp["off"]+fexp["size"]]
count = struct.unpack(">I", body[:4])[0]
print(f"# .fexports: {count} entries")
target_va = None
for i in range(count):
    va, no = struct.unpack(">II", body[8+i*8:16+i*8])
    end = body.find(b"\x00", no)
    nm = body[no:end].decode("ascii","replace")
    if nm == TARGET:
        target_va = va
        print(f"  -> {nm} @ VA 0x{va:08x}")
    elif "RecentPlay" in nm:
        print(f"  related: {nm} @ VA 0x{va:08x}")

if target_va is None:
    print("not found, dumping all exports with 'Record' in name:")
    for i in range(count):
        va, no = struct.unpack(">II", body[8+i*8:16+i*8])
        end = body.find(b"\x00", no)
        nm = body[no:end].decode("ascii","replace")
        if "Record" in nm:
            print(f"  {nm} @ 0x{va:08x}")
    sys.exit(1)

# Disassemble function. Use symtab size if available.
sym_size = 0
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
        if v == target_va and sz > 0:
            sym_size = sz
for s in sh:
    if s["nm"].startswith(".fimport_"):
        ib = data[s["off"]:s["off"]+s["size"]]
        if len(ib) < 8: continue
        cnt = struct.unpack(">I", ib[:4])[0]
        for i in range(cnt):
            va, no = struct.unpack(">II", ib[8+i*8:16+i*8])
            end = ib.find(b"\x00", no)
            nm = ib[no:end].decode("ascii","replace")
            sym_map.setdefault(va, s["nm"][len(".fimport_"):] + "::" + nm)

text = by_name[".text"]
base = text["addr"]
tb = data[text["off"]:text["off"]+text["size"]]
off = target_va - base
size = sym_size if sym_size else 0x500
fb = tb[off:off+size]
print(f"\nDisasm 0x{target_va:08x} size=0x{len(fb):x} (symtab size=0x{sym_size:x})\n")

md = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN)
md.detail = True

regs = {}
# Decode and look for: any 'li' or 'addi' loading a small constant that fits an FPD_REQUEST_ID
# (typically 0x27xx, 0x28xx, 0x77xx, 0x96.. etc — up to 0x1FFFF).
candidates = []
for ins in md.disasm(fb, target_va):
    w = struct.unpack(">I", ins.bytes)[0]
    opcd = (w >> 26) & 0x3F
    comment = ""
    # li / addi / addis / oris combinations to detect constants
    if opcd == 14:  # addi (also li when rA=0)
        rD = (w >> 21) & 0x1F
        rA = (w >> 16) & 0x1F
        simm = w & 0xFFFF
        if simm & 0x8000: simm -= 0x10000
        if rA == 0:
            regs[rD] = simm & 0xFFFFFFFF
            if 0x100 <= regs[rD] <= 0x1FFFF:
                candidates.append((ins.address, regs[rD], "li"))
                comment = f"  ; r{rD} = 0x{regs[rD]:x}  (candidate request id)"
        elif rA in regs:
            regs[rD] = (regs[rA] + simm) & 0xFFFFFFFF
            if 0x100 <= regs[rD] <= 0x1FFFF:
                candidates.append((ins.address, regs[rD], "addi"))
                comment = f"  ; r{rD} = 0x{regs[rD]:x}"
    elif opcd == 15:  # addis / lis
        rD = (w >> 21) & 0x1F
        rA = (w >> 16) & 0x1F
        imm = w & 0xFFFF
        if rA == 0:
            regs[rD] = (imm << 16) & 0xFFFFFFFF
        else:
            regs[rD] = ((regs.get(rA, 0) + (imm << 16))) & 0xFFFFFFFF
    elif opcd == 24:  # ori
        rA = (w >> 21) & 0x1F
        rS = (w >> 16) & 0x1F  # actually rS in source
        uimm = w & 0xFFFF
        # ori rA, rS, uimm — wait the encoding is opcd|rS|rA|UI for ori
        rS_real = (w >> 21) & 0x1F
        rA_real = (w >> 16) & 0x1F
        if rS_real in regs:
            regs[rA_real] = (regs[rS_real] | uimm) & 0xFFFFFFFF
            if 0x100 <= regs[rA_real] <= 0x1FFFF:
                candidates.append((ins.address, regs[rA_real], "ori"))
                comment = f"  ; r{rA_real} = 0x{regs[rA_real]:x}"
    # bl target?
    if (w & 0xFC000003) == 0x48000001:
        li = w & 0x03FFFFFC
        if li & 0x02000000: li -= 0x04000000
        target = (ins.address + li) & 0xFFFFFFFF
        lbl = sym_map.get(target, f"sub_{target:08x}")
        comment = f"  ; -> {lbl}"
    print(f"  0x{ins.address:08x}: {ins.bytes.hex():8s} {ins.mnemonic:8s} {ins.op_str}{comment}")

print(f"\n# request-id candidates (small constants loaded in fn):")
for addr, val, how in candidates:
    print(f"  pc=0x{addr:08x}: 0x{val:x} ({val}) via {how}")
