"""Diff coreinit.rpl exports vs Cemu registered exports.

Cemu registers coreinit functions across many files under src/Cafe/OS/libs/coreinit/.
Both cafeExportRegister (auto-derives name from symbol) and cafeExportRegisterFunc
(explicit name string) are used. Plus the deprecated osLib_addFunction.
"""
import re, struct, os, glob

ELF = r"C:\Users\Nikolaj\source\repos\Cemu\tools_tmp\coreinit.elf"
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

# Gather Cemu registrations
cemu_regs = set()
explicit_regs = set()
auto_regs = set()  # cafeExportRegister(ns, fnname, ...) — name from symbol
osLib_regs = set()

base = r"C:\Users\Nikolaj\source\repos\Cemu\src\Cafe\OS\libs\coreinit"
all_files = []
for root, _, files in os.walk(base):
    for n in files:
        if n.endswith((".cpp", ".h")):
            all_files.append(os.path.join(root, n))
# Also pick up registrations elsewhere that register into "coreinit"
for f in glob.glob(r"C:\Users\Nikolaj\source\repos\Cemu\src\**\*.cpp", recursive=True):
    all_files.append(f)

# Patterns
# 1. cafeExportRegisterFunc(fn, "coreinit", "ExplicitName", ...)
pat_explicit = re.compile(r'cafeExportRegisterFunc\([^,]+,\s*"coreinit"\s*,\s*"([^"]+)"')
# 2. cafeExportRegister("coreinit", FnSymbol, ...) → name == FnSymbol's last :: part
pat_auto = re.compile(r'cafeExportRegister\(\s*"coreinit"\s*,\s*([A-Za-z_][\w:]*)')
# 3. osLib_addFunction("coreinit", "ExplicitName", ...)
pat_oslib = re.compile(r'osLib_addFunction\(\s*"coreinit"\s*,\s*"([^"]+)"')

for f in all_files:
    try:
        with open(f, "r", encoding="utf-8", errors="replace") as fp:
            src = fp.read()
    except Exception:
        continue
    for m in pat_explicit.finditer(src):
        explicit_regs.add(m.group(1))
    for m in pat_auto.finditer(src):
        sym = m.group(1).split("::")[-1]
        auto_regs.add(sym)
    for m in pat_oslib.finditer(src):
        osLib_regs.add(m.group(1))

cemu_regs = explicit_regs | auto_regs | osLib_regs

# Diff
missing = sorted(rpl_exports - cemu_regs)
extra = sorted(cemu_regs - rpl_exports)
overlap = sorted(rpl_exports & cemu_regs)

print(f"RPL exports: {len(rpl_exports)}")
print(f"Cemu registrations:")
print(f"  cafeExportRegisterFunc (explicit name): {len(explicit_regs)}")
print(f"  cafeExportRegister (auto): {len(auto_regs)}")
print(f"  osLib_addFunction (deprecated): {len(osLib_regs)}")
print(f"  union total: {len(cemu_regs)}")
print(f"Overlap: {len(overlap)}")
print(f"Missing from Cemu: {len(missing)}")
print(f"In Cemu but NOT in RPL: {len(extra)}")
print()
print("--- Missing exports (Cemu doesn't register these) ---")
for m in missing:
    print(m)
print()
print("--- In Cemu but not in RPL (likely typos / private symbols) ---")
for m in extra:
    print(m)
