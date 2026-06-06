"""
Dump all printable strings from a decompressed nn_act.rpl and show rodata content.
"""
import struct, zlib, sys
from pathlib import Path

RPL_PATH = r"D:\Games\Console\Cafe\storage_slc\sys\title\00050010\1000400a\code\nn_act.rpl"
SHF_RPL_ZLIB = 0x08000000

def read_elf_header(data):
    e_shoff, = struct.unpack_from(">I", data, 0x20)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(">HHH", data, 0x2E)
    return e_shoff, e_shentsize, e_shnum, e_shstrndx

def read_section_headers(data, e_shoff, e_shentsize, e_shnum):
    shdrs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (sh_name, sh_type, sh_flags, sh_addr,
         sh_offset, sh_size, sh_link, sh_info,
         sh_addralign, sh_entsize) = struct.unpack_from(">IIIIIIIIII", data, off)
        shdrs.append({"sh_name": sh_name, "sh_type": sh_type,
                      "sh_flags": sh_flags, "sh_addr": sh_addr,
                      "sh_offset": sh_offset, "sh_size": sh_size,
                      "name": "", "data": b""})
    return shdrs

def decompress_sections(raw, shdrs):
    for s in shdrs:
        if s["sh_size"] == 0 or s["sh_offset"] == 0:
            continue
        blob = raw[s["sh_offset"]: s["sh_offset"] + s["sh_size"]]
        if s["sh_flags"] & SHF_RPL_ZLIB:
            uncompressed_size = struct.unpack_from(">I", blob, 0)[0]
            s["data"] = zlib.decompress(blob[4:])
        else:
            s["data"] = blob

def resolve_names(shdrs, shstrndx):
    strtab = shdrs[shstrndx]["data"]
    for s in shdrs:
        off = s["sh_name"]
        end = strtab.index(b"\x00", off)
        s["name"] = strtab[off:end].decode("ascii", errors="replace")

def extract_strings(data, min_len=4):
    results = []
    current = []
    offset_start = 0
    for i, b in enumerate(data):
        if 0x20 <= b <= 0x7E:
            if not current:
                offset_start = i
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                results.append((offset_start, "".join(current)))
            current = []
    if len(current) >= min_len:
        results.append((offset_start, "".join(current)))
    return results

raw = Path(RPL_PATH).read_bytes()
e_shoff, e_shentsize, e_shnum, e_shstrndx = read_elf_header(raw)
shdrs = read_section_headers(raw, e_shoff, e_shentsize, e_shnum)
decompress_sections(raw, shdrs)
resolve_names(shdrs, e_shstrndx)

print("=== All strings per section ===\n")
for sec in shdrs:
    if not sec["data"]:
        continue
    strings = extract_strings(sec["data"], min_len=5)
    if not strings:
        continue
    # Only show sections with interesting strings (not just symbols)
    path_like = [s for s in strings if "/" in s[1] or "\\" in s[1] or "." in s[1]]
    print(f"\n--- Section: {sec['name']}  (addr={sec['sh_addr']:#010x}, {len(sec['data'])} bytes) ---")
    for off, s in path_like:
        va = sec["sh_addr"] + off
        print(f"  {va:#010x}  {s!r}")
    if not path_like:
        # just show first 20 strings
        for off, s in strings[:20]:
            va = sec["sh_addr"] + off
            print(f"  {va:#010x}  {s!r}")

print("\n\n=== Searching for 'act', 'account', 'dat', 'common' across ALL sections ===")
keywords = [b"common", b"act/", b"account", b".dat", b"/vol/", b"sys/", b"usr/"]
for sec in shdrs:
    for kw in keywords:
        idx = 0
        while True:
            pos = sec["data"].find(kw, idx)
            if pos == -1:
                break
            va = sec["sh_addr"] + pos
            ctx = sec["data"][max(0,pos-20):pos+40]
            # show null-terminated string around it
            print(f"  [{sec['name']}] {va:#010x}: kw={kw!r}  ctx={ctx!r}")
            idx = pos + 1
