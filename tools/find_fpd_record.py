"""Locate the FPD module inside the decrypted IOSU image by scanning for
the record.bin / fpd path strings, then identify which PT_LOAD segment
contains them and which segments form the FPD module.

Outputs:
  - VA of every occurrence of relevant strings
  - segment index + perms for each
  - guess at the FPD module's .text/.rodata/.data/.bss quartet
"""
import json
import struct

FW = r"C:\Users\Nikolaj\source\repos\Cemu\tools\fw_decrypted.bin"
PHDRS = r"C:\Users\Nikolaj\source\repos\Cemu\tools\fw_phdrs.json"

with open(FW, "rb") as f:
    data = f.read()

with open(PHDRS, "r") as f:
    _phdrs_raw = json.load(f)
phdrs = _phdrs_raw["phdrs"]

# We're looking for:
#   /vol/storage_mlc01/usr/save/system/fpd/...
#   record.bin
#   record_v??.bin (in case there's a versioned name)
#   Records, frd:, friends, fpd: ...
needles = [
    b"record.bin",
    b"/usr/save/system/fpd",
    b"storage_mlc01/usr/save/system/fpd",
    b"system/fpd",
    b"RecentPlayRecord",
    b"recent_play_record",
    b"fpd_record",
    b"frd:",
    b"fpd:",
    b"FpdSave",
    b"RecordFile",
]

def file_off_to_va(off):
    """Map a file offset back to its VA, using the program-header table."""
    for i, ph in enumerate(phdrs):
        if ph["type"] != 1:  # PT_LOAD only
            continue
        p_off, p_va, p_filesz = ph["abs_file_off"], ph["vaddr"], ph["filesz"]
        if p_off <= off < p_off + p_filesz:
            return p_va + (off - p_off), i, ph
    return None, -1, None

print(f"# scanning {len(data):,} bytes for FPD string anchors\n")
all_hits = []
for needle in needles:
    start = 0
    while True:
        off = data.find(needle, start)
        if off < 0:
            break
        va, seg_idx, seg = file_off_to_va(off)
        # extract surrounding string until null
        end = off
        while end < len(data) and data[end] != 0 and end - off < 200:
            end += 1
        ctx = data[off:end].decode("ascii", errors="replace")
        all_hits.append((va, seg_idx, seg, ctx, off, needle))
        start = off + 1

# print summary grouped by segment
by_seg = {}
for hit in all_hits:
    by_seg.setdefault(hit[1], []).append(hit)

for seg_idx in sorted(by_seg.keys()):
    seg = phdrs[seg_idx] if seg_idx >= 0 else None
    if seg:
        perms_str = "".join([
            "R" if seg.get("flags", 0) & 4 else "-",
            "W" if seg.get("flags", 0) & 2 else "-",
            "X" if seg.get("flags", 0) & 1 else "-",
        ])
        print(f"# segment {seg_idx}  VA 0x{seg['vaddr']:08x}-0x{seg['vaddr']+seg['memsz']:08x}  {perms_str}  filesz=0x{seg['filesz']:x}")
    else:
        print(f"# segment {seg_idx}  (unmapped)")
    for va, _, _, ctx, off, needle in by_seg[seg_idx]:
        marker = "  "
        if va is not None:
            print(f"  VA 0x{va:08x}  file 0x{off:08x}  {ctx!r}")
        else:
            print(f"  file 0x{off:08x}  {ctx!r}  (no VA mapping)")
    print()
