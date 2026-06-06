"""
Decompress nn_act.rpl (Wii U RPL/ELF, PowerPC32 big-endian) and find
all functions that reference the string "common.dat".

RPL section compression: sections with SHF_RPL_ZLIB (0x08000000) are
prefixed with 4 bytes (LE uint32) = uncompressed size, followed by zlib data.
"""

import struct
import zlib
import sys
import re
from pathlib import Path

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    print("[WARN] capstone not found – disassembly will be skipped")

RPL_PATH = r"D:\Games\Console\Cafe\storage_slc\sys\title\00050010\1000400a\code\nn_act.rpl"
TARGET   = b"common.dat"

SHF_RPL_ZLIB = 0x08000000

# ── ELF structs (big-endian 32-bit) ─────────────────────────────────────────

def read_elf_header(data):
    """Return (e_shoff, e_shentsize, e_shnum, e_shstrndx)."""
    if data[:4] != b'\x7fELF':
        raise ValueError("Not an ELF file")
    ei_class = data[4]   # 1 = 32-bit
    ei_data  = data[5]   # 2 = big-endian
    assert ei_class == 1 and ei_data == 2, "Expected 32-bit big-endian ELF"
    # Ehdr fields we care about start at offset 0x20
    e_shoff, = struct.unpack_from(">I", data, 0x20)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(">HHH", data, 0x2E)
    return e_shoff, e_shentsize, e_shnum, e_shstrndx

def read_section_headers(data, e_shoff, e_shentsize, e_shnum):
    """Return list of dicts with sh_name, sh_type, sh_flags, sh_addr,
    sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize."""
    shdrs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (sh_name, sh_type, sh_flags, sh_addr,
         sh_offset, sh_size, sh_link, sh_info,
         sh_addralign, sh_entsize) = struct.unpack_from(">IIIIIIIIII", data, off)
        shdrs.append({
            "sh_name":      sh_name,
            "sh_type":      sh_type,
            "sh_flags":     sh_flags,
            "sh_addr":      sh_addr,
            "sh_offset":    sh_offset,
            "sh_size":      sh_size,
            "sh_addralign": sh_addralign,
            "name":         "",     # filled in later
            "data":         b"",    # decompressed payload
        })
    return shdrs

def decompress_sections(raw, shdrs):
    """Decompress RPL sections in-place."""
    for s in shdrs:
        if s["sh_size"] == 0 or s["sh_offset"] == 0:
            continue
        blob = raw[s["sh_offset"] : s["sh_offset"] + s["sh_size"]]
        if s["sh_flags"] & SHF_RPL_ZLIB:
            uncompressed_size = struct.unpack_from(">I", blob, 0)[0]
            decompressed = zlib.decompress(blob[4:])
            assert len(decompressed) == uncompressed_size, \
                f"Section size mismatch: expected {uncompressed_size}, got {len(decompressed)}"
            s["data"] = decompressed
        else:
            s["data"] = blob

def resolve_names(shdrs, shstrndx):
    """Fill the 'name' field of each section header."""
    strtab = shdrs[shstrndx]["data"]
    for s in shdrs:
        off = s["sh_name"]
        end = strtab.index(b"\x00", off)
        s["name"] = strtab[off:end].decode("ascii", errors="replace")

# ── String search ────────────────────────────────────────────────────────────

def find_string_offsets(sec, needle):
    """Return list of (virtual_address, file_offset_in_section_data)."""
    hits = []
    start = 0
    while True:
        idx = sec["data"].find(needle, start)
        if idx == -1:
            break
        va = sec["sh_addr"] + idx
        hits.append((va, idx))
        start = idx + 1
    return hits

# ── Cross-reference scan (load-immediate or address-of patterns on PPC) ──────

def find_xrefs_to_va(code_sec, target_va):
    """
    Scan a code section for instructions that load target_va.
    PPC uses lis rX, HI16 + addi/ori rX, rX, LO16 (or just lis + offset).
    We do a quick byte scan for any 4-byte instruction that encodes the
    upper 16 bits (HI16) of target_va, then check surrounding instructions.
    Returns list of (va_of_instruction, matched_va).
    """
    hi16 = (target_va >> 16) & 0xFFFF
    lo16 = target_va & 0xFFFF
    hits = []
    base = code_sec["sh_addr"]
    d = code_sec["data"]
    # Search for 'lis rX, HI16' (opcode 0x3C = 0b001111, bits 31-26)
    for i in range(0, len(d) - 3, 4):
        word, = struct.unpack_from(">I", d, i)
        opcode = (word >> 26) & 0x3F
        imm    = word & 0xFFFF
        # lis = addis with rA=0 → opcode 15 (0x0F)
        if opcode == 15 and imm == hi16:
            instr_va = base + i
            # look ahead up to 8 instructions for matching lo16
            for j in range(4, 36, 4):
                if i + j + 3 >= len(d):
                    break
                next_word, = struct.unpack_from(">I", d, i + j)
                next_imm   = next_word & 0xFFFF
                next_op    = (next_word >> 26) & 0x3F
                # addi (14) or ori (24) or lwz (32) with lo16
                if next_op in (14, 24, 32, 36) and next_imm == lo16:
                    hits.append((instr_va, target_va))
                    break
    return hits

# ── Function-boundary heuristic ──────────────────────────────────────────────

def find_function_start(code_data, code_base, instr_va):
    """
    Walk backwards from instr_va looking for:
      - stwu r1, -N(r1)  (function prologue, opcode 37, rS=1, rA=1)
      - or blr / b before it (end of previous function)
    Returns estimated function start VA.
    """
    offset = instr_va - code_base
    # Walk back up to 2 KB
    limit = max(0, offset - 2048)
    best  = instr_va
    for i in range(offset & ~3, limit, -4):
        word, = struct.unpack_from(">I", code_data, i)
        opcode = (word >> 26) & 0x3F
        rS     = (word >> 21) & 0x1F
        rA     = (word >> 16) & 0x1F
        # stwu r1, -N(r1): opcode 37, rS=1, rA=1, imm negative
        if opcode == 37 and rS == 1 and rA == 1:
            imm = word & 0xFFFF
            if imm & 0x8000:  # sign bit set → negative offset → valid prologue
                best = code_base + i
                break
        # blr (opcode 19, XO 16 = 0x4E800020) or unconditional b ending prior fn
        if word == 0x4E800020:  # blr
            best = code_base + i + 4
            break
    return best

# ── Disassembly ───────────────────────────────────────────────────────────────

def disassemble_range(data, base_va, start_va, length=256):
    if not HAS_CAPSTONE:
        return ["(capstone not available)"]
    md = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32 + capstone.CS_MODE_BIG_ENDIAN)
    md.detail = False
    offset = start_va - base_va
    chunk  = data[offset : offset + length]
    lines  = []
    for insn in md.disasm(chunk, start_va):
        lines.append(f"  {insn.address:#010x}:  {insn.mnemonic:<10} {insn.op_str}")
    return lines

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    raw = Path(RPL_PATH).read_bytes()
    print(f"[*] Loaded {RPL_PATH}  ({len(raw)} bytes)")

    e_shoff, e_shentsize, e_shnum, e_shstrndx = read_elf_header(raw)
    shdrs = read_section_headers(raw, e_shoff, e_shentsize, e_shnum)
    decompress_sections(raw, shdrs)
    resolve_names(shdrs, e_shstrndx)

    print(f"[*] {e_shnum} sections decompressed")
    for s in shdrs:
        if s["data"]:
            print(f"      [{s['name']:20s}] addr={s['sh_addr']:#010x} size={len(s['data']):#x} flags={s['sh_flags']:#010x}")

    # ── Step 1: find "common.dat" in any section ────────────────────────────
    all_string_vas = []
    for sec in shdrs:
        hits = find_string_offsets(sec, TARGET)
        for va, local_off in hits:
            print(f"\n[STRING] '{TARGET.decode()}' found in section '{sec['name']}'"
                  f"  VA={va:#010x}  local_off={local_off:#x}")
            # also show surrounding bytes to get full path
            ctx_start = max(0, local_off - 64)
            ctx_end   = min(len(sec["data"]), local_off + len(TARGET) + 64)
            snippet   = sec["data"][ctx_start:ctx_end]
            # Extract null-terminated string that contains our match
            abs_in_ctx = local_off - ctx_start
            str_start  = abs_in_ctx
            while str_start > 0 and snippet[str_start - 1] != 0:
                str_start -= 1
            str_end = abs_in_ctx + len(TARGET)
            while str_end < len(snippet) and snippet[str_end] != 0:
                str_end += 1
            full_str = snippet[str_start:str_end]
            print(f"         full string: {full_str}")
            all_string_vas.append((va, full_str.decode("ascii", errors="replace")))

    if not all_string_vas:
        print(f"\n[!] '{TARGET.decode()}' not found in any section – check compression/paths")
        return

    # ── Step 2: find code cross-references ──────────────────────────────────
    code_sections = [s for s in shdrs if s["sh_type"] == 1 and  # SHT_PROGBITS
                     s["sh_flags"] & 0x4 and s["sh_addr"] != 0] # SHF_EXECINSTR

    print(f"\n[*] Scanning {len(code_sections)} code section(s) for xrefs …")

    found_any = False
    for string_va, full_str in all_string_vas:
        for csec in code_sections:
            xrefs = find_xrefs_to_va(csec, string_va)
            for (ref_va, _) in xrefs:
                found_any = True
                fn_va = find_function_start(csec["data"], csec["sh_addr"], ref_va)
                print(f"\n{'='*70}")
                print(f"  XREF → \"{full_str}\"  (string VA {string_va:#010x})")
                print(f"  Reference at {ref_va:#010x}  in section '{csec['name']}'")
                print(f"  Estimated function start: {fn_va:#010x}")
                print(f"  Disassembly (from function start, ~256 bytes):")
                for line in disassemble_range(csec["data"], csec["sh_addr"], fn_va, 512):
                    print(line)

    if not found_any:
        # Fallback: raw scan for any instruction word that encodes the high-half
        print("\n[!] No lis-based xrefs found.")
        print("    Trying raw 16-bit immediate scan …")
        for string_va, full_str in all_string_vas:
            hi = (string_va >> 16) & 0xFFFF
            lo = string_va & 0xFFFF
            for csec in code_sections:
                d = csec["data"]
                base = csec["sh_addr"]
                for i in range(0, len(d) - 3, 4):
                    w, = struct.unpack_from(">I", d, i)
                    if (w & 0xFFFF) == hi or (w & 0xFFFF) == lo:
                        va = base + i
                        print(f"  Possible ref at {va:#010x}: {w:#010x}  (string {string_va:#010x} '{full_str}')")

if __name__ == "__main__":
    main()
