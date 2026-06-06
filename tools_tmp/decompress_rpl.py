"""Decompress an RPL/RPX into a stock ELF32 BE PPC binary.

RPL is ELF32 BE PPC with sections optionally zlib-compressed
(SHF_RPL_ZLIB = 0x08000000). Compressed body starts with a BE uint32
giving the uncompressed size, followed by the zlib stream.

Usage:
    py -3 decompress_rpl.py <input.rpl> <output.elf>
"""
import struct
import sys
import zlib

SHF_RPL_ZLIB = 0x08000000


def main():
    inp, outp = sys.argv[1], sys.argv[2]
    with open(inp, "rb") as f:
        data = bytearray(f.read())

    # ELF32 header
    assert data[:4] == b"\x7fELF"
    e_shoff   = struct.unpack(">I", data[0x20:0x24])[0]
    e_shentsz = struct.unpack(">H", data[0x2E:0x30])[0]
    e_shnum   = struct.unpack(">H", data[0x30:0x32])[0]
    e_shstrnd = struct.unpack(">H", data[0x32:0x34])[0]

    # Read all section headers
    sh = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsz
        name, type_, flags, addr, sh_off, sh_size, link, info, align, ent = \
            struct.unpack(">IIIIIIIIII", data[off:off+40])
        sh.append(dict(idx=i, name=name, type=type_, flags=flags, addr=addr,
                       off=sh_off, size=sh_size, link=link, info=info,
                       align=align, ent=ent, hdr_off=off))

    # Decompress in-place; rebuild flat ELF body afterwards.
    new_bodies = {}
    for s in sh:
        if s["size"] == 0:
            continue
        body = bytes(data[s["off"]:s["off"]+s["size"]])
        if s["flags"] & SHF_RPL_ZLIB:
            uncompressed_size = struct.unpack(">I", body[:4])[0]
            try:
                inflated = zlib.decompress(body[4:])
            except zlib.error as e:
                print(f"section {s['idx']}: decompress failed: {e}")
                continue
            assert len(inflated) == uncompressed_size, (len(inflated), uncompressed_size)
            new_bodies[s["idx"]] = inflated
            s["flags"] &= ~SHF_RPL_ZLIB
            s["size"] = len(inflated)
        else:
            new_bodies[s["idx"]] = body

    # Repack: keep ELF header + program headers (none in RPL really), then
    # write each section body with 16-byte alignment, then section headers.
    out = bytearray(data[:e_shoff])  # preserve ELF header region

    # ELF body up to first section. Sections will be appended fresh.
    # Use 0x40 as start of section bodies.
    body_off = max(0x40, len(out))
    out = bytearray(data[:0x34])  # only the bare ELF header
    while len(out) < 0x40:
        out.append(0)

    for s in sh:
        if s["size"] == 0:
            s["off"] = 0
            continue
        body = new_bodies.get(s["idx"], b"")
        while len(out) % 4 != 0:
            out.append(0)
        s["off"] = len(out)
        s["size"] = len(body)
        out += body

    while len(out) % 4 != 0:
        out.append(0)
    new_shoff = len(out)
    for s in sh:
        out += struct.pack(">IIIIIIIIII",
                           s["name"], s["type"], s["flags"], s["addr"],
                           s["off"], s["size"], s["link"], s["info"],
                           s["align"], s["ent"])

    # Patch e_shoff in header
    out[0x20:0x24] = struct.pack(">I", new_shoff)

    with open(outp, "wb") as f:
        f.write(out)
    print(f"Wrote {outp} ({len(out)} bytes), {e_shnum} sections")


if __name__ == "__main__":
    main()
