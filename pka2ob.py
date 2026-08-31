from __future__ import annotations

import mmap
import struct
import sys
import time
from pathlib import Path

SRC_DIR = Path("decrypted/data/things")
OUT_DIR = Path("objectbuilder")

DAT_SIGNATURE = 0x542143B0  # stock 10.56, registered in OB 0.5.9 versions.xml
SPR_SIGNATURE = 0x542143DE
SRC_SPR_SIGNATURE = 0x5D97AB7B
SRC_DAT_SIGNATURE = 0xBCBCF8F6
SPRITE_PIXELS = 32 * 32
MAX_SPRITES_PER_THING = 4096  # OB SpriteExtent.DEFAULT_DATA_SIZE

# Attribute payload table — confirmed against the client's record parser.
U16_ATTRS = {0x00, 0x09, 0x1A, 0x1D, 0x1E, 0x21, 0x23}
U32_ATTRS = {0x16, 0x19}
FLAGS = {1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
         21, 23, 24, 27, 28, 31, 32, 36, 37, 38, 39, 40, 0x28, 0x29}
# 0x2B is new in the 2026-08-31 build. Its 5-byte payload length was pinned by
# the exact-EOF identity: L=5 is the only value in 0..32 that makes the dat
# parse to byte-exact EOF. Re-pin after every client update.
FIXED_LEN_ATTRS = {0x2B: 5}


def parse_dat(data: bytes):
    sig = struct.unpack_from("<I", data, 0)[0]
    assert sig == SRC_DAT_SIGNATURE, f"bad src dat sig {sig:#x}"
    pos = 12
    counts = struct.unpack_from("<4H", data, 4)

    def parse_record(rid: int):
        nonlocal pos
        while True:
            a = data[pos]
            pos += 1
            if a == 0xFF:
                break
            if a in FLAGS:
                pass
            elif a in U16_ATTRS:
                pos += 2
            elif a in U32_ATTRS:
                pos += 4
            elif a == 0x22:  # market
                pos += 6
                n = struct.unpack_from("<H", data, pos)[0]
                pos += 2 + n + 4
            elif a == 0x2A:  # 8 x i16 (per-direction offsets)
                pos += 16
            elif a in FIXED_LEN_ATTRS:
                pos += FIXED_LEN_ATTRS[a]
            else:
                raise ValueError(f"rid {rid}: unknown attr {a:#x} at {pos - 1:#x}")

        w, h = data[pos], data[pos + 1]
        pos += 2
        exact = 0
        if w > 1 or h > 1:
            exact = data[pos]
            pos += 1
        layers, px, py, pz, frames = struct.unpack_from("<5B", data, pos)
        pos += 5
        n = w * h * layers * px * py * pz * frames
        if n > 65536:
            raise ValueError(f"rid {rid}: bad sprite list size {n}")
        # sequential read — NO permutation, exactly like the client parser
        sids = list(struct.unpack_from(f"<{n}I", data, pos))
        pos += 4 * n
        return {"w": w, "h": h, "exact": exact, "layers": layers,
                "px": px, "py": py, "pz": pz, "frames": frames, "sids": sids}

    cats = []
    for ci, expected in enumerate(counts):
        recs = []
        for i in range(expected):
            if pos >= len(data):  # missile header count lies; read-until-EOF
                print(f"[!] category {ci}: header says {expected}, file has {len(recs)}")
                break
            recs.append(parse_record(i))
        cats.append(recs)
        print(f"[*] category {ci}: {len(recs)}/{expected} records, pos={pos:#x}")
    if pos != len(data):
        raise ValueError(f"trailing bytes: pos={pos:#x} size={len(data):#x}")
    return cats


def clamp_record(rec: dict, rid: int) -> None:
    """OB throws if a thing has > 4096 sprites. File order is already
    [frames]...[w], so truncating the tail drops trailing frames only."""
    per_frame = rec["w"] * rec["h"] * rec["layers"] * rec["px"] * rec["py"] * rec["pz"]
    total = per_frame * rec["frames"]
    if total <= MAX_SPRITES_PER_THING:
        return
    new_frames = max(1, MAX_SPRITES_PER_THING // per_frame)
    print(f"[!] rid {rid}: {rec['frames']}f * {per_frame} = {total} > 4096, "
          f"clamped to {new_frames} frames")
    rec["frames"] = new_frames
    del rec["sids"][per_frame * new_frames:]


def write_record(buf: bytearray, rec: dict, is_outfit: bool) -> None:
    buf.append(0xFF)  # attributes stripped
    if is_outfit:
        buf.append(1)  # frame group count (OB 10.56 outfit marker)
        buf.append(0)  # group type: default/idle
    buf.append(rec["w"])
    buf.append(rec["h"])
    if rec["w"] > 1 or rec["h"] > 1:
        buf.append(rec["exact"])
    buf.extend((rec["layers"], rec["px"], rec["py"], rec["pz"], rec["frames"]))
    if rec["frames"] > 1:
        # synthesized animator (client uses 100 ms phases too)
        buf.extend(struct.pack("<BIB", 0, 0, 0))
        for _ in range(rec["frames"]):
            buf.extend(struct.pack("<II", 100, 100))
    buf.extend(struct.pack(f"<{len(rec['sids'])}I", *rec["sids"]))


def convert_dat(cats) -> bytes:
    items, creatures, effects, missiles = cats
    buf = bytearray()
    buf.extend(struct.pack("<I", DAT_SIGNATURE))
    buf.extend(struct.pack("<4H", len(items) + 99, len(creatures),
                           len(effects), len(missiles)))
    for rec in items:
        write_record(buf, rec, False)
    for rec in creatures:
        write_record(buf, rec, True)
    for rec in effects:
        write_record(buf, rec, False)
    for rec in missiles:
        write_record(buf, rec, False)
    print(f"[*] OB dat: items={len(items)} (hdr {len(items) + 99}), "
          f"outfits={len(creatures)}, effects={len(effects)}, missiles={len(missiles)}")
    return bytes(buf)


def convert_spr(src_path: Path, out_path: Path) -> int:
    """Copy every sprite verbatim (colorkey + u16 size + RLE), appending a
    trailing (transparent, 0) chunk when the RLE covers < 1024 px.
    Source table: sprite ID N -> u32 at 8 + 4*(N-1); ID 1 is the null slot."""
    with open(src_path, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        sig, count, reserved = struct.unpack_from("<III", mm, 0)
        assert sig == SRC_SPR_SIGNATURE, f"bad src spr sig {sig:#x}"
        # table base = +0x08: entry 0 (the "reserved" u32) is sprite ID 1
        src_offs = list(struct.unpack_from(f"<{count}I", mm, 8))
        n = count
        print(f"[*] src spr: count={count} ({sum(1 for o in src_offs if o)} non-null)")

        sizes = [0] * n
        padded = 0
        t0 = time.time()
        for i, o in enumerate(src_offs):
            if o == 0:
                continue
            dlen = struct.unpack_from("<H", mm, o + 3)[0]
            end = o + 5 + dlen
            p = o + 5
            px = 0
            while p < end:
                t, c = struct.unpack_from("<HH", mm, p)
                p += 4 + 4 * c
                px += t + c
            assert p == end and px <= SPRITE_PIXELS, f"sprite {i + 1}: px={px}"
            if px < SPRITE_PIXELS:
                dlen += 4
                padded += 1
            sizes[i] = 5 + dlen
        print(f"[*] pass 1: {time.time() - t0:.1f}s, {padded} sprites need trailing pad")

        header = 8 + 4 * n
        cursor = header
        out_offs = [0] * n
        for i, s in enumerate(sizes):
            if s:
                out_offs[i] = cursor
                cursor += s

        t0 = time.time()
        with open(out_path, "wb") as out:
            out.write(struct.pack("<II", SPR_SIGNATURE, n))
            out.write(struct.pack(f"<{n}I", *out_offs))
            for i, o in enumerate(src_offs):
                if o == 0:
                    continue
                if sizes[i] == 5 + struct.unpack_from("<H", mm, o + 3)[0]:
                    out.write(mm[o:o + sizes[i]])  # verbatim
                else:
                    dlen = struct.unpack_from("<H", mm, o + 3)[0]
                    end = o + 5 + dlen
                    p = o + 5
                    px = 0
                    while p < end:
                        t, c = struct.unpack_from("<HH", mm, p)
                        p += 4 + 4 * c
                        px += t + c
                    out.write(b"\xff\x00\xff")
                    out.write(struct.pack("<H", dlen + 4))
                    out.write(mm[o + 5:end])
                    out.write(struct.pack("<HH", SPRITE_PIXELS - px, 0))
        print(f"[*] pass 2: {time.time() - t0:.1f}s")
        mm.close()
    written = out_path.stat().st_size
    assert written == cursor, f"size mismatch: wrote {written:#x}, expected {cursor:#x}"
    print(f"[*] wrote {out_path} ({written:,} bytes, {n} sprites)")
    return n


def write_otfi(path: Path) -> None:
    path.write_text(
        "DatSpr\n"
        "  extended: true\n"
        "  transparency: true\n"
        "  frame-durations: true\n"
        "  frame-groups: true\n"
        "  metadata-controller: default\n"
        "  attribute-server: tfs1.4\n"
        "  metadata-file: Tibia.dat\n"
        "  sprites-file: Tibia.spr\n"
        "  sprite-size: 32\n"
        "  sprite-data-size: 4096\n"
    )
    print(f"[*] wrote {path}")


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cats = parse_dat((SRC_DIR / "things.dat").read_bytes())
    items, creatures, effects, missiles = cats

    # Last 99 item records are outfit data; last 98 creature records are
    # effect data. Move each block to the front of its real category.
    # Both sizes are build-specific: 07-22 = 98/98, 08-31 = 99/98. Re-derive
    # after every client update.
    OUTFITS_FROM_ITEMS = 99
    EFFECTS_FROM_CREATURES = 98
    outfits = items[-OUTFITS_FROM_ITEMS:] + creatures[:-EFFECTS_FROM_CREATURES]
    effects = creatures[-EFFECTS_FROM_CREATURES:] + effects
    real_items = items[:-OUTFITS_FROM_ITEMS]
    print(f"[*] moved {OUTFITS_FROM_ITEMS} outfit records out of items and "
          f"{EFFECTS_FROM_CREATURES} effect records out of creatures; "
          f"items={len(real_items)}, outfits={len(outfits)}, effects={len(effects)}")

    for cat, first in ((real_items, 100), (outfits, 1), (effects, 1), (missiles, 1)):
        for i, rec in enumerate(cat):
            clamp_record(rec, first + i)

    cats = (real_items, outfits, effects, missiles)
    max_sid = max((s for rec in (r for c in cats for r in c) for s in rec["sids"]),
                  default=0)
    print(f"[*] max sprite ID referenced by dat: {max_sid}")

    ob_dat = convert_dat(cats)
    (OUT_DIR / "Tibia.dat").write_bytes(ob_dat)
    print(f"[*] wrote {OUT_DIR / 'Tibia.dat'} ({len(ob_dat):,} bytes)")

    total = convert_spr(SRC_DIR / "things.spr", OUT_DIR / "Tibia.spr")
    if max_sid > total:
        print(f"[!] WARNING: dat references sprite ID {max_sid} > spr max {total}")
        return 1

    write_otfi(OUT_DIR / "things.otfi")
    print("[+] Done. Open Tibia.dat in Object Builder (10.56 extended).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
