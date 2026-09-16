import os
import sys
import zlib
from Crypto.Cipher import AES

GAME_DIR = os.path.expandvars(r"%LOCALAPPDATA%\PokeAlliance Games\PokeAlliance")
OUT_DIR = "decrypted"

SKIP_EXT = {".exe", ".dll", ".log", ".old", ".dmp", ".bak"}

# 32b master key
HARD = bytes.fromhex(
    "4134b92fc9efc14977d582971a767931889000d4456c2443eb1b40732c60cd3e"
)


def decrypt(data):
    """PKA1: AES-256-GCM, AAD = the whole header, tag = last 16 bytes."""
    if data[:4] != b"PKA1" or len(data) < 36:
        return None
    hdr = 68 if int.from_bytes(data[4:8], "little") & 1 else 20
    cipher = AES.new(HARD, AES.MODE_GCM, nonce=data[8:20])
    cipher.update(data[:hdr])
    try:
        pt = cipher.decrypt_and_verify(data[hdr:-16], data[-16:])
    except ValueError:
        return None
    try:
        return zlib.decompress(pt)
    except zlib.error:
        return pt


def main():
    game_dir = sys.argv[1] if len(sys.argv) > 1 else GAME_DIR
    out_dir = sys.argv[2] if len(sys.argv) > 2 else OUT_DIR

    stats = {"decrypted": 0, "raw": 0, "skipped": 0}
    failed = []
    spr_parts = []

    for root, _dirs, files in os.walk(game_dir):
        for name in files:
            src = os.path.join(root, name)
            rel = os.path.relpath(src, game_dir)
            ext = os.path.splitext(name)[1].lower()
            if ext in SKIP_EXT:
                stats["skipped"] += 1
                continue

            with open(src, "rb") as f:
                data = f.read()

            out = decrypt(data)
            dst = os.path.join(out_dir, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)

            if out is not None:
                with open(dst, "wb") as f:
                    f.write(out)
                stats["decrypted"] += 1
                if ".spr.part" in name:
                    spr_parts.append((rel, out))
            else:
                # Not a PKA1 container -> copy raw
                with open(dst, "wb") as f:
                    f.write(data)
                stats["raw"] += 1
                if data[:4] == b"PKA1":
                    failed.append(rel)

    # Reassemble things.spr from decrypted parts
    if spr_parts:
        def part_num(rel):
            return int(rel.rsplit("part", 1)[1])
        spr_parts.sort(key=lambda p: part_num(p[0]))
        spr_out = os.path.join(out_dir, os.path.dirname(spr_parts[0][0]),
                               "things.spr")
        with open(spr_out, "wb") as f:
            for _rel, blob in spr_parts:
                f.write(blob)
        print(f"things.spr reassembled: {os.path.getsize(spr_out)} bytes "
              f"from {len(spr_parts)} parts")

    print(f"decrypted: {stats['decrypted']}, raw/copied: {stats['raw']}, "
          f"skipped: {stats['skipped']}")
    if failed:
        print("WARNING: these are PKA1 but failed to decrypt:")
        for rel in failed:
            print("  ", rel)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
