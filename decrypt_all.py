import os
import sys
import zlib
from Crypto.Cipher import AES

GAME_DIR = os.path.expandvars(r"%LOCALAPPDATA%\PokeAlliance Games\PokeAlliance")
OUT_DIR = "decrypted"

SKIP_EXT = {".exe", ".dll", ".log", ".bak"}


def load_master_key(game_dir):
    with open(os.path.join(game_dir, "init.lua"), "rb") as f:
        init = f.read()
    return init[0:16] + init[48:64]


def decrypt_self_keyed(data):
    """Files whose path contains 'init.lua': key/iv from the file itself."""
    if len(data) <= 0x1F or (len(data) - 80) % 16 != 0:
        return None
    key = data[0:16] + data[48:64]
    iv = data[32:48]
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(data[80:])
    try:
        return zlib.decompress(pt)
    except zlib.error:
        return None


def decrypt_with_key(data, key):
    """Regular files: IV = file[0:16], ciphertext = file[16:]."""
    if len(data) <= 0x0F or (len(data) - 16) % 16 != 0:
        return None
    pt = AES.new(key, AES.MODE_CBC, data[0:16]).decrypt(data[16:])
    try:
        return zlib.decompress(pt)
    except zlib.error:
        return None


def main():
    game_dir = sys.argv[1] if len(sys.argv) > 1 else GAME_DIR
    out_dir = sys.argv[2] if len(sys.argv) > 2 else OUT_DIR
    master_key = load_master_key(game_dir)

    stats = {"decrypted": 0, "raw": 0, "skipped": 0, "failed": 0}
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

            if "init.lua" in rel.replace(os.sep, "/"):
                out = decrypt_self_keyed(data)
            else:
                out = decrypt_with_key(data, master_key)

            dst = os.path.join(out_dir, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)

            if out is not None:
                with open(dst, "wb") as f:
                    f.write(out)
                stats["decrypted"] += 1
                if ".spr.part" in name:
                    spr_parts.append((rel, out))
            else:
                # Not encrypted (or unknown scheme) -> copy raw
                with open(dst, "wb") as f:
                    f.write(data)
                stats["raw"] += 1
                if len(data) > 0x0F and (len(data) - 16) % 16 == 0:
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
        print("WARNING: these looked encrypted but failed to decrypt:")
        for rel in failed:
            print("  ", rel)
        stats["failed"] = len(failed)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
