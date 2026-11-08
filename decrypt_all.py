import os
import struct
import sys
import zlib
from Crypto.Cipher import AES

GAME_DIR = r"C:\PokeAlliance"
OUT_DIR = "decrypted"

SKIP_EXT = {".exe", ".dll", ".log", ".old", ".dmp", ".bak"}

HARD = bytes.fromhex(
    "4134b92fc9efc14977d582971a767931889000d4456c2443eb1b40732c60cd3e"
)


def u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def decrypt(data):
    if data[:4] != b"PKA1" or len(data) < 36:
        return None
    hdr = 68 if u32(data, 4) & 1 else 20
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


def spr_blocks(path):
    with open(path, "rb") as f:
        head = f.read(0x30)
        if head[:4] != b"PKB1":
            raise ValueError("not a PKB1 container")
        count, start = u32(head, 0x14), u32(head, 0x28)
        f.seek(0)
        index = f.read(start)

        aad_end = 0x30 + (count - 1) * 12 + 4
        nonce = index[aad_end:aad_end + 12]
        tag = index[aad_end + 12:aad_end + 28]
        cipher = AES.new(HARD, AES.MODE_GCM, nonce=nonce)
        cipher.update(index[:aad_end])
        cipher.decrypt_and_verify(b"", tag)

        f.seek(start)
        for i in range(count):
            chunk = f.read(u32(index, 0x30 + 12 * i))
            cipher = AES.new(HARD, AES.MODE_GCM, nonce=chunk[:12])
            yield zlib.decompress(cipher.decrypt(chunk[12:]))


def main():
    game_dir = sys.argv[1] if len(sys.argv) > 1 else GAME_DIR
    out_dir = sys.argv[2] if len(sys.argv) > 2 else OUT_DIR

    stats = {"decrypted": 0, "spr": 0, "raw": 0, "skipped": 0}
    failed = []

    for root, _dirs, files in os.walk(game_dir):
        for name in files:
            src = os.path.join(root, name)
            rel = os.path.relpath(src, game_dir)
            dst = os.path.join(out_dir, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)

            if os.path.splitext(name)[1].lower() in SKIP_EXT:
                stats["skipped"] += 1
                continue

            with open(src, "rb") as f:
                magic = f.read(4)
                f.seek(0)

                if magic == b"PKB1":
                    with open(dst, "wb") as out:
                        for i, block in enumerate(spr_blocks(src), 1):
                            out.write(block)
                            if i % 1000 == 0:
                                print(f"  things.spr: {i} chunks...", flush=True)
                    stats["spr"] += 1
                    print(f"things.spr: {os.path.getsize(dst):,} bytes")
                    continue

                data = f.read()

            out = decrypt(data)
            if out is None:
                with open(dst, "wb") as out_f:
                    out_f.write(data)
                stats["raw"] += 1
                if magic == b"PKA1":
                    failed.append(rel)
            else:
                with open(dst, "wb") as out_f:
                    out_f.write(out)
                stats["decrypted"] += 1

    print(f"decrypted: {stats['decrypted']}, spr: {stats['spr']}, "
          f"raw/copied: {stats['raw']}, skipped: {stats['skipped']}")
    if failed:
        print("WARNING: these are PKA1 but failed to decrypt:")
        for rel in failed:
            print("  ", rel)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
