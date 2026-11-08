# PokeAlliance — Assets & Cryptography Documentation

PokeAlliance is a PokeTibia (OTClient fork, DirectX build). Its client is `PokeAlliance_dx.exe` (x86-64, base `0x140000000`). Unlike PokeXGames' homebrew Salsa20 scheme, PokeAlliance uses standard crypto — **AES-256-GCM + zlib** via an embedded OpenSSL 3.x EVP — and one global 32-byte key covers both the asset tree and the `PKB1` sprite container.

In the last analysis i did, `modules/` shipped `.otmod` manifests and `.lua` scripts as ordinary `PKA1` files. They re gone now, the scripts are inside the signed, packed client, decrypted at startup and handed to `luaL_loadbuffer`. The CDN manifest has no `.lua` or `.otmod`, so `modules/` only holds UI files.

## 1. The Assets

The installed client ships **7,637 asset files** (~702.7 MB) under `data/` and `modules/`, all AES-256-GCM + zlib except `things.spr`, which is the `PKB1` container (§2). (7,647 files are on disk; 5 `.exe`, 3 `.dll`, 1 `.log` and 1 `.bak` are not assets and are skipped.)

| Extension | Files | Size | What it is |
|---|---:|---:|---|
| `.png` | 7,065 | 191.8 MB | UI skins, icons, item/creature images, bitmap font atlases |
| `.otui` | 238 | 287.0 KB | OTML widget trees — every window and widget in the UI |
| `.ogg` | 133 | 93.3 MB | sound effects and music |
| `.frag` | 105 | 42.3 KB | GLSL fragment-shader sources |
| `.svg` | 41 | 11.2 KB | vector profile/wallet/navigation icons |
| `.otfont` | 30 | 4.3 KB | font descriptors, both kinds (bitmap and TTF — see below) |
| `.ttf` | 16 | 3.7 MB | TrueType files loaded via `.otfont` |
| `.mp4` | 2 | 7.6 MB | profile background and video-player clip |
| `.otml` | 2 | 56.1 KB | OTClient Markup Language config trees (see below) |
| `.spr` | 1 | 383.6 MB | the sprite atlas — every tile graphic in the game (§3) |
| `.zip` | 1 | 20.8 MB | `pokemons.zip`, 1,015 PNGs packed as one asset (see below) |
| `.dat` | 1 | 1.5 MB | object definitions — what every item/creature *is* (§4) |
| `.otfi` | 1 | 157 B | the loader's format manifest (see below) |
| `.rc` | 1 | 83 B | Windows resource script (see below) |
| **Total** | **7,637** | **702.7 MB** | |

- **`things.spr` is one file now.** The old `.part1 … part3` split is gone; the single `PKB1` container is described in §2.
- **`.ttf` fonts are now `PKA1`-encrypted**; older builds shipped them raw.

### The unusual formats

- **`.otfi`** — manifest for the dat/spr pair. `extended: true` (u32 sprite IDs), `transparency: true` (RGBA), no frame durations/groups: the 10.98 feature set (§3–§5). Frame timing comes from attribute `0x2C` instead (§4).
- **`.otml`** — indentation-based config, same parser family as `.otui`. `cursors.otml` maps 7 cursors to images and click points; `things.otml` (194.2 KB plain) is a per-thing override table (opacity, speed, sound, split-sprite, …) for ~20.5k ids.
- **`.otmod`** — module manifest: name, Lua scripts, sandbox and load order. Older builds only — none ship now (see the note at the top).
- **`.otfont`** — font descriptor, either a bitmap `.png` atlas or a TTF family with per-style `.ttf` files. That's why both extensions ship.
- **`.zip`** — `data/images/pokemons.zip` is one `PKA1` asset whose plaintext is a normal ZIP of 1,015 Pokémon PNGs. Decrypt, then unzip.
- **`.rc`** — stale Windows icon script (`IDI_ICON1 ICON "otcicon.ico"`). No `.ico` ships and the loader ignores it; encrypted only because it sits in `data/images/ui/`.

## 2. The Encryption

```
AES-256-GCM → zlib (RFC 1950)
```

**Key (32 bytes) = a constant in the binary's `.rdata`** — no per-file derivation, no rotation between builds. The packed binary hides the constant, but the `PKB1` header tag confirms it is unchanged (below).

### File format

Every asset except `things.spr` starts with a `PKA1` header:

```
+0x00   4       "PKA1" magic
+0x04   4       flags
+0x08   12      GCM nonce
+0x14   16      salt        (flags & 1 only)
+0x24   32      masked key  (flags & 1 only)
        ...     ciphertext
        last 16 GCM tag
```

The header is **68 bytes when `flags & 1`**, 20 bytes otherwise. **The AAD is the entire header** — that single detail is what makes or breaks the tag check. GCM is a stream cipher, so the payload is not block-aligned. Inflate the plaintext to get the original file.

### `init.lua` (absent in this build)

The 68-byte path (`flags & 1`) is unused here — no installed asset sets it. Older builds used it so `init.lua` could hide the same key via `master XOR SHA256(master || salt)`.

The *PROBABLE* Themida-packed image shows no plaintext strings, no Lua bytecode and no zlib streams; `.rsrc` is just a 22 KB icon/manifest. All 7,640 CDN files are on disk (1,094 under `/modules/`), so the scripts come from the binary or the login server and stay in memory.

### `PKB1` — `things.spr`

`things.spr` is one 402,257,209-byte container of 4,379 individually encrypted 262,144-byte blocks, using the **same** `HARD` key:

```
+0x00   4       "PKB1" magic
+0x04   4       version = 1
+0x08   4       blockSize = 0x40000 (262,144)
+0x0C   4       total uncompressed size = 1,147,846,676
+0x14   4       chunk count = 4,379
+0x18   16      blob (not used for decryption)
+0x28   4       dataStart = 0xCD88 (52,616)
+0x30   ...     index: 4,379 x (u32 size, u32 end offset, u32 flags = 0)
+0xCD6C 12      header GCM nonce
+0xCD78 16      header GCM tag (AAD = header[0:0xCD6C], plaintext = empty)
+0xCD88 ...     chunk data
```

Each chunk is `nonce(12) || AES-256-GCM(zlib(block), HARD) || trailing 16 B`. Skipping `verify()` recovers the zlib stream, and `zlib.decompress()` ignores the trailing 16 bytes. Equivalently, use `AES-256-CTR` with `IV = nonce || 0x00000002` (GCM's first encryption counter). All 4,379 chunks inflate: 4,378 × 262,144 B + a final 180,244 B = exactly 1,147,846,676 bytes.

`AES-256-GCM(HARD, nonce = trailer[0:12], AAD = header[0:0xCD6C], plaintext = "")` verifies against `trailer[12:28]`, proving there is no new key hidden in the packed binary.

### Decryptor reference

```python
import zlib
from Crypto.Cipher import AES

HARD = bytes.fromhex(
    "4134b92fc9efc14977d582971a767931889000d4456c2443eb1b40732c60cd3e")

data  = open(path, "rb").read()
flags = int.from_bytes(data[4:8], "little")
hdr   = 68 if flags & 1 else 20 

c = AES.new(HARD, AES.MODE_GCM, nonce=data[8:20])
c.update(data[:hdr])
plain = zlib.decompress(c.decrypt_and_verify(data[hdr:-16], data[-16:]))
```

Per `PKB1` chunk, after slicing it out with the `+0x30` index:

```python
chunk = open(chunk_path, "rb").read()
nonce = chunk[:12]                         
c = AES.new(HARD, AES.MODE_GCM, nonce=nonce)
block = zlib.decompress(c.decrypt(chunk[12:-16]))
```

A complete decryptor for the asset tree is included in `decrypt_all.py`.

```
python decrypt_all.py [game_dir] [out_dir]
```

## 3. `things.spr` — Sprite Archive

No per-sprite encryption inside — once the `PKB1` container is decrypted, sprite data is raw RLE:

```
+0x00   u32             signature 0x5D97AB7B
+0x04   u32             sprite count = 787,675
+0x08   u32[count]      absolute offsets; entry i-1 = sprite ID i (1-based)
                        entry 0 (sprite ID 1) = 0 (null slot, part of the table)
                        table ends at 3,150,708 = 8 + 4 × 787,675
        sprite data:    3-byte colorkey (FF 00 FF) + u16 data_size
                        + RLE chunks { u16 transparent, u16 colored,
                                       colored × 4 bytes RGBA }
```

Verified on all 586,208 non-null sprites: offsets monotonic, last sprite ends exactly at EOF (201,467 offsets are zero). Two quirks:

- **The offset table starts at `+0x08`, not `+0x0C`.** What looks like a "reserved" u32 is sprite ID 1's null entry. Reading from `+0x0C` shifts every sprite by one table entry → chopped tiles and neighbor sprites leaking in. This single off-by-one was the root cause of a long "torn sprites" debugging saga.
- **Trailing transparent run is omitted**: sprites can decode to fewer than 1024 pixels; the client fills the rest with transparency. ObjectBuilder needs exactly 1024, so converters must append a trailing `(transparent, 0)` chunk.

## 4. `things.dat` — Object Definitions

```
+0x00   u32   signature 0xBCBCF8F6
+0x04   u16   items = 51,996    (IDs from 100)
+0x06   u16   creatures = 3,998 (IDs from 1)
+0x08   u16   effects = 2,888
+0x0A   u16   missiles = 251    (152 here + 99 at the end of effects)
+0x0C   records: { attribute bytes … 0xFF } { visual block }
        visual: u8 width, u8 height, [u8 exactSize if w>1 or h>1],
                u8 layers, patternX, patternY, patternZ, frames,
                u32 spriteID × (w×h×layers×pX×pY×pZ×frames)
```

- **Sprite-ID list order is stock**: `[frames][pz][py][px][layers][h][w]` — the client reads the list sequentially with no permutation. Any "remap" scrambles correct data (the second root cause of the torn-sprites saga).
- **Custom attribute table** (do NOT trust stock Tibia tables): `0x08`, `0x28`, `0x29` are **flags** here (not payloads); `0x2A` has a fixed **16-byte** payload (8×i16); `0x2B` has a fixed **5-byte** payload; `0x2C` is **variable** — `u8 count + count × u32 ms` of frame durations, new in the 2026-11-07 build (one occurrence, count=32, all 100 ms, pinned by exact-EOF parsing). With those, the whole 7,507,301-byte file parses to exact EOF. Re-pin this table after every client update; `0x2C` is exactly what broke the September converter.
- **No stock animator blocks** in the visual data — the client synthesizes 100 ms phases for multi-frame records; the single `0x2C` above is the only stored timing, and `pka2ob.py` turns it back into a normal 100 ms animator.
- **Category tails are stored one block early**: the last 99 item records are outfits, the last 98 creature records are effects and the last 99 effect records are missiles. The header counts are correct in aggregate, but a parser reading each count in turn sees only 152 missiles and labels those 99 records as effects. The first ObjectBuilder conversion showed them as effects 2888–2986; they are missiles.

## 5. ObjectBuilder Conversion

Conversion to Tibia 10.56 extended for ObjectBuilder 0.6.0 is implemented in `pka2ob.py` (reads `decrypted/data/things/`, writes `objectbuilder/`):

- Signatures → `0x542143B0` (dat) / `0x542143DE` (spr) — already in OB 0.6.0's `config/versions.xml` as `10.56`, with `32x32` / `dataSize=4096` in `config/sprites.xml`. No OB config edits needed.
- All attributes stripped (`0xFF` only); visual data kept. Outfits get the 10.56 frame-group marker; multi-frame records get a synthesized animator (100 ms phases).
- **No sid remap, no direction flip** (§4).
- Sprites copied verbatim + the trailing transparent pad from §3; on the current build 279,773 of the 586,208 non-null sprites need it.
- **4096 clamp**: records exceeding OB's per-thing sprite limit are clamped by dropping trailing frames (18 records on the current build).
- **Category reshuffle** (re-derived on the 2026-11-08 build; the old 07-22 OB counts 50,605 / 3,888 / 2,980 / 152 are stale): the three tails from §4 are prepended to outfits, effects and missiles, preserving on-disk order. Resulting OB counts: items 51,897 records (header 51,996), outfits 3,999, effects 2,887, missiles 251.
- Outfit views *can* be horizontally centered post-conversion by appending shifted copies as new sprites (deduped by content hash) and rewriting outfit sid refs — originals untouched. This is an **optional, unapplied** step; the 592,330 → 710,760 sprite figures are from the 2026-07-22 build and do not describe the delivered 787,675-sprite folder.

ObjectBuilder needs all three files in **one folder**. `pka2ob.py` writes `objectbuilder/` with `Tibia.dat` (8,297,398 B), `Tibia.spr` (1,148,965,768 B) and `things.otfi` (255 B). OB hardcodes the `Tibia.*` names and scans the folder for the `.otfi`.
```
DatSpr
  extended: true
  transparency: true
  frame-durations: true
  frame-groups: true
  metadata-controller: default
  attribute-server: tfs1.4
  metadata-file: Tibia.dat
  sprites-file: Tibia.spr
  sprite-size: 32
  sprite-data-size: 4096
```

Result validated on the current build by a full independent OB-layout parse: 51,897 / 3,999 / 2,887 / 251 physical records land on byte 8,297,398 == file size, max sprite ID 787,675 == spr count, all 586,208 non-null sprites exactly 1024 px and contiguous to EOF.
