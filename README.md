# PokeAlliance — Assets & Cryptography Documentation

PokeAlliance is a PokeTibia (OTClient fork, DirectX build). Its client is `PokeAlliance_dx.exe` (x86-64, base `0x140000000`). Unlike PokeXGames' homebrew Salsa20 scheme, PokeAlliance uses standard crypto — **AES-256-GCM + zlib** via an embedded OpenSSL 3.x EVP — and the key is a 32-byte constant in the binary, masked inside `init.lua`. No dynamic analysis is needed; everything below was verified by decrypting the full installed asset tree (**5,795 files**).

## 1. The Assets

The installed client ships **5,795 asset files** (~579 MB) under `data/` and `modules/`, all of them AES-256-GCM + zlib. (5,807 files are on disk; 4 `.exe`, 3 `.dll`, 2 `.dmp`, 1 `.log`, 1 `.old` and 1 `.bak` are not assets and are skipped.)

| Extension | Files | Size | What it is |
|---|---:|---:|---|
| `.png` | 4,908 | 153.0 MB | UI skins, icons, item/creature images, bitmap font atlases |
| `.otui` | 259 | 239.7 KB | OTML widget trees — every window and widget in the UI |
| `.lua` | 230 | 685.6 KB | client core and module scripts (Lua 5.1) |
| `.otmod` | 120 | 24.3 KB | module manifests — name, `sandboxed`, `scripts`, `load-later` |
| `.ogg` | 114 | 92.9 MB | sound effects and music |
| `.frag` | 107 | 43.3 KB | GLSL fragment-shader sources |
| `.otfont` | 30 | 4.2 KB | font descriptors, both kinds (bitmap and TTF — see below) |
| `.ttf` | 16 | 3.4 MB | TrueType files loaded via `.otfont` |
| `.spr` | 3 | 318.5 MB | the sprite atlas — every tile graphic in the game (§3) |
| `.mp4` | 3 | 9.0 MB | login video, gacha opening, profile background |
| `.otml` | 2 | 51.5 KB | OTClient Markup Language config trees (see below) |
| `.rc` | 1 | 83 B | Windows resource script (see below) |
| `.dat` | 1 | 1.3 MB | object definitions — what every item/creature *is* (§4) |
| `.otfi` | 1 | 157 B | the loader's format manifest (see below) |
| **Total** | **5,795** | **579.1 MB** | |

- **`things.spr` is one logical file in 3 pieces.** The 3 `.spr` entries above are `things.spr.part1 … part3`, not 3 sprite archives. Decrypt each part independently, then concatenate in numeric order.

### The unusual formats

The extensions below are OTClient-specific or one-offs, so here is what each one actually contains (all decrypted).

**`.otfi` — "OTClient Feature Information": the loader's manifest for the dat/spr pair.** It does not hold any game data; it tells the client *which files to open and which dialect of the format to expect*. Full decrypted content:

```
DatSpr
  extended: true
  custom: false
  transparency: true
  frame-durations: false
  frame-groups: false
  metadata-file: things.dat
  sprites-file: things.spr
  otml-file: things.otml
```

`extended: true` means u32 sprite IDs; `transparency: true` means RGBA sprites; `frame-durations: false` + `frame-groups: false` mean there is no per-frame timing data and no frame-group blocks in the dat. Those four flags are what make the format the "10.98 feature set" (§3, §4, §5).

**`.otml` — "OTClient Markup Language", the client's indentation-based config tree** (same parser family as `.otui`). There are two, and they do completely different jobs:

- `data/cursors/cursors.otml` (179 B) — maps each logical cursor to its image and click point:
  ```
  Cursors
    target:
      image: targetcursor     # -> data/cursors/targetcursor.png
      hot-spot: 9 9           #    pixel that registers the click
  ```
- `data/things/things.otml` (52.5 KB encrypted → 194 KB plain) — a **per-thing appearance override table**, holding what the dat alone can't express. Sections `creatures` (22 ids), `effects` (341), `missiles` (56) and `items` (20,150), with properties `opacity`, `name-displacement`, `speed-factor`, `sound`, `split-sprite`, `async-animation`, `askuse`, `askmove`, `is-depot` and `not-proprietary`. The `.otfi` above is what tells the loader to read this file alongside `things.dat`.

**`.otmod` — a module manifest.** One per directory under `modules/`. It names the module, lists the Lua scripts to load, and sets the sandbox and load-order behaviour the module manager reads:

```
Module
  name: client
  description: Initialize the client and setups its main window
  reloadable: false
  sandboxed: true
  scripts: [ client ]
  @onLoad: init()
  @onUnload: terminate()

  load-later:
    - client_styles
    - client_locales
```

**`.otfont` — a font descriptor, in two flavours.** This is why there are both `.otfont` and `.ttf` files. A bitmap font points at a `.png` glyph atlas; a TTF font names a `family` and maps each style to a `.ttf` file that the font engine opens directly:

```
# bitmap
Font
  name: damas
  texture: damas              # -> data/fonts/damas.png
  height: 13
  glyph-size: 16 16
  y-offset: -2
  spacing: 0 -5
  space-width: 6
  default: true

# TrueType
Font
  type: ttf
  family: poppins
  default: true
  styles:
    regular:
      file: poppins-regular   # -> data/fonts/poppins-regular.ttf
    bold:
      file: poppins-bold
      outline-width: 1
```

**`.rc` — a Windows resource script, and a stale one.** Nothing to do with OTClient; a `.rc` is fed to the Windows resource compiler at build time to embed the application icon into the `.exe`. Full decrypted content:

```
IDI_ICON1    ICON  DISCARDABLE    "otcicon.ico"
```

It is a leftover from the client's build: **no `.ico` file ships with the client**, and the asset loader never reads `.rc`. It is encrypted along with everything else simply because it sits in `data/images/ui/`. Safe to ignore.

## 2. The Encryption

```
AES-256-GCM → zlib (RFC 1950)
```

**Key (32 bytes) = a constant in the binary's `.rdata`** — one global key for the whole tree, no per-file derivation. `init.lua` carries it masked rather than in the clear.

### File format

Every asset starts with a `PKA1` header:

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

### `init.lua`

The only file with `flags & 1`. Its 32-byte key field is `master XOR SHA256(master || salt)`, and unmasking it reproduces the master constant — the file *stores* the key, it does not derive one.

### `things.spr.partN`

`things.spr` is split into `things.spr.part1 … part3`. Each part is an independent `PKA1` file; decrypt each and concatenate in numeric order to rebuild `things.spr` (1,070,067,591 bytes).

### Decryptor reference

```python
import zlib
from Crypto.Cipher import AES

HARD = bytes.fromhex(
    "4134b92fc9efc14977d582971a767931889000d4456c2443eb1b40732c60cd3e")

data  = open(path, "rb").read()
flags = int.from_bytes(data[4:8], "little")
hdr   = 68 if flags & 1 else 20            # only init.lua has the flag

c = AES.new(HARD, AES.MODE_GCM, nonce=data[8:20])
c.update(data[:hdr])                       # AAD = the whole header
plain = zlib.decompress(c.decrypt_and_verify(data[hdr:-16], data[-16:]))
```

A complete ready-to-run decryptor implementing this (including the `.partN` reassembly) is included in `decrypt_all.py`:

```
python decrypt_all.py [game_dir] [out_dir]
```

### Red herring

An older build carried an "ENC3" handler (XXTEA, constants `0xDEADDEAD`/`0xB00BEEEF`) — **unreachable dead code** (its guard checks a string that is always empty). The `ENC3` magic is gone from the current binary, but the XXTEA core and those constants are still in there. The real scheme is the AES-GCM one above. Don't waste time on it.

## 3. `things.spr` — Sprite Archive

No per-sprite encryption inside — once reassembled, sprite data is raw RLE.

```
+0x00   u32             signature 0x5D97AB7B
+0x04   u32             sprite count = 659,664
+0x08   u32[count]      absolute offsets; entry i-1 = sprite ID i (1-based)
                        entry 0 (sprite ID 1) = 0 (null slot, part of the table)
        sprite data:    3-byte colorkey (FF 00 FF) + u16 data_size
                        + RLE chunks { u16 transparent, u16 colored,
                                       colored × 4 bytes RGBA }
```

Verified on all 535,519 non-null sprites: offsets monotonic, last sprite ends exactly at EOF. Two quirks:

- **The offset table starts at `+0x08`, not `+0x0C`.** What looks like a "reserved" u32 is sprite ID 1's null entry. Reading from `+0x0C` shifts every sprite by one table entry → chopped tiles and neighbor sprites leaking in. This single off-by-one was the root cause of a long "torn sprites" debugging saga.
- **Trailing transparent run is omitted**: sprites can decode to fewer than 1024 pixels; the client fills the rest with transparency. ObjectBuilder needs exactly 1024, so converters must append a trailing `(transparent, 0)` chunk.

## 4. `things.dat` — Object Definitions

```
+0x00   u32   signature 0xBCBCF8F6
+0x04   u16   items = 50,704    (IDs from 100)
+0x06   u16   creatures = 3,887 (IDs from 1)
+0x08   u16   effects = 2,882
+0x0A   u16   missiles = 251    (lies — only 152 records exist; read to EOF)
+0x0C   records: { attribute bytes … 0xFF } { visual block }
        visual: u8 width, u8 height, [u8 exactSize if w>1 or h>1],
                u8 layers, patternX, patternY, patternZ, frames,
                u32 spriteID × (w×h×layers×pX×pY×pZ×frames)
```

- **Sprite-ID list order is stock**: `[frames][pz][py][px][layers][h][w]` — the client reads the list sequentially with no permutation. Any "remap" scrambles correct data (the second root cause of the torn-sprites saga).
- **Custom attribute table** (do NOT trust stock Tibia tables): `0x08`, `0x28`, `0x29` are **flags** here (not payloads); `0x2A` has a fixed **16-byte** payload (8×i16); `0x2B` has a fixed **5-byte** payload. With those, the whole file parses to exact EOF.
- **No animator bytes anywhere**, even for multi-frame records — the client synthesizes 100 ms phases.

## 5. ObjectBuilder Conversion

The client format uses the extended/transparency layout (what OTClient labels the 10.98 feature set: u32 sprite IDs, RGBA sprites, no frame-durations/groups). Conversion to Tibia 10.56 extended for ObjectBuilder 0.5.9 is implemented in `pka2ob.py` (expects the decrypted `data/things/`, writes an output directory):

- Signatures → `0x542143B0` (dat) / `0x542143DE` (spr) — already in OB's `versions.xml`, no OB config edits needed.
- All attributes stripped (`0xFF` only); visual data kept. Outfits get the 10.56 frame-group marker; multi-frame records get a synthesized animator (100 ms phases).
- **No sid remap, no direction flip** — source order is already stock.
- Sprites copied verbatim + the trailing transparent pad when RLE covers < 1024 px. Offset table read from **+0x08**.
- **4096 clamp**: records exceeding OB's per-thing sprite limit are clamped by dropping trailing frames.
- **Category reshuffle**: the last 99 item records (game IDs 50705–50803) are actually **outfit** data (patternX=4 + frames) → moved to the front of outfits; the last 98 creature records (3790–3887) are actually **effect** data → moved to the front of effects. Resulting OB counts: items 50,605 records, outfits 3,888, effects 2,980, missiles 152.
- Outfit views can be horizontally centered post-conversion by appending shifted copies as new sprites (deduped by content hash) and rewriting outfit sid refs — originals untouched (592,330 → 710,760 sprites, measured on the 2026-07-22 build).

Result validated by full OB-layout parse (dat to exact EOF, every sprite exactly 1024 px) and confirmed visually in ObjectBuilder.
