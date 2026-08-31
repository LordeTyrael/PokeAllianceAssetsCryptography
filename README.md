# PokeAlliance — Assets & Cryptography Documentation

PokeAlliance is a PokeTibia (OTClient fork, DirectX build). Its client is `PokeAlliance_dx.exe` (x86-64, base `0x140000000`). Unlike PokeXGames' homebrew Salsa20 scheme, PokeAlliance uses standard crypto — **AES-256-CBC + zlib** via an embedded OpenSSL 3.x EVP — and the key is stored inside `init.lua` itself. No dynamic analysis is needed; everything below was verified by decrypting the full installed asset tree (**8,020 files**).

## 1. The Assets

The installed client ships **8,020 asset files** (~687 MB) under `data/` and `modules/`, all of them AES-256-CBC + zlib except the 16 `.ttf` fonts and files ≤ 15 bytes. (8,029 files are on disk; 4 `.exe`, 3 `.dll`, 1 `.log` and 1 `.bak` are not assets and are skipped.)

| Extension | Files | Size | What it is |
|---|---:|---:|---|
| `.png` | 7,069 | 187.9 MB | UI skins, icons, item/creature images, bitmap font atlases |
| `.otui` | 287 | 291.1 KB | OTML widget trees — every window and widget in the UI |
| `.lua` | 242 | 794.8 KB | client core and module scripts (Lua 5.1) |
| `.otmod` | 134 | 25.5 KB | module manifests — name, `sandboxed`, `scripts`, `load-later` |
| `.ogg` | 114 | 93.0 MB | sound effects and music |
| `.frag` | 107 | 44.5 KB | GLSL fragment-shader sources |
| `.otfont` | 30 | 3.9 KB | font descriptors, both kinds (bitmap and TTF — see below) |
| `.ttf` | 16 | 7.0 MB | TrueType files loaded via `.otfont`; stored **raw** |
| `.spr` | 12 | 387.5 MB | the sprite atlas — every tile graphic in the game (§3) |
| `.mp4` | 3 | 9.0 MB | squirtle video, 2 years vid, gacha copied video |
| `.otml` | 2 | 56.2 KB | OTClient Markup Language config trees (see below) |
| `.rc` | 1 | 64 B | Windows resource script (see below) |
| `.dat` | 1 | 1.5 MB | object definitions — what every item/creature *is* (§4) |
| `.otfi` | 1 | 144 B | the loader's format manifest (see below) |
| `.txt` | 1 | 96 B | creature displacement offsets (see below) |
| **Total** | **8,020** | **687.0 MB** | |

- **`things.spr` is one logical file in 12 pieces.** The 12 `.spr` entries above are `things.spr.part1 … part12`, not 12 sprite archives. Decrypt each part independently, then concatenate in numeric order.
- **A few files are stored raw** — files ≤ 15 bytes, and the `.ttf` fonts. Everything else is AES-256-CBC + zlib.

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

- `data/cursors/cursors.otml` (176 B) — maps each logical cursor to its image and click point:
  ```
  Cursors
    target:
      image: targetcursor     # -> data/cursors/targetcursor.png
      hot-spot: 9 9           #    pixel that registers the click
  ```
- `data/things/things.otml` (56.2 KB encrypted → 194 KB plain) — a **per-thing appearance override table**, holding what the dat alone can't express. Sections `creatures` (22 ids), `effects` (341), `missiles` (56) and `items` (20,150), with properties `opacity`, `name-displacement`, `speed-factor`, `sound`, `split-sprite`, `async-animation`, `askuse`, `askmove`, `is-depot` and `not-proprietary`. The `.otfi` above is what tells the loader to read this file alongside `things.dat`.

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

**`.otfont` — a font descriptor, in two flavours.** This is why there are both `.otfont` and `.ttf` files, and why the `.ttf` files are stored raw. A bitmap font points at a `.png` glyph atlas; a TTF font names a `family` and maps each style to a `.ttf` file that the font engine opens directly:

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
      file: poppins-regular   # -> data/fonts/poppins-regular.ttf (raw)
    bold:
      file: poppins-bold
      outline-width: 1
```

**`.rc` — a Windows resource script, and a stale one.** Nothing to do with OTClient; a `.rc` is fed to the Windows resource compiler at build time to embed the application icon into the `.exe`. Full decrypted content:

```
IDI_ICON1    ICON  DISCARDABLE    "otcicon.ico"
```

It is a leftover from the client's build: **no `.ico` file ships with the client**, and the asset loader never reads `.rc`. It is encrypted along with everything else simply because it sits in `data/images/ui/`. Safe to ignore.

**`.txt` — `modules/game_displacement/displacements.txt`, a save artifact from a stock dev module.** `game_displacement` is a shipped (not injected) outfit-offset editor whose window is dead code — `showWindow()` starts with `if 1 == 1 then return end`, so it never opens. Its save button appends to this file; nothing in the client ever reads it back.

Each line is `{lookType, {direction, {outfitX, outfitY, nameX, nameY}}}` — the pixel nudge for the creature's **sprite** and for its **name label**, per facing direction. Blocks are appended, one per save, four directions each. Full decrypted content (228 bytes):

```
{370, {0, {-66, -16, 0, 0}}}
{370, {1, {-66, -16, 0, 0}}}
{370, {2, {-66, -16, 0, 0}}}
{370, {3, {-66, -16, 0, 0}}}

{370, {0, {0, 0, 0, 0}}}
{370, {1, {0, 0, 0, 0}}}
{370, {2, {0, 0, 0, 0}}}
{370, {3, {0, 0, 0, 0}}}
```

Two blocks for lookType 370, four directions each — the second block zeroes everything, so it was saved twice and the later (zeroed) save is what a reader would apply last. Written by `g_game.getOutfitDisplacement()` / `getNameDisplacement()`, consumed by nothing.

## 2. The Encryption

```
AES-256-CBC → PKCS7 padding → zlib (RFC 1950)
```

**Key (32 bytes) = `init.lua[0x00:0x10] + init.lua[0x30:0x40]`** — the raw on-disk bytes of the *encrypted* `init.lua`. One global key for everything.

### Regular files (everything except `init.lua`)

```
+0x00   16      IV
+0x10   n*16    AES-256-CBC ciphertext of the zlib stream
```

Inflate after decryption; PKCS7 padding after the zlib stream is ignored by `zlib.decompress`. Files ≤ 15 bytes are stored raw, and a few files are raw regardless (e.g. the `.ttf` fonts).

### `init.lua` (self-keyed)

```
+0x00   16      key part 1
+0x10   16      unused
+0x20   16      IV
+0x30   16      key part 2
+0x40   16      unused
+0x50   n*16    AES-256-CBC ciphertext of the zlib stream
```

Any path containing `init.lua` uses this layout.

### `things.spr.partN`

`things.spr` is split into `things.spr.part1 … part12`. Each part is an independent regular-format encrypted file; decrypt each and concatenate in numeric order to rebuild `things.spr` (1,157,414,014 bytes).

### Decryptor reference

```python
import zlib
from Crypto.Cipher import AES

init = open("init.lua", "rb").read()
key  = init[0x00:0x10] + init[0x30:0x40]          # 32-byte AES-256 key

# init.lua itself (self-keyed):
plain = zlib.decompress(
    AES.new(key, AES.MODE_CBC, init[0x20:0x30]).decrypt(init[0x50:]))

# any other file:
data = open(path, "rb").read()
plain = zlib.decompress(
    AES.new(key, AES.MODE_CBC, data[0x00:0x10]).decrypt(data[0x10:]))
```

A complete ready-to-run decryptor implementing this (including the `.partN` reassembly) is included in `decrypt_all.py`:

```
python decrypt_all.py [game_dir] [out_dir]
```

### Red herring

The binary contains an "ENC3" handler (XXTEA, constants `0xDEADDEAD`/`0xB00BEEEF`) — **unreachable dead code** in this build (its guard checks a string that is always empty). The real scheme is the AES one above. Don't waste time on it.

## 3. `things.spr` — Sprite Archive

No per-sprite encryption inside — once reassembled, sprite data is raw RLE.

```
+0x00   u32             signature 0x5D97AB7B
+0x04   u32             sprite count = 653,783
+0x08   u32[count]      absolute offsets; entry i-1 = sprite ID i (1-based)
                        entry 0 (sprite ID 1) = 0 (null slot, part of the table)
        sprite data:    3-byte colorkey (FF 00 FF) + u16 data_size
                        + RLE chunks { u16 transparent, u16 colored,
                                       colored × 4 bytes RGBA }
```

Verified on all 623,134 non-null sprites: offsets monotonic, last sprite ends exactly at EOF. Two quirks:

- **The offset table starts at `+0x08`, not `+0x0C`.** What looks like a "reserved" u32 is sprite ID 1's null entry. Reading from `+0x0C` shifts every sprite by one table entry → chopped tiles and neighbor sprites leaking in. This single off-by-one was the root cause of a long "torn sprites" debugging saga.
- **Trailing transparent run is omitted**: sprites can decode to fewer than 1024 pixels; the client fills the rest with transparency. ObjectBuilder needs exactly 1024, so converters must append a trailing `(transparent, 0)` chunk.

## 4. `things.dat` — Object Definitions

```
+0x00   u32   signature 0xBCBCF8F6
+0x04   u16   items = 50,599    (IDs from 100)
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

The client format uses the extended/transparency layout (what OTClient labels the 10.98 feature set: u32 sprite IDs, RGBA sprites, no frame-durations/groups). Conversion to Tibia 10.56 extended for ObjectBuilder 0.5.9 is implemented in `pka2ob.py` (expects `decrypted/data/things/`, writes `ob3108/`):

- Signatures → `0x542143B0` (dat) / `0x542143DE` (spr) — already in OB's `versions.xml`, no OB config edits needed.
- All attributes stripped (`0xFF` only); visual data kept. Outfits get the 10.56 frame-group marker; multi-frame records get a synthesized animator (100 ms phases).
- **No sid remap, no direction flip** — source order is already stock.
- Sprites copied verbatim + the trailing transparent pad when RLE covers < 1024 px. Offset table read from **+0x08**.
- **4096 clamp**: records exceeding OB's per-thing sprite limit are clamped by dropping trailing frames.
- **Category reshuffle**: the last 99 item records (game IDs 50600–50698) are actually **outfit** data (patternX=4 + frames) → moved to the front of outfits; the last 98 creature records (3790–3887) are actually **effect** data → moved to the front of effects. Resulting OB counts: items 50,500 records, outfits 3,888, effects 2,980, missiles 152.
- Outfit views can be horizontally centered post-conversion by appending shifted copies as new sprites (deduped by content hash) and rewriting outfit sid refs — originals untouched (592,330 → 710,760 sprites, measured on the 2026-07-22 build).

Result validated by full OB-layout parse (dat to exact EOF, every sprite exactly 1024 px) and confirmed visually in ObjectBuilder.
