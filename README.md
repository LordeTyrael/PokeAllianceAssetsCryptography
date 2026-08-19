# PokeAlliance — Assets & Cryptography Documentation

PokeAlliance is a PokeTibia (OTClient fork, DirectX build). Its client is `PokeAlliance_dx.exe` (x86-64, base `0x140000000`). Unlike PokeXGames' homebrew Salsa20 scheme, PokeAlliance uses standard crypto — **AES-256-CBC + zlib** via an embedded OpenSSL 3.x EVP — and the key is stored inside `init.lua` itself. No dynamic analysis is needed; everything below was verified by decrypting the full installed asset tree (**8,034 files**).

## 1. The Encryption

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

`things.spr` is split into `things.spr.part1 … part11`. Each part is an independent regular-format encrypted file; decrypt each and concatenate in numeric order to rebuild `things.spr` (1,079,396,629 bytes).

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

## 2. `things.spr` — Sprite Archive

No per-sprite encryption inside — once reassembled, sprite data is raw RLE.

```
+0x00   u32             signature 0x5D97AB7B
+0x04   u32             sprite count = 592,330
+0x08   u32[count]      absolute offsets; entry i-1 = sprite ID i (1-based)
                        entry 0 (sprite ID 1) = 0 (null slot, part of the table)
        sprite data:    3-byte colorkey (FF 00 FF) + u16 data_size
                        + RLE chunks { u16 transparent, u16 colored,
                                       colored × 4 bytes RGBA }
```

Verified on all 561,681 non-null sprites: offsets monotonic, last sprite ends exactly at EOF. Two quirks:

- **The offset table starts at `+0x08`, not `+0x0C`.** What looks like a "reserved" u32 is sprite ID 1's null entry. Reading from `+0x0C` shifts every sprite by one table entry → chopped tiles and neighbor sprites leaking in. This single off-by-one was the root cause of a long "torn sprites" debugging saga.
- **Trailing transparent run is omitted**: sprites can decode to fewer than 1024 pixels; the client fills the rest with transparency. ObjectBuilder needs exactly 1024, so converters must append a trailing `(transparent, 0)` chunk.

## 3. `things.dat` — Object Definitions

```
+0x00   u32   signature 0xBCBCF8F6
+0x04   u16   items = 50,231    (IDs from 100)
+0x06   u16   creatures = 3,796 (IDs from 1)
+0x08   u16   effects = 2,763
+0x0A   u16   missiles = 247    (lies — only 148 records exist; read to EOF)
+0x0C   records: { attribute bytes … 0xFF } { visual block }
        visual: u8 width, u8 height, [u8 exactSize if w>1 or h>1],
                u8 layers, patternX, patternY, patternZ, frames,
                u32 spriteID × (w×h×layers×pX×pY×pZ×frames)
```

- **Sprite-ID list order is stock**: `[frames][pz][py][px][layers][h][w]` — the client reads the list sequentially with no permutation. Any "remap" scrambles correct data (the second root cause of the torn-sprites saga).
- **Custom attribute table** (do NOT trust stock Tibia tables): `0x08`, `0x28`, `0x29` are **flags** here (not payloads); `0x2A` has a fixed **16-byte** payload (8×i16). With those, the whole file parses to exact EOF.
- **No animator bytes anywhere**, even for multi-frame records — the client synthesizes 100 ms phases.

## 4. ObjectBuilder Conversion

The client format uses the extended/transparency layout (what OTClient labels the 10.98 feature set: u32 sprite IDs, RGBA sprites, no frame-durations/groups). Conversion to Tibia 10.56 extended for ObjectBuilder 0.5.9 is implemented in `pka2ob.py` (expects `decrypted/objectbuilder/`, writes `objectbuilder/`):

- Signatures → `0x542143B0` (dat) / `0x542143DE` (spr) — already in OB's `versions.xml`, no OB config edits needed.
- All attributes stripped (`0xFF` only); visual data kept. Outfits get the 10.56 frame-group marker; multi-frame records get a synthesized animator (100 ms phases).
- **No sid remap, no direction flip** — source order is already stock.
- Sprites copied verbatim + the trailing transparent pad when RLE covers < 1024 px. Offset table read from **+0x08**.
- **4096 clamp**: records exceeding OB's per-thing sprite limit are clamped by dropping trailing frames.
- **Category reshuffle**: the last 98 item records (game IDs 50233–50330) are actually **outfit** data (patternX=4 + frames) → moved to the front of outfits; the last 98 creature records (3699–3796) are actually **effect** data → moved to the front of effects. Resulting OB counts: items 50,133 records, outfits 3,796, effects 2,861, missiles 148.
- Outfit views can be horizontally centered post-conversion by appending shifted copies as new sprites (deduped by content hash) and rewriting outfit sid refs — 592,330 → 710,760 sprites, originals untouched.

Result validated by full OB-layout parse (dat to exact EOF, every sprite exactly 1024 px) and confirmed visually in ObjectBuilder.
