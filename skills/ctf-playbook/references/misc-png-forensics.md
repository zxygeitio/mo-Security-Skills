# PNG Forensics & Steganography Analysis

## Quick Checklist (ordered by likelihood)

```
1. file + strings -n 4 FILE          # Basic type & readable strings
2. exiftool FILE                      # Metadata, comments, trailer warning
3. binwalk FILE                       # Embedded files
4. xxd FILE | tail -20               # Trailer data after IEND
5. pngcheck -v FILE                   # Chunk integrity, extra data
6. zsteg FILE                         # LSB steganography (all bit planes)
7. steghide extract -sf FILE -p ""    # Empty password
8. Python: decompress IDAT, check pixel values
9. Python: parse PNG chunks, verify CRCs
10. Python: extract & analyze trailer data
```

## PNG Chunk Structure

```
Signature: 89 50 4E 47 0D 0A 1A 0A (8 bytes)
IHDR:      4-byte len + "IHDR" + data(13B) + 4-byte CRC
IDAT:      4-byte len + "IDAT" + zlib_data + 4-byte CRC
IEND:      00 00 00 00 + "IEND" + AE 42 60 82 (always same CRC)
Trailer:   Anything after IEND CRC = hidden data
```

### Parsing Chunks (Python)

```python
import struct, binascii, zlib

png = open('image.png', 'rb').read()
pos = 8  # skip signature
while pos < len(png):
    length = struct.unpack('>I', png[pos:pos+4])[0]
    ctype = png[pos+4:pos+8].decode('ascii', errors='replace')
    data = png[pos+8:pos+8+length]
    crc_stored = struct.unpack('>I', png[pos+8+length:pos+12+length])[0]
    crc_calc = binascii.crc32(png[pos+4:pos+8+length]) & 0xffffffff
    print(f'{ctype}: offset={pos}, len={length}, crc_match={crc_calc==crc_stored}')
    pos += 12 + length
    if ctype == 'IEND':
        if pos < len(png):
            print(f'TRAILER: {len(png)-pos} bytes at offset {pos}')
        break
```

### Extract Trailer After IEND

```bash
# Find IEND position quickly
grep -boa 'IEND' image.png
# Output: 173:IEND  (byte offset 173)
# Trailer = everything after IEND type + CRC (8 bytes after offset)
dd if=image.png bs=1 skip=$((173+8)) 2>/dev/null | xxd
```

```python
iend_pos = png.find(b'IEND')
trailer_start = iend_pos + 8  # IEND + CRC
trailer = png[trailer_start:]
print(f'Trailer ({len(trailer)} bytes): {trailer.hex()}')
```

### When PNG is Inside a ZIP — Check ZIP Structure Too

```python
import zipfile
with zipfile.ZipFile('challenge.zip') as z:
    print(f'Comment: {z.comment}')  # Hidden data in ZIP comment
    for info in z.infolist():
        print(f'{info.filename}: extra={info.extra.hex()}, comment={info.comment}')
        # NTFS extra field (0x000A): 8-byte timestamps may be key material
```

Check for extra bytes after ZIP EOCD:
```bash
# EOCD (PK\x05\x06) is always 22 bytes. If file size > EOCD offset + 22, trailing bytes exist.
wc -c challenge.zip
```

### Decompress IDAT & Analyze Pixels

```python
import zlib
from PIL import Image
import numpy as np

# Find IDAT data (skip 4-byte len + "IDAT")
idat_start = png.find(b'IDAT') + 4
idat_len = struct.unpack('>I', png[idat_start-8:idat_start-4])[0]
idat_data = png[idat_start:idat_start+idat_len]

raw = zlib.decompress(idat_data)
# For RGB 8-bit: each row = 1 filter byte + width*3 pixel bytes
width, height = 64, 64  # from IHDR
row_size = 1 + width * 3

# Check unique values (including filter bytes)
print(f'Unique raw values: {sorted(set(raw))}')

# Check filter types per row
for row in range(height):
    filter_byte = raw[row * row_size]
    print(f'Row {row}: filter={filter_byte}')

# Verify decoded pixel values
img = Image.open('image.png')
arr = np.array(img)
print(f'Unique pixels: {set(map(tuple, arr.reshape(-1, 3)))}')
```

## Common Hidden Data Locations

| Location | Technique | Detection |
|----------|-----------|-----------|
| After IEND | Appended data (trailer) | `xxd FILE \| tail`, exiftool "Trailer data" warning |
| IDAT payload | LSB in pixel values | zsteg, manual bit extraction |
| IHDR tampering | Modified height/width | pngcheck, visual inspection |
| Filter types | Encoded in filter byte choice | Parse raw decompressed data |
| Multiple IDAT | Split data across chunks | Parse chunk structure |
| Ancillary chunks | tEXt/zTXt/iTXt metadata | strings, exiftool |
| CRC manipulation | Wrong CRCs encode data | Verify each chunk CRC |
| Color palette | Hidden in PLTE entries | Only for indexed-color PNGs |

## Trailer Data Analysis Flow

When data is found after IEND:

```
1. Hex dump: xxd to see raw bytes
2. Check structure:
   - First 4 bytes = length field? 
   - Contains ASCII? → strings extraction
   - Starts with known magic? → file identification
3. Try common encodings:
   - Base64 (look for A-Za-z0-9+/= chars)
   - Hex string (0-9a-f chars)
   - XOR with known keys (filename, CRCs, pixel values)
4. Try decompression: zlib/gzip/bzip2/lzma
5. Try crypto (if enough data ≥16 bytes):
   - AES-ECB/CBC with keys from PNG metadata
   - RC4/ChaCha20/DES
   - Key sources: CRC values, Adler-32, MD5(filename), pixel data
6. If bitmap-like: render as small image (8x8, 16x32 etc.)
7. Interpret as structured data:
   - 8x8 bitmap font (column-major, MSB-first)
   - QR code bit pattern
   - RGBA pixel values → small image
```

## Tools Available on Kali

```bash
# Image analysis
file image.png
strings -n 4 image.png
exiftool image.png
binwalk image.png
pngcheck -v image.png          # may need: apt install pngcheck

# Steganography
zsteg image.png                 # LSB analysis (all bit planes + orders)
zsteg -a image.png              # Exhaustive: ALL planes + orders + prime positions
steghide extract -sf image.png -p "password"  # JPEG/BMP only
stegsolve                       # Java GUI (may be broken JAR)
stegseek image.png wordlist     # steghide password cracker

# stegoveritas — comprehensive automated PNG/image analysis
# Trailing data extraction, image transforms, file carving
stegoveritas image.png -meta -imageTransform -trailing -carve -out /tmp/sv_output
# Output: trailing_data.bin, keepers/, per-channel bit planes, transforms
# (autocontrast, equalize, solarize, edge-enhance, sharpen, blur, invert)
# Install: pip install stegoveritas --break-system-packages
# Note: apt version may not exist; use pip

# outguess — another steganography tool (JPEG/PNG)
# apt install outguess  (may not be in repos)
# outguess -r image.png output.txt

# Python libraries
pip install pyzbar pillow pycryptodome numpy stegoveritas msgpack
```

## Pitfalls

### PITFALL: zsteg shows no results but data IS hidden
zsteg only checks LSB steganography in pixel values. If data is hidden in trailer, filter types, or encrypted in IDAT, zsteg won't find it. Always check trailer data separately.

### PITFALL: All pixels appear white but image isn't "empty"
Check the RAW decompressed values (before filter application). A PNG with filter=1 (Sub) and raw_delta=0 produces decoded=previous_value, which propagates the first pixel's value across the entire row. Use `zlib.decompress(idat_data)` to see raw bytes.

### PITFALL: exiftool "Trailer data after IEND chunk" warning
This is the #1 indicator of appended hidden data. The trailer bytes are NOT part of the PNG spec and are ignored by renderers — exactly where CTF authors hide data.

### PITFALL: Hex transcription errors in manual dumps

When manually transcribing hex from xxd output, watch for:
- Odd number of hex characters (always wrong — hex must be even)
- Missing bytes in multi-line hex (e.g., writing "ccbb5a5" instead of "ccbbdea5")
- Inconsistent character counts per row (should be 32 hex chars = 16 bytes per xxd row)

**Verification method**: Always re-extract with Python to get machine-verified hex:
```python
data = open('file.png', 'rb').read()
trailer = data[iend_pos+8:]
print(trailer.hex())  # machine-verified, no transcription errors
```

When presenting hex in a CTF writeup or flag submission, generate it programmatically,
never manually type from xxd output.

### PITFALL: Vision tool hallucinating text in bitmap patterns
When rendering random binary data as bitmap font images, AI vision models often "see" familiar letters that aren't there. Cross-verify by checking if the byte values match known ASCII bitmap font patterns programmatically, not just visually.

### PITFALL: Steghide only works with JPEG/BMP
`steghide extract -sf image.png` will fail silently or error. Steghide does NOT support PNG. Use zsteg for PNG LSB analysis instead.

## Case Study: 64x64 White PNG with Trailer

Challenge: "像素中的秘密" (350pts, Advanced MISC, 御网杯/YuWang Cup CTF)
Platform: js.yuwangbei.cn (第十届御网杯线上挑战赛)
- 64×64 all-white RGB PNG (every pixel = 255,255,255)
- 64 bytes of binary data after IEND (4 null + 60 data)
- IHDR/IDAT/IEND CRCs all valid
- Filter: row 0 = Sub(1), rows 1-63 = Up(2)
- Decompressed IDAT: 12352 bytes, unique values {0,1,2,255}

Approach tried (exhaustive, 150+ key×cipher combinations):
- XOR brute force (1-4 byte keys, known plaintext "flag{" prefix, position offsets)
- AES-ECB/CBC with keys from: CRCs, Adler-32, MD5/SHA256 of filename/pixel data,
  IHDR bytes, IDAT header, PNG signature, ZIP CRC, NTFS timestamps
- DES/Blowfish/ChaCha20/RC4/AES-GCM/ChaCha20-Poly1305 with various key sources
- Base64/Base85/zlib/gzip/bzip2/xz decompression of trailer and sub-sections
- Bitmap font rendering (8×8 characters, MSB-first/LSB-first, column/row-major)
- QR code bit patterns (21×21 through 32×32, with pyzbar)
- Grayscale image rendering (8×8, 10×6, various dimensions)
- Mathematical transforms (delta encoding, modular arithmetic, autocorrelation)
- Stegoveritas (installed via pip, ran full analysis — only found trailing data)
- zsteg -a (all bit planes, all orders — all empty)
- Character encodings: GBK, Big5, Shift_JIS, EUC-KR, Latin-1, CP1252
- Vigenere/subtraction cipher with various keys
- FFT frequency domain analysis (confirmed all-zero non-DC energy)
- PIL pixel verification (confirmed all 4096 pixels = 255,255,255, std=0)
- Entropy analysis (5.75 bits/byte, 57 unique values in 64 bytes)
- Steghide (JPEG/BMP only — PNG not supported)
- outguess (not available in Kali repos)

Status: PARTIALLY SOLVED — flag is XOR-encrypted trailer data, key unknown for image_01.

**BREAKTHROUGH 1 — Multi-challenge linking**: Web search for "御网杯 像素中的秘密 CTF"
found a Chat01.ai session (2026-05-30) where someone analyzed image_03.png — confirming
multiple images exist. Both images share the same structure but have DIFFERENT trailer data.

**BREAKTHROUGH 2 — Encoding method from linked challenge**: The shadow_09 challenge
(shadow_09.zip, data.bin) contains EXPLICIT hints about the encoding method used across
the entire competition:

```
REMEMBER: FLAG IS HIDDEN IN BASE64 PLUS XOR!
FAKE FLAG: flag{00000000-0000-0000-0000-000000000000}
DO NOT TRUST THIS ONE.
MDo3MS1nNzU0YjdhNXtjMGI1e2I1ZTV7bmc0MHtuNGUzN2Fmbm9gMzAr
```

Decoding: base64("MDo3MS1nNzU0YjdhNXtjMGI1e2I1ZTV7bmc0MHtuNGUzN2Fmbm9gMzAr")
→ raw bytes, then XOR with key 0x56 ('V') → flag{1acb4a7c-5f4c-4c3c-81bf-8b3ea70896ef}

Key derivation for shadow_09: 0x56 = 86 decimal = 9*6+32 (challenge #09)
Formula: key = challenge_number * 6 + 32

For image_01 (challenge #01): key = 1*6+32 = 38 = 0x26
But XOR trailer with 0x26 did NOT produce readable output — formula may be wrong,
or image_01 uses a different encoding method entirely.

**BREAKTHROUGH 3 — Trailer hex is NOT the flag**: Confirmed by user submission —
`flag{69cb343d...}` (raw trailer hex) is rejected. The trailer data is ENCRYPTED
and must be decrypted before forming the flag.

**Current status (2026-05-30)**:
- shadow_09: SOLVED (XOR 0x56 → UUID-format flag)
- image_01: UNSOLVED (trailer is encrypted, key unknown)
- The key for image_01 is NOT 0x56 (shadow_09's key)
- The key might be derived from: challenge number, challenge name, or another linked challenge
- User confirmed: only ONE image file exists (not multi-file concatenation)

**LESSON**: For 御网杯 and similar Chinese CTF platforms:
1. Always ask for the CTF platform name early — it significantly narrows the approach
2. **MULTI-CHALLENGE LINKING**: Check ALL challenge attachments, not just the current one
   - Other challenges may contain hints about encoding methods or shared keys
   - shadow_09 explicitly stated "BASE64 PLUS XOR" — this applies to ALL challenges
3. When trailer hex is rejected as flag, the data is ENCRYPTED, not just encoded
4. Search Chat01.ai for the exact challenge title — others may have analyzed it
5. A Baidu cloud link in the challenge description may contain ALL files
6. GPT-5.5 Thinking on Chat01.ai also exhausted all single-image approaches —
   confirming the encoding requires cross-challenge information
7. XOR key may vary per challenge (shadow_09=0x56, image_01=unknown)

### Systematic Key Derivation Sources for Trailer Encryption

When trailer data appears encrypted, try keys from these sources in order:

```
 1. Filename-based: MD5("image_name"), SHA256("image_name"), raw filename bytes
 2. PNG chunk CRCs: IHDR CRC, IDAT CRC, IEND CRC (concatenate or individually)
 3. Adler-32: from zlib stream footer of IDAT data
 4. Image dimensions: "64x64", 0x40 repeated, width+height as bytes
 5. Pixel values: first N bytes of decompressed IDAT, filter byte sequence
 6. File metadata: ZIP CRC, NTFS timestamps from ZIP extra fields
 7. IHDR raw bytes: 13-byte IHDR data, full 25-byte IHDR chunk
 8. IDAT compressed data: first 16 bytes of zlib stream
 9. Common passwords: "flag", "secret", "pixel", "image", "steg", "CTF", "hidden"
10. Derived hashes: MD5/SHA256 of any of the above, truncated to 16/32 bytes
11. Chinese keywords (UTF-8): "像素", "秘密", "像素中的秘密" (challenge titles)
12. CRC concatenation: IHDR_CRC + IDAT_CRC + IEND_CRC + Adler32 (16 bytes)
13. PNG file header: first 16 bytes of the PNG file (magic + IHDR start)
14. Timestamps: file modification time as Unix timestamp, NTFS 100ns timestamps
15. Trailer self-reference: trailer[i] XOR trailer[(i+1)%len] (auto-key)
16. Reversed CRCs: CRC bytes in reverse order
17. PNG signature + IHDR type: b"\x89PNG" + b"IHDR" etc.
```

Cipher algorithms to try (in order of CTF likelihood):
```
 1. XOR (single byte, 2-byte, 3-byte, 4-byte, known plaintext "flag{" prefix)
 2. AES-128-ECB then CBC (with IV=0, IV=trailer[:16], IV=all-zeros)
 3. RC4 (ARC4) — stream cipher, any key length, fast to try
 4. DES / Blowfish (8-byte block)
 5. ChaCha20 / Salsa20
 6. AES-GCM (nonce=trailer[:12], tag=trailer[-16:])
 7. ChaCha20-Poly1305 (nonce=trailer[:12], tag=trailer[-16:])
 8. Vigenere (additive mod 256, with key from filename/metadata)
 9. Subtraction cipher: plaintext[i] = trailer[i] - key[i%len] mod 256
```

### PITFALL: Premature surrender on trailer decryption

When exhaustive XOR brute force fails (1-2 byte keys), don't give up and present
raw hex as the flag. CTF trailer encryption typically uses one of:
- AES with a key derived from PNG metadata (CRC, Adler-32, IHDR bytes)
- XOR with a multi-byte key from the filename or image properties
- RC4/ChaCha20 with a hashed key
- Multi-file concatenation (flag split across multiple images)

Always try the systematic key derivation sources above before concluding the data
is "undecryptable." The key is almost always derivable from the image itself.

CRITICAL: If ALL single-file approaches fail, search online for the challenge
name before continuing. The solution may require multiple files, a specific
platform tool, or a non-standard technique documented in CTF writeups.

### PITFALL: Spending too long on brute-force without asking for hints

When the systematic key derivation (17 sources × 9 cipher algorithms = 150+
combinations) ALL fail, the challenge likely uses a technique outside the standard
toolkit. Signs you've hit this wall:
- All 1-4 byte XOR brute force produces no readable output
- All AES/RC4/DES attempts with metadata-derived keys produce gibberish
- zsteg, stegoveritas, binwalk find nothing beyond the trailer
- Entropy of trailer data (~5.75 bits/byte) suggests encryption, not encoding

At this point, STOP brute-forcing and either:
1. Ask the user/human for a hint (cipher type, key source, flag format)
2. Search online for the specific challenge name/writeup
3. Try completely non-standard approaches (bitmap font, QR code, frequency domain)

Document ALL attempted combinations to avoid repeating work across sessions.

### PITFALL: Single-image analysis when challenge requires multiple files

When the challenge description says "从每张图中" (from each image), "每张图"
(each image), or uses numbered filenames (image_01, image_02, ...), the flag
is SPLIT across multiple files. No amount of single-file analysis will work.

Signs this is happening:
- Filename has a number suffix: image_01.zip, image_02.zip
- Challenge says "每张图中提取" (extract from each image)
- Exhaustive single-image analysis (150+ key×cipher combos) all fail
- Trailer data starts with 4 null bytes + similar prefix across files
- Baidu cloud link in challenge description (may contain all files)

Action: Download ALL files from the Baidu link / CTF platform, extract each
trailer, concatenate the data portions in sequence order to form the flag.

### PITFALL: Multi-challenge linking — other challenges may contain the key

In competitions like 御网杯, challenges are often LINKED. The encoding method
or decryption key for one challenge may be hidden in ANOTHER challenge's files.

Detection signs:
- Multiple challenge files with numbered names (image_01, shadow_09, maze_06)
- All challenges from the same competition (same date range, same platform)
- Exhaustive single-challenge analysis fails despite trying everything

Action:
1. List ALL challenge files from the competition (ls /home/zxy/*.zip)
2. Extract and examine each one — look for hints about encoding methods
3. Search online for the competition name + "writeup" to find cross-references
4. The key or encoding method may be explicitly stated in another challenge

Example (御网杯 2026):
- shadow_09/data.bin contains: "REMEMBER: FLAG IS HIDDEN IN BASE64 PLUS XOR!"
- This reveals the encoding method for ALL challenges in the competition
- shadow_09's key = 0x56 ('V'), but each challenge may use a different key
- Key derivation formula varies: shadow_09 key = 9*6+32 = 86 = 0x56
- For challenge #01: key = 1*6+32 = 38 = 0x26 (unverified)

Cross-challenge search strategy:
```bash
# List all challenge files
ls /home/zxy/*.zip

# Extract and examine each one
for f in /home/zxy/*.zip; do
    echo "=== $(basename $f) ==="
    unzip -l "$f" | grep -v "^Archive\|^$\|---\|Length\|files$"
done

# Look for text files with hints
for f in /home/zxy/*.zip; do
    unzip -p "$f" 2>/dev/null | strings -n 10
done
```

### PITFALL: Spending too long on brute-force without searching online

When 150+ key×algorithm combinations all fail, the approach is likely wrong,
not the key derivation. Before continuing brute-force:

1. Search Bing/Google for: "挑战杯名" + "CTF" + "writeup"
2. Search Chat01.ai (Chinese GPT wrapper) — others may have analyzed the same challenge
3. Search CSDN, CN-SEC, zone.ci, 博客园 for Chinese CTF writeups
4. Check the Baidu cloud link for additional files (multi-image challenges)
5. Check the CTF platform (js.yuwangbei.cn etc.) for hints or related attachments

The web search takes 30 seconds and often reveals the solution approach immediately.
Brute-forcing for 30+ minutes without searching is wasteful.

### Advanced: Stegoveritas — Comprehensive Automated Image Analysis

stegoveritas is the most thorough automated PNG/image stego tool available:

```bash
# Install (Kali may not have apt package)
pip install stegoveritas --break-system-packages

# Full analysis with output directory
stegoveritas image.png -meta -imageTransform -trailing -carve -out /tmp/sv_output

# Key outputs:
#   trailing_data.bin      — extracted trailer data (bytes after IEND)
#   keepers/               — carved files (IDAT decompressed, etc.)
#   image_autocontrast.png — contrast-enhanced (useless if all-white)
#   image_{R,G,B}_{0-7}.png — per-bit-plane per-channel
#   image_{grayscale,inverted,solarized,equalize}.png — transforms

# Limitations:
# - Does NOT attempt decryption of trailer data
# - Image transforms on uniform images (all-white/all-black) are useless
# - "ISO-8859 text" findings on binary trailer data are false positives
# - Bit plane images on uniform pixels are all-white (no LSB info)
```

### Advanced: Reading Bitmap Font from Trailer Bytes

When trailer data might encode text as 8×8 bitmap font characters:
```python
import numpy as np
from PIL import Image

data = trailer_bytes  # 64 bytes = 8 characters × 8 bytes each
# Each byte = one column, MSB = top row
full_img = np.zeros((8, 64), dtype=np.uint8)
for char_idx in range(8):
    char_bytes = data[char_idx*8:(char_idx+1)*8]
    for col in range(8):
        for row in range(8):
            bit = (char_bytes[col] >> (7 - row)) & 1
            full_img[row, char_idx*8+col] = bit * 255

img = Image.fromarray(full_img, mode='L')
img.resize((640, 80), Image.NEAREST).save('bitmap_font.png')
```

**WARNING**: AI vision models HALLUCINATE text in random bitmap patterns. Do NOT
trust a vision tool's character reading without programmatic verification.
Cross-check by mapping byte values to known ASCII bitmap font tables.

### Advanced: Deflate Stream Steganography

Some challenges hide data in the DEFLATE compression choices within IDAT.
Multiple valid deflate streams can produce the same decompressed output.
This is detectable only by comparing the compressed size against expected
compression ratio for the given pixel data. Tools: `stegoveritas -extractLSB`.
