```markdown
# CTF Writeup: Invisible WORDs
**Category:** Steganography  
**Difficulty:** Medium  
**Flag:** `picoCTF{w0rd_d4wg_y0u_f0und_5h3113ys_m4573rp13c3_b48ea7de}`

---

## Challenge Description

> Do you recognize this cyberpunk baddie? We don't either. AI art generators are all
> the rage nowadays, which makes it hard to get a reliable known cover image. But we
> know you'll figure it out. The suspect is believed to be trafficking in classics.
> That probably won't help crack the stego, but we hope it will give motivation to
> bring this criminal to justice!

**Hints:**
- Something doesn't quite add up with this image...
- How's the image quality?

**Given File:** `output.bmp`

---

## Simple Explanation Before We Begin

Think of a BMP image as a grid of pixels.  
Each pixel stores its color using a fixed number of bits.  
In this challenge, each pixel uses **32 bits (4 bytes)**.  
But here is the trick — the actual color only needs **15 bits**.  
So **17 bits per pixel are secretly free** to hide data.  
That free space is where our hidden file lives.

---

## Step 1 — Download the File

```bash
wget https://artifacts.picoctf.net/c/400/output.bmp
```

This downloads the BMP image we need to analyze.

---

## Step 2 — Check Basic File Info

```bash
file output.bmp
ls -lh output.bmp
```

**Output:**
```
output.bmp: PC bitmap, Windows 98/2000 and newer format, 960 x 540 x 32
-rw-rw-r-- 1 ved ved 2.0M Mar 16 2023 output.bmp
```

**What we learn:**
- It is a valid BMP file
- Resolution is 960x540
- Bit depth is **32 bits per pixel**
- File size is 2MB

---

## Step 3 — Read the Metadata

```bash
exiftool output.bmp
```

**Key part of output:**
```
Bit Depth        : 32
Red Mask         : 0x00007c00
Green Mask       : 0x000003e0
Blue Mask        : 0x0000001f
Alpha Mask       : 0x00000000
```

### This is the KEY discovery!

Let us break down what the masks mean:

| Color   | Mask         | Bits Used |
|---------|--------------|-----------|
| Red     | `0x00007c00` | 5 bits    |
| Green   | `0x000003e0` | 5 bits    |
| Blue    | `0x0000001f` | 5 bits    |
| **Total**   |              | **15 bits** |

The image says it uses **32 bits per pixel**.  
But the color masks only use **15 bits** for actual color data.  
That means **the lower 2 bytes (16 bits) of every pixel are NOT used for color**.  
These hidden bytes are the **"Invisible WORDs"** from the challenge title!  
> A "WORD" in computer terms = 2 bytes = 16 bits

---

## Step 4 — Confirm Hidden Data With Raw Hex

```bash
xxd -s 138 -l 64 output.bmp
```

**Output:**
```
0000008a: 3867 504b 9552 0304 c618 1400 ce3d 0000  8gPK.R.......=..
```

### Spot the magic!

Look at bytes at position `0x8c` to `0x91`:
```
50 4b 03 04
```

This is the **ZIP file magic signature** (`PK` = Philip Katz, inventor of ZIP)!

So the hidden WORDs form a **ZIP file** embedded inside the image pixels.

### How the pixel layout looks:

```
[ 2 bytes COLOR ][ 2 bytes HIDDEN ZIP DATA ][ 2 bytes COLOR ][ 2 bytes HIDDEN ZIP DATA ] ...
```

Pixel data starts at byte offset **138** in the BMP file.  
The hidden data starts at offset **140** (138 + 2).

---

## Step 5 — Extract the Hidden ZIP File

```bash
python3 -c "
data = open('output.bmp', 'rb').read()
hidden = b''.join(data[i:i+2] for i in range(140, len(data), 4))
open('hidden_full.zip', 'wb').write(hidden)
print(f'Extracted {len(hidden)} bytes')
" && file hidden_full.zip
```

**Output:**
```
Extracted 1036800 bytes
hidden_full.zip: Zip archive data, at least v2.0 to extract
```

### What the script does (line by line):

```python
data = open('output.bmp', 'rb').read()
# Read the entire BMP file as raw bytes

hidden = b''.join(data[i:i+2] for i in range(140, len(data), 4))
# Start at byte 140 (skip first 2 bytes of first pixel = color data)
# Take 2 bytes, skip 2 bytes, take 2 bytes, skip 2 bytes...
# This collects all the HIDDEN WORDs and skips the COLOR WORDs

open('hidden_full.zip', 'wb').write(hidden)
# Save the result as a ZIP file
```

---

## Step 6 — Fix the ZIP File (Find the Real End)

When we try to open the ZIP:
```bash
unzip -l hidden_full.zip
```

**Output:**
```
End-of-central-directory signature not found.
```

The ZIP file has **padding at the end** (leftover BMP pixels full of `ff00`).  
ZIP files can be read from the **end**, so we need to find where the ZIP truly ends.

Every valid ZIP file ends with an **End of Central Directory (EOCD)** signature:
```
50 4b 05 06
```

Let us find it and cut the file at the right place:

```bash
python3 -c "
data = open('output.bmp', 'rb').read()
hidden = b''.join(data[i:i+2] for i in range(140, len(data), 4))
idx = hidden.rfind(b'PK\x05\x06')
if idx != -1:
    print(f'EOCD found at offset {idx} (0x{idx:x})')
    open('hidden_fixed.zip', 'wb').write(hidden[:idx+22])
    print(f'Written {idx+22} bytes to hidden_fixed.zip')
"
```

**Output:**
```
EOCD found at offset 169575 (0x29667)
Written 169597 bytes to hidden_fixed.zip
```

> We add **22 bytes** because the EOCD record itself is 22 bytes long.

---

## Step 7 — List and Extract ZIP Contents

```bash
unzip -l hidden_fixed.zip
```

**Output:**
```
Archive:  hidden_fixed.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
   448642  2023-03-16 07:57   ZnJhbmtlbnN0ZWluLXRlc3QudHh0
```

The filename looks like **Base64**! Let us decode it:

```bash
echo "ZnJhbmtlbnN0ZWluLXRlc3QudHh0" | base64 -d
```

**Output:**
```
frankenstein-test.txt
```

This matches the challenge hint: *"The suspect is believed to be trafficking in classics"*  
Frankenstein is a classic novel by Mary Shelley!

Now extract it:

```bash
unzip -o hidden_fixed.zip
```

---

## Step 8 — Find the Flag in the Text File

```bash
grep -i "picoCTF{" ZnJhbmtlbnN0ZWluLXRlc3QudHh0
```

**Output:**
```
At that age I became acquainted with the celebrated 
picoCTF{w0rd_d4wg_y0u_f0und_5h3113ys_m4573rp13c3_b48ea7de}
```

---

## Flag

```
picoCTF{w0rd_d4wg_y0u_f0und_5h3113ys_m4573rp13c3_b48ea7de}
```

---

## Full Attack Chain (Quick Reference)

```
output.bmp
    │
    ├── [exiftool] → 32-bit depth but only 15-bit color masks
    │                → 2 bytes per pixel are HIDDEN (Invisible WORDs)
    │
    ├── [xxd] → Found PK ZIP signature in hidden bytes
    │
    ├── [python3] → Extracted every 2nd WORD from pixel data
    │            → Got raw ZIP bytes
    │
    ├── [python3] → Found EOCD signature, trimmed padding
    │            → Got valid hidden_fixed.zip
    │
    ├── [unzip] → Extracted frankenstein-test.txt (Base64 filename)
    │
    └── [grep] → Found flag inside the Frankenstein novel text
```

---

## Key Concepts Learned

### 1. BMP Bitfield Steganography
BMP files with 32-bit depth and 15-bit color masks leave **hidden space per pixel**.  
This space is invisible to image viewers but readable by raw byte analysis.

### 2. Magic Bytes / File Signatures
Every file type has a unique starting signature:
| Signature | File Type |
|-----------|-----------|
| `50 4B 03 04` | ZIP archive |
| `FF D8 FF` | JPEG image |
| `89 50 4E 47` | PNG image |
| `25 50 44 46` | PDF file |

Knowing these helps identify hidden files inside other files.

### 3. ZIP File Structure
```
[Local File Headers + Data] ... [Central Directory] ... [EOCD = PK\x05\x06]
```
ZIP files are designed to be read from the **end** using the EOCD record.

### 4. Why Standard Tools Failed
Tools like `binwalk` expect hidden files to be **contiguous blocks**.  
Here the ZIP data was **interleaved** (every 2nd WORD), so only a custom  
Python script could extract it correctly.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `wget` | Download the BMP file |
| `file` | Identify file type |
| `exiftool` | Read BMP metadata and color masks |
| `xxd` | Inspect raw hex bytes |
| `python3` | Custom byte extraction script |
| `unzip` | Extract ZIP archive |
| `grep` | Search for flag in text |

---

*Writeup by: CTF Player*  
*Challenge: picoCTF — Invisible WORDs*
```
