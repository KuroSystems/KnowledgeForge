# CTF Lab Writeup: Investigative Reversing 4
### Platform: picoCTF | Category: Reverse Engineering | Difficulty: Medium

---

## 1. Executive Summary

This challenge presented us with a **64-bit ELF binary** named `mystery` and **five BMP image files** (`Item01_cp.bmp` through `Item05_cp.bmp`). The core vulnerability was not a traditional security flaw, but rather a **forensic reverse engineering puzzle**: the binary had been used to encode a secret flag into the pixel data of the five images using **Least Significant Bit (LSB) steganography**.

To recover the flag, we had to:
1. Reverse engineer the binary to understand *exactly* how it hid data
2. Reconstruct a precise decoder based on the binary's logic
3. Extract the flag character by character from the modified images

**Flag recovered:** `picoCTF{N1c3_R3ver51ng_5k1115_000000000003c500b8a}`

**Primary skills demonstrated:**
- Static binary reverse engineering with `objdump`
- Assembly-to-logic translation
- LSB steganography decoding
- Structured analytical thinking

---

## 2. Reconnaissance & Enumeration

### 2.1 First Contact — What Are We Dealing With?

Before touching any tool, we asked the most fundamental question in CTF play:

> *"What kind of file is this, and what environment does it expect?"*

We ran:
```bash
file mystery
```
```
mystery: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
for GNU/Linux 3.2.0, BuildID[sha1]=b671dc4e..., not stripped
```

**Breaking down what this tells us:**

| Property | Value | Significance |
|---|---|---|
| `ELF 64-bit` | Linux executable format | Needs a Linux x86-64 environment to run |
| `LSB` | Little-endian byte order | Affects how we interpret multi-byte values in assembly |
| `dynamically linked` | Uses shared libraries | We can see library calls like `fopen`, `fread` |
| `not stripped` | Symbol table intact | **Gold mine** — function and variable names are preserved |

> 💡 **Beginner Tip:** The phrase "not stripped" is extremely important in reverse engineering. When a binary is *stripped*, all the helpful function and variable names are removed, leaving only raw addresses. A non-stripped binary still contains names like `encodeDataInFile` or `flag_index`, which dramatically accelerates analysis. Always check this first.

**Why not just run the binary?**
The challenge description says "run this on the server." Running it locally would fail silently because there is no `flag.txt` on our machine. More importantly, *running unknown binaries blindly is dangerous practice*. We chose the safer, more educational path: **static analysis first**.

---

### 2.2 String Extraction — The Low-Hanging Fruit

Before disassembling anything, we always run `strings` on a binary. This extracts all sequences of printable ASCII characters (default minimum length: 4).

```bash
strings mystery
```

**Why `strings` first?**
It takes under a second and can immediately reveal:
- Hardcoded passwords or keys
- File paths the binary reads/writes
- Error messages that hint at program logic
- Function names (in non-stripped binaries)

**Key findings from `strings` output:**

```
encodeDataInFile     ← Core function: hides data IN files
encodeAll            ← Orchestrator function: processes all images
codedChar            ← Likely transforms a character before hiding it
flag_index           ← Global variable tracking position in flag
flag_size            ← How long the flag is
buff / buff_index    ← Buffer management
Item01_cH / p.bmp    ← Fragmented strings of "Item01_cp.bmp"
flag.txt             ← The binary reads the flag FROM this file
chal2.c              ← Original source file name (developer left it in!)
```

> 💡 **Beginner Tip:** Fragmented strings like `Item01_cH` and `p.bmp` appearing separately are an artifact of how the compiler stores string literals that are built at runtime by writing a digit into the middle. The `H` is a placeholder that gets overwritten with the image number (`1`–`5`) during execution.

**What the strings told us conceptually:**
The binary reads a flag from `flag.txt`, then uses `encodeDataInFile` to hide it inside the BMP image files. The output files are the `_cp.bmp` files we were given. This means **the flag is already inside those image files** — we just need to understand the hiding scheme.

---

## 3. Exploitation — Reverse Engineering the Encoder

### 3.1 The Approach Decision

At this point we had two paths:

| Path | Description | Verdict |
|---|---|---|
| **Blind stego tools** | Run `steghide`, `zsteg`, `stegsolve` on the BMPs | ❌ Too generic — won't match custom encoding |
| **Static disassembly** | Read the assembly and reconstruct exact logic | ✅ Precise, guaranteed to work |

> 🚫 **The Road Not Taken:** Many beginners immediately throw stego tools at image challenges. Tools like `steghide` and `zsteg` are excellent for *standard* hiding schemes, but this binary uses a *custom* encoding. We would have gotten no output, or worse, garbage that looks like output. Because we had the binary, static analysis was always the right call.

---

### 3.2 Disassembling `encodeAll` — Understanding the File Order

```bash
objdump -d -M intel mystery | sed -n '/<encodeAll>/,/<main>/p'
```

**Breaking down this command:**
- `objdump -d` — Disassemble all executable sections
- `-M intel` — Use Intel syntax (AT&T syntax puts destination last; Intel is more readable for most people)
- `sed -n '/<encodeAll>/,/<main>/p'` — Print only lines between the two function labels

**Key assembly decoded:**

```asm
mov BYTE PTR [rbp-0x1], 0x35    ; counter = 0x35 = ASCII '5'
...
loop:
  ; write counter byte into filename at digit position
  mov [rbp-0x3b], al            ; digit into "Item0X.bmp"
  mov [rbp-0x1b], al            ; digit into "Item0X_cp.bmp"
  call encodeDataInFile          ; process this image pair
  sub BYTE PTR [rbp-0x1], 1     ; counter--
  cmp BYTE PTR [rbp-0x1], 0x30  ; compare with '0' = 48
  jg loop                        ; if counter > '0', loop
```

**What this means in plain English:**
- The loop starts with digit `'5'` (0x35) and counts *down* to `'1'` (0x31, which is > 0x30)
- It processes: `Item05` → `Item04` → `Item03` → `Item02` → `Item01`
- **The images are processed in reverse order (5 to 1)**

> 💡 **This is critical for decoding!** If we had assumed the images were processed 1→5, our flag characters would have been in the wrong order.

---

### 3.3 Disassembling `encodeDataInFile` — The Core Logic

This function takes two arguments: the **source** BMP filename and the **output** `_cp` BMP filename.

#### Phase 1: Header Copy (Bytes 0 to 2018)

```asm
mov DWORD PTR [rbp-0x24], 0x7e3   ; limit = 0x7E3 = 2019
mov DWORD PTR [rbp-0x8], 0x0      ; i = 0
loop1:
  fread(1 byte from source)
  fputc(that byte to output)        ; copy unchanged
  i++
  if i < 2019: goto loop1
```

**In plain English:** The first 2019 bytes are copied verbatim. This is the BMP file header and metadata — we never touch it.

> 💡 **Why 2019 bytes?** BMP files have a fixed header structure. The actual pixel data starts at an offset specified in the header. The developer chose 2019 bytes as the boundary before pixel data begins for these specific images.

#### Phase 2: The Encoding Body (positions 0 to 49)

```asm
mov DWORD PTR [rbp-0xc], 0         ; outer_pos = 0
outer_loop:
  ; --- Compute outer_pos % 5 ---
  imul with 0x66666667 and sar...   ; compiler-optimized division
  ; if remainder != 0: copy byte unchanged, continue
  ; if remainder == 0: ENCODE a flag character
  
  inner_loop (j = 0 to 7):
    read 1 byte from source
    result = codedChar(j, flag[flag_index], source_byte)
    fputc(result to output)
  flag_index++
  
  outer_pos++
  if outer_pos <= 0x31 (49): goto outer_loop
```

**Decoded logic:**
- For 50 positions (0–49), every position where `pos % 5 == 0` triggers encoding
- Positions 0, 5, 10, 15, 20, 25, 30, 35, 40, 45 → **10 encoding events per image**
- Each encoding event consumes **8 bytes** and encodes **1 flag character**
- At all other positions, 1 byte is copied unchanged

**Per image: 10 flag characters hidden across 80 bytes of pixel data.**
**Across 5 images: 50 flag characters total.**

---

### 3.4 Disassembling `codedChar` — The Bit-Level Operation

```asm
codedChar(int bit_index, char flag_char, char original_byte):
  mask1 = 0x01   ; binary: 00000001
  mask2 = 0xFE   ; binary: 11111110

  if bit_index != 0:
    flag_char = flag_char >> bit_index    ; shift to get target bit to position 0

  flag_char = flag_char & 0x01           ; isolate just bit 0 (the target bit)
  original_byte = original_byte & 0xFE  ; clear the LSB of the pixel byte
  original_byte = original_byte | flag_char  ; set LSB = target flag bit
  return original_byte
```

**In plain English:**
For each of the 8 bytes used to encode one character:
1. Extract bit `j` from the flag character (shift right by `j`, then AND with 1)
2. Clear the lowest bit of the pixel byte (AND with `0xFE = 11111110`)
3. Replace that lowest bit with the flag bit (OR)

This is textbook **LSB (Least Significant Bit) steganography**.

> 💡 **Why LSB?** Changing only the least significant bit of a pixel value changes that pixel's color by at most 1 unit out of 255 — completely invisible to the human eye. This is why LSB steganography is so popular: the images look identical before and after encoding.

**Visual example:**

```
Flag char 'p' = 0x70 = 01110000

Bit 0 = 0 → pixel 201 (11001001) → 11001000 = 200
Bit 1 = 0 → pixel 134 (10000110) → 10000110 = 134  (LSB already 0)
Bit 2 = 0 → pixel  87 (01010111) → 01010110 =  86
Bit 3 = 0 → pixel 200 (11001000) → 11001000 = 200  (LSB already 0)
Bit 4 = 1 → pixel  91 (01011011) → 01011011 =  91  (LSB already 1)
Bit 5 = 1 → pixel 170 (10101010) → 10101011 = 171
Bit 6 = 1 → pixel  43 (00101011) → 00101011 =  43  (LSB already 1)
Bit 7 = 0 → pixel 198 (11000110) → 11000110 = 198  (LSB already 0)

Decoding: read LSBs = 0,0,0,0,1,1,1,0 = 01110000 = 0x70 = 'p' ✓
```

---

### 3.5 Writing the Decoder

With the full picture now understood, we wrote a Python decoder that mirrors the binary's logic exactly:

```python
from pathlib import Path

def decode_image(path):
    data = Path(path).read_bytes()
    
    pos = 2019          # Skip the 2019-byte header (untouched region)
    characters = []
    
    for i in range(50):           # 50 outer positions
        if i % 5 == 0:            # Encoding event
            char_bits = 0
            for bit in range(8):  # Read 8 bytes, extract 1 bit each
                char_bits |= (data[pos] & 1) << bit   # LSB → bit position
                pos += 1
            characters.append(chr(char_bits))
        else:
            pos += 1              # Non-encoding position, skip
    
    return ''.join(characters)

# Images processed in reverse order (5 → 1) as encodeAll revealed
flag = ''.join(decode_image(f'Item0{i}_cp.bmp') for i in range(5, 0, -1))
print(flag)
```

**Breaking down the decoder:**

| Line | Purpose |
|---|---|
| `pos = 2019` | Skip the untouched header region |
| `for i in range(50)` | Mirror the 50-iteration outer loop |
| `if i % 5 == 0` | Only these positions contain encoded data |
| `data[pos] & 1` | Extract LSB of pixel byte |
| `<< bit` | Place it in the correct bit position of the character |
| `range(5, 0, -1)` | Reverse order: Image 5 first, Image 1 last |

**Output:**
```
picoCTF{N1c3_R3ver51ng_5k1115_000000000003c500b8a}
```

---

## 4. "Privilege Escalation" — Avoiding Dead Ends

In this reversing challenge, the equivalent of privilege escalation was **achieving confidence in our analysis**. Here are the traps that could have cost significant time:

### Trap 1: Wrong File Order
If we had processed images 1→5 instead of 5→1, we would have gotten garbled characters. The assembly clearly showed the loop decrementing from `'5'` to `'1'`, but this is easy to miss if you skim rather than read carefully.

### Trap 2: Wrong Header Offset
Using `0x7E3 = 2019` is non-obvious. If we had used a standard BMP offset (e.g., 54 bytes for a simple BMP), we would have decoded garbage. The binary hardcodes 2019 — we read it directly from the assembly.

### Trap 3: Wrong Encoding Position Logic
The `% 5 == 0` condition means positions 0, 5, 10... trigger encoding, not positions 1, 6, 11... An off-by-one assumption here would shift every extracted character.

### Trap 4: Bit Order
`codedChar` encodes **bit 0 first** (LSB-first order). If we had assumed MSB-first, every character would decode as a mirrored bit pattern — valid-looking bytes but wrong characters.

> 🧠 **Key Lesson:** Every parameter in our decoder was derived directly from the assembly. We made **zero assumptions**. This is the discipline that separates reliable reverse engineering from lucky guessing.

---

## 5. Lessons Learned & Mitigation

### 5.1 For the Attacker (Learner Takeaways)

| Lesson | Application |
|---|---|
| **Always `file` first** | Determine execution environment before anything else |
| **`strings` is free intelligence** | Run it on every unknown binary before disassembling |
| **Non-stripped = treasure** | Function names in assembly cut analysis time dramatically |
| **LSB steganography is common** | Changing only the last bit is visually undetectable |
| **Read loops carefully** | The direction (increment vs. decrement) changes everything |
| **Derive, don't assume** | Every magic number in your decoder should come from the assembly |

### 5.2 For the Defender (Blue Team Mitigation)

**1. Strip production binaries**
```bash
strip --strip-all mystery
```
A stripped binary removes all symbol names, making `encodeDataInFile`, `flag_index`, and `codedChar` invisible to the attacker. This forces them to work with raw addresses, increasing analysis time significantly.

> ⚠️ Note: Stripping is **security through obscurity** — it slows attackers down but does not make the logic unrecoverable.

**2. Detect LSB steganography with statistical analysis**
Tools like `stegdetect` or custom chi-square analysis can detect the statistical anomaly that LSB encoding introduces in pixel data. In a high-security environment, image files being exfiltrated could be automatically scanned for LSB patterns:

```bash
stegdetect Item01_cp.bmp
```

A significant deviation from expected pixel value distributions indicates possible embedded data.

**3. Integrity monitoring for binary outputs**
If this binary represents a production data-processing tool, a blue team could implement **file integrity monitoring (FIM)** using tools like AIDE or Tripwire to alert when image files are unexpectedly modified at the byte level beyond normal processing.

---

## Appendix: Full Attack Chain Summary

```
[mystery binary] → reads flag.txt
       ↓
[encodeAll] → iterates images 5 → 4 → 3 → 2 → 1
       ↓
[encodeDataInFile] → for each image:
    • Copy bytes 0–2018 unchanged (BMP header)
    • For positions 0–49 in pixel body:
        - if pos % 5 == 0: encode 1 flag char across 8 bytes via LSB
        - else: copy byte unchanged
       ↓
[codedChar] → extracts 1 bit from flag char, replaces pixel LSB
       ↓
[Item01_cp.bmp ... Item05_cp.bmp] → output images with hidden flag

[Our decoder] → reverses this entire process
       ↓
picoCTF{N1c3_R3ver51ng_5k1115_000000000003c500b8a}
```

---
*Writeup authored following structured reverse engineering methodology. Every conclusion was derived from direct assembly analysis — zero guesswork.*
