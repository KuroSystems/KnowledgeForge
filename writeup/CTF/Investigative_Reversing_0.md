# CTF Lab Writeup: Investigative Reversing 0
### PicoCTF | Category: Reverse Engineering + Forensics | Difficulty: Beginner-Intermediate

---

## 1. Executive Summary

This challenge presented two artifacts: a compiled Linux binary (`mystery`) and a PNG image (`mystery.png`). The core objective was to recognize that **neither file alone contains the flag** — the binary *writes* the flag into the image, and the image *stores* the flag in a hidden location with a deliberate transformation applied to obscure it.

### Primary Techniques Used
| Technique | Purpose |
|-----------|---------|
| File format forensics | Detect data hidden after PNG's IEND marker |
| Static binary analysis | Understand the byte transformation algorithm |
| Reverse engineering | Invert the encoding to recover the original flag |

### The Core Vulnerability / Challenge Mechanic
The binary reads a `flag.txt` file and **appends a transformed version** of the flag to `mystery.png`. The transformation shifts specific bytes by fixed integer offsets. The challenge is: (1) finding the hidden data, and (2) understanding and reversing the transformation.

**Flag:** `picoCTF{f0und_1t_303d6aeb}`

---

## 2. Reconnaissance & Enumeration

### 2.1 — First Contact: Know Your Files

Before doing *anything* with unknown files, a professional always asks: **"What am I actually dealing with?"** File extensions can lie. A file named `.png` could be a ZIP, an ELF binary, or anything else. The `file` command reads the **magic bytes** (the first few bytes of any file) to determine its true type.

```bash
file mystery mystery.png
```

#### Why `file` and not something else?
- `file` is fast, non-destructive, and gives us ground truth about file format.
- We could have opened the PNG in an image viewer immediately, but that tells us nothing about hidden content or the binary's role.
- We could have run the binary immediately, but running unknown binaries without understanding them first is dangerous practice.

#### Output Analysis
```
mystery:     ELF 64-bit LSB pie executable, x86-64, not stripped
mystery.png: PNG image data, 1411 x 648, 8-bit/color RGB, non-interlaced
```

**Key observations and why they matter:**

| Finding | Why It Matters |
|---------|---------------|
| `ELF 64-bit` | Confirms it's a Linux executable, not a script or archive |
| `not stripped` | **Gold.** Symbol names are preserved, making disassembly far more readable. We won't need to manually rename functions |
| `PIE executable` | Position Independent Executable — memory addresses are randomized at runtime, but this only matters if we're doing dynamic analysis (we aren't) |
| PNG is `8-bit/color RGB` | Standard image format, no unusual encoding |

> 💡 **Beginner Tip:** The phrase "not stripped" refers to whether debugging symbols have been removed from the binary. Stripped binaries are harder to reverse because all function names are removed. Always check this first — it dramatically changes your approach.

---

### 2.2 — Image Forensics: Strings Analysis

The hint explicitly says *"use some forensics skills on the image."* The most fundamental forensics technique for any binary file is extracting **printable ASCII strings** embedded within it.

```bash
strings mystery.png
```

#### Why `strings` on an image?
- Images are binary files, but they often contain embedded text (metadata, comments, or hidden data).
- `strings` scans the entire file byte-by-byte and prints any sequence of 4+ printable characters. It doesn't care about file format — it's a raw scan.
- This is faster than a hex editor for a first pass and can immediately reveal anomalies.

#### The Critical Finding
Among the image noise, the very end of the output contained:

```
IEND
picoCTK
k5zsid6q_303d6aeb}
```

**Why is this suspicious?**
- `IEND` is the **termination marker** for PNG files. Nothing meaningful should appear after it in a valid PNG.
- `picoCTK` looks like a corrupted `picoCTF` — the `F` has been changed to `K`.
- The string `k5zsid6q_303d6aeb}` looks like the *tail* of a flag, but `k5z...` doesn't look right for a standard flag beginning.

> 🚩 **Red Flag Identified:** Data after IEND = hidden/appended content. Some bytes appear corrupted or transformed.

---

### 2.3 — Confirming the Hidden Data with a Hex Dump

`strings` gave us a hint, but it interprets bytes as text. To see the **exact raw bytes** appended after IEND, we use `xxd` — a hex dump tool.

```bash
xxd mystery.png | tail -n 20
```

#### Breaking Down the Command
- **`xxd`**: Converts binary file to hexadecimal representation. Each line shows: offset | hex bytes | ASCII representation.
- **`| tail -n 20`**: Pipes output to `tail`, which shows only the last 20 lines. Since we know the hidden data is at the *end* of the file (after IEND), this is an efficient way to jump straight there without scrolling through an 1,800-line hex dump of an entire PNG.

#### Why `xxd` and not a GUI hex editor?
- We're working in a terminal environment. `xxd` is universally available on Linux systems.
- For scripting and precision, command-line tools are preferable.
- A GUI hex editor (like GHex or HxD) would show the same data but would require a graphical environment.

#### Output Analysis
```
0001e860: ...5600 0000 0049 454e 44ae  .Z.8..V....IEND.
0001e870: 4260 8270 6963 6f43 544b 806b 357a 7369  B`.picoCTK.k5zsi
0001e880: 6436 715f 3330 3364 3661 6562 7d         d6q_303d6aeb}
```

**Decoding this output:**

| Hex | ASCII | Notes |
|-----|-------|-------|
| `49 45 4e 44` | `IEND` | PNG termination marker |
| `ae 42 60 82` | (binary) | IEND CRC checksum — normal PNG ending |
| `70 69 63 6f 43 54 4b` | `picoCTK` | Flag prefix — but `K` (0x4b) should be `F` (0x46)! |
| `80` | (non-printable) | Should be `{` (0x7b) — difference is 5 |
| Rest | `k5zsid6q...` | Remaining transformed flag bytes |

> 💡 **Beginner Tip:** In hex, each pair of characters represents one byte. `0x4b` = decimal 75 = ASCII `K`. `0x46` = decimal 70 = ASCII `F`. The difference is exactly 5. This is our first clue about the transformation.

---

## 3. Initial Analysis — Reverse Engineering the Binary

### 3.1 — Dynamic Analysis Attempt (and Why It Failed)

The natural instinct for many beginners is to just *run the binary* and see what happens.

```bash
./mystery
```

**Output:**
```
No flag found, please make sure this is run on the server
zsh: segmentation fault (core dumped)
```

**What happened here?**
- The binary printed a message and then **crashed** (segmentation fault).
- It's looking for files that exist on the CTF server (`flag.txt`), not on our local machine.
- The segfault occurs because the binary tried to read from a file handle that is NULL (the file didn't exist), and it didn't handle that error gracefully.

**Why we didn't try to fake the environment:**
- We *could* have created a dummy `flag.txt` and run the binary to watch it execute. This is a valid dynamic analysis approach.
- However, **static analysis** (reading the disassembly) is more precise and teaches us *exactly* what every byte transformation is, without needing to set up the runtime environment.
- Since the binary is not stripped, static analysis is highly approachable here.

> 🛤️ **Road Not Taken:** Dynamic analysis with `strace ./mystery` (which traces system calls) would have shown us which files it tried to open. This is also a valid approach, but we chose static analysis as it gives us complete algorithmic understanding.

---

### 3.2 — Static Analysis: Disassembling `main`

Since dynamic execution failed, we turn to **static analysis** — reading the binary's machine code without running it.

```bash
objdump -d mystery | grep -A 200 '<main>'
```

#### Breaking Down the Command
- **`objdump`**: The GNU disassembler. Converts binary machine code back into human-readable assembly.
- **`-d`**: Disassemble all executable sections. This converts the raw binary instructions into AT&T syntax assembly.
- **`grep -A 200 '<main>'`**: Find the line containing `<main>` and print 200 lines **A**fter it. Since the binary is not stripped, `main` is labeled clearly.

#### Why `objdump` and not `ghidra` or `IDA Pro`?
- `ghidra` and IDA Pro are more powerful and produce decompiled C-like pseudocode, which is easier to read.
- However, `objdump` is universally available, requires no installation, and for a binary this small, the assembly is very readable.
- For CTF purposes, matching the tool's complexity to the problem's complexity is good practice.

---

### 3.3 — Reading the Assembly: Reconstructing the Algorithm

This is the most important section. Let's walk through the key assembly blocks and translate them into plain English.

#### Block 1: Opening Files
```asm
lea    0xe55(%rip),%rsi    # "r"      ← open mode: read
lea    0xe50(%rip),%rdi    # "flag.txt" ← filename
call   fopen               # open flag.txt for reading

lea    0xe49(%rip),%rsi    # "a"      ← open mode: APPEND
lea    0xe44(%rip),%rdi    # "mystery.png" ← filename  
call   fopen               # open mystery.png for appending
```

**Translation:** The binary opens `flag.txt` for *reading* and `mystery.png` for *appending*. This confirms our theory — the binary **reads** the flag and **writes** it into the PNG.

> 💡 **Key Insight:** Open mode `"a"` means append — new data is added to the *end* of the file. This is exactly why we found the flag data after the `IEND` marker!

#### Block 2: Reading the Flag
```asm
mov    $0x1a,%esi    # size = 1
mov    $0x1,%edx     # count = 26 (0x1a in hex)
call   fread         # read 26 bytes from flag.txt
```

**Translation:** The binary reads exactly **26 bytes** from `flag.txt`. This tells us the flag is exactly 26 characters long. ✓ (Our extracted data is also 26 bytes — confirmed!)

#### Block 3: Writing Bytes 0–5 Unchanged
```asm
movzbl -0x30(%rbp),%eax    # load byte[0]
fputc(...)                  # write it unchanged
movzbl -0x2f(%rbp),%eax    # load byte[1]
fputc(...)                  # write unchanged
# ... repeated for bytes 2, 3, 4, 5
```

**Translation:** The first 6 bytes (`p`, `i`, `c`, `o`, `C`, `T`) are written to the PNG **without modification**. This is why we see `picoCT` intact in the appended data.

#### Block 4: The +5 Loop (Bytes 6–14)
```asm
movl   $0x6,-0x4c(%rbp)    # counter i = 6
jmp    check_loop

loop_body:
    mov    -0x4c(%rbp),%eax      # load i
    movzbl -0x30(%rbp,%rax,1),%eax  # load byte[i]
    add    $0x5,%eax             # byte[i] += 5  ← THE TRANSFORMATION
    fputc(...)                   # write transformed byte
    addl   $0x1,-0x4c(%rbp)     # i++

check_loop:
    cmpl   $0xe,-0x4c(%rbp)     # compare i to 14 (0xe)
    jle    loop_body             # if i <= 14, loop again
```

**Translation:** For bytes at index 6 through 14, **add 5** to each byte value before writing. This is the encoding that corrupted `F` → `K` (70 + 5 = 75) and `{` → `\x80` (123 + 5 = 128).

#### Block 5: The -3 Operation (Byte 15)
```asm
movzbl -0x21(%rbp),%eax    # load byte[15]
sub    $0x3,%eax            # byte[15] -= 3  ← DIFFERENT TRANSFORMATION
fputc(...)                  # write it
```

**Translation:** Byte at index 15 has **3 subtracted** from it before writing.

#### Block 6: Bytes 16–25 Unchanged
```asm
movl   $0x10,-0x48(%rbp)    # counter i = 16 (0x10)
# loop from 16 to 25 (0x19), writing each byte unchanged
```

**Translation:** The final 10 bytes are written without modification.

---

### 3.4 — Confirming with `.rodata`

To double-check our understanding of the filenames, we dump the read-only data section:

```bash
objdump -s -j .rodata mystery
```

#### Breaking Down the Command
- **`-s`**: Display full section contents as hex + ASCII.
- **`-j .rodata`**: Only show the `.rodata` section (read-only data). This is where C string literals like filenames and messages are stored.

**Output confirms:**
```
"r"  "flag.txt"   ← opened for reading
"a"  "mystery.png" ← opened for appending
"No flag found, please make sure this is run on the server"
```

This **conclusively proves** our model of the binary's behavior.

---

## 4. Flag Recovery — Reversing the Transformation

### 4.1 — The Complete Transformation Map

| Byte Index | Range | Operation Applied | Reverse Operation |
|-----------|-------|-------------------|------------------|
| 0–5 | `picoCT` | None | None |
| 6–14 | 9 bytes | `+5` | `-5` |
| 15 | 1 byte | `-3` | `+3` |
| 16–25 | `_303d6aeb}` | None | None |

### 4.2 — Extracting and Decoding

First, we extract the exact 26 appended bytes:

```bash
python3 -c "
data = open('mystery.png','rb').read()
iend = data.find(b'IEND')
appended = data[iend+8:]  # skip 4 bytes 'IEND' + 4 bytes CRC
print('Raw hex:', appended.hex())
print('Length:', len(appended))
"
```

#### Why `iend+8`?
- `IEND` is 4 bytes.
- The CRC (checksum) following it is 4 bytes.
- So we skip 8 bytes past the start of `IEND` to reach our appended data.

**Output:** 26 bytes confirmed. ✓

Then we apply the reverse transformation:

```python
python3 -c "
appended = bytes.fromhex('7069636f43544b806b357a73696436715f33303364366165627d')
flag = bytearray(appended)

# Reverse the +5 encoding on bytes 6-14
for i in range(6, 15):
    flag[i] -= 5

# Reverse the -3 encoding on byte 15
flag[15] += 3

print('Flag:', flag.decode())
"
```

**Output:**
```
Flag: picoCTF{f0und_1t_303d6aeb}
```

---

## 5. Lessons Learned & Mitigation

### 5.1 — Key Takeaways for CTF Players

#### 🔑 Lesson 1: Understand PNG File Structure
Every PNG file must end with an `IEND` chunk followed by a 4-byte CRC. **Anything after that is anomalous.** This is one of the most common steganography techniques — appending hidden data after a valid file's terminator.

> **Practice this:** Run `xxd` on any PNG you find in a CTF. Always check the last 50 bytes. If you see data after `IEND` (hex: `49 45 4e 44 ae 42 60 82`), investigate immediately.

#### 🔑 Lesson 2: "Not Stripped" is a Gift
When a binary is not stripped, function names are preserved in the symbol table. Always run `file` first — if you see "not stripped," your disassembly will be significantly more readable and you can use `grep` to jump directly to named functions like `main`.

#### 🔑 Lesson 3: Cross-Reference Multiple Artifacts
This challenge required **both** files. The image alone shows corrupted data. The binary alone crashes without `flag.txt`. Only by understanding **how the binary transforms data** could we reverse the encoding in the image. In real-world forensics, artifacts always tell more of the story together than separately.

#### 🔑 Lesson 4: Simple Transforms Are Everywhere
Adding or subtracting small constants from byte values is one of the simplest encoding schemes. It's not encryption — it's **obfuscation**. Whenever you see garbled text that's "almost" recognizable (like `picoCTK` instead of `picoCTF`), look for byte-level arithmetic transformations.

---

### 5.2 — Blue Team: Detection & Mitigation

#### Mitigation 1: Never Append Sensitive Data to Public Files
The fundamental flaw here is that the binary appends secret data (the flag) to a file that is publicly distributed (`mystery.png`). In a real application, this mirrors the mistake of logging sensitive data (passwords, tokens) to files that are accessible to unauthorized parties.

**Fix:** Sensitive data should be written only to access-controlled destinations. Never commingle secret data with public assets.

#### Mitigation 2: File Integrity Monitoring
A blue team could detect this type of tampering using **file integrity monitoring (FIM)** tools like `Tripwire` or `AIDE`. These tools hash files at a known-good baseline and alert on any changes — including data appended after a file's logical end.

**Detection Rule Example:**
```bash
# Alert if mystery.png size changes after initial deployment
sha256sum mystery.png > mystery.png.sha256
# Later verification:
sha256sum -c mystery.png.sha256  # FAIL = tampering detected
```

#### Mitigation 3: PNG Validation
Implement server-side PNG validation that checks for data after the `IEND` marker before serving image files. Any valid PNG parser should treat post-IEND data as an error.

---

### 5.3 — Full Attack Chain Visualization

```
mystery.png (forensics)          mystery (reverse engineering)
      │                                    │
      ▼                                    ▼
strings → data after IEND      objdump → fopen("flag.txt","r")
      │                                    │
      ▼                                    ▼
xxd → 26 raw bytes              .rodata → filenames confirmed
      │                                    │
      ▼                                    ▼
      └──────────────┬─────────────────────┘
                     ▼
         Byte transformation map:
         [0-5]=unchanged, [6-14]+=5, [15]-=3, [16-25]=unchanged
                     │
                     ▼
         Python reverse transform
                     │
                     ▼
         picoCTF{f0und_1t_303d6aeb} 🎉
```

---

*Writeup authored using a systematic, single-step iterative methodology. Every command was chosen based on evidence, and every output was fully analyzed before proceeding.*
