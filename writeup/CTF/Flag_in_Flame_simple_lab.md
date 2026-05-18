# 🔥 CTF Lab Writeup: Flag in Flame
### Platform: picoCTF | Category: Digital Forensics | Difficulty: Beginner–Intermediate

---

## 1. Executive Summary

**Lab Name:** Flag in Flame
**Category:** Digital Forensics / Steganography
**Difficulty:** Beginner–Intermediate
**Primary Techniques Used:**
- Base64 Decoding
- File Signature Analysis (Magic Bytes)
- Binary Forensics & Data Carving
- Hexadecimal Decoding

**The Core Story:**
A SOC team discovered a suspicious log file after a breach. Instead of normal log entries, it contained what appeared to be an enormous, unreadable block of text. Our job was to peel back the layers of obfuscation — like an onion — to reveal the hidden flag buried inside.

**Flag:** `picoCTF{forensics_analysis_is_amazing_c75dd08e}`

> 💡 **Key Learning:** This challenge beautifully demonstrates how attackers (and challenge designers) use **multiple layers of encoding** to hide data in plain sight. A file can look like logs, behave like an image, and hide a flag as hex — all at once.

---

## 2. Reconnaissance & Enumeration

### 2.1 Understanding What We Have

Before touching any tool, the most important skill in forensics is **reading the challenge description carefully.** Let's break it down:

| Clue | What It Tells Us |
|------|-----------------|
| "Suspiciously large log file" | The file is larger than a normal log — data is hidden inside |
| "Enormous block of encoded text" | It's not random noise — it's *encoded*, meaning reversible |
| "Hint: Use Base64 to decode and generate an image file" | The encoding is Base64, and the output is an image |

> 🧠 **Concept — What is Base64?**
> Base64 is an encoding scheme (NOT encryption) that converts binary data (like images, executables) into a text-safe format using only 64 printable characters: `A-Z`, `a-z`, `0-9`, `+`, `/`, and `=` for padding. It's commonly used to transmit binary files over text-based systems like email or HTTP. **Because it's an encoding, not encryption, it is 100% reversible with no key needed.**

---

### 2.2 Downloading the File

```bash
wget https://challenge-files.picoctf.net/.../logs.txt
```

**Breaking down the command:**
| Component | Purpose |
|-----------|---------|
| `wget` | A non-interactive network downloader. Perfect for grabbing files from URLs in the terminal |
| `URL` | The direct link to the challenge file |

**Output Analysis:**
```
Length: 1592212 (1.5M) [application/octet-stream]
logs.txt saved [1592212/1592212]
```

> 🚩 **Red Flag #1:** Notice the MIME type is `application/octet-stream`. This means the server is serving it as **raw binary data**, NOT as a text log file. A real log file would typically be `text/plain`. This is our first hint that something unusual is inside.

> 🚩 **Red Flag #2:** 1.5MB is enormous for a log file with "text" content. Base64 encoding inflates file size by approximately **33%** — meaning the original hidden file was roughly **1.1MB**.

---

### 2.3 Inspecting the File Structure

```bash
grep -oP '^[A-Za-z0-9+/=]+$' logs.txt | head -c 50; echo
```

**Breaking down the command:**
| Component | Purpose |
|-----------|---------|
| `grep` | Searches for patterns in files |
| `-o` | Prints **only** the matching part (not the whole line) |
| `-P` | Enables **Perl-Compatible Regular Expressions (PCRE)** for advanced pattern matching |
| `'^[A-Za-z0-9+/=]+$'` | The regex pattern — matches lines containing **only** valid Base64 characters from start (`^`) to end (`$`) |
| `head -c 50` | Shows only the first 50 **characters** of output (not lines) to keep it manageable |
| `echo` | Adds a newline at the end for clean terminal output |

**Output:**
```
iVBORw0KGgoAAAANSUhEUgAAA4AAAASACAIAAAAh8bSOAAEAAE
```

> 🧠 **Concept — File Magic Bytes (Signatures):**
> Every file format has a unique "fingerprint" at the very start of its binary content called **magic bytes**. Even when Base64-encoded, this fingerprint is preserved because Base64 is deterministic. The string `iVBORw0KGgo` is the Base64 representation of the PNG magic bytes:
>
> | Base64 | Decoded Hex | ASCII Meaning |
> |--------|-------------|---------------|
> | `iVBORw0KGgo=` | `89 50 4E 47 0D 0A 1A 0A` | `‰PNG....` (PNG header) |
>
> This is how we **confirmed** the hidden file is a PNG image **before even decoding it.**

**🚫 What We Did NOT Do (and why):**
> You might be tempted to run `cat logs.txt` to read the file. Don't. On a 1.5MB file with a single massive line, this would flood your terminal with unusable output and potentially crash slow terminals. We used targeted commands instead.

---

## 3. Initial Foothold — Decoding & Extraction

### 3.1 Base64 Decoding

```bash
base64 -d logs.txt > decoded_flag.png
```

**Breaking down the command:**
| Component | Purpose |
|-----------|---------|
| `base64` | A standard Unix utility for encoding/decoding Base64 data |
| `-d` | Tells `base64` to **decode** (without this flag, it would encode instead) |
| `logs.txt` | The input file containing the Base64 string |
| `>` | Redirects output to a file instead of printing to screen |
| `decoded_flag.png` | The output filename. We name it `.png` because we already confirmed it's a PNG |

> 🧠 **Why redirect to a file?**
> The decoded output is **binary data** (an image). If you tried to print binary to a terminal, it would produce garbage characters and potentially corrupt your terminal session. Always redirect binary output to a file.

---

### 3.2 Validating the Decoded File

```bash
file decoded_flag.png && identify decoded_flag.png
```

**Breaking down the command:**
| Component | Purpose |
|-----------|---------|
| `file` | Reads the magic bytes of a file and reports its true type (ignores the filename extension) |
| `&&` | Only runs the second command if the first succeeds |
| `identify` | Part of the **ImageMagick** suite. Provides detailed image metadata |

**Output:**
```
decoded_flag.png: PNG image data, 896 x 1152, 8-bit/color RGB, non-interlaced
decoded_flag.png PNG 896x1152 896x1152+0+0 8-bit sRGB 1.13884MiB
```

> ✅ **Validation Check:** The `file` command confirms it's a real, valid PNG. ImageMagick reports:
> - **896 x 1152 pixels** — a tall, portrait-oriented image (like a document or QR code holder)
> - **8-bit RGB** — full-color image, no transparency
> - **1.13MiB** actual image data — consistent with our size estimate

---

### 3.3 Searching for Embedded Text

```bash
strings decoded_flag.png | grep -Ei "pico|flag|CTF"
```

**Breaking down the command:**
| Component | Purpose |
|-----------|---------|
| `strings` | Extracts sequences of printable characters from binary files (default: 4+ chars) |
| `\|` | Pipes the output of `strings` as input to `grep` |
| `grep -Ei` | `-E` enables extended regex, `-i` makes it case-insensitive |
| `"pico\|flag\|CTF"` | Search for any of these three patterns (the `\|` is the OR operator in regex) |

**Output:** `6ctf`

> 🔍 **Analysis:** We found `6ctf` — a fragment, not a complete flag. This tells us:
> 1. There IS flag-related data embedded in the binary structure
> 2. It's not stored as plain text — it's likely encoded (hex, binary, etc.)
> 3. We need deeper binary analysis

**🚫 What We Did NOT Do (and why):**
> At this point, a beginner might open the image in a viewer and look for a visible flag. That's valid! But we're building repeatable, scriptable skills. Additionally, the image might contain the flag in a format not immediately visible (like hex text on a complex background).

---

### 3.4 Deep Binary Analysis with Binwalk

```bash
binwalk --extract --force decoded_flag.png
```

**Breaking down the command:**
| Component | Purpose |
|-----------|---------|
| `binwalk` | A tool specifically designed to **scan binary files for embedded files and data** |
| `--extract` | Automatically extracts any files or data it finds embedded within |
| `--force` | Forces extraction even if binwalk is uncertain about the data type |

> 🧠 **Concept — How Binwalk Works:**
> Binwalk scans a binary file byte-by-byte, looking for known magic bytes and signatures. It can find ZIP files, executables, images, and raw data **hidden inside other files**. This is extremely common in CTF steganography challenges and real-world malware analysis.

**From the extracted data, you found this hex string:**
```
7069636F4354467B666F72656E736963735F616E616C797369735F69735F616D617A696E675F63373564643038657D
```

> 🔍 **Immediate Pattern Recognition:** Before decoding, let's spot the pattern manually. Hexadecimal pairs of `70 69 63 6F` can be looked up in an ASCII table:
>
> | Hex | ASCII |
> |-----|-------|
> | `70` | `p` |
> | `69` | `i` |
> | `63` | `c` |
> | `6F` | `o` |
>
> That spells `pico` — we're looking at the start of `picoCTF{...}` in hex!

---

### 3.5 Final Decoding — Hex to ASCII

```bash
echo "7069636F4354467B...7D" | xxd -r -p; echo
```

**Breaking down the command:**
| Component | Purpose |
|-----------|---------|
| `echo` | Outputs the hex string as text to pass it to the next command |
| `\|` | Pipes the hex string as input to `xxd` |
| `xxd` | A hex dump tool. Normally converts binary to hex, but can do the reverse |
| `-r` | **Reverse** mode — converts hex back to binary/ASCII |
| `-p` | **Plain** mode — interprets the input as a plain hex string (no formatting) |
| `; echo` | Adds a clean newline after the output |

**Output:**
```
picoCTF{forensics_analysis_is_amazing_c75dd08e}
```

---

## 4. The Exploitation Chain — Visualized

```
logs.txt (Base64 text)
        │
        ▼ base64 -d
decoded_flag.png (PNG image)
        │
        ├──▶ file / identify    → Confirms valid PNG (896x1152, RGB)
        ├──▶ strings + grep     → Finds fragment "6ctf" → hints at embedded data
        └──▶ binwalk --extract  → Carves out hidden hex string
                    │
                    ▼ xxd -r -p
        picoCTF{forensics_analysis_is_amazing_c75dd08e} 🎉
```

---

## 5. Lessons Learned & Mitigation

### 5.1 Key Takeaways for CTF Players

| Lesson | Application |
|--------|-------------|
| **Read magic bytes, not extensions** | A file named `.txt` can be a PNG. Always use `file` to confirm true type |
| **Base64 has a recognizable fingerprint** | `iVBORw0KGgo` always means PNG. Learn common Base64 signatures |
| **Encoding ≠ Encryption** | Base64, hex, ROT13 — these hide data but don't secure it. Never confuse them |
| **Layer your forensic tools** | `strings` → `binwalk` → `xxd` is a powerful forensics trinity |
| **Fragment clues matter** | `6ctf` wasn't the answer, but it confirmed we were on the right path |

---

### 5.2 Blue Team — Detection & Mitigation

**1. 🔵 Detecting Encoded Data in Log Files (SIEM Rule):**
> Real log files follow predictable patterns (timestamps, IP addresses, HTTP methods). A log file containing a massive Base64 blob is a massive anomaly. Blue teams should implement SIEM rules that flag log files with:
> - Lines exceeding a character threshold (e.g., >500 characters per line)
> - High entropy content (tools like `ent` or built-in SIEM entropy scoring)
> - Content matching Base64 regex patterns instead of log formats

**2. 🔵 Preventing Data Exfiltration via Encoding:**
> Attackers use Base64-encoded data in logs as a **covert exfiltration channel** — hiding stolen data in files that look legitimate. Mitigation strategies include:
> - **DLP (Data Loss Prevention)** tools that inspect outbound files for encoded content
> - **File integrity monitoring** on log directories to detect unexpected size increases
> - **Network traffic analysis** to flag Base64-heavy HTTP POST requests leaving the network

---

### 5.3 The Road Not Taken — Common Rabbit Holes

| Tempting Wrong Turn | Why We Skipped It |
|--------------------|-------------------|
| `cat logs.txt` | Too large — would flood terminal, no useful output |
| `steghide extract -sf decoded_flag.png` | Steghide requires a password; no password hint was given |
| Opening image in a viewer first | Valid, but not scriptable or reliable for all flag types |
| Assuming the flag was just visible text | `strings` showed only a fragment, suggesting deeper encoding |

---

> 🎓 **Final Encouragement:**
> If you solved this, you've just practiced a real-world skill set. Malware analysts regularly decode Base64 payloads, carve binaries with binwalk, and decode hex strings to understand what attackers hid in "innocent" files. You're thinking like a forensic analyst now. Keep that curiosity — it's your most powerful tool. 🔥

**Flag:** `picoCTF{forensics_analysis_is_amazing_c75dd08e}` ✅
