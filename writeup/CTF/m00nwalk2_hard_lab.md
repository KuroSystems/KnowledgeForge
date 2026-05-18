# CTF Writeup: m00nwalk2 — picoCTF

---

## Challenge Overview

| Field | Details |
|---|---|
| **Challenge** | m00nwalk2 |
| **Category** | Forensics / Steganography |
| **Files** | `message.wav`, `clue1.wav`, `clue2.wav`, `clue3.wav` |
| **Tools Used** | `wget`, `python3-sstv`, `tesseract`, `steghide` |

---

## Core Concepts

- **SSTV (Slow Scan Television):** A method of transmitting images over audio signals. Commonly used in CTF challenges disguised as "radio transmissions."
- **Steganography:** Hiding secret data inside ordinary files. Here, data is hidden inside a WAV audio file.
- **steghide:** A popular steganography tool that hides/extracts data inside media files using a password.

---

## Step-by-Step Solution

### Step 1 — Download All Files

```bash
wget [message.wav] [clue1.wav] [clue2.wav] [clue3.wav]
```

Downloaded four WAV files totaling ~34MB.

---

### Step 2 — Identify the Main File

```bash
file message.wav
```

**Output:**
```
RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 48000 Hz
```

Standard audio file. No obvious plaintext via `strings`. This signals **steganography** rather than simple encoding.

---

### Step 3 — Decode the Clue Files via SSTV

The clue files are **SSTV transmissions** — audio that encodes images. We decode them using the `sstv` Python library:

```bash
python3 -m sstv -d clue1.wav -o clue1.png
python3 -m sstv -d clue2.wav -o clue2.png
python3 -m sstv -d clue3.wav -o clue3.png
```

| File | SSTV Mode Detected |
|---|---|
| `clue1.wav` | Martin 1 |
| `clue2.wav` | Scottie 2 |
| `clue3.wav` | Martin 2 |

---

### Step 4 — Read the Decoded Images

Opened each decoded PNG and read the content visually:

| Image | Content | Meaning |
|---|---|---|
| `clue1.png` | `Password hidden_stegosaurus` | **The steghide password** |
| `clue2.png` | `The quieter you are the more you can HEAR` | Kali Linux motto — hints at audio steganography |
| `clue3.png` | `Alan Eliasen the FutureBoy` | Points to steganography tooling/methodology |

---

### Step 5 — Extract Hidden Data from message.wav

Armed with the password from Clue 1, we use `steghide` to extract the hidden payload:

```bash
steghide extract -sf message.wav -p hidden_stegosaurus
```

**Output:**
```
wrote extracted data to "steganopayload12154.txt"
```

---

### Step 6 — Read the Flag

```bash
cat steganopayload12154.txt
```

**Flag retrieved** ✅

---

## Attack Path Summary

```
clue1.wav  ─┐
clue2.wav  ─┼─► SSTV Decode ─► Images ─► Password: hidden_stegosaurus ─┐
clue3.wav  ─┘                                                            │
                                                                         ▼
                                          message.wav ──► steghide ──► FLAG
```

---

## Key Takeaways

| # | Lesson |
|---|---|
| 1 | **SSTV** encodes images into audio — always check audio files spectrally and with SSTV decoders |
| 2 | **Multiple files** in a CTF often work together — clues are rarely standalone |
| 3 | **steghide** is one of the most common steganography tools in CTF forensics challenges |
| 4 | When `strings` and metadata analysis yield nothing, pivot to **specialized steg tools** |
| 5 | Always check **all** provided files — the password here was in a completely separate audio file |

---

## Tools Reference

```bash
# Install SSTV decoder
pip install sstv

# Install steghide
sudo apt install steghide

# Decode SSTV audio to image
python3 -m sstv -d input.wav -o output.png

# Extract steghide payload
steghide extract -sf file.wav -p PASSWORD
```

---

> **Core Vulnerability/Concept:** Layered steganography — SSTV-encoded clue images reveal the password needed to extract a steghide payload from the primary audio transmission.
