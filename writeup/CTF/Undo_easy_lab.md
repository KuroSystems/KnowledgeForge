# CTF Lab Writeup: **Undo**
### Platform: PicoCTF | Category: General Skills | Difficulty: Beginner-Intermediate

---

## 1. Executive Summary

**Challenge:** Undo
**Target:** `nc foggy-cliff.picoctf.net 57385`
**Flag:** `picoCTF{Revers1ng_t3xt_Tr4nsf0rm@t10ns_fa04039f}`

This challenge presents a **multi-layer text transformation puzzle** delivered through an interactive netcat session. The server applied five sequential transformations to a plaintext flag and challenged the player to reverse each one using correct Linux commands.

The core skills tested are:
- Knowledge of Linux text manipulation utilities (`base64`, `rev`, `tr`)
- Understanding of classical ciphers (ROT13)
- Logical layered thinking — reversing a pipeline in the correct order

> 💡 **Key Insight:** This challenge is not about exploitation in the traditional sense. It is about **understanding how data encoding and transformation works at the command-line level** — a foundational skill every security professional must master.

---

## 2. Reconnaissance & Enumeration

### 2.1 Reading the Challenge

Before touching a terminal, always read the challenge description carefully. Let's break it down:

| Element | Value | What It Tells Us |
|--------|-------|-----------------|
| Description | "Reverse a series of Linux text transformations" | Multiple sequential operations were applied |
| Service | `nc foggy-cliff.picoctf.net 57385` | Interactive netcat session (no file to download) |
| Hint | "See `tr` command documentation" | At least one step involves character translation |

> 🧠 **Beginner Tip:** The hint explicitly points to `tr`. This is a strong signal. In CTFs, hints are breadcrumbs — never ignore them. Even if you don't need them, they help confirm you're on the right path.

### 2.2 Initial Connection — What Are We Dealing With?

**Command:**
```bash
nc foggy-cliff.picoctf.net 57385
```

**Breaking Down the Tool:**
- `nc` = **netcat**, often called the "Swiss Army knife" of networking.
- It establishes a raw TCP connection to the target host and port.
- Unlike a browser or SSH client, it sends and receives raw text — perfect for interactive challenges.
- **Why not `curl` or a browser?** This is a raw TCP socket service, not an HTTP server. `curl` speaks HTTP. `nc` speaks raw TCP. Wrong tool for the wrong protocol means no connection.

**Output received:**
```
===Welcome to the Text Transformations Challenge!===

Your goal: step by step, recover the original flag.
At each step, you'll see the transformed flag and a hint.
Enter the correct Linux command to reverse the last transformation.

--- Step 1 ---
Current flag: KXM5MzA0MG5zLWZhMDFnQHplMHNmYTRlRy1nazNnLXRhMWZlcmlyRShTR1BicHZj
Hint: Base64 encoded the string.
```

**Analysis:**
The server is an interactive tutor. It tells us:
1. The **current (transformed) state** of the flag
2. The **last transformation** that was applied
3. It expects us to type a Linux command to **reverse that specific transformation**

The string `KXM5MzA0MG5z...` is clearly Base64 — the character set (A-Z, a-z, 0-9, +, /) and the length are telltale signs.

---

## 3. Solving Each Transformation Layer

> 🧅 Think of this like peeling an onion. Each layer removed reveals the next. The transformations were applied in order 1→5, so we reverse them in order 5→1.

---

### Step 1 — Reversing Base64 Encoding

#### The Concept: What is Base64?

Base64 is an **encoding scheme** (not encryption) that converts binary data into a set of 64 printable ASCII characters. It is commonly used to safely transmit binary data over text-based protocols (email, URLs, JSON).

The Base64 alphabet is:
```
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
```

> ⚠️ **Critical Distinction for Beginners:** Base64 is **NOT encryption**. It provides zero security. Anyone can decode it instantly. Its purpose is data representation, not data protection.

#### The Command:
```bash
base64 -d
```

**Breaking It Down:**
| Part | Meaning |
|------|---------|
| `base64` | The Base64 utility available on all Linux/macOS systems |
| `-d` | Short for `--decode`. Without this flag, `base64` **encodes** by default |

**Why not alternatives?**
- You could use `openssl base64 -d` — this works but is longer and less idiomatic for simple decoding.
- You could use Python: `python3 -c "import base64; print(base64.b64decode('...'))"` — valid, but the server expects a clean Linux command, not a script.
- `base64 -d` is the **simplest, most direct, most universal** answer.

**Result:**
```
)s93040ns-fa01g@ze0sfa4eG-gk3g-ta1ferirE(SGPbpvc
```

---

### Step 2 — Reversing Text Reversal

#### The Concept: String Reversal

The hint says "Reversed the text." This means every character in the string was mirrored — the last character becomes the first, and so on.

```
Original:  picoCTF{...}
Reversed:  }...{FTCocip
```

To undo a reversal, you simply **reverse it again**. It is a self-inverse operation (like ROT13).

#### The Command:
```bash
rev
```

**Breaking It Down:**
| Part | Meaning |
|------|---------|
| `rev` | A simple Linux utility that reverses the order of characters on each line of input |

**Why not alternatives?**
- You could use `awk '{for(i=NF;i>0;i--) printf $i" "; print ""}` but that reverses **words**, not characters.
- You could use Python: `print(s[::-1])` — works, but `rev` is cleaner.
- `rev` is atomic, purpose-built, and readable. Always prefer the right tool.

**The Road Not Taken:** A common beginner mistake here is to try `sort -r` (which sorts lines in reverse) or `tac` (which reverses line order in a file). Neither reverses characters within a single line. Read hints carefully — "reversed the text" means character order.

**Result:**
```
cvpbPGS(Eriref1at_g3kg_Ge4afs0ez@g10af_sn04039s)
```

> 👀 **Pattern Recognition Alert:** Does `cvpbPGS` look familiar? It should. Keep this in mind — we'll return to it at Step 5.

---

### Step 3 — Reversing Underscore → Dash Substitution

#### The Concept: Character Translation with `tr`

The hint states: "Replaced underscores with dashes." This means every `_` in the original became a `-`. To reverse this, we replace every `-` back to `_`.

> 🔑 **Key Learning:** The `tr` command performs **character-by-character translation**. It maps each character in the first set to the corresponding character in the second set. It does NOT do string replacement — that's `sed`. It translates **individual characters**.

#### The Command:
```bash
tr '-' '_'
```

**Breaking It Down:**
| Part | Meaning |
|------|---------|
| `tr` | Translate or delete characters |
| `'-'` | The **source** character set — every dash found in input |
| `'_'` | The **destination** character set — replace each dash with an underscore |

**Why not `sed`?**
`sed 's/-/_/g'` would also work here, but:
- `sed` uses **regular expressions** and string patterns
- `tr` is faster and more appropriate for single-character substitution
- The hint explicitly says "see `tr` documentation" — use what the challenge points you to

**Why single quotes?**
The `-` character has special meaning in some shells and regex engines. Wrapping in single quotes `'` prevents the shell from misinterpreting it.

**Result:**
```
cvpbPGS(Eriref1at_g3kg_Ge4afs0ez@g10af_sn04039s)
```
*(dashes replaced with underscores)*

---

### Step 4 — Reversing Curly Brace → Parenthesis Substitution

#### The Concept: Multi-Character Translation

The hint states: "Replaced curly braces with parentheses." So `{` became `(` and `}` became `)`. We need to reverse both simultaneously.

#### The Command:
```bash
tr '()' '{}'
```

**Breaking It Down:**
| Part | Meaning |
|------|---------|
| `tr` | Translate characters |
| `'()'` | Source set: `(` maps to first char in dest, `)` maps to second |
| `'{}'` | Destination set: `(` → `{` and `)` → `}` |

**How `tr` handles multiple characters:**
`tr` maps position-by-position:
```
Position 1: ( → {
Position 2: ) → }
```

This is why `tr` is ideal here — it handles multiple character mappings in a single, clean command.

**Why this step matters:**
The `{` and `}` characters are the flag format delimiters for `picoCTF{...}`. Restoring them is a strong signal we are close to the final flag format.

**Result:**
```
cvpbPGS{Eriref1at_g3kg_Ge4afs0ez@g10af_sn04039s}
```

> 🎯 **Validation Checkpoint:** The string now has `{...}` format. This looks like a flag! The content is still scrambled, but the structure is correct. We're on the right path.

---

### Step 5 — Reversing ROT13

#### The Concept: What is ROT13?

ROT13 (**Rotate by 13**) is a simple Caesar cipher that shifts each letter of the alphabet by 13 positions.

```
A → N    N → A
B → O    O → B
...
M → Z    Z → M
```

Because the English alphabet has **26 letters**, shifting by 13 twice brings you back to the start:
```
A → (shift 13) → N → (shift 13) → A
```

**ROT13 is its own inverse.** Applying it twice returns the original text. This is why it is sometimes called a "trivial" cipher.

> 🔍 **Confirming ROT13 was used:** Remember `cvpbPGS` from Step 2? Let's verify:
> ```
> c → p
> v → i
> p → c
> b → o
> P → C
> G → T
> S → F
> ```
> `cvpbPGS` → `picoCTF` ✅ This confirmed ROT13 **two steps ago**, giving us high confidence in our approach.

#### The Command:
```bash
tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

**Breaking It Down:**
| Part | Meaning |
|------|---------|
| `tr` | Translate characters |
| `'A-Za-z'` | Source: all uppercase (A-Z) and all lowercase (a-z) letters |
| `'N-ZA-Mn-za-m'` | Destination: shifted by 13 positions for both cases |

**Decoding the destination set:**
```
N-Z  = letters N through Z (13 letters)
A-M  = letters A through M (13 letters)
Combined: N-ZA-M = the full alphabet starting at N, wrapping around
```
This creates the mapping:
```
A→N, B→O, C→P, ..., M→Z, N→A, O→B, ..., Z→M
```

**Why not use `caesar` or `rot13` command?**
- `rot13` is not universally available on all Linux systems
- `tr` is **POSIX standard** — available everywhere
- Understanding the `tr` implementation teaches you the underlying mechanics

**The Road Not Taken:**
- You might try `echo "string" | python3 -c "import codecs,sys; print(codecs.decode(sys.stdin.read(),'rot13'))"` — this works but is unnecessarily complex.
- You might try a Caesar cipher tool or online decoder — valid for manual solving but not useful in a terminal-driven CTF session.

**Result:**
```
picoCTF{Revers1ng_t3xt_Tr4nsf0rm@t10ns_fa04039f}
```

🚩 **FLAG CAPTURED!**

---

## 4. The Full Transformation Pipeline Visualized

Understanding the **full chain** is as important as solving each step:

```
ORIGINAL FLAG
picoCTF{Revers1ng_t3xt_Tr4nsf0rm@t10ns_fa04039f}
        │
        ▼  [1] ROT13 applied
cvpbPGS{Eriref1at_g3kg_Ge4afs0ez@g10af_sn04039s}
        │
        ▼  [2] { } replaced with ( )
cvpbPGS(Eriref1at_g3kg_Ge4afs0ez@g10af_sn04039s)
        │
        ▼  [3] _ replaced with -
cvpbPGS(Eriref1at-g3kg-Ge4afs0ez@g10af-sn04039s)
        │
        ▼  [4] String reversed
cvpbPGS(Eriref1at-g3kg-Ge4afs0ez@g10af-sn04039s) → )s93040ns-fa01g@ze0sfa4eG-gk3g-ta1ferirE(SGPbpvc
        │
        ▼  [5] Base64 encoded
KXM5MzA0MG5zLWZhMDFnQHplMHNmYTRlRy1nazNnLXRhMWZlcmlyRShTR1BicHZj

        ⬆ THIS IS WHAT THE SERVER GAVE US
```

We reversed this pipeline from bottom to top:
```
Base64 -d → rev → tr '-' '_' → tr '()' '{}' → tr ROT13
```

---

## 5. Lessons Learned & Mitigation

### 5.1 Key Takeaways for CTF Players

| Lesson | Detail |
|--------|--------|
| **Read hints seriously** | The `tr` hint eliminated guesswork about tool selection |
| **Recognize encoding patterns** | Base64 character sets and string length are visually identifiable |
| **Use pattern recognition** | Spotting `cvpbPGS` as ROT13 for `picoCTF` validated the entire approach early |
| **Understand tool purpose** | `tr` for character translation, `rev` for reversal, `base64` for encoding — right tool, right job |
| **Reverse pipelines LIFO** | The last transformation applied must be the first one reversed |

### 5.2 Real-World Security Relevance

> ⚠️ **Why does this matter beyond CTFs?**

**1. Obfuscated Malware:**
Malware authors frequently layer Base64, ROT13, and string reversal to evade signature-based detection. Malware analysts must recognize and strip these layers quickly using the exact same tools used in this challenge.

**Example real-world scenario:**
```bash
# Malware payload hidden in a script:
echo "cvpbPGS..." | base64 -d | rev | tr '()' '{}'
```
A security analyst needs to recognize this chain and unravel it — exactly what we just practiced.

**2. Blue Team Detection Recommendations:**
- **Monitor for chained piped commands** involving `base64 -d`, `tr`, and `rev` in shell history or SIEM logs — this pattern is rare in legitimate workflows and common in obfuscation.
- **Implement Content Inspection:** Decode and inspect Base64-encoded payloads at email gateways, web proxies, and endpoint agents before they reach execution.
- **User and Entity Behavior Analytics (UEBA):** Flag unusual command sequences in shell logs using tools like Splunk or Elastic SIEM.

### 5.3 Commands Reference Card

```bash
# Decode Base64
base64 -d

# Reverse a string
rev

# Replace character X with Y
tr 'X' 'Y'

# Replace multiple characters simultaneously
tr 'AB' 'XY'   # A→X and B→Y

# Apply ROT13
tr 'A-Za-z' 'N-ZA-Mn-za-m'

# Full pipeline to re-solve this challenge from scratch:
echo "KXM5MzA0MG5zLWZhMDFnQHplMHNmYTRlRy1nazNnLXRhMWZlcmlyRShTR1BicHZj" \
  | base64 -d \
  | rev \
  | tr '-' '_' \
  | tr '()' '{}' \
  | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

---

*Writeup authored using a systematic, step-by-step CTF methodology. Every command explained, every decision justified.*

**Flag:** `picoCTF{Revers1ng_t3xt_Tr4nsf0rm@t10ns_fa04039f}` ✅
