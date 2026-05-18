# CTF Lab Writeup: PowerAnalysis Part 2 (picoCTF)
### *A Beginner-Friendly Deep Dive into Correlation Power Analysis (CPA) on AES*

---

## 1. Executive Summary

| Field | Details |
|---|---|
| **Challenge Name** | PowerAnalysis: Part 2 |
| **Platform** | picoCTF |
| **Category** | Cryptography / Side-Channel Analysis |
| **Difficulty** | Hard |
| **Primary Technique** | Correlation Power Analysis (CPA) |
| **Tools Used** | Python 3, NumPy |
| **Flag** | `picoCTF{b7698f76b7e524ee7cd80dbde0cdff59}` |

### What Was This Challenge About?

This challenge placed us in the role of a hardware security researcher attacking a physical embedded system. The system was running **AES-128 encryption** — one of the most mathematically unbreakable symmetric encryption algorithms in existence. You could encrypt a trillion plaintexts with a trillion computers and never brute-force the key through mathematics alone.

But here's the critical insight that makes this challenge fascinating: **we didn't attack the math. We attacked the physics.**

The device leaked information about its secret key through its *power consumption* while it computed. By carefully measuring how much electricity the CPU drew at precise moments and applying statistics, we recovered all 16 bytes of the secret key. This is called a **Side-Channel Attack**, and it is one of the most powerful and practically relevant attack classes in modern cryptography.

---

## 2. Reconnaissance & Enumeration

### 2.1 Understanding What We Were Given

Before writing a single line of code, we needed to understand the shape of our data. This is the reconnaissance phase of a side-channel attack — analogous to running `nmap` before exploiting a web server.

We started by downloading and extracting the archive:

```bash
wget https://artifacts.picoctf.net/c/319/traces.zip && unzip traces.zip && ls -R
```

**Breaking down this command:**
- `wget <url>` — Downloads the file from the remote server. We used `wget` over `curl` here because `wget` automatically saves to disk by default, which is cleaner for binary files like `.zip` archives.
- `unzip traces.zip` — Extracts the archive. No special flags needed since there is no password and we want the default behavior (extract to current directory).
- `ls -R` — Lists files **recursively** (`-R`), so we can see the contents of the newly extracted `traces/` subdirectory in one command.

**What we found:**
```
./traces:
trace00.txt  trace01.txt  ...  trace99.txt
```

100 text files. That's our dataset. Now we needed to know what was *inside* them.

---

### 2.2 Inspecting the Trace Format

```bash
head -5 traces/trace00.txt && echo "---" && wc -l traces/trace00.txt && echo "---" && awk 'NR==1{print NF, "fields on line 1"}' traces/trace00.txt
```

**Breaking down this command:**
- `head -5` — Shows the first 5 lines. We used 5 rather than the full file because power trace files can be enormous. We only need to see the structure, not all the data.
- `&&` — Chains commands, executing the next only if the previous succeeded. This is safer than using `;` which runs regardless of success.
- `echo "---"` — A visual separator. Small habit, big readability improvement.
- `wc -l` — Counts the number of **lines** in the file (`-l`). This tells us if data is stored row-by-row or as one large blob.
- `awk 'NR==1{print NF}'` — `NR==1` means "on the first record (line)", `NF` prints the **number of fields** (space-delimited columns). This told us if the first line had multiple values or just one.

**What we learned:**
```
Plaintext: bdb5cd7a1014d46ed2fa6bc60f166df9
Power trace: [51, 66, 81, 84, 91, ...]
---
2 lines total
---
2 fields on line 1
```

Each file has **exactly 2 lines:**
1. **Line 1:** `Plaintext: <32 hex characters>` — the 16-byte input to the AES encryption
2. **Line 2:** `Power trace: [int, int, int, ...]` — the power consumption over time, measured in arbitrary units

> 💡 **Why does this structure matter?** In CPA, we need two things for every encryption: the *known* plaintext (so we can make hypotheses about the internal key operations) and the *measured* power trace (the physical side-channel evidence). This file gives us both, paired together.

---

### 2.3 Verifying Data Integrity and Alignment

```bash
python3 -c "
import re, glob
lengths = []
for fn in sorted(glob.glob('traces/trace*.txt')):
    with open(fn) as f:
        lines = f.readlines()
    trace = list(map(int, re.findall(r'\d+', lines[1])))
    lengths.append(len(trace))
print('Trace files:', len(lengths))
print('Min length:', min(lengths))
print('Max length:', max(lengths))
"
```

**Why this step was critical:**

CPA works by computing **column-wise statistics** across all traces. This means trace sample #437 from `trace00.txt` is compared against sample #437 from all other traces. If traces had different lengths, our matrix math would fail. 

**Result:** All 100 traces had exactly **2666 samples**. Perfect alignment confirmed. We could proceed directly to the attack without any preprocessing.

> ⚠️ **Common Rabbit Hole:** Beginners sometimes jump straight into writing attack code without verifying data integrity. If even one trace had a different length or was corrupted, the entire NumPy matrix operation would either crash or — worse — produce silently wrong results.

---

## 3. The Exploit: Correlation Power Analysis

### 3.1 The Conceptual Foundation — *Why Does Hardware Leak Secrets?*

Before we write a single line of attack code, we must understand *why this attack is even possible.* This is the most important conceptual leap in the entire writeup.

**The Physics of CMOS Transistors:**

Modern CPUs are built from billions of CMOS (Complementary Metal-Oxide-Semiconductor) transistors. These transistors switch between logical `0` and `1` states. A critical property of this technology: **transistors consume significantly more power when their output transitions from 0→1 or 1→0** than when they hold a stable state.

This means the instantaneous power draw of a CPU is **correlated with how many bits are changing** in the data it is processing at that moment. Specifically, the power consumption correlates with the **Hamming Weight** — the number of `1` bits — of the intermediate values being computed.

```
Data value 0x00 = 00000000 → HW = 0 → Low power draw
Data value 0xFF = 11111111 → HW = 8 → High power draw
Data value 0x0F = 00001111 → HW = 4 → Medium power draw
```

**The AES S-Box Connection:**

AES encryption begins its first round with a step called **SubBytes**, where each byte of the plaintext XORed with the key is passed through a fixed lookup table called the **S-Box**:

```
S-Box output = SBOX[ Plaintext_byte XOR Key_byte ]
```

The CPU computes this S-Box lookup for all 16 key bytes right at the start of encryption. If we can observe the power consumption *at the exact moment* the CPU processes each S-Box output, and if that power consumption correlates with the Hamming Weight of the S-Box output, then we can work backwards to find the key.

---

### 3.2 The CPA Attack Strategy

Here's the attack logic for **one key byte** (we repeat it 16 times):

```
For each possible key byte guess k (0x00 to 0xFF = 256 guesses):
  For each of our 100 traces:
    Compute: hypothesis = HW( SBOX[ plaintext_byte XOR k ] )
  
  Now we have a vector of 100 hypothetical power values.
  Correlate this vector against our 100 actual power measurements
  at each of the 2666 time samples.
  
  The correct k will produce a HIGH correlation at the exact time
  sample when the CPU was computing that S-Box output.
  Wrong guesses of k will produce near-zero (random) correlation.
```

This is elegant because:
- We never need to know *when* exactly the S-Box is computed — the correlation peak **tells us**
- We test all 256 possibilities and let statistics pick the winner
- Each key byte is recovered **independently**, so the 128-bit key space (2^128, astronomically large) reduces to **16 × 256 = 4096 guesses** — trivially small

---

### 3.3 The Attack Code — Full Breakdown

```python
import re, glob, numpy as np
```

- `re` — Regular expressions, used for parsing the power trace values out of the bracketed list format
- `glob` — File pattern matching, lets us load all `trace*.txt` files elegantly
- `numpy` — Numerical Python. **This is the key tool.** NumPy lets us operate on entire arrays simultaneously, turning what would be a slow nested Python loop into fast vectorized math.

> 💡 **Why NumPy over plain Python loops?** A naive Python implementation iterating through all 256 key guesses × 100 traces × 2666 samples would require ~68 million iterations. NumPy's vectorized operations perform this at near-C speed. The difference is seconds vs. potentially hours.

---

**The AES S-Box:**

```python
SBOX = [0x63, 0x7c, 0x77, ...]  # 256 values
```

This is the standard AES SubBytes lookup table — publicly known and fixed by the AES standard. There's no need to compute it; we hardcode it. The attacker's advantage is that this table is known, so we can predict what value *should* come out for any given `(plaintext, key_guess)` pair.

---

**The Hamming Weight Function:**

```python
def hw(v):
    return bin(v).count('1')
```

- `bin(v)` — Converts an integer to its binary string representation (e.g., `bin(7)` → `'0b111'`)
- `.count('1')` — Counts the number of `1` bits

This is our **power model** — the mathematical bridge between the data being processed and the expected power consumption.

---

**Loading the Data:**

```python
traces = np.array(traces, dtype=np.float64)  # shape: (100, 2666)
```

We load all traces into a **2D NumPy array** with shape `(100, 2666)`. Think of this as a spreadsheet where:
- Each **row** is one encryption measurement (100 rows = 100 encryptions)
- Each **column** is one time sample (2666 columns = 2666 moments in time)

Using `float64` (64-bit floating point) is important because Pearson correlation involves division and subtraction that can lose precision with integer types.

---

**The Core CPA Loop:**

```python
for byte_idx in range(16):          # For each of the 16 key bytes
    for k in range(256):            # For each of 256 possible key values
        hyp = np.array([hw(SBOX[plaintexts[t][byte_idx] ^ k]) 
                        for t in range(N_traces)])
```

- `byte_idx` — Which position in the 16-byte key we are currently attacking (0 through 15)
- `k` — Our key byte guess (0 through 255)
- `plaintexts[t][byte_idx]` — The `byte_idx`-th byte of the plaintext used in trace `t`
- `^ k` — XOR with our guess (this is what AES does internally before the S-Box)
- `SBOX[...]` — Look up the S-Box output (the intermediate value the CPU processed)
- `hw(...)` — Our power model: convert to Hamming Weight

This produces `hyp`, a vector of 100 values — one predicted power value per trace.

---

**Pearson Correlation:**

```python
cov = ((traces - trace_mean) * (hyp - hyp_mean)[:, None]).mean(axis=0)
corr = np.abs(cov / (hyp_std * trace_std + 1e-12))
```

The **Pearson correlation coefficient** measures how linearly related two variables are:
- Output of `+1.0` → Perfect positive correlation
- Output of `0.0` → No correlation (random)
- Output of `-1.0` → Perfect negative correlation

We take the **absolute value** because the leakage could be positively or negatively correlated depending on the hardware implementation.

Breaking down the vectorized math:
- `traces - trace_mean` — Centers each column of the trace matrix (subtracts column mean). Shape: `(100, 2666)`
- `hyp - hyp_mean` — Centers our hypothesis vector. Shape: `(100,)`
- `[:, None]` — Reshapes it to `(100, 1)` so NumPy can **broadcast** it across all 2666 columns simultaneously. This is the key efficiency trick.
- `.mean(axis=0)` — Averages across rows (the 100 traces), giving us one covariance value per time sample. Shape: `(2666,)`
- `/ (hyp_std * trace_std)` — Normalizes to get the correlation coefficient. The `+ 1e-12` prevents division by zero.

The result `corr` is a vector of 2666 correlation values — one per time sample. We take `corr.max()` to find the single highest correlation point across all time samples.

---

**Winner Selection:**

```python
if max_corr > best_corr:
    best_corr = max_corr
    best_k = k
```

The key guess `k` that produced the highest peak correlation across all 2666 time samples is declared the winner for that byte position.

---

### 3.4 Results

```
Byte 00: 0xb7  (max_corr=0.6176)
Byte 01: 0x69  (max_corr=0.5610)
Byte 02: 0x8f  (max_corr=0.6953)
...
Byte 15: 0x59  (max_corr=0.6319)

Recovered key: b7698f76b7e524ee7cd80dbde0cdff59
Flag: picoCTF{b7698f76b7e524ee7cd80dbde0cdff59}
```

All 16 bytes showed correlation values between **0.51 and 0.70**. In side-channel analysis, any correlation above approximately **0.3** is considered statistically significant with 100 traces. Values in the 0.5-0.7 range indicate clean, reliable leakage — the attack worked decisively.

---

### 3.5 The Roads Not Taken — What We Deliberately Avoided

> This section is crucial. Understanding *what not to do* is as important as understanding the solution.

**❌ Brute-Force the AES Key:**

AES-128 has a key space of 2^128 ≈ 3.4 × 10^38 possible keys. Even if you could test one billion keys per second, it would take longer than the age of the universe. **This is why AES is used worldwide.** The math is unbreakable. This path was never viable.

**❌ Simple Power Analysis (SPA):**

SPA looks at a *single* trace and tries to read the key directly from the power waveform by identifying visually distinct operations. This works against some naive RSA implementations where you can see the difference between squaring and multiply operations. Against AES with its repeated, uniform structure and measurement noise, SPA is not effective with limited traces. CPA's statistical approach is far more robust.

**❌ Template Attacks:**

Template attacks are more powerful than CPA but require a *profiling phase* where the attacker has a clone device they fully control. Since we only had a target device with limited measurements and no profiling capability, template attacks were not applicable here.

**❌ Attacking Later AES Rounds:**

We targeted the **first round S-Box** because this is the point where the relationship between our known plaintext and the secret key is simplest: `SBOX[plaintext XOR key]`. Attacking later rounds requires knowing partial results from previous rounds, which complicates the hypothesis model significantly. Always start with the first or last round.

**❌ Using All 2666 Time Samples for Selection:**

One might consider averaging across all time samples rather than taking the peak. This would actually dilute the signal — only a small window of samples contains the leakage from the S-Box operation. The peak correlation naturally finds that window.

---

## 4. "Privilege Escalation" — Scaling the Attack

In traditional CTF writeups, this section covers moving from user to root. In a side-channel context, our equivalent challenge was: *"What if 100 traces weren't enough? How would we handle more noise?"*

The challenge hint warned: *"You will need to figure out how to deal with the noise."*

### Noise Mitigation Strategies (Ordered by Complexity)

| Strategy | How It Works | When to Use |
|---|---|---|
| **More Traces** | More data → better statistical signal | Always the first resort |
| **Averaging** | Average multiple encryptions of the same plaintext | When you control the device |
| **Bandpass Filtering** | Remove high/low frequency noise with FFT | When noise has known frequency characteristics |
| **Principal Component Analysis (PCA)** | Dimensionality reduction to isolate leakage points | When traces are very noisy or misaligned |
| **Trace Alignment** | Cross-correlate traces to fix timing jitter | When device has random delays as countermeasure |

In our case, **100 traces with Pearson CPA was sufficient** because:
1. The leakage model (Hamming Weight of S-Box output) matched the actual hardware leakage well
2. The traces were perfectly aligned (no jitter)
3. The noise level, while present, was not extreme (correlation peaks still reached 0.5+)

---

## 5. Lessons Learned & Mitigation

### 5.1 Key Takeaways for Attackers (Blue Team Awareness)

| Lesson | Explanation |
|---|---|
| **Math ≠ Security** | AES is mathematically unbreakable, but its *physical implementation* is not. Security requires both algorithmic and implementation soundness. |
| **Statistics is a weapon** | Pearson correlation across 100 measurements extracted a 128-bit secret. Statistics can defeat randomness when patterns are present. |
| **Known intermediate values are dangerous** | CPA only works because we knew the plaintext. Preventing the attacker from knowing inputs or outputs closes this vector. |
| **The leakage model is the key insight** | Choosing `HW(SBOX[pt XOR k])` as our model was the critical hypothesis. A wrong model would yield zero correlation even with infinite traces. |

---

### 5.2 Defensive Mitigations

**🛡️ Defense 1: Masking (Software Countermeasure)**

The most widely deployed defense against CPA is **masking**. Instead of computing `SBOX[plaintext XOR key]` directly, the device computes:

```
masked_input  = plaintext XOR key XOR random_mask
masked_output = SBOX[masked_input] XOR f(random_mask)
```

The random mask changes every encryption. Now the attacker's hypothesis `HW(SBOX[pt XOR k])` no longer matches the actual intermediate value — the mask randomizes it. CPA correlation drops to zero because the leakage is now uniformly random from the attacker's perspective.

**Detection for Blue Teams:** Monitor firmware update mechanisms on embedded devices. Removing or patching masking countermeasures is a common attack vector against hardware security modules (HSMs).

---

**🛡️ Defense 2: Hiding (Hardware Countermeasure)**

Hiding makes it harder to *measure* the leakage rather than eliminating the leakage itself:

- **Noise injection circuits** — Add random electronic noise to the power supply rails
- **Clock jitter** — Randomize the CPU clock slightly so S-Box operations don't always occur at the same time sample, breaking trace alignment
- **Dual-rail logic** — Use circuit designs where every operation always switches the same number of transistors regardless of data value (zero Hamming Weight correlation by design)

**Blue Team Note:** Physical security of embedded devices matters. An attacker needs physical access to the power rails to measure traces. Tamper-evident enclosures, potting (encasing in epoxy), and active tamper-response circuits (that zero memory on detection) are practical hardware countermeasures deployed in payment terminals, smart cards, and HSMs.

---

### 5.3 Real-World Relevance

This attack is not theoretical. CPA has been demonstrated against:
- **Smart cards** (credit/debit cards using EMV)
- **Hardware Security Modules** (HSMs used in banking)
- **Automotive ECUs** (engine control units storing cryptographic keys)
- **IoT devices** (smart locks, industrial sensors)
- **Cryptocurrency hardware wallets**

The academic paper that formalized this attack — *"Differential Power Analysis"* by Kocher, Jaffe, and Jun (1999) — fundamentally changed how the hardware security industry thought about cryptographic implementations. Every payment card manufactured today includes some form of power analysis countermeasure as a direct result.

---

*This writeup was produced as part of the picoCTF PowerAnalysis: Part 2 challenge. The techniques described are for educational purposes in authorized security research and CTF competitions only.*
