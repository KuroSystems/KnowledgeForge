# Sum-O-Primes — PicoCTF Challenge Writeup
### *A Beginner-Friendly Deep Dive into RSA Cryptography Attacks*

---

## 1. Executive Summary

| Field | Details |
|---|---|
| **Challenge Name** | Sum-O-Primes |
| **Category** | Cryptography |
| **Difficulty** | Medium |
| **Platform** | PicoCTF |
| **Primary Vulnerability** | RSA Prime Factor Information Disclosure |
| **Core Concept** | Congruence of Squares / Algebraic Factorization |
| **Flag** | `picoCTF{pl33z_n0_g1v3_c0ngru3nc3_0f_5qu4r35_24929c45}` |

**Overview:**
This challenge presents a deliberately weakened RSA cryptosystem. The challenge author, in an act of (intentional) generosity, provides not only the standard RSA modulus $n$ (the product of two secret primes) but also their **sum** $x = p + q$. This single additional piece of information catastrophically breaks RSA security by transforming an computationally infeasible factorization problem into a simple algebraic equation solvable in milliseconds. The challenge hints at this with "I love squares :)" — a direct reference to the **Congruence of Squares** technique used in the exploit.

---

## 2. Reconnaissance & Enumeration

### 2.1 Understanding the Provided Files

Before writing a single line of code, a good CTF player always reads and understands **all** provided files. We were given two:

- `gen.py` — The script used to generate the challenge parameters
- `output.txt` — The actual output produced by running `gen.py`

> 💡 **Beginner Tip:** In cryptography challenges, `gen.py` is a goldmine. It tells you *exactly* how the encryption was set up, which often reveals the flaw. Always read it first!

#### Fetching `output.txt`

```bash
curl -s https://artifacts.picoctf.net/c/98/output.txt
```

**What `curl` is doing here:**
- `curl` is a command-line tool for transferring data from URLs
- `-s` stands for **silent mode** — it suppresses progress bars and error messages, giving us clean output
- We used `curl` instead of a browser because it delivers the raw text directly to our terminal, which is faster and scriptable

**Output:**
```
x = 1429cf99b5dd5dde...   ← This is the SUM of the two primes (p + q)
n = 64fc90f5ca6db24f...   ← This is the PRODUCT of the two primes (p × q)
c = 56ed81bbc1497011...   ← This is the CIPHERTEXT (the encrypted flag)
```

#### Fetching `gen.py`

```bash
curl -s https://artifacts.picoctf.net/c/98/gen.py
```

**The full source code revealed:**
```python
p = get_prime(1024)    # p is a random 1024-bit prime
q = get_prime(1024)    # q is a random 1024-bit prime

x = p + q              # ← THE CRITICAL MISTAKE: sum is revealed!
n = p * q              # Standard RSA modulus

e = 65537              # Standard RSA public exponent

m = math.lcm(p - 1, q - 1)   # Carmichael's totient λ(n)
d = pow(e, -1, m)             # Private key derivation

c = pow(FLAG, e, n)    # Standard RSA encryption
```

### 2.2 Identifying the Vulnerability

Let us establish some baseline RSA knowledge before proceeding.

#### Standard RSA Security Model
In normal RSA:
- You are given: $n$, $e$, and $c$
- You need to find: $p$ and $q$ such that $p \times q = n$
- This is called the **Integer Factorization Problem**
- For 1024-bit primes, this is considered **computationally infeasible** — it would take longer than the age of the universe with classical computers

#### Why the Sum Breaks Everything

When we are given *both* the sum and the product of two numbers, we have a **system of two equations with two unknowns**:

$$p + q = x \quad \text{(given as } x \text{)}$$
$$p \times q = n \quad \text{(given as } n \text{)}$$

This is no longer a hard problem. It is high school algebra.

The key identity we exploit is:

$$(p - q)^2 = (p + q)^2 - 4pq$$

Substituting our known values:

$$(p - q)^2 = x^2 - 4n$$

Therefore:

$$p - q = \sqrt{x^2 - 4n}$$

And now, with both the **sum** and **difference** of $p$ and $q$:

$$p = \frac{(p+q) + (p-q)}{2} = \frac{x + \sqrt{x^2 - 4n}}{2}$$

$$q = \frac{(p+q) - (p-q)}{2} = \frac{x - \sqrt{x^2 - 4n}}{2}$$

> 💡 **Beginner Tip:** This is why the challenge is called "Sum-O-Primes" and hints at "squares." The congruence of squares is a classical technique in number theory used for factoring large numbers. The challenge name and hint are directly telling you the mathematical path to the solution!

---

## 3. Exploitation

### 3.1 The Road Not Taken — Common Rabbit Holes

Before showing the solution, let's discuss what a beginner might *incorrectly* try:

#### ❌ Rabbit Hole 1: Brute Force Factorization
A beginner might reach for a tool like `msieve` or `yafu` to try to factor $n$ directly. **Do not do this.** The primes are 1024 bits each, making $n$ a 2048-bit number. Classical factorization tools have no realistic chance against numbers this large. You would be waiting forever.

#### ❌ Rabbit Hole 2: Ignoring `x` and Treating it as Standard RSA
Another mistake is to ignore the `x` value entirely and treat this as a standard RSA challenge. Some beginners might check whether $e$ is small (it isn't — it's the standard 65537), or whether $n$ is factorable on databases like [FactorDB](http://factordb.com). These paths would yield nothing.

#### ❌ Rabbit Hole 3: Misidentifying What `x` Represents
It would be easy to confuse `x` as some other RSA parameter (perhaps a second ciphertext or a nonce). Reading `gen.py` carefully eliminates this ambiguity — the source code explicitly shows `x = p + q`.

> 💡 **Lesson:** In CTF challenges, every piece of given information is there for a reason. If something unusual is provided, ask yourself: "How does this mathematically weaken the system?"

### 3.2 The Exploit Script — Step by Step

```python
import math
import urllib.request

# ── STEP 1: Fetch the parameters ──────────────────────────────────────────────
url = "https://artifacts.picoctf.net/c/98/output.txt"
req = urllib.request.urlopen(url)
lines = req.read().decode('utf-8').strip().split('\n')

x = int(lines[0].split(' = ')[1], 16)   # Sum of primes (hexadecimal → integer)
n = int(lines[1].split(' = ')[1], 16)   # RSA modulus (hexadecimal → integer)
c = int(lines[2].split(' = ')[1], 16)   # Ciphertext (hexadecimal → integer)
e = 65537                                # Public exponent (from gen.py)
```

**Why are we parsing hexadecimal?**
The `gen.py` script outputs values using Python's `{:x}` format specifier, which outputs integers in base-16 (hexadecimal). The `, 16` argument in `int(..., 16)` tells Python to interpret the string as a hexadecimal number and convert it to a standard Python integer.

```python
# ── STEP 2: Calculate the difference between primes ───────────────────────────
diff = math.isqrt(x**2 - 4*n)
```

**Why `math.isqrt()` instead of `math.sqrt()`?**
This is a critical choice. `math.sqrt()` returns a **floating point** number. For numbers with hundreds of digits, floating point introduces rounding errors that would give us completely wrong results. `math.isqrt()` computes the **exact integer square root** — it returns the largest integer $r$ such that $r^2 \leq x^2 - 4n$. This ensures perfect precision for arbitrarily large numbers.

```python
# ── STEP 3: Solve for individual primes ───────────────────────────────────────
p = (x + diff) // 2
q = (x - diff) // 2

# Verify our factorization is correct before proceeding
assert p * q == n, "Error: Incorrect factorization"
```

**Why the `assert` statement?**
This is defensive programming. Before we invest computation in deriving the private key and decrypting, we verify our math produced the correct primes. If the assert fails, we know the error is in our factorization step, not in the decryption step. Always validate intermediate results in cryptographic attacks.

```python
# ── STEP 4: Reconstruct the private key ───────────────────────────────────────
phi = (p - 1) * (q - 1)    # Euler's Totient φ(n)
d = pow(e, -1, phi)         # Modular multiplicative inverse of e mod φ(n)
```

**Euler's Totient vs. Carmichael's Totient:**
Notice that `gen.py` actually used `math.lcm(p-1, q-1)` (Carmichael's totient $\lambda(n)$) to generate $d$. We are using Euler's totient $\phi(n) = (p-1)(q-1)$ in our solve script. This is fine — both produce valid private keys because any $d$ satisfying $e \cdot d \equiv 1 \pmod{\lambda(n)}$ also satisfies $e \cdot d \equiv 1 \pmod{\phi(n)}$. The resulting decryptions will be identical.

**What is `pow(e, -1, phi)`?**
In Python 3.8+, `pow(a, -1, m)` computes the **modular multiplicative inverse** of $a$ modulo $m$. This finds $d$ such that $e \cdot d \equiv 1 \pmod{\phi(n)}$. Internally, Python uses the **Extended Euclidean Algorithm** to compute this efficiently.

```python
# ── STEP 5: Decrypt the ciphertext ────────────────────────────────────────────
m = pow(c, d, n)    # RSA decryption: m = c^d mod n
```

**Why does RSA decryption work this way?**
RSA encryption is: $c = m^e \pmod{n}$

RSA decryption is: $m = c^d \pmod{n}$

This works because $e$ and $d$ are mathematical inverses modulo $\phi(n)$, so:

$$c^d = (m^e)^d = m^{ed} \equiv m^1 \equiv m \pmod{n}$$

Python's built-in `pow(c, d, n)` uses **fast modular exponentiation** (also called square-and-multiply), making this efficient even for 2048-bit numbers.

```python
# ── STEP 6: Convert integer back to readable text ─────────────────────────────
hex_m = hex(m)[2:]                          # Convert integer to hex string
if len(hex_m) % 2 != 0:                    # Ensure even length for byte parsing
    hex_m = '0' + hex_m
print("Flag:", bytes.fromhex(hex_m).decode('utf-8'))
```

**Why this conversion chain?**
The flag was originally converted to an integer using `int(hexlify(FLAG.encode()), 16)` in `gen.py`. We reverse this process:
1. `hex(m)[2:]` — Converts the integer back to a hex string (`[2:]` strips the `0x` prefix)
2. Padding to even length — `bytes.fromhex()` requires pairs of hex characters
3. `bytes.fromhex(hex_m)` — Converts hex pairs back to raw bytes
4. `.decode('utf-8')` — Interprets those bytes as human-readable text

**Final Output:**
```
Flag: picoCTF{pl33z_n0_g1v3_c0ngru3nc3_0f_5qu4r35_24929c45}
```

---

## 4. Privilege Escalation

> *Not applicable to this challenge. This is a pure cryptography challenge with no shell access, user accounts, or system privileges involved. The "escalation" here was purely mathematical — escalating from an observer with ciphertext to an attacker with the plaintext by systematically dismantling the mathematical security guarantees of RSA.*

---

## 5. Lessons Learned & Mitigation

### 5.1 Core Takeaways

| # | Lesson |
|---|---|
| 1 | **Every extra piece of information is a potential vulnerability.** The sum of primes alone collapsed 1024-bit RSA security to a simple algebra problem. |
| 2 | **Read the source code first.** In `gen.py`, the vulnerability was immediately visible. Never jump to tools before understanding the problem fully. |
| 3 | **Use exact integer arithmetic.** Floating-point math is dangerous in cryptographic contexts. Always use `math.isqrt()` over `math.sqrt()` for large integer operations. |
| 4 | **RSA security is not just about key size.** Even with 2048-bit $n$, the system was trivially broken. Implementation details matter as much as key size. |
| 5 | **Hints are meaningful in CTF.** "I love squares" directly pointed to the $(p-q)^2 = (p+q)^2 - 4pq$ identity. Train yourself to interpret challenge metadata as mathematical clues. |

### 5.2 Blue Team Mitigations

#### 🛡️ Mitigation 1: Never Reveal Intermediate Cryptographic Parameters
The fix is straightforward — **only publish what is mathematically required for the recipient to decrypt the message.** In standard RSA, this means sharing only $n$, $e$, and $c$. The sum $x = p + q$ serves no legitimate cryptographic purpose for the recipient and must never be transmitted or stored in accessible locations.

**Detection:** A cryptographic code review or static analysis tool (e.g., **Bandit** for Python, **SonarQube**) scanning for RSA key generation code should flag any logging or transmission of raw prime values or their arithmetic combinations.

#### 🛡️ Mitigation 2: Use Well-Audited Cryptographic Libraries
Rather than implementing RSA from scratch (as this challenge does), developers should use established libraries such as:
- **Python:** `cryptography` library (`from cryptography.hazmat.primitives.asymmetric import rsa`)
- **Java:** `java.security.KeyPairGenerator`
- **C/C++:** OpenSSL's `RSA_generate_key_ex()`

These libraries generate, use, and **discard** prime factors internally, exposing only the public key ($n$, $e$) to the application layer. This architectural separation makes it structurally impossible to accidentally leak $p$, $q$, or their sum.

**Detection:** Security audits should flag any custom cryptographic implementations as high-risk for review, regardless of apparent correctness, following the principle: *"Don't roll your own crypto."*

---

*This writeup was produced using a systematic, step-by-step CTF methodology. Every command was run exactly once in sequence, with outputs analyzed before proceeding — a discipline that transfers directly to professional penetration testing engagements.*
