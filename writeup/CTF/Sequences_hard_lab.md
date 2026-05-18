# CTF Lab Writeup: **Sequences**
### Platform: PicoCTF | Category: General Skills / Cryptography | Difficulty: Medium

---

## 1. Executive Summary

**Challenge:** Sequences
**Platform:** PicoCTF
**Category:** General Skills / Mathematics / Cryptography
**Difficulty:** Medium
**Flag:** `picoCTF{b1g_numb3rs_afc4ce7f}`

This challenge presented us with a Python script implementing a **4th-degree linear recurrence sequence** that needed to be evaluated at index $N = 20,000,000$. The naive recursive implementation (even with Python's `functools.cache`) was computationally infeasible — it would overflow the call stack and take an astronomically long time to execute.

The core vulnerability here was not a security flaw in the traditional sense, but rather an **algorithmic inefficiency** that had to be overcome using a mathematical technique called **Matrix Exponentiation**. This allowed us to reduce the time complexity from $O(N)$ down to $O(\log N)$, making the computation feasible in seconds rather than centuries.

We also encountered and bypassed a **modern Python integer-to-string conversion safeguard** introduced to prevent Denial-of-Service attacks.

**Key skills exercised:**
- Linear recurrence theory
- Matrix exponentiation (fast power)
- Modular arithmetic properties
- Python environment limitations

---

## 2. Reconnaissance & Enumeration

### 2.1 Reading the Challenge Description Carefully

Before touching a single tool, the most important skill in CTF challenges is **reading the problem statement carefully**. The challenge told us two critical things:

> *"can you figure out how to make it run fast enough"*
> *"even an efficient solution might take several seconds to run. If your solution is taking several minutes, then you may need to reconsider your approach."*

This immediately tells us:
- The existing code is **too slow** — optimization is required
- The target solution runs in **seconds**, meaning the algorithm complexity needs to be drastically reduced
- The hint explicitly mentions **"matrix diagonalization"** — a mathematical technique

> 💡 **Beginner Tip:** In CTF challenges, hints are not optional flavour text. They are directional signals. When a challenge says "Google X", that is your roadmap. Never skip reading hints carefully.

---

### 2.2 Analyzing the Source Code

We downloaded and inspected the provided `sequences.py`:

```bash
curl -s https://artifacts.picoctf.net/c/66/sequences.py
```

**Why `curl`?** It fetches remote files from the command line without needing a browser. The `-s` flag means "silent" — it suppresses download progress output so our terminal stays clean.

**The full source code revealed:**

```python
import math
import hashlib
import sys
from tqdm import tqdm
import functools

ITERS = int(2e7)                           # Target index: 20,000,000
VERIF_KEY = "96cc5f3b460732b442814fd33cf8537c"
ENCRYPTED_FLAG = bytes.fromhex("42cbbce1487b443de1acf4834baed794f4bbd0dfb5885e6c7ed9a3c62b")

@functools.cache
def m_func(i):
    if i == 0: return 1
    if i == 2: return 3
    if i == 1: return 2
    if i == 3: return 4
    return 55692*m_func(i-4) - 9549*m_func(i-3) + 301*m_func(i-2) + 21*m_func(i-1)

def decrypt_flag(sol):
    sol = sol % (10**10000)                # Truncate to last 10,000 digits
    sol = str(sol)
    sol_md5 = hashlib.md5(sol.encode()).hexdigest()
    if sol_md5 != VERIF_KEY:
        print("Incorrect solution")
        sys.exit(1)
    key = hashlib.sha256(sol.encode()).digest()
    flag = bytearray([char ^ key[i] for i, char in enumerate(ENCRYPTED_FLAG)]).decode()
    print(flag)

if __name__ == "__main__":
    sol = m_func(ITERS)
    decrypt_flag(sol)
```

**What we extracted from code analysis:**

| Element | Value | Significance |
|---|---|---|
| Target Index | `ITERS = 20,000,000` | Far too large for naive recursion |
| Base Cases | `m(0)=1, m(1)=2, m(2)=3, m(3)=4` | Initial state vector values |
| Recurrence Coefficients | `21, 301, -9549, 55692` | Transition matrix values |
| Modulus | `10**10000` | Applied before hashing — we can use it early! |
| Verification | MD5 hash check | Confirms solution correctness before decryption |
| Decryption | XOR with SHA256 key | Standard symmetric decryption |

---

### 2.3 Understanding Why the Naive Approach Fails

The existing function uses `@functools.cache` (Python's memoization decorator), which stores previously computed values to avoid redundant recursion. Even so, for $N = 20,000,000$:

**Problem 1 — Stack Overflow:**
Python has a default recursion limit of approximately 1,000 calls deep. Even with caching, the *first* call to `m_func(20000000)` triggers a chain of recursive calls `20000000 → 19999999 → ...` before the cache kicks in, causing:
```
RecursionError: maximum recursion depth exceeded
```

**Problem 2 — Memory:**
Even if we increased Python's recursion limit, storing 20 million large numbers (each potentially thousands of digits) in the cache would consume enormous amounts of RAM.

**Problem 3 — Big Number Arithmetic:**
The recurrence has coefficient `55692`, meaning each term grows exponentially. Without applying a modulus early, these numbers would have millions of digits after just thousands of iterations, making arithmetic impossibly slow.

> 🚫 **The Road Not Taken:** You might think "I'll just increase Python's recursion limit with `sys.setrecursionlimit(25000000)`." We did not do this because even if we bypassed the stack limit, the computation would still take an extremely long time due to Problems 2 and 3 above. The challenge hint about "several minutes = wrong approach" confirmed we needed a fundamentally better algorithm.

---

## 3. Core Exploitation — Matrix Exponentiation

### 3.1 The Mathematical Foundation

Before writing a single line of code, let us understand the mathematical concept.

#### What is a Linear Recurrence?

Our sequence is defined as:

$$m(i) = 21 \cdot m(i-1) + 301 \cdot m(i-2) - 9549 \cdot m(i-3) + 55692 \cdot m(i-4)$$

This is called a **linear recurrence relation** — each term is a fixed linear combination of the previous $k$ terms (here $k=4$).

Famous examples include the **Fibonacci sequence**:
$$F(n) = F(n-1) + F(n-2)$$

#### Representing the Recurrence as a Matrix

The key insight is: **any linear recurrence can be represented as matrix multiplication.**

We define a **state vector** containing the last $k$ known values:

$$\vec{V_i} = \begin{pmatrix} m(i) \\ m(i-1) \\ m(i-2) \\ m(i-3) \end{pmatrix}$$

We then construct a **transition matrix** $T$ such that:

$$T \cdot \vec{V_i} = \vec{V_{i+1}}$$

For our recurrence, the transition matrix is:

$$T = \begin{pmatrix} 21 & 301 & -9549 & 55692 \\ 1 & 0 & 0 & 0 \\ 0 & 1 & 0 & 0 \\ 0 & 0 & 1 & 0 \end{pmatrix}$$

**Why does this work?** Let us verify by multiplying:

$$T \cdot \vec{V_3} = \begin{pmatrix} 21 \cdot m(3) + 301 \cdot m(2) - 9549 \cdot m(1) + 55692 \cdot m(0) \\ m(3) \\ m(2) \\ m(1) \end{pmatrix} = \begin{pmatrix} m(4) \\ m(3) \\ m(2) \\ m(1) \end{pmatrix} = \vec{V_4}$$

The top row applies the recurrence formula. The remaining rows simply "shift" the state vector forward, dropping the oldest value.

#### Why Matrix Exponentiation?

Since $T \cdot \vec{V_3} = \vec{V_4}$, it follows that:

$$T^n \cdot \vec{V_3} = \vec{V_{n+3}}$$

So to find $m(20,000,000)$, we compute:

$$T^{19,999,997} \cdot \vec{V_3}$$

and read the first element of the result.

**The magic:** Instead of computing $T$ applied 20 million times sequentially, we use **Exponentiation by Squaring**:

$$T^n = \begin{cases} I & \text{if } n = 0 \\ T^{n/2} \cdot T^{n/2} & \text{if } n \text{ is even} \\ T \cdot T^{n-1} & \text{if } n \text{ is odd} \end{cases}$$

This reduces 20,000,000 multiplications to just $\log_2(20,000,000) \approx 24$ matrix multiplications.

| Approach | Operations | Feasibility |
|---|---|---|
| Naive recursion | $O(N) = 20,000,000$ | ❌ Impossible |
| Matrix exponentiation | $O(\log N) \approx 24$ | ✅ Seconds |

> 💡 **Beginner Insight:** The hint said "matrix diagonalization." Diagonalization is another (more mathematically elegant) way to achieve the same result. However, matrix exponentiation is simpler to implement and equally valid. Both techniques exploit the same underlying principle: that linear recurrences have a closed-form matrix representation.

---

### 3.2 The Critical Modular Arithmetic Optimization

Looking at `decrypt_flag()`:
```python
sol = sol % (10**10000)
```

The solution is truncated to its last 10,000 decimal digits **before** hashing. This means:

$$\text{answer} = m(20,000,000) \pmod{10^{10000}}$$

**Why is this crucial for our solver?** Because of the fundamental property of modular arithmetic:

$$(A \times B) \pmod{M} = [(A \pmod{M}) \times (B \pmod{M})] \pmod{M}$$

This means we can apply the modulus **at every single matrix multiplication step**. Instead of multiplying enormous numbers (millions of digits), we keep all numbers below $10^{10000}$ throughout the entire computation. This makes each multiplication dramatically faster.

> 🚫 **The Road Not Taken:** If we had computed $T^{19999997}$ first and *then* applied the modulus at the end, each matrix element would grow to astronomical size — potentially millions of digits after just thousands of multiplications. Even though we only need 24 squarings, each squaring would be operating on impossibly large numbers. Applying modulus early is **non-negotiable** for performance.

---

### 3.3 Writing and Executing the Solver

```python
import hashlib
import sys

sys.set_int_max_str_digits(20000)   # Bypass Python's string conversion limit

ITERS = int(2e7)
MOD = 10**10000

def multiply_matrices(A, B):
    """Multiply two 4x4 matrices under modulo MOD"""
    C = [[0]*4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            for k in range(4):
                C[i][j] = (C[i][j] + A[i][k] * B[k][j]) % MOD
    return C

def power_matrix(A, p):
    """Compute A^p using exponentiation by squaring"""
    # Start with Identity matrix (A^0 = I)
    res = [[1 if i == j else 0 for j in range(4)] for i in range(4)]
    base = A
    while p > 0:
        if p % 2 == 1:      # If current bit is set, multiply result by current base
            res = multiply_matrices(res, base)
        base = multiply_matrices(base, base)   # Square the base
        p //= 2             # Move to next bit
    return res

# Transition matrix encoding the recurrence
T = [
    [21, 301, -9549, 55692],
    [1,  0,   0,     0    ],
    [0,  1,   0,     0    ],
    [0,  0,   1,     0    ]
]

# Initial state vector: [m(3), m(2), m(1), m(0)]
V3 = [4, 3, 2, 1]

# Compute T^(ITERS-3) * V3
T_pow = power_matrix(T, ITERS - 3)

# Extract m(ITERS) = first element of T^(ITERS-3) * V3
sol = 0
for i in range(4):
    sol = (sol + T_pow[0][i] * V3[i]) % MOD

# --- Decryption (unchanged from original) ---
VERIF_KEY = "96cc5f3b460732b442814fd33cf8537c"
ENCRYPTED_FLAG = bytes.fromhex("42cbbce1487b443de1acf4834baed794f4bbd0dfb5885e6c7ed9a3c62b")

sol_str = str(sol)
sol_md5 = hashlib.md5(sol_str.encode()).hexdigest()

if sol_md5 != VERIF_KEY:
    print("Incorrect solution. MD5 mismatch.")
    sys.exit(1)

key = hashlib.sha256(sol_str.encode()).digest()
flag = bytearray([char ^ key[i] for i, char in enumerate(ENCRYPTED_FLAG)]).decode()
print(flag)
```

**Line-by-line explanation of key sections:**

| Code | Explanation |
|---|---|
| `sys.set_int_max_str_digits(20000)` | Lifts Python's 4300-digit safety limit for integer conversion |
| `C[i][j] = (C[i][j] + A[i][k] * B[k][j]) % MOD` | Standard matrix multiplication with modular reduction at every step |
| `res = [[1 if i==j else 0 ...]]` | Initializes result as Identity matrix ($I \cdot A = A$) |
| `if p % 2 == 1` | Checks if the least significant bit of the exponent is set |
| `base = multiply_matrices(base, base)` | Squares the matrix (halves the effective exponent each iteration) |
| `power_matrix(T, ITERS - 3)` | We subtract 3 because our initial state is $\vec{V_3}$, not $\vec{V_0}$ |
| `T_pow[0][i] * V3[i]` | Dot product of first row of $T^n$ with the state vector gives $m(N)$ |

---

### 3.4 Encountering and Resolving the Python Safeguard

**The error we hit:**
```
ValueError: Exceeds the limit (4300 digits) for integer string conversion;
use sys.set_int_max_str_digits() to increase the limit
```

**Why does this happen?**
Python 3.11+ introduced a security limit on converting large integers to strings. This was added to prevent a class of Denial-of-Service attacks where an attacker sends an astronomically large number to an application, causing it to hang while converting to string (which is $O(N^2)$ for naive implementations).

Our number has up to 10,000 decimal digits — well beyond the default 4,300 digit limit.

**The fix:**
```python
sys.set_int_max_str_digits(20000)
```

This explicitly raises the limit to 20,000 digits, safely accommodating our 10,000-digit number.

> 💡 **Beginner Insight:** This is a great example of how even correct algorithms can fail due to **environment-specific constraints**. Always check Python version-specific behaviors when working with very large numbers.

---

## 4. "Privilege Escalation" — Verification and Decryption

In this challenge, the "privilege escalation" phase is the **decryption of the flag** — we need the correct value to unlock it.

### 4.1 The Verification Layer

```python
sol_md5 = hashlib.md5(sol_str.encode()).hexdigest()
if sol_md5 != VERIF_KEY:
    print("Incorrect solution")
    sys.exit(1)
```

**Purpose:** Before attempting decryption, the script verifies our answer using MD5. If the MD5 of our computed string matches `VERIF_KEY`, we have the correct answer.

> ⚠️ **Important Note:** MD5 is considered **cryptographically broken** for security purposes (vulnerable to collision attacks). However, here it is being used only as a **checksum** — not for security. This is an acceptable use case.

### 4.2 The Flag Decryption

```python
key = hashlib.sha256(sol_str.encode()).digest()
flag = bytearray([char ^ key[i] for i, char in enumerate(ENCRYPTED_FLAG)]).decode()
```

**How this works:**
1. Our computed number (as a string) is hashed with SHA256 to produce a 32-byte key
2. The key is XOR'd byte-by-byte with the `ENCRYPTED_FLAG` ciphertext
3. XOR with the correct key reveals the plaintext flag

This is a form of **stream cipher decryption**. XOR is its own inverse: if `C = P XOR K`, then `P = C XOR K`.

**Result:**
```
picoCTF{b1g_numb3rs_afc4ce7f}
```

---

## 5. Lessons Learned & Mitigation

### 5.1 Key Takeaways for Learners

#### 🎓 Lesson 1: Algorithm Complexity Is a Security Concern
The challenge demonstrates that choosing the wrong algorithm is not just an engineering problem — in CTF and real-world security contexts, computationally infeasible code can be both a vulnerability and a defense mechanism. Understanding **Big-O notation** is fundamental.

#### 🎓 Lesson 2: Matrix Exponentiation Is a Universal Tool
Whenever you see a **linear recurrence relation**, matrix exponentiation should immediately come to mind. It applies to:
- Fibonacci-style problems
- Dynamic programming optimizations
- Cryptographic constructions (some hash functions use LFSRs)

#### 🎓 Lesson 3: Apply Modulus Early and Often
If a problem specifies `result mod M`, **apply the modulus at every intermediate step**. This is not just a correctness requirement — it is a performance requirement. This principle appears in RSA, Diffie-Hellman, and virtually every cryptographic system.

#### 🎓 Lesson 4: Know Your Environment's Limits
Python has hidden constraints — recursion limits, integer string conversion limits, memory limits. A correct algorithm can still fail due to runtime environment constraints. Always check:
```python
sys.getrecursionlimit()     # Default: 1000
sys.get_int_max_str_digits() # Default: 4300 (Python 3.11+)
```

#### 🎓 Lesson 5: Read Hints and Problem Statements Literally
The challenge told us exactly what to Google. In real-world penetration testing, client-provided documentation and error messages similarly give away critical information. Never skip reading carefully.

---

### 5.2 Blue Team Mitigations

While this challenge is mathematical rather than a traditional vulnerability, the underlying concepts appear in real systems:

**1. Input Validation for Large Number Processing**
If your application accepts large integers from user input and converts them to strings or performs heavy arithmetic, enforce strict size limits:
```python
if len(str(user_input)) > MAX_DIGITS:
    raise ValueError("Input too large")
```
Python's built-in `sys.set_int_max_str_digits()` is actually a real-world mitigation for CVE-2020-10735.

**2. Avoid Recursive Algorithms for Unbounded Inputs**
In production code, never use recursive implementations for sequences that can scale to large inputs. Iterative or matrix-based implementations with explicit bounds checking are safer:
```python
# Dangerous in production:
def fib(n):
    return fib(n-1) + fib(n-2)   # Stack overflow risk

# Safe in production:
def fib_matrix(n):
    # Matrix exponentiation - O(log n), bounded memory
    ...
```

**3. Detecting Algorithmic DoS Attacks**
Monitor application response times. Sudden spikes when processing numeric inputs could indicate an adversary probing for algorithmic complexity vulnerabilities (HashDoS, BigNum DoS). Implement timeouts and rate limiting on compute-heavy endpoints.

---

### 5.3 Full Attack Chain Summary

```
Challenge Code Analysis
        │
        ▼
Identified: 4th-degree linear recurrence
        │
        ▼
Identified: Naive O(N) approach is infeasible at N=20,000,000
        │
        ▼
Technique: Represent recurrence as transition matrix T (4x4)
        │
        ▼
Technique: Compute T^(N-3) using Exponentiation by Squaring → O(log N)
        │
        ▼
Optimization: Apply MOD=10^10000 at every matrix multiplication step
        │
        ▼
Bypass: sys.set_int_max_str_digits(20000) for Python 3.11+ string limit
        │
        ▼
Decryption: MD5 verification → SHA256 key derivation → XOR decryption
        │
        ▼
FLAG: picoCTF{b1g_numb3rs_afc4ce7f}
```

---

> **Final Encouragement:** If this challenge felt difficult, that is completely normal. Matrix exponentiation sits at the intersection of linear algebra and computer science — two fields that take time to develop intuition for. The key is: next time you see a recurrence relation in a CTF, you will immediately recognize the pattern. That is how expertise is built — one challenge at a time. 🚀
