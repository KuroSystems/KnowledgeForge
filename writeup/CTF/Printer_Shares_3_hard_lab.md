# CTF Lab Writeup: Printer Shares 3
### Platform: PicoCTF | Difficulty: Beginner-Intermediate | Category: Network Exploitation / Privilege Escalation

---

## 1. Executive Summary

**Printer Shares 3** is a network-based CTF challenge hosted at `dolphin-cove.picoctf.net` on port `58302`. The challenge simulates a realistic and dangerously common real-world misconfiguration: a **publicly writable SMB (Samba) share** containing a **script that is automatically executed by a privileged cron job**.

The attack chain involved:
- Identifying a **Samba file-sharing service** on a non-standard port
- Enumerating **SMB shares** to discover a public and a private share
- Discovering a **debug script** with **world-writable permissions** inside the public share
- **Hijacking the cron job** by overwriting the script with a malicious payload
- Waiting for the privileged cron job to **execute our payload**, granting us access to the otherwise restricted private share
- **Exfiltrating the flag** back through the public share

**Primary Vulnerabilities Exploited:**
| Vulnerability | Category |
|---|---|
| Anonymous SMB Access | Misconfiguration |
| World-Writable Privileged Script | Insecure File Permissions |
| Cron Job Script Hijacking | Privilege Escalation |

> **Key Takeaway:** This challenge demonstrates that leaving a debug script in a publicly writable location — even if the sensitive data is "locked away" — can be catastrophic if that script is executed by a privileged process.

---

## 2. Reconnaissance & Enumeration

### 2.1 Understanding the Goal Before Scanning

Before touching a single tool, always read the challenge description carefully. The challenge tells us:

> *"Two printers are on 58302, one private, one public."*

This is a significant clue. In networking, **printers are commonly shared over SMB (Server Message Block)** — the same protocol used for Windows file sharing. The mention of "shares" in the title further reinforces this. So before we even scan, our hypothesis is:

> **"This is likely an SMB service. We should look for misconfigured shares."**

This is a critical mindset to develop. Forming a hypothesis before scanning makes your enumeration **targeted and efficient** rather than a blind spray of tools.

---

### 2.2 Service Identification with Nmap

**Conceptual Background: What is Nmap?**

`nmap` (Network Mapper) is the industry-standard tool for network reconnaissance. It sends specially crafted packets to a target and interprets the responses to determine what services are running, what versions they are, and how the system is configured.

**Command Used:**
```bash
nmap -sV -p 58302 dolphin-cove.picoctf.net
```

**Breaking Down Every Flag:**

| Flag | Full Name | What It Does | Why We Used It |
|---|---|---|---|
| `-sV` | Service Version Detection | Probes open ports to determine the service name and version | We need to confirm *what* is running, not just *that* something is running |
| `-p 58302` | Port Specification | Limits scanning to only this port | We already know the port from the challenge; scanning all 65535 ports would be wasteful and slow |

**Why NOT use `-sC` (default scripts) here?**

`-sC` runs Nmap's default Nmap Scripting Engine (NSE) scripts. While useful, it adds noise and time. Since we already knew the port, **precision was better than comprehensiveness** at this stage.

**Output Received:**
```
PORT      STATE SERVICE     VERSION
58302/tcp open  netbios-ssn Samba smbd 4.6.2
```

**Analysis of Output:**

The key finding here is `netbios-ssn Samba smbd`. This confirms our hypothesis:

- **`netbios-ssn`** — This is the NetBIOS Session Service, which is the underlying protocol that SMB uses for communication
- **`Samba`** — The open-source Linux implementation of the SMB protocol
- **`smbd`** — The Samba daemon (background process) responsible for file and printer sharing

Our hypothesis is **confirmed**. This is an SMB service. Now we enumerate it.

---

### 2.3 SMB Share Enumeration

**Conceptual Background: What is SMB and Why Does It Matter?**

**SMB (Server Message Block)** is a network file-sharing protocol. It allows systems to share files, printers, and other resources over a network. On Linux, this is implemented via **Samba**.

An SMB server exposes **"shares"** — think of them like shared folders. Each share has its own set of permissions. A critically important feature (and frequent vulnerability) is **anonymous/guest access** — the ability to browse or read/write to shares **without any credentials at all**.

This is exploitable because an administrator might set up a "public" share for convenience without realizing that the permissions cascade into a security vulnerability.

**Command Used:**
```bash
smbclient -L //dolphin-cove.picoctf.net -p 58302 -N
```

**Breaking Down Every Flag:**

| Flag | Full Name | What It Does | Why We Used It |
|---|---|---|---|
| `-L` | List Shares | Lists all available shares on the target server | We need to discover what shares exist before we can access them |
| `//dolphin-cove.picoctf.net` | Target Host | Specifies the SMB server address in UNC format | Standard SMB addressing convention |
| `-p 58302` | Port | Connects to a non-standard port | SMB normally runs on port 445; we override this |
| `-N` | No Password | Suppresses the password prompt and attempts anonymous/null authentication | Tests if guest access is allowed without needing credentials |

**Why NOT use a tool like `enum4linux` here?**

`enum4linux` is a powerful automated SMB enumeration tool. However:
- It generates **significant noise** and runs many queries simultaneously
- For this challenge, we only needed share names — `smbclient -L` is **surgical and precise**
- In real penetration tests, quiet enumeration is preferred to avoid triggering IDS/IPS alerts

**Output Received:**
```
Sharename       Type      Comment
---------       ----      -------
shares          Disk      Public Share With Guests
secure-shares   Disk      Printer for internal usage only
IPC$            IPC       IPC Service (Samba 4.19.5-Ubuntu)
```

**Analysis of Output:**

We now have a clear picture:

| Share | Type | Access Level | Significance |
|---|---|---|---|
| `shares` | Disk | Public (Guests allowed) | Our entry point |
| `secure-shares` | Disk | Internal only | Contains the flag |
| `IPC$` | IPC | Special | Inter-Process Communication; rarely exploitable directly |

The **`IPC$` share** is a default administrative share used for inter-process communication. It's almost never directly exploitable, so we ignore it.

Our target is clear: **get into `secure-shares` somehow, starting through `shares`.**

---

### 2.4 Exploring the Public Share

**Command Used:**
```bash
smbclient //dolphin-cove.picoctf.net/shares -p 58302 -N -c "ls"
```

**Breaking Down Every Flag:**

| Flag | What It Does |
|---|---|
| `/shares` | Specifies which share to connect to |
| `-N` | Anonymous login (no password) |
| `-c "ls"` | Executes the `ls` command inside the SMB session to list files, then exits |

**Why use `-c "ls"` instead of entering interactive mode?**

Using `-c` passes a command directly, making it **scriptable and non-interactive**. This is faster and cleaner than manually connecting and typing commands, especially when you're iterating through multiple steps.

**Output Received:**
```
script.sh    N    73    Thu Feb  5 02:52:17 2026
cron.log     N   215    Sat May  9 14:05:01 2026
```

**Analysis of Output:**

Two files immediately stand out:

- **`script.sh`** — A shell script. The challenge description mentioned a "debug script." This is almost certainly it.
- **`cron.log`** — A log file. The word "cron" is critical. **Cron** is Linux's task scheduler — it runs commands automatically at specified intervals.

The **combination** of these two files tells a story:
> *"There is a script (`script.sh`) that is being executed automatically on a schedule (`cron.log` proves it runs regularly)."*

This is the vulnerability pathway. Now we confirm our suspicion by reading both files.

---

## 3. Initial Foothold & Exploitation

### 3.1 Reading the Debug Script and Cron Log

**Conceptual Background: What is a Cron Job?**

A **cron job** is a scheduled task in Linux. The `cron` daemon checks a configuration file (crontab) and runs specified commands at specified times — every minute, every hour, every day, etc.

The format looks like this:
```
* * * * * /path/to/script.sh
```
The five asterisks mean "every minute, every hour, every day, every month, every day of the week" — i.e., **run every single minute.**

If a cron job runs a script that an attacker can modify, the attacker can make the system execute **any command they want** with the **same privileges as the user running the cron job.**

**Command Used:**
```bash
smbclient //dolphin-cove.picoctf.net/shares -p 58302 -N -c "get script.sh -; get cron.log -"
```

**Breaking Down the Command:**

| Part | What It Does |
|---|---|
| `get script.sh -` | Downloads `script.sh` and prints it to stdout (the `-` means "print to terminal instead of saving to file") |
| `;` | Chains a second command in the same SMB session |
| `get cron.log -` | Downloads and prints `cron.log` to stdout |

**Why chain both in one command?**

Efficiency. Opening and closing an SMB connection has overhead. By chaining commands with `;` inside `-c "..."`, we retrieve both files in a **single connection**.

**Output Received:**

`script.sh`:
```bash
#!/bin/bash
# this script runs every minute
echo "Health Check: $(date)"
```

`cron.log`:
```
Health Check: Sat May  9 08:31:01 UTC 2026
Health Check: Sat May  9 08:32:01 UTC 2026
Health Check: Sat May  9 08:33:01 UTC 2026
Health Check: Sat May  9 08:34:01 UTC 2026
Health Check: Sat May  9 08:35:01 UTC 2026
```

**Analysis:**

`script.sh` is a **trivial health check script** — it simply prints the current date and time. But look at `cron.log`:

- The timestamps show **exactly one-minute intervals** ✅
- This **proves** the cron job is active and executing the script
- The cron job is almost certainly running as a user with **access to `secure-shares`** (otherwise, why would it be the debug script for a private printer?)

**The Attack Vector is Confirmed:**
> *"If we can overwrite `script.sh`, and the cron job runs it every minute with elevated privileges, we can execute any command we want."*

---

### 3.2 Testing Write Permissions (The Critical Discovery)

**Conceptual Background: Why Write Permissions Matter**

In Linux, file permissions determine who can **read**, **write**, or **execute** a file. If an SMB share is misconfigured to allow **anonymous write access**, any unauthenticated user on the internet can **modify files** in that share.

When a **writable file is also executed by a privileged process**, the write permission becomes an **arbitrary code execution vulnerability**.

**Command Used:**
```bash
echo "ls -R / > /shares/output.txt" > payload.sh && smbclient //dolphin-cove.picoctf.net/shares -p 58302 -N -c "put payload.sh script.sh"
```

**Breaking Down Every Part:**

| Part | What It Does |
|---|---|
| `echo "..." > payload.sh` | Creates a local file called `payload.sh` with our malicious command inside |
| `ls -R /` | Lists all files recursively from the root of the filesystem |
| `> /shares/output.txt` | Redirects output to a file named `output.txt` (trying to write it back to the share) |
| `&&` | Only runs the second command if the first succeeds |
| `put payload.sh script.sh` | Uploads our local `payload.sh` to the server, overwriting `script.sh` |

**Why use `put` specifically?**

`put` is `smbclient`'s command to **upload** a file to the SMB share. It overwrites the remote file with our local file. This is the write permission test.

**Output:**
```
putting file payload.sh as \script.sh (0.0 kb/s) (average 0.0 kb/s)
```

**No error = Write access confirmed.** This is the moment the challenge becomes solvable.

**The Road Not Taken — What We Didn't Try:**

> ❌ **Attempting to access `secure-shares` directly:** We could have tried `smbclient //target/secure-shares -p 58302 -N`, but it was labeled "internal use only" and would almost certainly require credentials.

> ❌ **Brute-forcing SMB credentials:** Tools like `hydra` or `crackmapexec` could be used to guess passwords. However, the public share with a writable script was a **quieter, faster, and more elegant path**.

> ❌ **Looking for known Samba CVEs:** Samba 4.x has some known vulnerabilities (like EternalBlue variants), but attempting these against a CTF environment without evidence they're applicable is **wasted effort and unnecessary noise**.

---

### 3.3 The First Payload — Filesystem Reconnaissance

Our first payload attempted to dump the entire filesystem listing to a file in the share. However, this **failed silently** — `output.txt` never appeared.

**Why did this fail?**

The likely reason is a **path issue**. Inside the cron job's execution context, `/shares/` is not the path to the SMB share — that path only exists from the outside. The script runs in the server's local filesystem context, and the public share might be mounted at a different path (e.g., `/srv/samba/shares/` or `/home/samba/shares/`).

**This is a common rabbit hole** — assuming the share path on the server matches what you see from the client. Always consider the difference between **the attacker's perspective** and **the server's internal filesystem layout**.

**This failure taught us something valuable:** We need to work around the path uncertainty by using a more robust approach.

---

### 3.4 The Successful Payload — Flag Exfiltration

**Conceptual Background: The `find` Command**

The `find` command in Linux is a powerful filesystem search tool. Its syntax:
```bash
find [starting_directory] [criteria] [action]
```

For example:
```bash
find / -name '*flag*' -exec cp {} ./captured_flag.txt \;
```

| Part | What It Does |
|---|---|
| `find /` | Start searching from the root of the filesystem |
| `-name '*flag*'` | Match any file whose name contains the word "flag" (wildcards `*` match anything) |
| `-exec cp {} ./captured_flag.txt \;` | For each match found, execute `cp` (copy), where `{}` is replaced by the found file's path, copying it to `./captured_flag.txt` (relative to where the script runs) |

**Why is `./` safer than an absolute path?**

Since we don't know the server's internal path to the SMB share, using `./` (current directory — where the script itself lives) is **relative to the script's execution location**, which is exactly where `script.sh` and `cron.log` reside. This eliminates the path uncertainty that caused our first payload to fail.

**Command Used:**
```bash
echo "find / -name '*flag*' -exec cp {} ./captured_flag.txt \;" > payload.sh && smbclient //dolphin-cove.picoctf.net/shares -p 58302 -N -c "put payload.sh script.sh"
```

**Output:**
```
putting file payload.sh as \script.sh (0.0 kb/s) (average 0.0 kb/s)
```

Upload successful. Now we **wait for the cron job to fire** (up to 60 seconds).

---

### 3.5 Retrieving the Flag

**Command Used:**
```bash
smbclient //dolphin-cove.picoctf.net/shares -p 58302 -N -c "ls; get captured_flag.txt -"
```

**Breaking It Down:**

| Part | What It Does |
|---|---|
| `ls` | Lists the share contents to verify `captured_flag.txt` exists |
| `get captured_flag.txt -` | Downloads the file and prints it directly to terminal |

**Output:**
```
captured_flag.txt    N    45    Sat May  9 14:07:02 2026

picoCTF{5mb_pr1nter_5h4re5_r3v3r53_8f6de8c5}
```

🎉 **Flag captured:** `picoCTF{5mb_pr1nter_5h4re5_r3v3r53_8f6de8c5}`

---

## 4. Privilege Escalation

> **Note:** In this challenge, "privilege escalation" was achieved implicitly through the **cron job hijacking** mechanism. There was no separate local enumeration phase because the challenge is network-based and the escalation was embedded in the exploitation itself. However, understanding the underlying privilege escalation concept is critical.

### 4.1 How the Cron Job Hijacking Worked

**The Attack Chain Visualized:**

```
[Attacker]                    [Server]
    |                             |
    |-- Anonymous SMB Access -->  |
    |                             |
    |-- Overwrite script.sh ----> |  (Write permission misconfiguration)
    |                             |
    |                    [Cron Job fires - runs as privileged user]
    |                             |
    |                    [find / -name '*flag*'] (has access to secure-shares)
    |                             |
    |                    [Copies flag to ./captured_flag.txt]
    |                             |
    |<-- Read captured_flag.txt - |
    |                             |
[Flag obtained]
```

### 4.2 Why the Cron Job Had Access to the Flag

The cron job was running as a user (likely `root` or the Samba service user) that had **read permissions to the `secure-shares` directory**. This is the core design flaw:

- The **network-level access** to `secure-shares` was restricted (requiring credentials)
- But the **filesystem-level access** of the cron user was **not restricted**
- The debug script bridged these two security boundaries — and we exploited that bridge

This is known as a **Confused Deputy Problem**: a privileged entity (the cron job) is tricked into performing actions on behalf of an unprivileged attacker.

---

## 5. Lessons Learned & Mitigation

### 5.1 Key Takeaways for Attackers (Offensive Mindset)

| Lesson | Application |
|---|---|
| **Read challenge descriptions carefully** | The hint about "cron script" and "super secure directory" outlined the entire attack path before we touched a tool |
| **Hypothesis-driven enumeration** | Forming a hypothesis (SMB) before scanning made our reconnaissance targeted and fast |
| **Writable + Executed = RCE** | Always check if writable files are being executed by any scheduled or automated process |
| **Relative paths beat absolute paths** | When you don't know the server's internal structure, `./` keeps you anchored to what you know |
| **Patience is a technique** | Time-based exploitation (waiting for cron) is a legitimate and often overlooked attack vector |

---

### 5.2 Mitigation — Blue Team Perspective

**Vulnerability 1: Anonymous Write Access to SMB Share**

> 🔴 **Risk:** Any unauthenticated user on the internet can modify files in the public share.

**Fix:**
```ini
# In /etc/samba/smb.conf, change:
[shares]
   read only = yes          # Prevent writes
   guest ok = yes           # If guest access is needed, make it READ ONLY
   write list = @samba_admins  # Only allow specific users to write
```

Even if the share must be publicly readable, **write access should never be granted to anonymous users**.

**Detection:** Monitor SMB audit logs for `put`/write operations from anonymous or guest sessions. Tools like **Wazuh**, **Splunk**, or even native Samba audit logging can alert on this.

---

**Vulnerability 2: Cron Job Executing a World-Writable Script**

> 🔴 **Risk:** A privileged scheduled task runs a script that unprivileged users can modify.

**Fix:**
```bash
# Proper permissions for a script run by root via cron:
chmod 700 /path/to/script.sh      # Only root can read/write/execute
chown root:root /path/to/script.sh # Owned by root

# Verify with:
ls -la /path/to/script.sh
# Should show: -rwx------ 1 root root
```

**Additionally:** Never place scripts executed by privileged cron jobs in **world-accessible locations** like public SMB shares. Scripts with elevated execution context should live in **protected directories** (`/root/`, `/etc/cron.d/`, etc.)

**Detection:** Use **file integrity monitoring (FIM)** tools like **AIDE**, **Tripwire**, or **Wazuh FIM** to alert whenever critical scripts are modified. Any unexpected modification to a cron-executed script should trigger an immediate alert.

---

**Vulnerability 3: Leaving Debug Scripts in Production**

> 🟡 **Risk:** Debug artifacts expose internal system behavior and attack surface.

The challenge literally states: *"I accidentally left the debug script in place."*

**Fix:**
- Implement a **deployment checklist** that explicitly requires removal of debug scripts before production deployment
- Use **infrastructure-as-code** (Ansible, Terraform) to define exactly what files should exist in a share — anything else gets automatically removed
- Conduct regular **file audits** on publicly accessible shares

---

### 5.3 Final Reflection

This challenge, while labeled beginner-intermediate, encapsulates a **genuinely dangerous real-world attack pattern**. Misconfigured SMB shares have been responsible for some of the most significant breaches in history — including the **WannaCry ransomware outbreak** and countless corporate data theft incidents.

The combination of:
1. **Public write access** → Modification of a sensitive file
2. **Privileged scheduled execution** → Elevation of our access level
3. **Forgotten debug artifacts** → An unnecessary attack surface

...is **not theoretical**. Pentesters find this exact configuration in enterprise networks regularly.

> *"Security is not about how strong your lock is. It's about ensuring there's no open window next to the locked door."*

---

*Writeup authored following the systematic exploitation path documented in the live CTF session. All techniques demonstrated were performed in an authorized CTF environment.*
