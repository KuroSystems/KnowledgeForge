# 🔍 CTF Writeup: WebNet1 (picoCTF)
### Difficulty: Beginner-Intermediate | Category: Network Forensics

---

## 🧩 What Is This Challenge About?

We are given two files:
- **`capture.pcap`** — A recording of real network traffic (like a video replay of internet packets)
- **`picopico.key`** — A secret key file

The goal is to **find a hidden flag** inside that network traffic.

The hint says:
> *"Try using a tool like Wireshark. How can you decrypt the TLS stream?"*

---

## 🤔 What Is TLS? (Simple Explanation)

Imagine you're sending a letter, but you put it inside a **locked box** before mailing it.
Only the person with the **right key** can open the box and read the letter.

That's basically what **TLS** does on the internet — it **encrypts** (locks) network traffic so no one can read it in transit.

In this challenge, someone recorded all those locked boxes (the `.pcap` file).
We also have the **private key** (`picopico.key`) that was used to lock them.
So we can **unlock and read** everything!

---

## 🛠️ Tools You Need

| Tool | What It Does |
|------|-------------|
| `wget` | Downloads files from the internet |
| `tshark` | Command-line version of Wireshark — reads network captures |
| `xxd` | Converts hex (computer code) to readable text |

Install tshark if needed:
```bash
sudo apt install tshark
```

---

## 📥 Step 1 — Download the Files

First, we grab both challenge files from the server.

```bash
wget -O capture.pcap "https://challenge-files.picoctf.net/c_fickle_tempest/d1e9add4e31989553f239ebf71ba5972f9bed7bd4932f931e14bfba80d75f815/capture.pcap"

wget -O picopico.key "https://challenge-files.picoctf.net/c_fickle_tempest/d1e9add4e31989553f239ebf71ba5972f9bed7bd4932f931e14bfba80d75f815/picopico.key"
```

✅ **Result:** Both files are now saved locally.

---

## 🔑 Step 2 — Look at the Key File

```bash
cat picopico.key
```

**Output:**
```
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCwKlFP...
-----END PRIVATE KEY-----
```

### What Does This Mean?

The `-----BEGIN PRIVATE KEY-----` header tells us this is an **RSA Private Key** in PEM format.

Think of it like a **master key** to a lock. If we have this key, we can unlock (decrypt) the encrypted network traffic.

✅ **Confirmed:** We have a valid RSA private key. We can use this to decrypt the TLS traffic.

---

## 📊 Step 3 — Get a Bird's-Eye View of the Network Capture

```bash
tshark -r capture.pcap -q -z io,phs
```

**Output:**
```
Protocol Hierarchy Statistics
eth        frames:110
  ip       frames:110
    tcp    frames:110
      tls  frames:29
```

### What Does This Mean?

- **110 total packets** were captured
- **29 of them are TLS** (encrypted HTTPS traffic)
- There's no plain HTTP — everything is locked/encrypted
- The flag must be **hidden inside the TLS traffic**

✅ **Confirmed:** Target is the encrypted TLS stream.

---

## 🌐 Step 4 — Find the Server's IP Address and Port

```bash
tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields -e ip.dst -e tcp.dstport
```

**Output:**
```
172.31.22.220    443
172.31.22.220    443
172.31.22.220    443
172.31.22.220    443
```

### What Does This Mean?

- **`tls.handshake.type == 1`** means we're looking for the "Client Hello" — the first message sent when a TLS connection starts (like knocking on a door)
- The server is at IP **`172.31.22.220`** on port **`443`** (the standard HTTPS port)
- There were **4 separate TLS connections** to this server

✅ **We now know exactly where to aim our decryption.**

---

## 🔓 Step 5 — Decrypt the TLS Traffic and Read HTTP Data

This is the **key step**. We tell `tshark` to use our private key to unlock the TLS traffic:

```bash
tshark -r capture.pcap \
  -o "tls.keys_list:172.31.22.220,443,http,picopico.key" \
  -Y "http" \
  -T fields \
  -e http.request.uri \
  -e http.response.code \
  -e http.file_data
```

### What Does This Command Do?

| Part | Meaning |
|------|---------|
| `-r capture.pcap` | Read from our capture file |
| `-o "tls.keys_list:..."` | "Hey tshark, use THIS private key to decrypt TLS on this IP and port" |
| `-Y "http"` | Only show decrypted HTTP traffic |
| `-e http.request.uri` | Show the URL that was requested |
| `-e http.response.code` | Show the response code (200 = OK, 404 = not found) |
| `-e http.file_data` | Show the actual file content (in hex) |

**Output (summarized):**

```
/second.html       200    3c21646f63747970652068746d6c3e...
/starter-template.css   200    626f6479207b...
/vulture.jpg       200    ffd8ffe000104a46494600...7069636f4354467b686f6e65792e726f61737465642e7065616e7574737d...
/favicon.ico       404    ...
```

### What Do We See?

The server was serving a small website with these files:
- `second.html` — a webpage
- `starter-template.css` — a stylesheet
- **`vulture.jpg`** — an image file ← **🚨 This is suspicious!**
- `favicon.ico` — the little icon in browser tabs (not found)

Inside the raw hex data of `vulture.jpg`, there's something interesting hidden...

---

## 🕵️ Step 6 — Spot the Hidden Flag in the Image

Look carefully at the raw hex output from `vulture.jpg`. Hidden inside the JPEG binary data is this hex sequence:

```
7069636f4354467b686f6e65792e726f61737465642e7065616e7574737d
```

This is the flag, but written in **hexadecimal** (a number system computers use internally).

---

## 🔡 Step 7 — Decode the Hex to Readable Text

```bash
echo "7069636f4354467b686f6e65792e726f61737465642e7065616e7574737d" | xxd -r -p
```

### What Does This Command Do?

- `echo "..."` — prints the hex string
- `xxd -r -p` — converts hex back to regular text (`-r` = reverse, `-p` = plain mode)

**Output:**
```
picoCTF{honey.roasted.peanuts}
```

---

## 🚩 FLAG FOUND!

```
picoCTF{honey.roasted.peanuts}
```

---

## 🗺️ Full Attack Path (Summary)

```
Download Files
     │
     ▼
Inspect private key → Confirmed RSA private key (can decrypt TLS)
     │
     ▼
Analyze PCAP → 29 TLS frames, all going to 172.31.22.220:443
     │
     ▼
Decrypt TLS using private key → Exposed hidden HTTP traffic
     │
     ▼
Found vulture.jpg → Contains hidden flag in EXIF/binary data
     │
     ▼
Decode hex → picoCTF{honey.roasted.peanuts} 🎉
```

---

## 📚 Key Concepts Learned

### 1. 🔐 TLS Encryption and Its Weakness
TLS encrypts internet traffic so no one can snoop on it.
BUT — if the server uses **RSA key exchange** (old method), anyone who has the **private key** can decrypt ALL past recordings of the traffic.

This is why modern websites use **Forward Secrecy** (ECDHE) — even if someone steals the key later, they CANNOT decrypt old recordings.

### 2. 🖼️ Data Hidden in Images (Steganography)
The flag was hidden inside a JPEG image's **EXIF metadata** — the invisible data section that normally stores camera info (like GPS location, camera model, date taken).

You can always check for hidden data in images using:
```bash
exiftool image.jpg
strings image.jpg
```

### 3. 🦈 Using tshark for TLS Decryption
`tshark` (and Wireshark) can automatically decrypt TLS sessions if you provide the server's private key. This is a powerful forensic technique used by security analysts.

### 4. 🔢 Hex Encoding
Computers store everything as numbers. Hex (base-16) is a common way to represent raw binary data. The `xxd` tool lets you convert between hex and readable text easily.

---

## 🛡️ Real-World Lesson

This challenge simulates a **real attacker scenario**:
1. An attacker captures HTTPS traffic (via packet sniffer like Wireshark)
2. They later steal the server's private key (via breach, vulnerability, etc.)
3. They go back and decrypt ALL previously recorded traffic

**Defense:** Use TLS 1.3 with Forward Secrecy enabled. This makes old traffic safe even if the key is later compromised.

---

*Writeup by: CTF Student | Challenge: picoCTF WebNet1*