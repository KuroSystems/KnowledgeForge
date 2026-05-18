<div align="center">

```
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║    ⚡  K N O W L E D G E F O R G E   v 1 . 0  ⚡            ║
║                                                               ║
║         Local RAG Intelligence — Forged in Go                ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
```

<br/>

[![Go](https://img.shields.io/badge/Built%20with-Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://golang.org)
[![RAG](https://img.shields.io/badge/Architecture-RAG-FF6B35?style=for-the-badge&logo=lightning&logoColor=white)](https://github.com)
[![Ollama](https://img.shields.io/badge/LLM-Ollama-8A2BE2?style=for-the-badge&logo=ollama&logoColor=white)](https://ollama.ai)
[![TUI](https://img.shields.io/badge/Interface-Terminal%20UI-1A1A2E?style=for-the-badge&logo=windowsterminal&logoColor=white)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)

<br/>

> **A blazing-fast, fully local RAG (Retrieval-Augmented Generation) knowledge assistant**  
> *built in Go — query your markdown writeups with the power of local LLMs.*

<br/>

---

</div>

## ◈ What is KnowledgeForge?

**KnowledgeForge** is a terminal-based RAG knowledge assistant that indexes your local markdown files and lets you query them using locally-running LLMs via Ollama. No cloud. No API keys. No data leaves your machine.

It was built for **security researchers, CTF players, and bug bounty hunters** who maintain markdown writeups and want instant, intelligent recall across their entire knowledge base — right from the terminal.

```
  Your .md Writeups  →  Chunked & Embedded  →  Vector Index
                                                     ↓
  Your Query  ──────────────────────────────→  Semantic Search
                                                     ↓
  Local LLM (Ollama)  ←─────────── Relevant Chunks Retrieved
       ↓
  Synthesized Answer — entirely on your machine ⚡
```

<br/>

---

## ◈ Features

| Feature | Description |
|---------|-------------|
| ⚡ **Blazing Fast** | Written in Go — sub-400ms responses on local hardware |
| 🔒 **100% Local** | No telemetry, no API keys, no internet required |
| 🧠 **Smart Chunking** | Markdown files are chunked semantically for precision retrieval |
| 🔄 **Multi-Model** | Switch between LLMs (phi, gemma, mistral, etc.) on the fly |
| 🎛️ **Synthesis Mode** | Toggle between RAG-grounded answers and full synthesis |
| 📁 **Organized Knowledge** | Folder-based knowledge hub — CTF, bug bounty, research |
| 🖥️ **Beautiful TUI** | Split-panel terminal interface with real-time status bar |
| 📄 **1239+ Chunks** | Scales to large writeup collections without degradation |

<br/>

---

## ◈ Repository Structure

```
KnowledgeForge/
│
├── 📁 writeups/                    # Your knowledge base (markdown files)
│   ├── 📂 CTF/                     # Capture The Flag writeups
│   │   ├── Flag_in_Flame_simple.md
│   │   ├── Heap_Havoc_hard_lab.md
│   │   ├── Investigative_Reversing.md
│   │   ├── Invisible_WORDs_hard.md
│   │   ├── MSS_ADVANCE_Revenge.md
│   │   ├── MY_GIT_easy_lab.md
│   │   ├── PowerAnalysis_part2.md
│   │   ├── Printer_Shares_3_hard.md
│   │   ├── Sequences_hard_lab.md
│   │   ├── Sum-O-Primes_hard_lab.md
│   │   ├── Undo_easy_lab.md
│   │   ├── WebNet1_Hard_lab.md
│   │   └── m00nwalk2_hard_lab.md
│   │
│   └── 📂 bug_bounty/              # Bug Bounty program notes
│       ├── Circle_BBP.md
│       ├── Notion_Labs.md
│       └── Whatnot.md
│
└── 🔧 knowledgeforge                # Pre-compiled binary (ready to run)
```

> **Note:** Drop your `.md` writeup files into the `writeups/` folder — KnowledgeForge auto-indexes on startup.

<br/>

---

## ◈ Prerequisites

Before running KnowledgeForge, make sure you have **Ollama** installed and at least one model pulled:

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a lightweight model (recommended for speed)
ollama pull gemma:2b

# Or pull a more powerful one
ollama pull phi
ollama pull mistral
```

<br/>

---

## ◈ Installation & Usage

### Option 1 — Use the Pre-built Binary (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/KnowledgeForge.git
cd KnowledgeForge

# 2. Make the binary executable
chmod +x knowledgeforge

# 3. Add your writeups to the writeups/ folder
#    (or use the included ones to get started)

# 4. Launch KnowledgeForge
./knowledgeforge
```

### Option 2 — Build from Source

```bash
# Requires Go 1.21+
git clone https://github.com/yourusername/KnowledgeForge.git
cd KnowledgeForge

go build -o knowledgeforge .
./knowledgeforge
```

<br/>

---

## ◈ Interface & Keyboard Shortcuts

```
┌─────────────────────┬────────────────────────────────────────┐
│  LEFT PANEL         │  RIGHT PANEL                           │
│  Knowledge Hub      │  RAG Chat                              │
│  (File Browser)     │  (Query Interface)                     │
└─────────────────────┴────────────────────────────────────────┘
```

| Keybind | Action |
|---------|--------|
| `Enter` | Send query to the LLM |
| `Tab` | Switch between panels |
| `Ctrl+S` | Toggle **Synthesis Mode** (grounded ↔ free-form) |
| `Ctrl+R` | **Switch LLM model** (cycle through Ollama models) |
| `PgUp / PgDn` | Scroll through chat history |
| `Ctrl+C` | Quit |

<br/>

---

## ◈ Adding Your Own Writeups

KnowledgeForge auto-discovers and indexes any `.md` file placed inside the `writeups/` directory:

```bash
# Add a CTF writeup
cp my_ctf_writeup.md writeups/CTF/

# Add a bug bounty report
cp my_bbp_notes.md writeups/bug_bounty/

# Restart KnowledgeForge — it will re-index automatically
./knowledgeforge
```

**Supported format:** Standard Markdown (`.md`)  
**Recommended structure:** Use headers (`##`), code blocks (` ``` `), and bullet points for best chunking quality.

<br/>

---

## ◈ Example Queries

Once running, try queries like:

```
> What techniques did I use for heap exploitation in Heap_Havoc?

> Summarize my findings from the Notion Labs bug bounty program.

> What flags did I find related to steganography?

> How did I approach the PowerAnalysis challenge?
```

KnowledgeForge retrieves the most semantically relevant chunks from your writeups and synthesizes a precise answer.

<br/>

---

## ◈ Tech Stack

```
Language    →  Go 1.21+
LLM Backend →  Ollama (local inference)
Models      →  gemma:2b, phi, mistral (swappable)
Embeddings  →  Local embedding model via Ollama
Vector DB   →  In-memory semantic index
TUI         →  Bubble Tea / Lip Gloss
Chunking    →  Sliding window with markdown-aware splitting
```

<br/>

---

## ◈ Performance

Benchmarked on a standard development machine:

| Metric | Value |
|--------|-------|
| Indexing Speed | ~1239 chunks in < 5s |
| Query Latency | ~378ms (gemma:2b) |
| Memory Usage | Lightweight Go binary |
| Knowledge Files | 17 files across 2 categories |

<br/>

---

## ◈ Roadmap

- [ ] 🔍 Persistent vector index (no re-indexing on restart)
- [ ] 🌐 Web UI mode alongside TUI
- [ ] 📤 Export conversation as markdown
- [ ] 🗂️ Tag-based filtering per knowledge category
- [ ] 🔗 Multi-file cross-reference synthesis
- [ ] 📊 Relevance scoring display in chat panel

<br/>

---

## ◈ Contributing

Contributions are welcome. If you have writeup templates, chunking improvements, or UI enhancements:

```bash
# Fork → Clone → Branch → PR
git checkout -b feat/your-feature
git commit -m "feat: describe your change"
git push origin feat/your-feature
```

<br/>

---

## ◈ License

```
MIT License — use it, fork it, forge it.
```

<br/>

---

<div align="center">

```
⚡  Built for the ones who document everything and forget nothing.  ⚡
```

*KnowledgeForge — because your writeups deserve more than* `grep`

<br/>

**[⬆ Back to Top](#)**

</div>
