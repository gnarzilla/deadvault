# Deadlight Credential Vault | Auto-Authentication Without the Internet

![vault.deadlight](https://img.shields.io/badge/vault-alpha-yellow)
![deps](https://img.shields.io/badge/deps-openssl-blue)
![crypto](https://img.shields.io/badge/crypto-ChaCha20--Poly1305-blue)

[Why This Exists](#why-this-exists) · [Quick Start](#quick-start) · [How It Works](#how-it-works) · [Integration](#proxy-integration) · [Roadmap](#roadmap)

A local-first vault that auto-authenticates CLI tools and proxied requests when networks are hostile or nonexistent.

> Status: MVP core working — init, add/list/show/delete, `exec` token substitution,
> export/import, and non-interactive unlock via `DEADVAULT_PASSWORD`.
> SSH-agent integration and the vault-side proxy socket API are not yet built.
> A proof-of-concept credential-injection plugin exists on the proxy side.
> Security audit pending; not recommended for production secrets yet.

## Why this exists

SSH into 15 servers a day. Curl 10 APIs. You authenticate to internal services over a VPN that drops every 20 minutes. **Typing passwords is the bottleneck.** Or it is for me at least, so I'm building this.

Password managers solve this for browsers. Nothing solves it for terminals and proxied connections in the field.

| Actual workflows | Why existing tools fail | How deadvault works |
|---------------------|-------------------------|---------------------------|
| **SSH to 10 boxes during an incident** | Type password 10 times or set up keys (but you're on a borrowed laptop) | Keys stored encrypted; per-command injection via `exec` today (ssh-agent auto-load planned) |
| **curl GitHub API from satellite link** | Type token, connection drops mid-paste, retry | Token stored locally, injected into request headers. Works offline |
| **Authenticate through proxy.deadlight** | Browser extensions don't work with SOCKS/HTTP proxies | PoC plugin on the proxy side consumes vault credentials and injects server-side |
| **Field laptop dies, switch to backup** | Cloud password managers need internet to sync | Export encrypted DB → USB stick → Import. 30 seconds, zero network |

**deadvault's core purpose is to eliminate manual credential entry for CLI tools and proxies.**

## Part of the Deadlight Ecosystem

deadvault extends **deadlight-proxy** with credential injection. Works standalone for CLI workflows, but shines when paired with the proxy.

```
┌──────────────────────────────────────┐
│      Deadlight Stack (Optional)      │
└──────────────────────────────────────┘

    ┌──────────────┐         ┌──────────────┐
    │    vault     │────────►│    proxy     │
    │  .deadlight  │  inject │  .deadlight  │
    │              │  creds  │              │
    │ CLI auto-    │         │ SOCKS/HTTP/  │
    │ auth + store │         │ MITM gateway │
    └──────────────┘         └──────────────┘

           │  (reuses crypto)
           ▼

    ┌──────────────┐
    │     lib      │
    │  .deadlight  │
    │   C crypto   │
    └──────────────┘
```

**Standalone mode:** Auto-auth for SSH keys, curl, git, any CLI tool
**With proxy:** Credential injection into proxied requests (proof of concept; generalizing now)

## Quick Start

### Build from source (2 minutes)

```bash
# Clone repository
git clone https://github.com/gnarzilla/deadvault
cd deadvault

# Build (links OpenSSL)
make
# → Outputs: deadvault (~1.2 MB)

# Initialize vault
./deadvault init
# Prompts for master password
# Creates ~/.deadlight/vault.db (encrypted SQLite)

# Add your first credential
./deadvault add github-api \
    --type token \
    --value ghp_xxxxxxxxxxxx

# Use it
./deadvault exec github-api -- \
    curl -H "Authorization: Bearer {TOKEN}" \
    https://api.github.com/user
# → {TOKEN} replaced with decrypted value, no clipboard involved

# Skip the password prompt (scripts, wrappers)
DEADVAULT_PASSWORD='...' ./deadvault list
```

Your credentials are now offline-available and never touch your keyboard again.

## How It Works

### The 30-second version

1. **Encrypt at rest:** Master password → PBKDF2-SHA256 (100k iterations) → ChaCha20-Poly1305 key → Encrypted SQLite blobs
2. **Decrypt on demand:** `deadvault exec github-api -- curl ...` → Decrypt token → Inject into command
3. **Wipe immediately:** Decrypted credential lives in memory briefly, then `secure_zero`
4. **Proxy mode (in progress):** PoC plugin on the proxy side consumes vault-stored credentials and injects them into proxied traffic. The vault-side socket API it needs is not yet built.

### The cryptographic details

~300 LOC of public domain C (ChaCha20-Poly1305 + PBKDF2-SHA256):

```c
// Key derivation (master password → encryption key)
pbkdf2_sha256(
    master_password,
    salt,               // Random per-vault, stored in DB
    100000,             // Iterations
    derived_key         // 32 bytes for ChaCha20
);

// Encrypt credential
chacha20_poly1305_encrypt(
    plaintext_credential,
    derived_key,
    nonce,              // Random per-credential
    encrypted_blob      // Stored in SQLite
);

// Decrypt on use
chacha20_poly1305_decrypt(
    encrypted_blob,
    derived_key,
    nonce,
    plaintext           // ← Wiped right after use
);

secure_zero(plaintext, length);  // Wipe memory
```

**Why ChaCha20-Poly1305?**
- Software-only (no AES-NI required) → Works on old/embedded hardware
- Authenticated encryption (catches tampering) → Safer than AES-CBC
- ~300 LOC implementation → Auditable in an afternoon
- Public domain code → Zero licensing issues

**Why PBKDF2 over Argon2?**
- Already in lib.deadlight → No new code
- Smaller binary size
- Honest caveat: 100k iterations is modest against GPU-assisted offline attack — which is exactly what a stolen database enables. **Strong master passwords are load-bearing.** Argon2 is the likely direction when this is revisited.

### Database Schema (SQLite)

```sql
CREATE TABLE vault_meta (
    version INTEGER,
    salt BLOB,              -- For master key derivation
    created_at INTEGER
);

CREATE TABLE credentials (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE,       -- "github-api", "aws-prod", "ssh-bastion"
    type TEXT,              -- "token", "password", "ssh_key"
    encrypted_value BLOB,   -- ChaCha20-Poly1305 encrypted
    nonce BLOB,             -- Random per-credential
    metadata TEXT,          -- JSON: {"expires": "2026-12-31", "username": "..."}
    created_at INTEGER,
    last_used INTEGER
);
```

**Total size for 50 credentials:** tens of KB encrypted

## Core Features

### What it does
- **Encrypts credentials locally** – SQLite database, ChaCha20-Poly1305
- **Auto-injects into CLI commands** – `deadvault exec name -- command` (`{TOKEN}` / `{PASSWORD}` substitution)
- **Non-interactive unlock** – `DEADVAULT_PASSWORD` env var skips the password prompt (for scripts and wrappers)
- **Biometric unlock wrapper** – Termux-only, experimental Level 1 (see below)
- **Offline export/import** – Encrypted DB dumps for airgapped transfers
- **Memory safety** – Secure wipes on credential material

### What it doesn't (yet) do
- X SSH-agent auto-load on unlock (planned — `unlock` is non-persistent in the MVP, each command re-derives the key)
- X Vault-side proxy socket API (a PoC plugin exists on the proxy side; the vault side is in progress)
- X Browser integration (use your browser's password manager)
- X Cloud sync (export/import manually, or use encrypted USB sticks)
- X 2FA/TOTP generation (out of scope, use `oathtool`)
- X Graphical interface (CLI only, keep it simple)
- X Multi-user vaults (one vault per system user)

### Command Reference

```bash
# Initialize new vault
./deadvault init

# Add credentials
./deadvault add github-api --type token --value ghp_xxx
./deadvault add deploy-key --type ssh_key --file ~/.ssh/id_ed25519
./deadvault add db-pass --type password            # prompts for value
# Flags: --type token|password|ssh_key, --value <val>, --file <path>, --metadata <json>

# List / inspect
./deadvault list
./deadvault show github-api                        # metadata only, never the secret

# Use credential in command (auto-inject)
./deadvault exec github-api -- curl -H "Authorization: Bearer {TOKEN}" https://api.github.com/user

# Non-interactive (scripts, wrappers)
DEADVAULT_PASSWORD='...' ./deadvault list          # no prompt

# Export / import (encrypted, for backup or airgapped transfer)
./deadvault export --output backup.vault.enc
./deadvault import backup.vault.enc

# Lock/unlock
./deadvault lock                                   # wipes derived key (mostly a no-op in one-shot CLI mode)
./deadvault unlock                                 # verifies master password (non-persistent in MVP)

# Delete credential
./deadvault delete github-api
```

### Biometric unlock (Termux, experimental)

A Level 1 convenience wrapper — educational, not the final form. The fingerprint is a **gate, not a key**: on success the wrapper releases the master password from `~/.deadlight/.biometric_pw` (mode 600, Termux app-private storage) into `DEADVAULT_PASSWORD`. It stops a casual phone borrower, not root malware. The master password always remains a fallback.

```bash
# Prerequisites: Termux:API app (same source as your Termux) + pkg install termux-api
cp contrib/dvault contrib/dvault-enroll ~/bin/
chmod +x ~/bin/dvault ~/bin/dvault-enroll

dvault-enroll      # type the master password once, verified against the vault
dvault list        # fingerprint prompt, zero typing
```

## Proxy Integration

**Status: proof of concept.** A credential-injection plugin on the proxy side consumes
vault-stored credentials and injects them into proxied requests server-side, so the
client tool never sees the secret. The vault-side socket API, the domain→credential
mapping configuration, and the schema expansion the plugin needs are not yet built —
that's the current work.

Target flow once generalized:

```
Client (curl) → deadlight-proxy → detects auth needed → asks vault → vault decrypts
→ proxy injects Authorization header → remote API → response back → vault wipes plaintext
```

## Use Cases

### DevOps on Terrible Networks

**Problem:** SSH to 20 AWS instances during incident response. Satellite link drops every 5 minutes.

**Status:** Partially — keys store encrypted today and inject per-command via `exec`; transparent ssh-agent auto-load is planned. Until then, this is the gap that matters most.

### API Workflows Without Clipboard

**Problem:** Testing API endpoints with curl. Copying tokens from 1Password every time.

**Solution:**
```bash
./deadvault add stripe-test --type token --value sk_test_xxx
./deadvault exec stripe-test -- curl https://api.stripe.com/v1/charges \
    -H "Authorization: Bearer {TOKEN}"
```

### Field Laptop Failover

**Problem:** Primary laptop dies. Backup laptop needs all your credentials. No internet.

**Solution:**
```bash
# On primary (before disaster)
./deadvault export --output /mnt/usb/backup.vault.enc

# On backup laptop (after disaster)
./deadvault import /mnt/usb/backup.vault.enc
./deadvault unlock
# All credentials restored, zero network needed
```

### Proxy-Based Infrastructure Access

**Problem:** VPN requires MFA every 2 hours. Internal APIs need tokens. Browser doesn't help.

**Status:** Works against the PoC plugin; generalizing the vault side now.

## Roadmap

### Done (MVP core)
- ChaCha20-Poly1305 implementation (~300 LOC)
- SQLite integration (encrypted blobs)
- CLI: init, add, list, show, exec, delete, export, import
- Memory safety (secure_zero on credential material)
- Non-interactive unlock via `DEADVAULT_PASSWORD`
- Termux biometric wrapper (Level 1, educational)

### In progress
- Proxy-side credential injection (PoC exists; needs schema expansion + vault-side socket API)
- Domain→credential mapping for the proxy

### Planned
- SSH-agent integration (auto-load keys on unlock)
- Persistent unlock / agent daemon — the north star that unifies biometric unlock, ssh-agent, and the proxy socket API
- `vault exec` environment variable injection (not just `{TOKEN}` replacement)
- Expiry handling (warn before credential expires)
- Audit log (optional, disabled by default)

### Explicitly Out of Scope
- Browser extensions (use existing tools)
- Cloud sync (manual export/import is sufficient)
- GUI (CLI-first, always)
- 2FA generation (use `oathtool`)
- Windows support (WSL works, native not planned)

## Security

### Threat Model

**Protected against:**
- Database theft (encrypted; strength depends on the master password — see below)
- Memory dumps (credential material wiped after use)
- Tampering (Poly1305 MAC catches modifications)

**NOT protected against:**
- X Root-level malware (assumes trusted OS)
- X Unlocked vault on compromised system
- X Weak master passwords — no enforcement, and a weak password makes a stolen DB quickly crackable. This is the single most load-bearing user decision in the system.
- X Physical attacks on running system (use full-disk encryption + lock timeouts)

### Why No Cloud Sync?

**By design.** Cloud sync introduces:
- Network dependency (defeats offline-first goal)
- Third-party trust (Dropbox/iCloud/etc sees encrypted blobs)
- Complex conflict resolution
- Larger attack surface

**Alternative:** Manual encrypted exports. Transfer via USB, LoRa, encrypted email—whatever your threat model allows.

### Audit Status

- **Crypto implementation:** Public domain ChaCha20-Poly1305 (reference: DJB's code)
- **KDF:** PBKDF2-SHA256, 100k iterations (see caveat above)
- **SQLite:** Industry standard, used by browsers/phones/everything
- **Total custom code:** ~800 LOC (excluding SQLite amalgamation)

**Not yet audited by professionals.** Use at your own risk. Contributions welcome.

## Building from Source

### Prerequisites

```bash
# Debian/Ubuntu
apt-get install build-essential libssl-dev

# Alpine
apk add gcc musl-dev openssl-dev

# macOS
xcode-select --install
# + OpenSSL via Homebrew: brew install openssl

# Termux (Android)
pkg install git clang make openssl
```

### Compile

```bash
git clone https://github.com/gnarzilla/deadvault
cd deadvault
make

# Output: ./deadvault (~1.2 MB, links OpenSSL)
```

### Cross-compile for ARM

```bash
# Raspberry Pi
make CC=aarch64-linux-gnu-gcc

# Android (Termux)
# Already native, just run `make`
```

### Run Tests

```bash
make test

# PBKDF2/crypto primitive tests
make test-pbkdf2
```

## FAQ

**Q: Why not just use `pass` or `gopass?**
A: Those are great for managing passwords. deadvault is focused on *auto-injection* into CLI tools and proxy.deadlight integration. Different goals.

**Q: Is this trying to replace 1Password/Bitwarden?**
A: No. Use those for browsers. This is for terminals and proxied connections.

**Q: Why does every command ask for the master password?**
A: Unlock is non-persistent in the MVP — each invocation re-derives the key. Use `DEADVAULT_PASSWORD` for scripts, or the biometric wrapper on Termux. A persistent agent daemon is the planned fix.

**Q: Can I import from other password managers?**
A: Not yet. For now, manual `deadvault add` commands.

**Q: What if I forget my master password?**
A: You lose all credentials. No recovery mechanism by design. Write it down.

**Q: Does this work on Windows?**
A: WSL works. Native Windows support not planned (accept PRs though).

**Q: Why SQLite instead of flat files?**
A: Atomic transactions (corruption resistance), easier querying for proxy, better tooling.

**Q: How do I back up my vault?**
A: `deadvault export` creates an encrypted dump. Store on USB stick, encrypted cloud storage, whatever. Never commit `*.db`, `*.vault.enc`, or `.biometric_pw` to git.

## Contributing

Open to PRs for:
- Bug fixes
- Documentation improvements
- Test coverage
- Platform support (BSD, etc.)

## License

MIT (see [LICENSE](LICENSE))

ChaCha20-Poly1305 implementation is public domain (DJB's original code)

## Contact

- **GitHub:** [@gnarzilla](https://github.com/gnarzilla)
- **Email:** gnarzilla@deadlight.boo