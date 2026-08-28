# Security Assessment & Remediation Report

This document records a security review of the original *Secure Communication*
application and the fixes applied. The original code presented a strong title
("Diffie-Hellman + AES + SHA") but the implementation was cryptographically
broken and exposed several critical web vulnerabilities. All findings below were
remediated and verified.

**Summary:** 8 findings — **5 Critical, 2 High, 1 Medium** — all fixed.

---

## Findings & remediation

### 1. Broken key exchange (Critical)
- **Before:** "Diffie-Hellman" used the textbook parameters `P=23, G=9` and
  simulated *both* parties inside a single function, returning a shared value in
  the range 0–22. The effective key space was **23 possibilities** — brute-forced
  instantly.
- **After:** Real **X25519 Elliptic-Curve Diffie-Hellman** with a fresh ephemeral
  key pair per file (ephemeral-static / "sealed box" construction). 128-bit
  security level.

### 2. Weak key derivation (Critical)
- **Before:** The AES key was derived from a **hardcoded password**
  (`"s3cr3t*c0d3"`) with the 0–22 DH value used as the salt. Any attacker with
  the source could derive every key.
- **After:** **HKDF-SHA256** derives a 256-bit key from the ECDH shared secret
  using a random 16-byte per-file salt. No secrets in source code.

### 3. AES nonce/counter reuse (Critical)
- **Before:** AES-**CTR** mode with a single **hardcoded counter constant** reused
  for every file. Reusing a keystream across messages under one key allows
  recovering plaintext by XOR — a catastrophic failure.
- **After:** **AES-256-GCM** with a fresh random 96-bit nonce per file. GCM is an
  AEAD cipher providing confidentiality *and* authenticity.

### 4. SQL injection (Critical)
- **Before:** Login, signup, upload and hashcode lookups built SQL by string
  concatenation, e.g. `"select ... where filename='"+filename+"'"` and raw
  `INSERT` statements — classic SQL injection.
- **After:** All database access uses the **Django ORM** with parameterized
  queries. A `' OR '1'='1` login probe now returns *login failed*.
  *(Tested.)*

### 5. Plaintext password storage (Critical)
- **Before:** Passwords stored as `varchar(50)` in cleartext and compared
  directly on login.
- **After:** Passwords stored as **Argon2id** hashes via Django's password
  hashers (`make_password` / `check_password`). Verified: the stored field is
  `argon2$argon2id$...`.

### 6. Missing authentication & access control (High)
- **Before:** Session state was a module-level `global uname`; views performed no
  login check; the download/integrity pages listed **every user's files**, and
  anyone could download and decrypt them.
- **After:** Proper **Django session** authentication, a login guard on every
  protected view, and **per-owner filtering** so users can only see, download,
  and verify their own files. Verified: user *bob* cannot access user *alice*'s
  file (`access denied`), and unauthenticated requests are redirected to login.

### 7. Deprecated integrity hash (Medium/High)
- **Before:** **SHA-1** (deprecated, collision-broken) used for the integrity
  hashcode.
- **After:** **SHA-256**. Additionally, message integrity/authenticity is now
  intrinsic to AES-GCM — a tampered ciphertext fails to decrypt
  (`InvalidTag`). *(Tested with a bit-flip.)*

### 8. Insecure configuration & data handling (Medium)
- **Before:** `DEBUG=True` and a hardcoded `SECRET_KEY` committed to source;
  files read via `codecs.decode`, breaking on binary input; a required MySQL
  server with a blank `root` password.
- **After:** `SECRET_KEY` and `DEBUG` are read from environment variables (safe
  local fallback, and the old committed key was rotated); files are handled as
  **raw bytes** (binary-safe); the app runs on **SQLite** with no external
  server or default credentials. The receiver private key lives in a
  **git-ignored keystore**.

---

## Verification

All fixes were validated with automated crypto self-tests and a live end-to-end
HTTP test:

- Encrypt → decrypt round-trip on binary data — **pass**
- Fresh ephemeral key + nonce per file (no keystream reuse) — **pass**
- AES-GCM tamper detection (`InvalidTag`) — **pass**
- SQL-injection login probe (`' OR '1'='1`) rejected — **pass**
- Passwords stored as Argon2id hashes — **pass**
- Cross-user download blocked; unauthenticated access blocked — **pass**
- Integrity check: clean file passes, tampered file fails — **pass**

---

## Residual notes / production hardening

- The receiver private key is stored on the local filesystem; a production
  deployment should use a secrets manager or HSM.
- Serve over HTTPS and set `SESSION_COOKIE_SECURE` / `CSRF_COOKIE_SECURE`.
- Consider per-user key pairs for true end-to-end (rather than server-held)
  decryption.
