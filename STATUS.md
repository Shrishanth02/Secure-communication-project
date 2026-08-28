# Project Status

**Project:** Secure Communication (encrypted file vault)
**Status:** Complete - hardened, tested, and production-ready
**Version:** 1.0
**Last updated:** 28 August 2026
**Repository:** https://github.com/Shrishanth02/Secure-communication-project

Keep this file up to date whenever you change the project, so anyone (including
future you) can see where things stand at a glance.

---

## 1. Current state (summary)

The application is finished and working end to end. It was rebuilt from a broken
original into a secure, modern app, then hardened and penetration-tested. It runs
locally with no external services and is ready to be deployed online.

- Runs on: Python 3.10+, Django 4.2, SQLite (built in).
- User interface: complete, responsive, "Defender Maroon" theme.
- Security: real X25519 ECDH + AES-256-GCM + Argon2; hardened and reviewed.
- Documentation: complete (see section 6).

---

## 2. What is implemented

| Area | Status |
|---|---|
| Sign up / log in / log out | Done |
| Upload and encrypt a file | Done |
| Download and decrypt (owner only) | Done |
| File integrity check (SHA-256) | Done |
| Per-user access control (no cross-user access) | Done |
| Modern responsive UI (all 5 screens) | Done |
| Architecture diagram + full docs | Done |
| Production config (headers, HTTPS, secure cookies) | Done |

## 3. Security controls in place

- X25519 ECDH key agreement, fresh per file.
- HKDF-SHA256 key derivation, bound to `owner|filename`.
- AES-256-GCM authenticated encryption (random nonce; `owner|filename` as AAD).
- SHA-256 integrity fingerprint.
- Argon2id password hashing, with a password strength policy.
- Session-based login with session rotation; per-IP login throttling.
- Encrypted files stored in a private folder outside the web root.
- Filename sanitisation and path-traversal protection.
- Per-user file quota; 10 MB upload limit.
- Security headers (CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy).
- Fail-closed configuration: production requires a real secret key and DEBUG off.

## 4. Testing status (all passing)

- Functional: sign up, login, upload/encrypt, download/decrypt (identical file
  returned), integrity check (clean pass, tamper detected).
- Security: SQL injection blocked, cross-user access denied, CSRF blocked, XSS via
  filename neutralised, path traversal blocked, tampering detected, brute-force
  throttled.
- Red-team review: 18 findings examined - 16 fixed, 2 low-risk accepted, none
  severe. Details in `PENTEST.md`.
- `python manage.py check --deploy`: clean with a real secret key.

## 5. Known limitations and accepted items

These are safe for the current scope but are the natural things to improve next.

- Login throttling uses the local-memory cache (per process). For a multi-worker
  deployment, back it with Redis or add `django-axes`.
- One application-wide receiver key protects all files. Per-user keys would give
  full cryptographic separation between accounts.
- No file delete or rename feature yet; storage grows until the per-user quota.
- Content-Security-Policy allows inline styles (`style-src 'unsafe-inline'`). No
  known exploit; scripts are locked to `'self'`.
- Sign-up tells you if a username is already taken (a usability choice; login
  throttling limits automated probing).

## 6. Documentation

| File | Purpose |
|---|---|
| `README.md` | Overview, screenshots, architecture diagram, security summary |
| `HOW_TO_RUN.md` | How to install, run, use, and troubleshoot |
| `SECURITY.md` | Original vulnerability assessment and remediation (before/after) |
| `PENTEST.md` | Penetration test and red-team findings with resolutions |
| `DEPLOYMENT.md` | How to host the app online (production) |
| `STATUS.md` | This file - current status and roadmap |
| `Secure_Communication_Project_Documentation.docx` | Full illustrated user guide (kept locally) |

## 7. Roadmap (possible future updates)

- Per-user encryption keys for stronger account separation.
- File sharing between users with permissions.
- Delete and rename files.
- Store the master key in a secrets manager / KMS.
- Two-factor login (2FA).
- Redis-backed rate limiting for multi-worker deployments.
- Deploy to a cloud host with an HTTPS domain.

## 8. How to make an update

1. **Get the latest code** (if working on another machine):
   ```
   git clone https://github.com/Shrishanth02/Secure-communication-project
   ```
   or, in an existing copy: `git pull`
2. **Set up once:** `pip install -r requirements.txt` then `python manage.py migrate`
3. **Run it locally:** double-click `run.bat` (or `set DJANGO_DEBUG=True` then
   `python manage.py runserver`), and open `http://127.0.0.1:8000/index.html`.
4. **Make your change** in the code (see the file map in `README.md`).
5. **Test it:** click through the app, and run `python manage.py check`.
6. **Save and publish:**
   ```
   git add -A
   git commit -m "Describe your change"
   git push
   ```
7. **Update this file** (`STATUS.md`): change the "Last updated" date and move any
   finished roadmap item into "What is implemented".

## 9. Change history

| Date | Change |
|---|---|
| 28 Aug 2026 | Added run guide and status file |
| 28 Aug 2026 | Production hardening, UI, architecture diagram, and pentest remediation |
| 28 Aug 2026 | Security rebuild: real X25519 ECDH + AES-256-GCM, removed SQL injection, hashed passwords |
| (earlier) | Initial version (original college project) |
