# Deployment Guide

This app is production-ready: it runs on SQLite with WhiteNoise for static files
and ships hardened security settings that switch on automatically when
`DJANGO_DEBUG=False`. It has no external service dependencies.

---

## 1. Environment variables

Copy [`.env.example`](.env.example) and set real values:

```bash
DJANGO_SECRET_KEY=<64+ random chars>     # python -c "import secrets;print(secrets.token_urlsafe(64))"
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=yourdomain.com
DJANGO_CSRF_TRUSTED_ORIGINS=https://yourdomain.com
```

When `DEBUG=False` the app automatically enables: HTTPS redirect, HSTS
(1 year, subdomains, preload), `Secure` + `HttpOnly` + `SameSite=Lax` session &
CSRF cookies, and the `CompressedManifestStaticFilesStorage` for static assets.
Always-on: CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy`, `Permissions-Policy`, and a 10 MB upload cap.

## 2. Install, migrate, collect static

```bash
pip install -r requirements.txt
python manage.py migrate
python manage.py collectstatic --no-input
```

## 3. Run a production WSGI server

**Linux (Gunicorn):**

```bash
pip install gunicorn
gunicorn Secure.wsgi:application --bind 0.0.0.0:8000 --workers 3
```

**Windows / cross-platform (Waitress, already in requirements):**

```bash
waitress-serve --listen=0.0.0.0:8000 Secure.wsgi:application
```

## 4. Put TLS in front

Terminate HTTPS at a reverse proxy (nginx, Caddy, or your platform's load
balancer) and forward to the WSGI server. Ensure the proxy sets
`X-Forwarded-Proto: https` — the app already trusts that header
(`SECURE_PROXY_SSL_HEADER`) to detect HTTPS behind the proxy.

Minimal nginx location block:

```nginx
location / {
    proxy_pass         http://127.0.0.1:8000;
    proxy_set_header   Host $host;
    proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Proto $scheme;
}
```

WhiteNoise serves `/static/` from the app itself, so no separate static host is
required (you may still front it with a CDN).

## 5. Persistent data & secrets — back these up, never commit them

| Path | What it is |
|---|---|
| `db.sqlite3` | Accounts (Argon2 hashes) and file metadata |
| `secure_store/` | Encrypted files (ciphertext), outside the web root |
| `SecureApp/secure_keystore/receiver.key` | The server's X25519 **private** key |

**If `receiver.key` is lost, previously uploaded files cannot be decrypted.**
In a hardened deployment, store it in a secrets manager / KMS and mount it at
runtime, and restrict filesystem permissions (`chmod 600`).

## 6. Verify the deployment

```bash
DJANGO_DEBUG=False DJANGO_SECRET_KEY=... python manage.py check --deploy
```

Expect no warnings once a strong `SECRET_KEY` is set.

---

## One-command local production smoke test

```bash
DJANGO_DEBUG=False \
DJANGO_SECRET_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(64))')" \
DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost \
DJANGO_SECURE_SSL_REDIRECT=False \
sh -c 'python manage.py collectstatic --no-input && waitress-serve --listen=127.0.0.1:8000 Secure.wsgi:application'
```
