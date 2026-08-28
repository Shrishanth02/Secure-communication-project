# How to Run - Secure Communication

A short, practical guide to running the application, using it, and understanding
how it works. No prior technical knowledge is required.

---

## 1. What you need

- **Python 3.10 or newer** installed. Download it from https://www.python.org/downloads/
  and, on the installer's first screen, tick **"Add Python to PATH"**.
- That's all. There is no separate database or server to install - the app uses a
  built-in database (SQLite).

To check Python is installed, open **Command Prompt** and run:

```
python --version
```

---

## 2. First-time setup (do this once)

Open **Command Prompt**, move into the project folder, and run the two commands below.

```
cd "C:\Users\91809\Downloads\PROJECT SAMANVAY\Secure-communication-project"
```

```
pip install -r requirements.txt
```

```
python manage.py migrate
```

- The first command installs the packages the app needs.
- The second creates the database. You only run these once.

---

## 3. Run the app (every time)

**Easiest way:** double-click **`run.bat`** in the project folder. A window opens
and starts the server. Leave that window open while you use the app.

**Or, from Command Prompt** (inside the project folder):

```
set DJANGO_DEBUG=True
```

```
python manage.py runserver
```

When it is ready, you will see a line like:

```
Starting development server at http://127.0.0.1:8000/
```

---

## 4. Open it in your browser

Go to this address:

```
http://127.0.0.1:8000/index.html
```

The home page will appear.

> **Important:** the app is production-safe by default and will **refuse to start
> without DEBUG mode** for local use. That is why running
> `python manage.py runserver` on its own may show nothing or an error. Always
> use `run.bat` (or run `set DJANGO_DEBUG=True` first). This is a safety feature,
> not a bug.

---

## 5. How to use it (step by step)

1. **Sign up** - click "Sign up", fill in the form, and Submit. Passwords must be
   at least 8 characters and not too common.
2. **Login** - click "Login" and enter your username and password.
3. **Upload a file** - open "Upload File", choose a file, and click
   "Upload & Encrypt". The file is locked (encrypted) and you get a confirmation
   with a unique SHA-256 fingerprint.
4. **Download a file** - open "Download Files" and click "Click Here" in the
   Download column. Only your own files appear here, and they come back exactly
   as you uploaded them.
5. **Check integrity** - open "Check Integrity" and click "Click Here" next to a
   file to confirm it has not been changed.
6. **Logout** - closes your private space safely.

A full walkthrough with screenshots is in the project documentation
(`Secure_Communication_Project_Documentation.docx`).

---

## 6. How it works (in brief)

- When you upload a file, the app creates a fresh one-time key using **X25519**
  (an elliptic-curve key exchange), strengthens it with **HKDF-SHA256**, and locks
  the file with **AES-256-GCM**. AES-GCM both scrambles the file and adds a tamper
  seal, so any later change is detected.
- A **SHA-256** fingerprint of each stored file is kept so integrity can be checked
  at any time.
- Passwords are stored as **Argon2** hashes, never as plain text.
- Encrypted files are kept in a private folder outside the website's public area
  and are only ever returned to their logged-in owner.

See `README.md` for the architecture diagram and `SECURITY.md` / `PENTEST.md`
for the full security details.

---

## 7. Stopping the app

Click the server window (the black Command Prompt window) and press
**Ctrl + C** (or **Ctrl + Break**), or simply close the window.

---

## 8. Troubleshooting

| Problem | What to do |
|---|---|
| The page shows nothing / won't load | Make sure the server window is open and says "Starting development server...". Start it with `run.bat`. |
| It refuses to start with a SECRET_KEY error | You started it without DEBUG mode. Use `run.bat`, or run `set DJANGO_DEBUG=True` first. |
| "That port is already in use" | Another copy is already running. Close the other server window, or run on a different port: `python manage.py runserver 127.0.0.1:8001` and open `http://127.0.0.1:8001/index.html`. |
| The page looks plain / unstyled | Confirm DEBUG mode is on (use `run.bat`), then refresh the browser. |
| "Please login first" | You are not logged in. Go to Login first. |
| "Too many failed attempts" | This is the anti-guessing protection. Wait a few minutes and try again. |

---

## 9. Running it online (production)

For hosting the app on the internet, see **`DEPLOYMENT.md`** and
**`.env.example`**. In short: set a strong secret key, turn DEBUG off, list your
website address, collect the static files, and run it behind an HTTPS web address.
