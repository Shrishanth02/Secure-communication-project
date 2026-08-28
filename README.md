# Secure Communication using Diffie-Hellman, AES & SHA

A Django-based web application that implements **secure file communication** using:

- 🔐 **Diffie-Hellman Key Exchange** — Generates a shared secret key between parties
- 🔒 **AES Encryption** — Encrypts files using the Diffie-Hellman shared key via PBKDF2
- 🕵️ **Steganography** — Hides the secret key inside the encrypted file using zero-width Unicode characters
- ✅ **SHA-1 Data Integrity** — Generates & verifies file integrity via hashcodes
- 👤 **User Authentication** — Signup/Login system with MySQL backend

---

## 📋 Requirements

| Dependency | Version |
|---|---|
| Python | 3.x |
| Django | 2.1.7 |
| PyMySQL | 0.9.3 |
| pyaes | 1.6.1 |
| pbkdf2 | 1.3 |
| MySQL/MariaDB | 5.x+ |

---

## 🚀 Setup Instructions

### 1. Install Dependencies

```bash
pip install Django==2.1.7 PyMySQL==0.9.3 pyaes==1.6.1 pbkdf2==1.3
```

### 2. Setup MySQL Database

Make sure MySQL is running, then execute the SQL from `DB.txt`:

```sql
CREATE DATABASE secureapp;
USE secureapp;

CREATE TABLE signup(
    username varchar(50) PRIMARY KEY,
    password varchar(50),
    contact_no varchar(15),
    gender varchar(20),
    email varchar(50),
    address varchar(50)
);

CREATE TABLE files(
    owner varchar(50),
    filename varchar(50),
    hashcode varchar(300),
    upload_date varchar(30)
);
```

### 3. Configure Database

Edit `Secure/settings.py` if your MySQL credentials differ:

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'secureapp',
        'HOST': '127.0.0.1',
        'PORT': '3306',
        'USER': 'root',
        'PASSWORD': '',  # Change if you have a password
    }
}
```

### 4. Run the Application

```bash
python manage.py runserver
```

Then open your browser at: **http://127.0.0.1:8000/index.html**

---

## 🌐 Application Flow

1. **Register** — Create a new account via `/Signup.html`
2. **Login** — Authenticate via `/UserLogin.html`
3. **Upload File** — Encrypt and upload a file; the Diffie-Hellman key is steganographically hidden inside the encrypted content
4. **Download File** — Extract the hidden key and decrypt the file
5. **File Integrity** — Verify file integrity using SHA-1 hashcodes

---

## 🔬 Cryptographic Details

| Step | Algorithm | Purpose |
|---|---|---|
| Key Exchange | Diffie-Hellman (P=23, G=9) | Generate shared secret |
| Key Derivation | PBKDF2 | Derive 256-bit AES key from DH shared key |
| Encryption | AES-CTR mode | Encrypt file contents |
| Key Hiding | Zero-width Unicode steganography | Embed DH key in ciphertext |
| Integrity | SHA-1 | Detect tampering |

---

## 📁 Project Structure

```
Secure-communication-project/
├── manage.py               # Django management script
├── requirements.txt        # Dependencies
├── DB.txt                  # Database setup SQL
├── run.bat                 # Quick run script
├── Secure/                 # Django project settings
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
└── SecureApp/              # Main application
    ├── views.py            # Core logic (encryption, upload, download)
    ├── urls.py             # URL routing
    ├── templates/          # HTML templates
    │   ├── index.html
    │   ├── Signup.html
    │   ├── UserLogin.html
    │   ├── UserScreen.html
    │   └── UploadFile.html
    └── static/
        ├── style.css
        ├── images/
        └── files/          # Encrypted file storage
```

---

## ⚠️ Notes

- This project is for **educational purposes** — demonstrating cryptographic concepts in a web application
- The Diffie-Hellman parameters (P=23, G=9) are intentionally simple for demonstration
- Always run MySQL server before starting the Django application
