from django.db import models


class Account(models.Model):
    """A registered user. Passwords are stored as Argon2/PBKDF2 hashes
    (via django.contrib.auth.hashers), never in plaintext."""
    username = models.CharField(max_length=50, primary_key=True)
    password = models.CharField(max_length=256)  # hashed
    contact_no = models.CharField(max_length=15, blank=True)
    gender = models.CharField(max_length=20, blank=True)
    email = models.CharField(max_length=100, blank=True)
    address = models.CharField(max_length=200, blank=True)

    def __str__(self):
        return self.username


class SecureFile(models.Model):
    """An uploaded, encrypted file plus the non-secret parameters required to
    decrypt it (ephemeral public key, HKDF salt, AES-GCM nonce) and a SHA-256
    integrity digest of the stored ciphertext."""
    owner = models.CharField(max_length=50, db_index=True)
    filename = models.CharField(max_length=200)
    ephemeral_pub = models.CharField(max_length=128)  # hex
    salt = models.CharField(max_length=64)            # hex
    nonce = models.CharField(max_length=64)           # hex
    hashcode = models.CharField(max_length=128)       # sha256 hex of stored file
    upload_date = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("owner", "filename")

    def __str__(self):
        return f"{self.owner}/{self.filename}"
