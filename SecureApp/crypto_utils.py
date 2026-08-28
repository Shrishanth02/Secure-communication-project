"""
Cryptographic core for the Secure Communication app.

Design (ephemeral-static ECDH, a.k.a. a "sealed box" / ECIES scheme):

  * The application owns ONE long-lived X25519 "receiver" key pair. The private
    key never leaves the server (stored in a git-ignored keystore file); the
    public key is what senders encrypt to.
  * For every file uploaded, a fresh EPHEMERAL X25519 key pair is generated.
    A Diffie-Hellman exchange between the ephemeral private key and the
    receiver public key produces a shared secret that is unique per file.
  * The shared secret is stretched into a 256-bit AES key with HKDF-SHA256
    using a random per-file salt.
  * The file is encrypted with AES-256-GCM using a random 96-bit nonce. GCM is
    an AEAD cipher, so it provides confidentiality AND authenticity/integrity
    in one primitive (a tampered ciphertext fails to decrypt).
  * Only the ephemeral PUBLIC key, salt and nonce are stored/embedded. They are
    all non-secret. To decrypt, the server combines its receiver PRIVATE key
    with the stored ephemeral public key to reconstruct the same shared secret.

This replaces the original toy scheme (textbook DH with P=23/G=9, a hardcoded
password, a fixed AES-CTR nonce and SHA-1) with modern, real cryptography.
"""

import os
import hashlib

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

# ---------------------------------------------------------------------------
# Zero-width steganography (retained as a demonstration feature).
# We now hide only the file's EPHEMERAL PUBLIC KEY -- public data that is safe
# to embed -- instead of the secret key the original code leaked.
# ---------------------------------------------------------------------------
SPACE0 = "​"  # zero-width space      -> bit 0
SPACE1 = "‌"  # zero-width non-joiner -> bit 1


def hide(text, message):
    """Embed `message` (a string) invisibly near the middle of `text`."""
    bits = "".join(format(ord(ch), "08b") for ch in str(message))
    midpoint = len(text) // 2
    hidden = "".join(SPACE0 if b == "0" else SPACE1 for b in bits)
    return text[:midpoint] + hidden + text[midpoint:]


def show(text):
    """Recover a message previously embedded with `hide`. Returns None if none."""
    bits = "".join("0" if ch == SPACE0 else "1" if ch == SPACE1 else "" for ch in text)
    if not bits:
        return None
    chars = [chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits), 8)]
    return "".join(chars) or None


# ---------------------------------------------------------------------------
# Receiver identity (long-lived X25519 key pair).
# ---------------------------------------------------------------------------
_KEYSTORE_DIR = os.path.join(os.path.dirname(__file__), "secure_keystore")
_RECEIVER_KEY_PATH = os.path.join(_KEYSTORE_DIR, "receiver.key")


def _load_or_create_receiver_key():
    """Return the server's long-lived X25519 private key, creating it on first run.

    The key file is created atomically with owner-only (0600) permissions and
    the keystore directory is restricted to 0700. (On POSIX these are enforced;
    on Windows they are best-effort.) In production the key should live in a
    secrets manager / KMS — see DEPLOYMENT.md."""
    os.makedirs(_KEYSTORE_DIR, exist_ok=True)
    try:
        os.chmod(_KEYSTORE_DIR, 0o700)
    except OSError:
        pass
    if os.path.exists(_RECEIVER_KEY_PATH):
        with open(_RECEIVER_KEY_PATH, "rb") as fh:
            return X25519PrivateKey.from_private_bytes(fh.read())
    private_key = X25519PrivateKey.generate()
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Atomic, owner-only create. O_EXCL closes the race where two workers each
    # generate a different key on first run.
    try:
        fd = os.open(_RECEIVER_KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, raw)
        finally:
            os.close(fd)
    except FileExistsError:
        with open(_RECEIVER_KEY_PATH, "rb") as fh:
            return X25519PrivateKey.from_private_bytes(fh.read())
    return private_key


_HKDF_INFO_PREFIX = b"secure-communication-file-encryption|"


def _derive_aes_key(shared_secret, salt, aad=b""):
    """HKDF-SHA256: stretch a DH shared secret into a 256-bit AES key, binding
    the per-file context (aad) into the derivation `info`."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=_HKDF_INFO_PREFIX + aad,
    ).derive(shared_secret)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def encrypt_file(plaintext_bytes, aad=b""):
    """
    Encrypt raw file bytes.

    `aad` binds the ciphertext (and key derivation) to per-file context such as
    owner|filename: it is used both as HKDF `info` and as AES-GCM associated
    data, so a ciphertext cannot be transplanted onto a different file/owner row
    without failing authentication.

    Returns a dict with the ciphertext and the non-secret parameters needed to
    decrypt later:  ciphertext, ephemeral_pub (hex), salt (hex), nonce (hex).
    """
    receiver_private = _load_or_create_receiver_key()
    receiver_public = receiver_private.public_key()

    # Fresh ephemeral key pair for this file -> a real per-file DH exchange.
    ephemeral_private = X25519PrivateKey.generate()
    shared_secret = ephemeral_private.exchange(receiver_public)

    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_aes_key(shared_secret, salt, aad)

    ciphertext = AESGCM(key).encrypt(nonce, plaintext_bytes, aad)

    ephemeral_pub_raw = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "ciphertext": ciphertext,
        "ephemeral_pub": ephemeral_pub_raw.hex(),
        "salt": salt.hex(),
        "nonce": nonce.hex(),
    }


def decrypt_file(ciphertext, ephemeral_pub_hex, salt_hex, nonce_hex, aad=b""):
    """
    Reverse of `encrypt_file`. `aad` must match what was used to encrypt.
    Raises cryptography.exceptions.InvalidTag if the ciphertext was tampered
    with (or the aad/context does not match), and ValueError if any stored
    parameter is malformed.
    """
    receiver_private = _load_or_create_receiver_key()
    pub_bytes = bytes.fromhex(ephemeral_pub_hex)
    if len(pub_bytes) != 32:
        raise ValueError("Invalid ephemeral public key length")
    ephemeral_public = X25519PublicKey.from_public_bytes(pub_bytes)
    shared_secret = receiver_private.exchange(ephemeral_public)
    key = _derive_aes_key(shared_secret, bytes.fromhex(salt_hex), aad)
    return AESGCM(key).decrypt(bytes.fromhex(nonce_hex), ciphertext, aad)


def sha256_hex(data_bytes):
    """SHA-256 integrity digest (upgraded from the original SHA-1)."""
    return hashlib.sha256(data_bytes).hexdigest()
