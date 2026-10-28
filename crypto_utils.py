"""Cryptography helpers: key derivation + AES-256-GCM encryption.

The master password is NEVER stored. A 32-byte key is derived from it with
PBKDF2-HMAC-SHA256 (600,000 iterations) and a unique random salt per user.
Every entry is encrypted with AES-256-GCM using a fresh random nonce.
"""
import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 600_000
SALT_SIZE = 16
NONCE_SIZE = 12
VERIFIER_TEXT = "securevault-key-check"


class DecryptionError(Exception):
    """Raised when data cannot be decrypted (wrong key or tampered data)."""


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def new_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(master_password.encode("utf-8"))


def encrypt(key: bytes, plaintext: str) -> str:
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return b64e(nonce + ciphertext)


def decrypt(key: bytes, token: str) -> str:
    try:
        raw = b64d(token)
        nonce, ciphertext = raw[:NONCE_SIZE], raw[NONCE_SIZE:]
        return AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8")
    except (InvalidTag, ValueError, UnicodeDecodeError) as exc:
        raise DecryptionError("Wrong key or corrupted/tampered data") from exc


def make_verifier(key: bytes) -> str:
    """Encrypted known text, used to check a master password at login."""
    return encrypt(key, VERIFIER_TEXT)


def verify_key(key: bytes, verifier: str) -> bool:
    try:
        return decrypt(key, verifier) == VERIFIER_TEXT
    except DecryptionError:
        return False
