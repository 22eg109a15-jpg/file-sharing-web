import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

def derive_key_from_password(password: str, salt: bytes, iterations: int = 390_000) -> bytes:
    """
    Derives a Fernet-compatible key from a user password using PBKDF2-HMAC-SHA256.
    The output is a 32-byte key, which is then URL-safe base64 encoded.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    # Fernet requires a URL-safe base64 encoded 32-byte key
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def fernet_encrypt_bytes(data: bytes, key: bytes) -> bytes:
    """Encrypts byte data using a Fernet key."""
    f = Fernet(key)
    return f.encrypt(data)

def fernet_decrypt_bytes(token: bytes, key: bytes) -> bytes:
    """Decrypts a Fernet token (ciphertext) back to original data."""
    f = Fernet(key)
    return f.decrypt(token)

def generate_fernet_key() -> bytes:
    """Generates a new, random 32-byte URL-safe base64 encoded Fernet key."""
    return Fernet.generate_key()
