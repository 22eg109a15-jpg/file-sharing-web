import os
from pathlib import Path
from typing import Iterable, List
from crypto_utils import derive_key_from_password, fernet_encrypt_bytes, fernet_decrypt_bytes
import secrets
import shutil

def _iter_paths(paths: Iterable[str]) -> List[Path]:
    """Helper to convert string paths to Path objects and filter existing files."""
    out = []
    for p in paths:
        p = Path(p)
        if p.exists() and p.is_file():
            out.append(p)
    return out

def encrypt_files_password_mode(file_paths: Iterable[str], password: str):
    """
    Encrypts files IN-PLACE using a password-derived key.
    Prepends a 'SALT' header and a unique salt to the ciphertext for self-contained decryption.
    """
    for p in _iter_paths(file_paths):
        data = p.read_bytes()
        salt = secrets.token_bytes(16)
        key = derive_key_from_password(password, salt)
        enc = fernet_encrypt_bytes(data, key)
        # Format: b"SALT" (4 bytes) + salt (16 bytes) + ciphertext
        blob = b"SALT" + salt + enc
        p.write_bytes(blob)
        # Rename the file to indicate it's encrypted
        p.rename(p.with_suffix(p.suffix + '.penc'))

def decrypt_files_password_mode(file_paths: Iterable[str], password: str):
    """
    IN-PLACE decrypt. Expects the file to start with the 'SALT' header and 16-byte salt.
    """
    for p in _iter_paths(file_paths):
        blob = p.read_bytes()
        
        # Check for the SALT header (4 bytes) and minimum length
        if not blob.startswith(b"SALT") or len(blob) < 4 + 16 + 1:
            raise ValueError(f"{p.name}: Not a valid password-encrypted file (missing SALT header or too short).")

        salt = blob[4:20]
        token = blob[20:]
        
        key = derive_key_from_password(password, salt)
        data = fernet_decrypt_bytes(token, key)
        
        # Write decrypted data
        p.write_bytes(data)
        
        # Rename the file by removing the '.penc' suffix
        if p.suffix == '.penc':
            p.rename(p.with_suffix(''))
        else:
            # If it doesn't have the expected suffix, we rename it with a temporary suffix 
            # to avoid overwriting the original, but the user must manually clean up.
            p.rename(p.with_name(p.stem + '_decrypted'))


def encrypt_folder_password_mode(folder_path: str, password: str, exclude: set = None):
    """Recursively encrypts all files within a folder."""
    folder_path = Path(folder_path)
    if not folder_path.is_dir():
        raise ValueError("Path is not a directory.")
        
    exclude = exclude or set()
    for root, _, files in os.walk(folder_path):
        for name in files:
            if name in exclude:
                continue
            # Use encrypt_files_password_mode which handles the in-place encryption/renaming
            encrypt_files_password_mode([os.path.join(root, name)], password)

def decrypt_folder_password_mode(folder_path: str, password: str, exclude: set = None):
    """Recursively decrypts all files within a folder."""
    folder_path = Path(folder_path)
    if not folder_path.is_dir():
        raise ValueError("Path is not a directory.")
        
    exclude = exclude or set()
    for root, _, files in os.walk(folder_path):
        for name in files:
            if name in exclude:
                continue
            # Use decrypt_files_password_mode which handles the in-place decryption/renaming
            decrypt_files_password_mode([os.path.join(root, name)], password)
