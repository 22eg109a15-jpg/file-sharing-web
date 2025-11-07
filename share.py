import os, json, base64, zipfile, datetime, shutil
from pathlib import Path
from typing import Iterable, List, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from crypto_utils import generate_fernet_key, fernet_encrypt_bytes, fernet_decrypt_bytes

# ---------- RSA KEY UTILITIES ----------

def generate_rsa_keypair(save_dir: str, key_name: str = "mykey", password: Optional[str] = None) -> (str, str):
    """Generate RSA 2048 keypair and save as PEM. Returns (pub_path, priv_path)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    priv_enc = serialization.NoEncryption()
    if password:
        priv_enc = serialization.BestAvailableEncryption(password.encode())

    private_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=priv_enc
    )
    public_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    save = Path(save_dir); save.mkdir(parents=True, exist_ok=True)
    priv_path = str(save / f"{key_name}_private.pem")
    pub_path  = str(save / f"{key_name}_public.pem")
    
    Path(priv_path).write_bytes(private_bytes)
    Path(pub_path).write_bytes(public_bytes)
    
    return pub_path, priv_path

def load_public_key(pub_path: str) -> PublicKeyTypes:
    """Loads a public key from a PEM file."""
    pub_key_bytes = Path(pub_path).read_bytes()
    return serialization.load_pem_public_key(pub_key_bytes, backend=default_backend())

def load_private_key(priv_path: str, password: Optional[str] = None) -> PrivateKeyTypes:
    """Loads a private key from a PEM file, optionally with a password."""
    priv_key_bytes = Path(priv_path).read_bytes()
    pw_bytes = password.encode() if password else None
    return serialization.load_pem_private_key(priv_key_bytes, password=pw_bytes, backend=default_backend())

# ---------- SHARING IMPLEMENTATION (Automatic E2E) ----------

def create_share_package(file_paths: Iterable[str], recipient_public_pem: str, output_folder: str, package_name: Optional[str] = None) -> str:
    """
    Sender-side: Automatically encrypts files and creates a secure package (.sfs).
    1. Generates a new Fernet key.
    2. Encrypts files with the Fernet key.
    3. Encrypts (wraps) the Fernet key with the recipient's RSA Public Key.
    4. Bundles encrypted key, manifest, and files into a .sfs (zip).
    """
    paths = [Path(p) for p in file_paths if Path(p).is_file()]
    if not paths:
        raise ValueError("No valid files selected for sharing.")

    # 1. Generate the symmetric key for file encryption
    fkey_raw = generate_fernet_key() 
    fkey = base64.urlsafe_b64decode(fkey_raw) # Unwrap base64 for RSA operation

    # 2. Encrypt (wrap) the symmetric key with the recipient's Public Key (E2E encryption)
    pub = load_public_key(recipient_public_pem)
    wrapped_key = pub.encrypt(
        fkey,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 3. Create the manifest and package file
    if not package_name:
        package_name = f"secure_share_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.sfs"
        
    out_path = Path(output_folder) / package_name
    out_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Use a temporary directory for zipping
    temp_dir = Path(output_folder) / "temp_sfs_content"
    if temp_dir.exists(): shutil.rmtree(temp_dir)
    temp_dir.mkdir()
    
    manifest = {
        "version": 1,
        "created": datetime.datetime.now().isoformat(),
        "files": []
    }

    # Write the wrapped key
    (temp_dir / "key.bin").write_bytes(wrapped_key)
    (temp_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    (temp_dir / "data").mkdir()
    
    # 4. Encrypt and add files to the temporary data folder
    for idx, p in enumerate(paths):
        # Store files in a sub-directory 'data'
        stored_name = f"data/file{idx:04d}.enc" 
        data = p.read_bytes()
        token = fernet_encrypt_bytes(data, fkey_raw) # Use base64 wrapped key for Fernet
        
        (temp_dir / stored_name).write_bytes(token)

        manifest["files"].append({
            "original_name": p.name,
            "stored_name": stored_name,
            "size": len(data)
        })

    # Update manifest with final data
    (temp_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

    # Create the final zip file (.sfs is a zip archive)
    # shutil.make_archive creates a .zip file on disk and returns its path.
    zip_path_str = shutil.make_archive(str(out_path.with_suffix('')), 'zip', temp_dir)
    
    # Define the final intended path (.sfs)
    final_path = out_path.with_suffix('.sfs')
    
    # *** FIX HERE: Rename the created .zip file to have the .sfs extension ***
    Path(zip_path_str).rename(final_path)
    
    # Clean up temp files
    shutil.rmtree(temp_dir)
    
    return str(final_path)

def extract_share_package(sfs_path: str, recipient_private_pem: str, output_folder: str, private_key_password: Optional[str] = None):
    """
    Receiver-side: Open .sfs, automatically unwrap key with private key, and decrypt all files.
    """
    sfs_file = Path(sfs_path)
    if not sfs_file.exists():
        raise FileNotFoundError(f"Package file not found: {sfs_path}")

    outdir = Path(output_folder); outdir.mkdir(parents=True, exist_ok=True)
    temp_extract_dir = outdir / "temp_extraction"
    if temp_extract_dir.exists(): shutil.rmtree(temp_extract_dir)
    temp_extract_dir.mkdir()

    try:
        # 1. Extract the package contents (manifest, wrapped key, encrypted data)
        with zipfile.ZipFile(sfs_path, "r") as z:
            z.extractall(temp_extract_dir)
        
        wrapped_key = (temp_extract_dir / "key.bin").read_bytes()
        manifest = json.loads((temp_extract_dir / "manifest.json").read_text())

        # 2. Unwrap the key using the recipient's Private Key (Automatic Decryption)
        priv = load_private_key(recipient_private_pem, private_key_password)
        
        # The key is unwrapped back to raw bytes
        fkey_raw = priv.decrypt(
            wrapped_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        # Re-base64 encode the key for use with Fernet
        fkey_b64 = base64.urlsafe_b64encode(fkey_raw) 
        
        # 3. Decrypt and save files
        for f_info in manifest["files"]:
            stored_name = f_info["stored_name"]
            original_name = f_info["original_name"]
            
            enc_data_path = temp_extract_dir / stored_name
            if not enc_data_path.exists():
                 print(f"Warning: Encrypted file missing: {stored_name}")
                 continue

            token = enc_data_path.read_bytes()
            data = fernet_decrypt_bytes(token, fkey_b64)
            
            # Save the final decrypted file to the main output folder
            (outdir / original_name).write_bytes(data)

    finally:
        # Clean up temporary files
        if temp_extract_dir.exists():
            shutil.rmtree(temp_extract_dir)