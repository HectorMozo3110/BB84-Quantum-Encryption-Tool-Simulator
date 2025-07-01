# secure_packager.py
# Secure packaging and unpackaging of encrypted files with BB84, AES + HMAC, and post-quantum signature validation
# ----------------------------------------------------------------------------
# Copyright 2025 Hector Mozo
# Licensed under the Apache License, Version 2.0 (the "License");
# ...
# ----------------------------------------------------------------------------


import json
import base64
from typing import List, Tuple, Dict

# Core AES encryption and key utilities
from core.aes_engine import aes_encrypt, aes_decrypt
from core.key_utils import (
    derive_aes_key_from_bits,
    verify_key_integrity,
    bits_to_bytes
)

# Attempt to import optional post-quantum signature module (Dilithium2)
try:
    from pqcrypto.sign.dilithium2 import generate_keypair, sign, verify
    PQCRYPTO_AVAILABLE = True
except ImportError:
    PQCRYPTO_AVAILABLE = False

def save_encrypted_file(
    plaintext: bytes,
    key_a_bits: List[int],
    key_b_bits: List[int],
    original_filename: str = "file"
) -> bytes:
    """
    Encrypts the file and returns a secure JSON package (as bytes).
    Includes encrypted file, metadata, quantum-derived key protection, and post-quantum signature.
    """
    # Derive AES-256 key with salt using key A
    key_with_salt = derive_aes_key_from_bits(key_a_bits)

    # Encrypt plaintext using AES-256 in CBC mode
    encrypted = aes_encrypt(plaintext, key_with_salt)

    # Encode key A for storage (base64 encoding of byte-converted bit sequence)
    key_a_bytes = base64.b64encode(bits_to_bytes(key_a_bits)).decode("utf-8")

    # Build encryption package with metadata
    package = {
        "ciphertext": base64.b64encode(encrypted).decode("utf-8"),
        "salt": base64.b64encode(key_with_salt[32:]).decode("utf-8"),  # last 16 bytes are salt
        "key_a_encoded": key_a_bytes,
        "key_b": "".join(map(str, key_b_bits)),
        "original_filename": original_filename,
        "extension": original_filename.split(".")[-1] if "." in original_filename else "bin"
    }

    # Attach post-quantum signature if available
    if PQCRYPTO_AVAILABLE:
        pk, sk = generate_keypair()
        package_bytes = json.dumps(package).encode("utf-8")
        signature = sign(package_bytes, sk)
        package["pq_signature"] = base64.b64encode(signature).decode("utf-8")
        package["pq_public_key"] = base64.b64encode(pk).decode("utf-8")

    # Return the complete JSON package as bytes
    return json.dumps(package).encode("utf-8")

def load_and_decrypt_bytes(
    package_bytes: bytes,
    key_b_bits: List[int]
) -> Tuple[bytes, Dict[str, str], bool]:
    """
    Loads encrypted package and decrypts using derived key if valid.
    Validates post-quantum signature and key integrity before decrypting.

    Returns:
        - Decrypted plaintext bytes
        - Metadata dict
        - Boolean indicating integrity success
    """
    # Load JSON package from bytes
    package = json.loads(package_bytes.decode("utf-8"))

    # Verify post-quantum signature, if included
    if PQCRYPTO_AVAILABLE and "pq_signature" in package and "pq_public_key" in package:
        pq_signature = base64.b64decode(package["pq_signature"])
        pq_public_key = base64.b64decode(package["pq_public_key"])

        # Rebuild package without signature fields for validation
        unsigned_package = {k: v for k, v in package.items() if k not in ("pq_signature", "pq_public_key")}
        unsigned_bytes = json.dumps(unsigned_package).encode("utf-8")
        try:
            if verify(unsigned_bytes, pq_signature, pq_public_key) != unsigned_bytes:
                return b"", {}, False
        except Exception:
            return b"", {}, False

    # Extract encrypted components and metadata
    salt = base64.b64decode(package["salt"])
    ciphertext = base64.b64decode(package["ciphertext"])
    encoded_key_a = base64.b64decode(package["key_a_encoded"])

    # Reconstruct stored key A bits from decoded bytes
    stored_key_a_bits = [int(bit) for byte in encoded_key_a for bit in f"{byte:08b}"]

    # Derive AES key using Bob’s bits and the stored salt
    candidate_key = derive_aes_key_from_bits(key_b_bits, salt)

    # Validate integrity using HMAC check between stored and recomputed key
    integrity_ok = verify_key_integrity(candidate_key, stored_key_a_bits)
    if not integrity_ok:
        return b"", {}, False

    # Decrypt the ciphertext using AES
    plaintext = aes_decrypt(ciphertext, candidate_key)

    # Return decrypted content and extracted metadata
    metadata = {
        "original_filename": package.get("original_filename", "decrypted_file"),
        "extension": package.get("extension", "bin")
    }

    return plaintext, metadata, True
