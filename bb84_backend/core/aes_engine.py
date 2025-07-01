# aes_engine.py
# Independent AES-256 engine (military-grade), CBC mode with PKCS#7 padding.
# ----------------------------------------------------------------------------
# Copyright 2025 Hector Mozo
# Licensed under the Apache License, Version 2.0 (the "License");
# ...
# ----------------------------------------------------------------------------


import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

__all__ = ["aes_encrypt", "aes_decrypt"]

def aes_encrypt(data: bytes, key_with_salt: bytes) -> bytes:
    """
    AES-256 encryption using CBC mode and secure random IV.
    Padding: PKCS#7.

    Args:
        data: Raw plaintext bytes.
        key_with_salt: 48 bytes = 32-byte AES key + 16-byte salt.

    Returns:
        IV + ciphertext (raw binary).
    """
    key = key_with_salt[:32]
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    pad_len = 16 - (len(data) % 16)
    padded_data = data + bytes([pad_len] * pad_len)

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(encrypted: bytes, key_with_salt: bytes) -> bytes:
    """
    AES-256 decryption using CBC mode and PKCS#7 padding removal.

    Args:
        encrypted: Encrypted data with IV prefix.
        key_with_salt: 48 bytes = 32-byte AES key + 16-byte salt.

    Returns:
        Decrypted original plaintext (bytes).
    """
    key = key_with_salt[:32]
    iv = encrypted[:16]
    ciphertext = encrypted[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = padded[-1]

    return padded[:-pad_len]
