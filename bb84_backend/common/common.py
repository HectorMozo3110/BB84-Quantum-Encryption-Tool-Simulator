# common.py
# General-purpose utility functions used across BB84 secure communication system.
# ----------------------------------------------------------------------------
# Copyright 2025 Hector Mozo
# Licensed under the Apache License, Version 2.0 (the "License");
# ...
# ----------------------------------------------------------------------------


import hashlib
import base64

def encode_key(bits):
    """
    Encodes a list of bits (0/1 integers) into a base64 URL-safe string.
    Useful for transmitting or storing binary keys as strings.
    """
    return base64.urlsafe_b64encode(''.join(map(str, bits)).encode()).decode()

def decode_key(encoded: str):
    """
    Decodes a base64-encoded string into a list of bits (0/1 integers).
    """
    return [int(b) for b in base64.urlsafe_b64decode(encoded.encode()).decode()]

def sha256_bytes(data: bytes) -> bytes:
    """
    Returns the SHA-256 hash of a byte array.
    Useful for fingerprinting or quick integrity checks.
    """
    return hashlib.sha256(data).digest()
