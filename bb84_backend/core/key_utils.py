# key_utils.py
# Utilities for BB84 quantum key post-processing and AES-256 derivation.
# Includes entropy validation, conversion, and HMAC integrity check.
# ----------------------------------------------------------------------------
# Copyright 2025 Hector Mozo
# Licensed under the Apache License, Version 2.0 (the "License");
# ...
# ----------------------------------------------------------------------------


from typing import List
from hashlib import pbkdf2_hmac
import hmac
import os

def check_key_entropy(bits: List[int]) -> bool:
    """
    Checks whether a bit sequence has acceptable entropy (i.e., balanced 0s and 1s).
    
    Returns:
        True if entropy is acceptable, False otherwise.
    """
    ones = sum(bits)
    balance_ratio = abs(ones - len(bits) / 2) / len(bits)
    return balance_ratio < 0.4  # Threshold can be tightened if needed

def bits_to_bytes(bits: List[int]) -> bytes:
    """
    Converts a list of bits (0/1 integers) to a bytes object.
    Pads with 0s to ensure byte alignment.

    Args:
        bits: List of 0s and 1s

    Returns:
        Byte representation of bit list
    """
    padding = (8 - len(bits) % 8) % 8
    bits += [0] * padding
    return bytes(
        int("".join(map(str, bits[i:i+8])), 2)
        for i in range(0, len(bits), 8)
    )

def bytes_to_bits(data: bytes) -> List[int]:
    """
    Converts bytes into a flat list of bits (0/1 integers).

    Args:
        data: Byte input

    Returns:
        List of bits
    """
    return [int(bit) for byte in data for bit in f"{byte:08b}"]

def derive_aes_key_from_bits(bits: List[int], salt: bytes = None, iterations: int = 100_000) -> bytes:
    """
    Derives a secure 256-bit AES key from quantum-generated bits using PBKDF2-HMAC-SHA256.
    Produces a 48-byte output: 32-byte key + 16-byte salt.

    Args:
        bits: BB84 shared bits
        salt: Optional fixed salt (for verification); auto-generated if None
        iterations: PBKDF2 iteration count

    Returns:
        Key + salt as bytes
    """
    raw = bits_to_bytes(bits)
    salt = salt or os.urandom(16)
    key = pbkdf2_hmac('sha256', raw, salt, iterations, dklen=32)
    return key + salt

def verify_key_integrity(key_with_salt: bytes, bits: List[int], iterations: int = 100_000) -> bool:
    """
    Verifies that the provided key was derived from the given bits and salt.

    Args:
        key_with_salt: Original key+salt (48 bytes)
        bits: BB84 shared bits for recomputation

    Returns:
        True if HMAC matches; False otherwise
    """
    salt = key_with_salt[32:]
    expected_key = pbkdf2_hmac('sha256', bits_to_bytes(bits), salt, iterations, dklen=32)
    return hmac.compare_digest(key_with_salt[:32], expected_key)
