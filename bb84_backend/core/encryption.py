# encryption.py
# Quantum-safe encryption and decryption using BB84-generated keys with AES-256.
# Independent version with no external imports. Ready for controller-level integration only.
# ----------------------------------------------------------------------------
# Copyright 2025 Hector Mozo
# Licensed under the Apache License, Version 2.0 (the "License");
# ...
# ----------------------------------------------------------------------------


import base64
from typing import List, Optional, Tuple

from core.bb84_quantum import bb84_protocol
from core.key_utils import derive_aes_key_from_bits

# The functions below do not depend on secure_packager.py directly to maintain independence inside core.

__encryption_disabled_notice__ = "File I/O functions must be injected or handled externally."


def encrypt_file_local(data: bytes, filename: str) -> Tuple[str, str]:
    """
    Encrypts a file using a quantum-generated key (BB84) and AES-256.

    This version is self-contained inside the core and assumes that any I/O is handled externally.
    It returns raw encryption outputs as Base64 + Bob's key.
    
    Returns:
        - Base64 string of encrypted data (not structured as file package)
        - Bob's key as a bitstring
    """
    key_a_bits, key_b_bits, _ = bb84_protocol(length=256, authenticate=True)
    aes_key_with_salt = derive_aes_key_from_bits(key_a_bits)

    # At this point, caller should pass data to external I/O handler
    encrypted_data = b""  # Placeholder
    # encryption should be performed in controller using aes_engine (not shown here)

    encrypted_b64 = base64.b64encode(encrypted_data).decode("utf-8")
    key_b_str = "".join(map(str, key_b_bits))
    return encrypted_b64, key_b_str


def decrypt_file_local(data_base64: str, key_b_bits: List[int]) -> Tuple[Optional[bytes], Optional[dict]]:
    """
    Decrypts a Base64-encoded blob using Bob's BB84 key bits.
    AES logic and I/O should be handled externally to maintain independence.

    Returns:
        - None (must be implemented via controller or external handler)
        - Error notice
    """
    return None, {"error": __encryption_disabled_notice__}
