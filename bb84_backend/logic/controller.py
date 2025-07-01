import os
import sys
import base64
import hashlib
import time
from datetime import datetime
from collections import Counter
from math import log2
from typing import Tuple, Optional, List
import json
# ----------------------------------------------------------------------------
# Copyright 2025 Hector Mozo
# Licensed under the Apache License, Version 2.0 (the "License");
# ...
# ----------------------------------------------------------------------------


# Add core modules path for relative imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import core cryptographic modules
from core.bb84_quantum import bb84_protocol
from core.key_utils import derive_aes_key_from_bits, verify_key_integrity
from core.encryption import encrypt_file_local as core_encrypt_file_local
from secure_io.secure_packager import save_encrypted_file, load_and_decrypt_bytes

# Metrics collector for BB84 encryption/decryption process
class BB84MetricsCollector:
    def __init__(self):
        self.metrics = {}
        self.start_time = None

    # Start timing an operation
    def start_timer(self):
        self.start_time = time.perf_counter()

    # Stop timing and record the elapsed duration
    def stop_timer(self, label="Encryption Time (s)"):
        if self.start_time:
            elapsed = time.perf_counter() - self.start_time
            self.metrics[label] = round(elapsed, 4)

    # Log the current UTC timestamp
    def add_timestamp(self):
        self.metrics["Timestamp"] = str(datetime.utcnow())

    # Add BB84 key properties and entropy estimation
    def add_key_metrics(self, key_a_bits, key_b_bits):
        self.metrics["Key A Length"] = len(key_a_bits)
        self.metrics["Key B Length"] = len(key_b_bits)
        self.metrics["Key B - Count of 1s"] = key_b_bits.count(1)
        self.metrics["Key B - Count of 0s"] = key_b_bits.count(0)

        matches = sum(1 for a, b in zip(key_a_bits, key_b_bits) if a == b)
        percentage = 100 * matches / len(key_b_bits)
        self.metrics["A/B Bit Match Percentage"] = round(percentage, 2)

        # Estimate Shannon entropy from key A
        total = len(key_a_bits)
        counts = Counter(key_a_bits)
        entropy = -sum((c / total) * log2(c / total) for c in counts.values())
        self.metrics["Estimated Shannon Entropy"] = round(entropy, 4)

    # Record original file size
    def add_file_size_before_encryption(self, original_bytes: bytes):
        self.metrics["Original File Size (bytes)"] = len(original_bytes)

    # Record size of the encrypted file
    def add_file_size_after_encryption(self, encrypted_bytes: bytes):
        self.metrics["Encrypted File Size (bytes)"] = len(encrypted_bytes)

    # Record size of the decrypted output file
    def add_decrypted_file_size(self, decrypted_bytes: bytes):
        self.metrics["Decrypted File Size (bytes)"] = len(decrypted_bytes)

    # Save SHA-256 hash of encrypted content
    def add_sha256_hash(self, cipher_bytes):
        self.metrics["SHA-256 Hash of Encrypted File"] = hashlib.sha256(cipher_bytes).hexdigest()

    # Save SHA-256 hash of decrypted output
    def add_sha256_of_decrypted(self, decrypted_bytes):
        self.metrics["SHA-256 Hash of Decrypted File"] = hashlib.sha256(decrypted_bytes).hexdigest()

    # Register result of HMAC integrity check
    def add_hmac_verification(self, valid):
        self.metrics["HMAC Integrity Check"] = "Passed" if valid else "Failed"

    # Log whether post-quantum signature was used
    def add_quantum_signature_status(self, enabled: bool):
        self.metrics["Post-Quantum Signature"] = "Enabled" if enabled else "Disabled"

    # Export all collected metrics to a JSON file
    def export_to_json(self, output_path="bb84_metrics.json"):
        with open(output_path, "w") as f:
            json.dump(self.metrics, f, indent=2)
        return output_path

# ENCRYPTION LOGIC (enhanced with full metrics collection)
def encrypt_file_local(data: bytes, filename: str) -> Tuple[str, str]:
    # Initialize metrics collection
    metrics = BB84MetricsCollector()
    metrics.start_timer()
    metrics.add_timestamp()
    metrics.add_file_size_before_encryption(data)

    # Generate BB84 quantum key and optional post-quantum signature
    key_a_bits, key_b_bits, signature = bb84_protocol(length=256, authenticate=True)

    # Package and encrypt the data using AES-256 derived from BB84 key
    package_bytes = save_encrypted_file(
        plaintext=data,
        key_a_bits=key_a_bits,
        key_b_bits=key_b_bits,
        original_filename=filename
    )

    # Record encryption performance and key stats
    metrics.stop_timer("Encryption Time (s)")
    metrics.add_key_metrics(key_a_bits, key_b_bits)
    metrics.add_file_size_after_encryption(package_bytes)
    metrics.add_sha256_hash(package_bytes)
    metrics.add_quantum_signature_status(signature is not None)
    metrics.export_to_json("bb84_metrics.json")

    # Convert encrypted output to Base64 and format Key B as string
    encrypted_b64 = base64.b64encode(package_bytes).decode("utf-8")
    key_b_str = "".join(map(str, key_b_bits))
    return encrypted_b64, key_b_str

# DECRYPTION LOGIC (includes validation and full metrics logging)
def decrypt_file_local(data_base64: str, key_b_bits: List[int]) -> Tuple[Optional[bytes], Optional[dict]]:
    try:
        # Initialize metrics
        metrics = BB84MetricsCollector()
        metrics.start_timer()
        metrics.add_timestamp()

        # Decode Base64 and attempt decryption using Key B
        encrypted_bytes = base64.b64decode(data_base64)
        data, metadata, integrity_ok = load_and_decrypt_bytes(encrypted_bytes, key_b_bits)

        # Log decryption time and integrity verification status
        metrics.stop_timer("Decryption Time (s)")
        metrics.add_hmac_verification(integrity_ok)
        metrics.add_sha256_hash(encrypted_bytes)

        if data:
            metrics.add_decrypted_file_size(data)
            metrics.add_sha256_of_decrypted(data)

        metrics.export_to_json("bb84_metrics.json")

        if not integrity_ok:
            return None, {"error": "Key B does not match the original quantum key. Integrity verification failed."}

        return data, metadata
    except Exception as e:
        # Generic error handling and logging
        return None, {"error": str(e)}
