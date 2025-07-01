# bb84_quantum.py
# BB84 Quantum Key Distribution using Qiskit AerSimulator with optional post-quantum authentication.
# ----------------------------------------------------------------------------
# Copyright 2025 Hector Mozo
# Licensed under the Apache License, Version 2.0 (the "License");
# ...
# ----------------------------------------------------------------------------


from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
from typing import List, Tuple
import secrets

# Optional: Post-quantum authentication (fallback if not available)
try:
    from pqcrypto.sign.dilithium2 import generate_keypair, sign, verify
    PQCRYPTO_AVAILABLE = True
except ImportError:
    PQCRYPTO_AVAILABLE = False

def generate_random_bits(length: int) -> List[int]:
    """
    Generates a secure random bitstring of given length using system entropy.
    """
    return [secrets.randbits(1) for _ in range(length)]

def generate_random_bases(length: int) -> List[str]:
    """
    Randomly assigns measurement bases ('Z' or 'X') for each qubit.
    """
    return [secrets.choice(['Z', 'X']) for _ in range(length)]

def measure_qubit(bit: int, basis: str, measure_basis: str) -> int:
    """
    Simulates the quantum measurement of a single qubit using Qiskit AerSimulator.
    """
    circuit = QuantumCircuit(1, 1)
    
    if bit == 1:
        circuit.x(0)
    if basis == 'X':
        circuit.h(0)

    if measure_basis == 'X':
        circuit.h(0)
    circuit.measure(0, 0)

    simulator = AerSimulator()
    result = simulator.run(circuit, shots=1).result()
    counts = result.get_counts()

    return int(max(counts, key=counts.get))

def bb84_protocol(length: int = 128, authenticate: bool = False) -> Tuple[List[int], List[int], List[int]]:
    """
    Runs the BB84 protocol simulation and returns the matching keys and their indices.

    Args:
        length: Number of qubits to simulate (default 128).
        authenticate: If True, perform post-quantum authentication using Dilithium (if available).

    Returns:
        A tuple containing:
        - Alice's key bits (from matching positions)
        - Bob's key bits (from matching positions)
        - List of matching indices (positions where bases matched)
    """
    alice_bits = generate_random_bits(length)
    alice_bases = generate_random_bases(length)
    bob_bases = generate_random_bases(length)

    bob_results = [
        measure_qubit(bit, prep_basis, measure_basis)
        for bit, prep_basis, measure_basis in zip(alice_bits, alice_bases, bob_bases)
    ]

    matching_indices = [i for i in range(length) if alice_bases[i] == bob_bases[i]]
    key_alice = [alice_bits[i] for i in matching_indices]
    key_bob = [bob_results[i] for i in matching_indices]

    if authenticate and PQCRYPTO_AVAILABLE:
        public_data = "".join(alice_bases).encode("utf-8")
        pk, sk = generate_keypair()
        signature = sign(public_data, sk)
        if not verify(public_data, signature, pk):
            raise ValueError("Post-quantum signature verification failed.")

    return key_alice, key_bob, matching_indices
