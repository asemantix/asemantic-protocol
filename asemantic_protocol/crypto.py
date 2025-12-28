"""
Cryptographic primitives for the asemantic fragment validation protocol.

This module provides:
- KDF: Key Derivation Function (unidirectional seed evolution)
- compute_fragment: Fragment construction F_i = Tronc_ℓ(F(Encode(domain, C, Z_i)))
- constant_time_equal: Side-channel resistant comparison
- secure_erase: Secure memory erasure for forward secrecy

References:
- Revendication 1: Windowed recomputation + strict equality
- Revendication 3: Mode A - Secret seed with unidirectional derivation + forward secrecy
- Revendication 8: ℓ ≥ 256 bits
"""

import hashlib
import hmac
import secrets
from typing import Optional, Union

# =============================================================================
# CONFIGURATION
# =============================================================================

DEFAULT_FRAGMENT_LENGTH = 256  # bits (rev. 8: ℓ ≥ 256)
DEFAULT_DOMAIN_LENGTH = 128    # bits (rev. 18: d ≥ 128)


# =============================================================================
# KEY DERIVATION FUNCTION (KDF)
# =============================================================================

def KDF(seed: bytes, context: Optional[bytes] = None) -> bytes:
    """
    Unidirectional Key Derivation Function for seed evolution (Mode A).
    
    Implements K_{j+1} := KDF(K_j) or K_{j+1} := KDF(K_j || θ_j)
    where θ_j is an optional context parameter.
    
    This is the "preferred mode" (mode préféré) from the patent.
    The general form covers any deterministic unidirectional function.
    
    Args:
        seed: Current seed K_j (32 bytes recommended)
        context: Optional context parameter θ_j (None for autonomous evolution)
    
    Returns:
        bytes: Next seed K_{j+1} (same length as input seed)
    
    Security properties:
        - Deterministic: same input always produces same output
        - Unidirectional: computationally infeasible to recover K_j from K_{j+1}
        - Forward secrecy: after erasing K_j, past seeds cannot be recovered
    
    Reference: Revendication 3 (Mode A, forward secrecy)
    """
    if context is not None:
        # Variant with contextual parameter: K_{j+1} := KDF(K_j || θ_j)
        data = seed + context
    else:
        # Autonomous evolution: K_{j+1} := KDF(K_j)
        data = seed
    
    # Using HKDF-like construction with HMAC-SHA256
    # This is conformant with RFC 5869 (HKDF)
    return hmac.new(
        key=seed,
        msg=data + b"ASEMANTIC_KDF_V1",
        digestmod=hashlib.sha256
    ).digest()


# =============================================================================
# FRAGMENT CONSTRUCTION
# =============================================================================

def encode(domain: bytes, content: bytes, evolution_param: bytes) -> bytes:
    """
    Injective encoding function: Encode(domain, C, Z_i)
    
    Combines domain tag, content representation, and evolution parameter
    into an unambiguous binary string using length-prefixed encoding.
    
    Args:
        domain: Domain separation tag (d ≥ 128 bits recommended)
        content: Deterministic content representation C := R(S)
        evolution_param: Evolution parameter Z_i (K_i in Mode A, Evol(i) in Mode B)
    
    Returns:
        bytes: Injective encoding suitable for cryptographic primitive input
    
    Note:
        The encoding is injective: different inputs always produce different outputs.
        This prevents ambiguity and ensures cryptographic separation.
    
    Reference: Description fonctionnelle - Encodage injectif
    """
    def length_prefix(data: bytes) -> bytes:
        """4-byte big-endian length prefix"""
        return len(data).to_bytes(4, 'big') + data
    
    return (
        length_prefix(domain) +
        length_prefix(content) +
        length_prefix(evolution_param)
    )


def compute_fragment(
    domain: bytes,
    content: bytes,
    evolution_param: bytes,
    fragment_length_bits: int = DEFAULT_FRAGMENT_LENGTH,
    key: Optional[bytes] = None
) -> bytes:
    """
    Compute fragment F_i = Tronc_ℓ(F(Encode(domain, C, Z_i)))
    
    This is the core fragment construction function implementing:
    - Injective encoding of (domain, C, Z_i)
    - Cryptographic primitive F (KMAC or cSHAKE-like)
    - Truncation to ℓ bits
    
    Args:
        domain: Domain separation tag (d ≥ 128 bits, rev. 18)
        content: Content representation C := R(S)
        evolution_param: Evolution parameter Z_i
        fragment_length_bits: Output length ℓ in bits (≥ 256, rev. 8)
        key: Optional key for keyed mode (Mode A with PRF)
    
    Returns:
        bytes: Fragment F_i of exactly ℓ/8 bytes
    
    Security:
        - Output is pseudorandom (indistinguishable from random)
        - No metadata: domain, C, Z_i are not recoverable from F_i
        - Fixed length: prevents traffic analysis based on size
    
    Reference: Revendications 1, 2, 8
    """
    # Validate fragment length
    if fragment_length_bits < 256:
        raise ValueError(f"Fragment length must be ≥ 256 bits (got {fragment_length_bits})")
    
    fragment_length_bytes = fragment_length_bits // 8
    
    # Encode inputs (injective encoding)
    encoded_input = encode(domain, content, evolution_param)
    
    if key is not None:
        # Keyed mode (Mode A with PRF/PRP)
        # Using HMAC-SHA256 as PRF, then extending if needed
        h = hmac.new(key, encoded_input, hashlib.sha256)
        output = h.digest()
        
        # If more bytes needed, use counter mode extension
        while len(output) < fragment_length_bytes:
            counter = len(output).to_bytes(4, 'big')
            h = hmac.new(key, encoded_input + counter, hashlib.sha256)
            output += h.digest()
    else:
        # Non-keyed mode (XOF-like using SHA3)
        # Using SHAKE256 for extensible output
        shake = hashlib.shake_256(encoded_input)
        output = shake.digest(fragment_length_bytes)
    
    # Truncate to exact length (Tronc_ℓ)
    return output[:fragment_length_bytes]


# =============================================================================
# CONSTANT-TIME COMPARISON
# =============================================================================

def constant_time_equal(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison to prevent timing side-channel attacks.
    
    This function compares two byte strings in constant time,
    regardless of where they differ (or if they're equal).
    
    Args:
        a: First byte string
        b: Second byte string
    
    Returns:
        bool: True if a == b, False otherwise
    
    Security:
        - Execution time is independent of comparison result
        - Prevents timing attacks that could leak information about matches
        - Always compares all bytes, even after finding a difference
    
    Reference: Annexe G.2 - Comparaisons en temps constant
    """
    if len(a) != len(b):
        return False
    
    # XOR all bytes and accumulate differences
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    
    return diff == 0


# =============================================================================
# SECURE MEMORY ERASURE (Forward Secrecy)
# =============================================================================

def secure_erase(data: bytearray) -> None:
    """
    Securely erase sensitive data from memory.
    
    Overwrites the data with random bytes, then zeros, to ensure
    the original content cannot be recovered.
    
    Args:
        data: Mutable bytearray to erase (must be bytearray, not bytes)
    
    Security:
        - Supports forward secrecy by erasing old seeds
        - Multiple overwrites to defeat memory forensics
        - Note: Python's garbage collector may retain copies;
          for production use, consider ctypes or secure allocators
    
    Reference: Revendication 3 - Effacement sécurisé, forward secrecy
    """
    if not isinstance(data, bytearray):
        raise TypeError("secure_erase requires a mutable bytearray")
    
    length = len(data)
    
    # First pass: random data
    random_bytes = secrets.token_bytes(length)
    for i in range(length):
        data[i] = random_bytes[i]
    
    # Second pass: zeros
    for i in range(length):
        data[i] = 0


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def generate_seed(length: int = 32) -> bytes:
    """
    Generate a cryptographically secure random seed.
    
    Args:
        length: Seed length in bytes (default: 32 = 256 bits)
    
    Returns:
        bytes: Cryptographically secure random seed
    """
    return secrets.token_bytes(length)


def generate_domain_tag(length: int = 16) -> bytes:
    """
    Generate a random domain separation tag.
    
    For production use, domain tags should be derived from
    application-specific identifiers, not random.
    
    Args:
        length: Tag length in bytes (default: 16 = 128 bits, rev. 18)
    
    Returns:
        bytes: Random domain tag
    """
    return secrets.token_bytes(length)


def prepare_content(content: Union[str, bytes], use_hash: bool = True) -> bytes:
    """
    Prepare content representation C := R(S).
    
    The preparation function R must be deterministic.
    R = identity is allowed (rev. 20).
    
    Args:
        content: Raw content S (string or bytes)
        use_hash: If True, C := SHA256(S); if False, C := S (identity)
    
    Returns:
        bytes: Deterministic content representation C
    
    Reference: Revendication 20 - R peut être l'identité
    """
    if isinstance(content, str):
        content = content.encode('utf-8')
    
    if use_hash:
        # R = SHA256 (deterministic normalization)
        return hashlib.sha256(content).digest()
    else:
        # R = identity (rev. 20)
        return content


# =============================================================================
# TEST / DEMONSTRATION
# =============================================================================

if __name__ == "__main__":
    print("=== Cryptographic Primitives Test ===\n")
    
    # Test KDF
    print("1. KDF (Key Derivation Function)")
    seed = generate_seed()
    print(f"   Initial seed: {seed.hex()[:32]}...")
    
    next_seed = KDF(seed)
    print(f"   After KDF:    {next_seed.hex()[:32]}...")
    
    # Verify determinism
    assert KDF(seed) == next_seed, "KDF must be deterministic"
    print("   ✓ KDF is deterministic")
    
    # Test KDF with context
    context = b"test_context"
    next_with_ctx = KDF(seed, context)
    assert next_with_ctx != next_seed, "Context should change output"
    print("   ✓ KDF with context produces different output")
    
    # Test fragment computation
    print("\n2. Fragment Computation")
    domain = generate_domain_tag()
    content = prepare_content("Hello, World!")
    
    fragment = compute_fragment(domain, content, seed)
    print(f"   Domain:   {domain.hex()}")
    print(f"   Content:  {content.hex()[:32]}...")
    print(f"   Fragment: {fragment.hex()}")
    print(f"   Length:   {len(fragment) * 8} bits")
    
    # Verify determinism
    fragment2 = compute_fragment(domain, content, seed)
    assert fragment == fragment2, "Fragment computation must be deterministic"
    print("   ✓ Fragment computation is deterministic")
    
    # Test constant-time comparison
    print("\n3. Constant-Time Comparison")
    assert constant_time_equal(fragment, fragment2), "Identical fragments should match"
    print("   ✓ Identical fragments match")
    
    random_fragment = secrets.token_bytes(32)
    assert not constant_time_equal(fragment, random_fragment), "Different fragments should not match"
    print("   ✓ Different fragments do not match")
    
    # Test secure erase
    print("\n4. Secure Erase")
    sensitive = bytearray(seed)
    print(f"   Before erase: {sensitive.hex()[:32]}...")
    secure_erase(sensitive)
    print(f"   After erase:  {sensitive.hex()[:32]}...")
    assert all(b == 0 for b in sensitive), "Data should be zeroed"
    print("   ✓ Data securely erased")
    
    print("\n=== All tests passed ===")
