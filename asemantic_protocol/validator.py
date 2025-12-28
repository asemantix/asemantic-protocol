"""
Fragment Validator for the asemantic fragment validation protocol.

This module handles the reception side:
- Windowed recomputation on [t..t+ν]
- Strict equality acceptance
- Early stop on first match (rev. 7)
- Silent reject (rev. 23)

References:
- Revendication 1: Windowed recomputation + strict equality
- Revendication 7: Early stop at first match
- Revendication 17: No persistent list of accepted fragments
- Revendication 23: Silent reject
"""

from typing import Optional, Tuple, Callable
from enum import Enum

from .crypto import (
    compute_fragment,
    constant_time_equal,
    prepare_content,
    KDF,
    DEFAULT_FRAGMENT_LENGTH
)
from .state import ReceiverState


class ValidationResult(Enum):
    """Result of fragment validation."""
    ACCEPT = "accept"
    REJECT = "reject"
    ERROR = "error"


class FragmentValidator:
    """
    Fragment validator for reception side.
    
    Implements the core validation logic:
    1. For each j in [t..t+ν], compute F̂_j
    2. Compare F̂_j with received F_rx (constant-time)
    3. If match found: ACCEPT, advance anchor to j*+1
    4. If no match: SILENT REJECT
    
    Key properties:
    - NO metadata consumed from transport (rev. 9)
    - NO index transmitted (rev. 1)
    - Windowed recomputation (rev. 1)
    - Strict equality (rev. 1)
    - Early stop (rev. 7)
    - Silent reject (rev. 23)
    
    Usage:
        validator = FragmentValidator(domain, window_size=7)
        result, index = validator.validate(fragment_rx, state, content)
        
        if result == ValidationResult.ACCEPT:
            # Fragment accepted at index
            state.advance(index + 1, new_seed)
    
    Reference: Mise en œuvre du procédé - Réception
    """
    
    def __init__(
        self,
        domain: bytes,
        window_size: int = 7,
        fragment_length: int = DEFAULT_FRAGMENT_LENGTH,
        use_keyed_mode: bool = True,
        evol_func: Optional[Callable[[int], bytes]] = None
    ):
        """
        Initialize the fragment validator.
        
        Args:
            domain: Domain separation tag (must match emitter)
            window_size: Window width ν (0-10 recommended)
            fragment_length: Expected fragment length in bits
            use_keyed_mode: Use seed as key (Mode A)
            evol_func: Evolution function for Mode B
        """
        self.domain = domain
        self.window_size = window_size
        self.fragment_length = fragment_length
        self.use_keyed_mode = use_keyed_mode
        self.evol_func = evol_func
        
        # Statistics (for debugging/testing)
        self._stats = {
            "total_validations": 0,
            "accepts": 0,
            "rejects": 0,
            "comparisons": 0
        }
    
    def validate(
        self,
        fragment_rx: bytes,
        state: ReceiverState,
        content: bytes,
        content_is_prepared: bool = False
    ) -> Tuple[ValidationResult, Optional[int]]:
        """
        Validate a received fragment.
        
        Performs windowed recomputation and strict equality check.
        
        Args:
            fragment_rx: Received fragment F_rx
            state: Receiver state (anchor, seed)
            content: Content S or prepared content C
            content_is_prepared: If True, content is already C := R(S)
        
        Returns:
            Tuple of (result, matched_index):
            - (ACCEPT, j*) if match found at index j*
            - (REJECT, None) if no match (silent reject)
            - (ERROR, None) if validation error
        
        Note:
            On ACCEPT, caller must advance state with:
            state.advance(matched_index + 1, new_seed)
        
        Reference: Revendications 1, 7, 23
        """
        self._stats["total_validations"] += 1
        
        # Validate fragment length
        expected_length = self.fragment_length // 8
        if len(fragment_rx) != expected_length:
            return (ValidationResult.ERROR, None)
        
        # Prepare content if needed
        if content_is_prepared:
            prepared_content = content
        else:
            prepared_content = prepare_content(content, use_hash=True)
        
        # Get window range
        anchor = state.anchor
        window = range(anchor, anchor + self.window_size + 1)
        
        # Mode-specific validation
        if state.mode == "A":
            return self._validate_mode_a(
                fragment_rx, state, prepared_content, window
            )
        else:
            return self._validate_mode_b(
                fragment_rx, state, prepared_content, window
            )
    
    def _validate_mode_a(
        self,
        fragment_rx: bytes,
        state: ReceiverState,
        content: bytes,
        window: range
    ) -> Tuple[ValidationResult, Optional[int]]:
        """
        Mode A validation with secret seed.
        
        For each j in [t..t+ν]:
        1. Derive K_j from K_t
        2. Compute F̂_j = Tronc(F(Encode(domain, C, K_j)))
        3. Compare with F_rx
        """
        # Start with seed at anchor
        current_seed = state.seed
        if current_seed is None:
            return (ValidationResult.ERROR, None)
        
        for j in window:
            self._stats["comparisons"] += 1
            
            # Compute expected fragment
            if self.use_keyed_mode:
                # Keyed mode: seed is the key
                expected = compute_fragment(
                    domain=self.domain,
                    content=content,
                    evolution_param=current_seed,
                    fragment_length_bits=self.fragment_length,
                    key=current_seed
                )
            else:
                # Non-keyed mode: seed in input
                expected = compute_fragment(
                    domain=self.domain,
                    content=content,
                    evolution_param=current_seed,
                    fragment_length_bits=self.fragment_length,
                    key=None
                )
            
            # Strict equality check (constant-time)
            if constant_time_equal(expected, fragment_rx):
                self._stats["accepts"] += 1
                # Return matched index and seed for next state
                return (ValidationResult.ACCEPT, j)
            
            # Advance seed for next iteration (temporary, not persisted)
            current_seed = KDF(current_seed)
        
        # No match found - silent reject (rev. 23)
        self._stats["rejects"] += 1
        return (ValidationResult.REJECT, None)
    
    def _validate_mode_b(
        self,
        fragment_rx: bytes,
        state: ReceiverState,
        content: bytes,
        window: range
    ) -> Tuple[ValidationResult, Optional[int]]:
        """
        Mode B validation with deterministic evolution.
        
        For each j in [t..t+ν]:
        1. Compute Z_j = Evol(j)
        2. Compute F̂_j = Tronc(F(Encode(domain, C, Z_j)))
        3. Compare with F_rx
        """
        if self.evol_func is None:
            return (ValidationResult.ERROR, None)
        
        for j in window:
            self._stats["comparisons"] += 1
            
            # Get evolution parameter
            evolution_param = self.evol_func(j)
            
            # Compute expected fragment
            expected = compute_fragment(
                domain=self.domain,
                content=content,
                evolution_param=evolution_param,
                fragment_length_bits=self.fragment_length,
                key=None
            )
            
            # Strict equality check
            if constant_time_equal(expected, fragment_rx):
                self._stats["accepts"] += 1
                return (ValidationResult.ACCEPT, j)
        
        # Silent reject
        self._stats["rejects"] += 1
        return (ValidationResult.REJECT, None)
    
    def validate_and_commit(
        self,
        fragment_rx: bytes,
        state: ReceiverState,
        content: bytes,
        content_is_prepared: bool = False
    ) -> Tuple[ValidationResult, Optional[int]]:
        """
        Validate and atomically commit state on acceptance.
        
        This is a convenience method that combines validation
        and state advancement in one atomic operation.
        
        Args:
            fragment_rx: Received fragment
            state: Receiver state (will be modified on accept)
            content: Content S or C
            content_is_prepared: If True, content is C
        
        Returns:
            Tuple of (result, matched_index)
        
        Reference: Revendication 24 - Atomicité
        """
        result, matched_index = self.validate(
            fragment_rx, state, content, content_is_prepared
        )
        
        if result == ValidationResult.ACCEPT and matched_index is not None:
            # Compute new seed for state update
            if state.mode == "A":
                new_seed = state.get_seed_for_index(matched_index + 1)
            else:
                new_seed = None
            
            # Atomic commit
            success = state.advance(matched_index + 1, new_seed)
            if not success:
                return (ValidationResult.ERROR, None)
        
        return (result, matched_index)
    
    @property
    def stats(self) -> dict:
        """Get validation statistics."""
        return self._stats.copy()
    
    def reset_stats(self) -> None:
        """Reset validation statistics."""
        self._stats = {
            "total_validations": 0,
            "accepts": 0,
            "rejects": 0,
            "comparisons": 0
        }


# =============================================================================
# CONSTANT-TIME VARIANT (for side-channel resistance)
# =============================================================================

class ConstantTimeValidator(FragmentValidator):
    """
    Constant-time variant of FragmentValidator.
    
    This variant always explores the entire window,
    regardless of when/if a match is found.
    
    Use this when timing side-channel resistance is
    more important than efficiency.
    
    Reference: Description fonctionnelle - Note sur la stratégie d'exploration
    """
    
    def _validate_mode_a(
        self,
        fragment_rx: bytes,
        state: ReceiverState,
        content: bytes,
        window: range
    ) -> Tuple[ValidationResult, Optional[int]]:
        """
        Constant-time Mode A validation.
        
        Always explores entire window to prevent timing leaks.
        """
        current_seed = state.seed
        if current_seed is None:
            return (ValidationResult.ERROR, None)
        
        matched_index = None
        
        # Always iterate through entire window
        for j in window:
            self._stats["comparisons"] += 1
            
            if self.use_keyed_mode:
                expected = compute_fragment(
                    domain=self.domain,
                    content=content,
                    evolution_param=current_seed,
                    fragment_length_bits=self.fragment_length,
                    key=current_seed
                )
            else:
                expected = compute_fragment(
                    domain=self.domain,
                    content=content,
                    evolution_param=current_seed,
                    fragment_length_bits=self.fragment_length,
                    key=None
                )
            
            # Check match but DON'T return early
            if constant_time_equal(expected, fragment_rx):
                if matched_index is None:  # Keep first match
                    matched_index = j
            
            current_seed = KDF(current_seed)
        
        # Return result after full iteration
        if matched_index is not None:
            self._stats["accepts"] += 1
            return (ValidationResult.ACCEPT, matched_index)
        else:
            self._stats["rejects"] += 1
            return (ValidationResult.REJECT, None)


# =============================================================================
# DEMONSTRATION
# =============================================================================

if __name__ == "__main__":
    from .crypto import generate_seed, generate_domain_tag
    from .fragment import FragmentBuilder
    
    print("=== Fragment Validator Demo ===\n")
    
    # Shared parameters (provisioned out-of-band)
    domain = generate_domain_tag()
    seed = generate_seed()
    window_size = 7
    
    print(f"Domain: {domain.hex()[:16]}...")
    print(f"Window size: {window_size}")
    
    # Create emitter and receiver
    builder = FragmentBuilder.mode_a(domain, seed)
    state = ReceiverState.mode_a(seed)
    validator = FragmentValidator(domain, window_size)
    
    content = b"SENSOR_DATA_12345"
    print(f"Content: {content.decode()}")
    
    # Test 1: Valid fragment
    print("\n--- Test 1: Valid Fragment ---")
    fragment = builder.build(content)
    print(f"Fragment: {fragment.hex()[:32]}...")
    
    result, index = validator.validate_and_commit(fragment, state, content)
    print(f"Result: {result.value}")
    print(f"Matched at index: {index}")
    print(f"New anchor: {state.anchor}")
    
    builder.advance()  # Keep emitter in sync
    
    # Test 2: Another valid fragment
    print("\n--- Test 2: Second Valid Fragment ---")
    fragment2 = builder.build(content)
    result, index = validator.validate_and_commit(fragment2, state, content)
    print(f"Result: {result.value}")
    print(f"Matched at index: {index}")
    
    builder.advance()
    
    # Test 3: Invalid fragment (random)
    print("\n--- Test 3: Invalid Fragment (random) ---")
    import secrets
    fake_fragment = secrets.token_bytes(32)
    result, index = validator.validate(fake_fragment, state, content)
    print(f"Result: {result.value} (silent reject)")
    print(f"Matched: {index}")
    
    # Test 4: Replay attack (old fragment)
    print("\n--- Test 4: Replay Attack (old fragment) ---")
    result, index = validator.validate(fragment, state, content)
    print(f"Result: {result.value} (old fragment rejected)")
    
    # Statistics
    print("\n--- Validation Statistics ---")
    stats = validator.stats
    print(f"Total validations: {stats['total_validations']}")
    print(f"Accepts: {stats['accepts']}")
    print(f"Rejects: {stats['rejects']}")
    print(f"Total comparisons: {stats['comparisons']}")
    
    print("\n=== Demo complete ===")
