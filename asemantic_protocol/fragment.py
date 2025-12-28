"""
Fragment Builder for the asemantic fragment validation protocol.

This module handles the emission side:
- Fragment construction F_i = Tronc_ℓ(F(Encode(domain, C, Z_i)))
- Mode A: Secret seed evolution K_{j+1} := KDF(K_j)
- Mode B: Deterministic evolution Z_i := Evol(i)

References:
- Revendication 1: Fragment construction
- Revendication 3: Mode A - Secret seed
- Revendication 4: Mode B - Deterministic evolution
"""

from typing import Optional, Callable
from .crypto import (
    compute_fragment,
    KDF,
    prepare_content,
    generate_seed,
    generate_domain_tag,
    secure_erase,
    DEFAULT_FRAGMENT_LENGTH
)


class FragmentBuilder:
    """
    Fragment builder for emission side.
    
    Constructs asemantic fragments F_i from content S using:
    - Domain separation tag (provisioned out-of-band)
    - Content representation C := R(S)
    - Evolution parameter Z_i (Mode A: seed K_i, Mode B: Evol(i))
    
    The fragment is the ONLY thing transmitted on the channel.
    No metadata, no index, no timestamp.
    
    Usage (Mode A - recommended):
        builder = FragmentBuilder.mode_a(domain, seed)
        fragment = builder.build(content)
        # send fragment on channel
        builder.advance()  # K_{i+1} := KDF(K_i)
    
    Usage (Mode B):
        builder = FragmentBuilder.mode_b(domain, lambda i: i.to_bytes(8, 'big'))
        fragment = builder.build(content)
        builder.advance()
    
    Reference: Mise en œuvre du procédé - Émission
    """
    
    def __init__(
        self,
        domain: bytes,
        mode: str,
        seed: Optional[bytes] = None,
        evol_func: Optional[Callable[[int], bytes]] = None,
        fragment_length: int = DEFAULT_FRAGMENT_LENGTH,
        use_keyed_mode: bool = True
    ):
        """
        Initialize the fragment builder.
        
        Args:
            domain: Domain separation tag (d ≥ 128 bits recommended)
            mode: "A" for secret seed mode, "B" for deterministic evolution
            seed: Initial seed K_0 for Mode A (required if mode="A")
            evol_func: Evolution function Evol(i) for Mode B
            fragment_length: Output length in bits (≥ 256)
            use_keyed_mode: If True, use seed as key (Mode A PRF variant)
        """
        self.domain = domain
        self.mode = mode.upper()
        self.fragment_length = fragment_length
        self.use_keyed_mode = use_keyed_mode
        
        # Current index (logical, not transmitted)
        self._index = 0
        
        if self.mode == "A":
            if seed is None:
                raise ValueError("Mode A requires a seed")
            self._seed = bytearray(seed)  # Mutable for secure erase
            self._evol_func = None
        elif self.mode == "B":
            if evol_func is None:
                raise ValueError("Mode B requires an evolution function")
            self._seed = None
            self._evol_func = evol_func
        else:
            raise ValueError(f"Unknown mode: {mode}")
    
    @classmethod
    def mode_a(
        cls,
        domain: bytes,
        seed: bytes,
        fragment_length: int = DEFAULT_FRAGMENT_LENGTH,
        use_keyed_mode: bool = True
    ) -> "FragmentBuilder":
        """
        Create a Mode A fragment builder (secret seed).
        
        Mode A uses a secret seed K_i shared out-of-band between
        emitter and receiver. The seed evolves unidirectionally:
        K_{i+1} := KDF(K_i)
        
        This mode provides:
        - Authentication (secret-based)
        - Forward secrecy (with seed erasure)
        
        Args:
            domain: Domain separation tag
            seed: Initial seed K_0 (shared out-of-band)
            fragment_length: Output length in bits
            use_keyed_mode: Use seed as PRF key (recommended)
        
        Returns:
            FragmentBuilder configured for Mode A
        
        Reference: Revendication 3
        """
        return cls(
            domain=domain,
            mode="A",
            seed=seed,
            fragment_length=fragment_length,
            use_keyed_mode=use_keyed_mode
        )
    
    @classmethod
    def mode_b(
        cls,
        domain: bytes,
        evol_func: Callable[[int], bytes],
        fragment_length: int = DEFAULT_FRAGMENT_LENGTH
    ) -> "FragmentBuilder":
        """
        Create a Mode B fragment builder (deterministic evolution).
        
        Mode B uses a deterministic function Evol(i) that can be
        computed locally by both emitter and receiver without
        transmitting the index.
        
        Examples of Evol:
        - Counter: i.to_bytes(8, 'big')
        - Calendar: date_to_bytes(current_date())
        
        Note: Mode B does not provide authentication unless
        C := R(S) or the primitive F is keyed.
        
        Args:
            domain: Domain separation tag
            evol_func: Function i -> bytes
            fragment_length: Output length in bits
        
        Returns:
            FragmentBuilder configured for Mode B
        
        Reference: Revendication 4
        """
        return cls(
            domain=domain,
            mode="B",
            evol_func=evol_func,
            fragment_length=fragment_length
        )
    
    def build(
        self,
        content: bytes,
        content_is_prepared: bool = False
    ) -> bytes:
        """
        Build a fragment from content.
        
        Computes F_i = Tronc_ℓ(F(Encode(domain, C, Z_i)))
        
        Args:
            content: Raw content S or prepared content C
            content_is_prepared: If True, content is already C := R(S)
        
        Returns:
            bytes: Fragment F_i (ℓ/8 bytes)
        
        Note:
            Call advance() after sending to evolve the seed/index.
            Do NOT call advance() if the fragment is not sent.
        """
        # Prepare content if needed
        if content_is_prepared:
            prepared = content
        else:
            prepared = prepare_content(content, use_hash=True)
        
        # Get evolution parameter Z_i
        if self.mode == "A":
            evolution_param = bytes(self._seed)
            key = bytes(self._seed) if self.use_keyed_mode else None
        else:
            evolution_param = self._evol_func(self._index)
            key = None
        
        # Compute fragment
        fragment = compute_fragment(
            domain=self.domain,
            content=prepared,
            evolution_param=evolution_param,
            fragment_length_bits=self.fragment_length,
            key=key if self.use_keyed_mode else None
        )
        
        return fragment
    
    def advance(self) -> None:
        """
        Advance the evolution state after successful emission.
        
        Mode A: K_{i+1} := KDF(K_i), old seed is securely erased
        Mode B: i := i + 1
        
        IMPORTANT: Call this ONLY after the fragment has been
        successfully sent on the channel.
        
        Reference: Revendication 3 - Effacement sécurisé
        """
        if self.mode == "A":
            # Compute next seed
            next_seed = KDF(bytes(self._seed))
            
            # Securely erase old seed (forward secrecy)
            secure_erase(self._seed)
            
            # Update to new seed
            self._seed = bytearray(next_seed)
        
        # Advance index (both modes)
        self._index += 1
    
    @property
    def current_index(self) -> int:
        """Current logical index (not transmitted)."""
        return self._index
    
    def get_state(self) -> dict:
        """
        Get current state for persistence.
        
        Returns:
            dict: State that can be saved and restored
        """
        state = {
            "mode": self.mode,
            "index": self._index,
            "domain": self.domain.hex(),
            "fragment_length": self.fragment_length
        }
        
        if self.mode == "A":
            state["seed"] = bytes(self._seed).hex()
        
        return state
    
    @classmethod
    def from_state(
        cls,
        state: dict,
        evol_func: Optional[Callable[[int], bytes]] = None
    ) -> "FragmentBuilder":
        """
        Restore a FragmentBuilder from saved state.
        
        Args:
            state: Previously saved state dict
            evol_func: Evolution function for Mode B (required if Mode B)
        
        Returns:
            FragmentBuilder: Restored builder
        """
        domain = bytes.fromhex(state["domain"])
        
        if state["mode"] == "A":
            builder = cls.mode_a(
                domain=domain,
                seed=bytes.fromhex(state["seed"]),
                fragment_length=state["fragment_length"]
            )
        else:
            if evol_func is None:
                raise ValueError("Mode B requires evol_func to restore")
            builder = cls.mode_b(
                domain=domain,
                evol_func=evol_func,
                fragment_length=state["fragment_length"]
            )
        
        builder._index = state["index"]
        return builder


# =============================================================================
# DEMONSTRATION
# =============================================================================

if __name__ == "__main__":
    print("=== Fragment Builder Demo ===\n")
    
    # Generate shared parameters (provisioned out-of-band)
    domain = generate_domain_tag()
    seed = generate_seed()
    
    print(f"Domain tag: {domain.hex()}")
    print(f"Initial seed: {seed.hex()[:32]}...")
    
    # Mode A demonstration
    print("\n--- Mode A (Secret Seed) ---")
    builder_a = FragmentBuilder.mode_a(domain, seed)
    
    content = b"ALARM_LEVEL_3"
    print(f"\nContent: {content.decode()}")
    
    for i in range(3):
        fragment = builder_a.build(content)
        print(f"Fragment {i}: {fragment.hex()[:48]}...")
        builder_a.advance()
    
    # Mode B demonstration
    print("\n--- Mode B (Counter) ---")
    
    def counter_evol(i: int) -> bytes:
        return i.to_bytes(8, 'big')
    
    builder_b = FragmentBuilder.mode_b(domain, counter_evol)
    
    for i in range(3):
        fragment = builder_b.build(content)
        print(f"Fragment {i}: {fragment.hex()[:48]}...")
        builder_b.advance()
    
    # State persistence demo
    print("\n--- State Persistence ---")
    state = builder_a.get_state()
    print(f"Saved state: mode={state['mode']}, index={state['index']}")
    
    restored = FragmentBuilder.from_state(state)
    print(f"Restored: mode={restored.mode}, index={restored.current_index}")
    
    print("\n=== Demo complete ===")
