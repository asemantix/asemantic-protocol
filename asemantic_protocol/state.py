"""
Receiver State Management for the asemantic fragment validation protocol.

This module handles:
- Monotonic anchor t management
- Seed state K_t (Mode A)
- Atomic state updates (anti-rollback)
- State persistence

References:
- Revendication 1: Monotonic anchor
- Revendication 17: No persistent list of accepted fragments
- Revendication 21: Secure element anchoring (SE/TPM/NVRAM)
- Revendication 22: Window slides only on acceptance
- Revendication 24: Atomic state update
"""

import json
import os
from typing import Optional
from pathlib import Path
from .crypto import KDF, secure_erase


class ReceiverState:
    """
    Manages the receiver's local state for fragment validation.
    
    The state consists of:
    - Anchor t: Minimum acceptable index (monotonic, never decreases)
    - Seed K_t: Current seed aligned with anchor (Mode A only)
    
    Key properties:
    - NO persistent list of accepted fragments (rev. 17)
    - Window [t..t+ν] slides ONLY on acceptance (rev. 22)
    - Atomic updates prevent inconsistent states (rev. 24)
    
    Usage:
        state = ReceiverState.mode_a(initial_seed, persistence_path)
        
        # Validation attempt
        if validator.validate(fragment_rx, state):
            state.advance(matched_index)  # Atomic commit
    
    Reference: Annexe E - Hygiène d'implémentation
    """
    
    def __init__(
        self,
        mode: str,
        anchor: int = 0,
        seed: Optional[bytes] = None,
        persistence_path: Optional[str] = None
    ):
        """
        Initialize receiver state.
        
        Args:
            mode: "A" for secret seed, "B" for deterministic evolution
            anchor: Initial anchor t (default: 0)
            seed: Initial seed K_0 for Mode A
            persistence_path: File path for state persistence (optional)
        """
        self.mode = mode.upper()
        self._anchor = anchor
        self._persistence_path = persistence_path
        
        if self.mode == "A":
            if seed is None:
                raise ValueError("Mode A requires a seed")
            # Mutable for secure erase (forward secrecy)
            self._seed = bytearray(seed)
        else:
            self._seed = None
        
        # Load persisted state if exists
        if persistence_path and os.path.exists(persistence_path):
            self._load_state()
    
    @classmethod
    def mode_a(
        cls,
        seed: bytes,
        persistence_path: Optional[str] = None,
        initial_anchor: int = 0
    ) -> "ReceiverState":
        """
        Create Mode A receiver state (secret seed).
        
        Args:
            seed: Initial seed K_0 (shared out-of-band with emitter)
            persistence_path: File path for state persistence
            initial_anchor: Starting anchor value
        
        Returns:
            ReceiverState configured for Mode A
        """
        return cls(
            mode="A",
            anchor=initial_anchor,
            seed=seed,
            persistence_path=persistence_path
        )
    
    @classmethod
    def mode_b(
        cls,
        persistence_path: Optional[str] = None,
        initial_anchor: int = 0
    ) -> "ReceiverState":
        """
        Create Mode B receiver state (no seed).
        
        Args:
            persistence_path: File path for state persistence
            initial_anchor: Starting anchor value
        
        Returns:
            ReceiverState configured for Mode B
        """
        return cls(
            mode="B",
            anchor=initial_anchor,
            persistence_path=persistence_path
        )
    
    @property
    def anchor(self) -> int:
        """
        Current anchor t (minimum acceptable index).
        
        The anchor is monotonic: it can only increase.
        Fragments with index < t are automatically rejected.
        """
        return self._anchor
    
    @property
    def seed(self) -> Optional[bytes]:
        """
        Current seed K_t (Mode A only).
        
        Returns immutable copy to prevent accidental modification.
        """
        if self._seed is None:
            return None
        return bytes(self._seed)
    
    def get_seed_for_index(self, index: int) -> Optional[bytes]:
        """
        Derive the seed for a given index in the window.
        
        Starting from K_t, derives K_j for j in [t..t+ν].
        
        Args:
            index: Target index j
        
        Returns:
            bytes: Seed K_j, or None if index < anchor
        
        Note:
            This is a temporary derivation for validation.
            The persistent state is NOT modified.
        """
        if self.mode != "A":
            return None
        
        if index < self._anchor:
            return None  # Index is before anchor (rejected)
        
        # Start from current seed
        current = bytes(self._seed)
        
        # Derive forward to reach target index
        for _ in range(index - self._anchor):
            current = KDF(current)
        
        return current
    
    def advance(
        self,
        new_anchor: int,
        new_seed: Optional[bytes] = None
    ) -> bool:
        """
        Atomically advance the state after acceptance.
        
        This implements the monotonic anchor update:
        t ← j* + 1
        
        In Mode A, also updates the seed to K_{j*+1}.
        
        Args:
            new_anchor: New anchor value (must be > current anchor)
            new_seed: New seed K_{new_anchor} for Mode A
        
        Returns:
            bool: True if update succeeded, False otherwise
        
        Security:
            - Monotonic: new_anchor must be > current anchor
            - Atomic: either fully commits or doesn't change state
            - Forward secrecy: old seeds are securely erased
        
        Reference: Revendications 1, 17, 21, 22, 24
        """
        # Validate monotonicity
        if new_anchor <= self._anchor:
            return False  # Anchor can only increase
        
        if self.mode == "A":
            if new_seed is None:
                return False
            
            # Securely erase old seed (forward secrecy - rev. 3)
            old_seed = self._seed
            
            # Update state atomically
            self._seed = bytearray(new_seed)
            self._anchor = new_anchor
            
            # Erase old seed after successful update
            secure_erase(old_seed)
        else:
            # Mode B: only update anchor
            self._anchor = new_anchor
        
        # Persist state if configured
        if self._persistence_path:
            self._save_state()
        
        return True
    
    def _save_state(self) -> None:
        """
        Persist state to file (atomic write).
        
        Uses atomic write pattern:
        1. Write to temporary file
        2. Sync to disk
        3. Atomic rename
        
        This ensures state is never corrupted even on power failure.
        
        Reference: Revendication 21 - Ancrage SE/NVRAM
        """
        if not self._persistence_path:
            return
        
        state = {
            "mode": self.mode,
            "anchor": self._anchor,
            "version": 1
        }
        
        if self.mode == "A" and self._seed:
            state["seed"] = bytes(self._seed).hex()
        
        # Atomic write pattern
        temp_path = self._persistence_path + ".tmp"
        
        try:
            with open(temp_path, 'w') as f:
                json.dump(state, f)
                f.flush()
                os.fsync(f.fileno())
            
            # Atomic rename
            os.replace(temp_path, self._persistence_path)
        except Exception as e:
            # Clean up temp file on failure
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise e
    
    def _load_state(self) -> None:
        """
        Load state from persistence file.
        
        Only accepts state if anchor is >= current anchor
        (prevents rollback attacks).
        """
        if not self._persistence_path or not os.path.exists(self._persistence_path):
            return
        
        try:
            with open(self._persistence_path, 'r') as f:
                state = json.load(f)
            
            # Validate and apply
            loaded_anchor = state.get("anchor", 0)
            
            # Anti-rollback: only accept if >= current
            if loaded_anchor >= self._anchor:
                self._anchor = loaded_anchor
                
                if self.mode == "A" and "seed" in state:
                    self._seed = bytearray(bytes.fromhex(state["seed"]))
        
        except (json.JSONDecodeError, IOError):
            # Corrupted state file - keep current state
            pass
    
    def get_window_range(self, window_size: int) -> range:
        """
        Get the valid window range [t..t+ν].
        
        Args:
            window_size: Window width ν
        
        Returns:
            range: Range object for iteration
        """
        return range(self._anchor, self._anchor + window_size + 1)
    
    def is_in_window(self, index: int, window_size: int) -> bool:
        """
        Check if an index is within the current window.
        
        Args:
            index: Index to check
            window_size: Window width ν
        
        Returns:
            bool: True if index ∈ [t..t+ν]
        """
        return self._anchor <= index <= self._anchor + window_size
    
    def __repr__(self) -> str:
        return f"ReceiverState(mode={self.mode}, anchor={self._anchor})"


# =============================================================================
# SECURE ELEMENT SIMULATION (for testing)
# =============================================================================

class SecureElementState(ReceiverState):
    """
    Simulated Secure Element state with enhanced anti-rollback.
    
    In production, this would interface with:
    - TPM (Trusted Platform Module)
    - SE (Secure Element)
    - NVRAM with monotonic counter
    
    This simulation adds:
    - Rollback detection on load
    - Counter-based verification
    
    Reference: Revendication 21 - SE/TPM/NVRAM
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._rollback_counter = 0
    
    def advance(self, new_anchor: int, new_seed: Optional[bytes] = None) -> bool:
        """Advance with rollback counter increment."""
        success = super().advance(new_anchor, new_seed)
        if success:
            self._rollback_counter += 1
        return success
    
    def _save_state(self) -> None:
        """Save with rollback counter."""
        if not self._persistence_path:
            return
        
        state = {
            "mode": self.mode,
            "anchor": self._anchor,
            "rollback_counter": self._rollback_counter,
            "version": 1
        }
        
        if self.mode == "A" and self._seed:
            state["seed"] = bytes(self._seed).hex()
        
        # Atomic write
        temp_path = self._persistence_path + ".tmp"
        with open(temp_path, 'w') as f:
            json.dump(state, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, self._persistence_path)
    
    def _load_state(self) -> None:
        """Load with rollback detection."""
        if not self._persistence_path or not os.path.exists(self._persistence_path):
            return
        
        try:
            with open(self._persistence_path, 'r') as f:
                state = json.load(f)
            
            loaded_counter = state.get("rollback_counter", 0)
            
            # Rollback detection
            if loaded_counter < self._rollback_counter:
                raise SecurityError("Rollback attack detected!")
            
            # Apply state
            self._anchor = state.get("anchor", 0)
            self._rollback_counter = loaded_counter
            
            if self.mode == "A" and "seed" in state:
                self._seed = bytearray(bytes.fromhex(state["seed"]))
        
        except (json.JSONDecodeError, IOError):
            pass


class SecurityError(Exception):
    """Raised when a security violation is detected."""
    pass


# =============================================================================
# DEMONSTRATION
# =============================================================================

if __name__ == "__main__":
    import tempfile
    from .crypto import generate_seed
    
    print("=== Receiver State Demo ===\n")
    
    # Create temporary persistence file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        persistence_path = f.name
    
    try:
        # Mode A demonstration
        print("--- Mode A (Secret Seed) ---")
        seed = generate_seed()
        state = ReceiverState.mode_a(seed, persistence_path)
        
        print(f"Initial: {state}")
        print(f"Anchor: {state.anchor}")
        print(f"Window [0..10]: {list(state.get_window_range(10))[:5]}...")
        
        # Simulate acceptance at index 5
        print("\n[Accepting fragment at index 5]")
        new_seed = state.get_seed_for_index(6)  # K_6 for new anchor
        success = state.advance(6, new_seed)
        print(f"Advance success: {success}")
        print(f"New anchor: {state.anchor}")
        print(f"Window [6..16]: {list(state.get_window_range(10))[:5]}...")
        
        # Test monotonicity (should fail)
        print("\n[Attempting rollback to index 3]")
        success = state.advance(3, seed)
        print(f"Rollback attempt: {success} (expected: False)")
        
        # Verify persistence
        print("\n--- State Persistence ---")
        state2 = ReceiverState.mode_a(seed, persistence_path)
        print(f"Loaded state: {state2}")
        print(f"Anchor preserved: {state2.anchor == state.anchor}")
        
        # Mode B demonstration
        print("\n--- Mode B (No Seed) ---")
        state_b = ReceiverState.mode_b()
        print(f"Initial: {state_b}")
        
        state_b.advance(10)
        print(f"After advance to 10: {state_b}")
        
    finally:
        # Cleanup
        if os.path.exists(persistence_path):
            os.remove(persistence_path)
    
    print("\n=== Demo complete ===")
