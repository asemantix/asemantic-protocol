"""
Asemantic Fragment Validation Protocol (PoC)

Python implementation of the protocol described in the patent:
validation exclusivement locale de fragments asémantiques auto-porteurs
avec fenêtre bornée et ancre monotone.
"""

from .fragment import FragmentBuilder
from .validator import FragmentValidator, ValidationResult
from .state import ReceiverState
from .crypto import (
    KDF,
    compute_fragment,
    constant_time_equal,
    generate_seed,
    generate_domain_tag,
    DEFAULT_FRAGMENT_LENGTH,
)

__all__ = [
    "FragmentBuilder",
    "FragmentValidator",
    "ReceiverState",
    "ValidationResult",
    "KDF",
    "compute_fragment",
    "constant_time_equal",
    "generate_seed",
    "generate_domain_tag",
    "DEFAULT_FRAGMENT_LENGTH",
]
