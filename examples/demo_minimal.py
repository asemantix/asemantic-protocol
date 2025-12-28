#!/usr/bin/env python3
"""
Minimal end-to-end demo of the asemantic fragment validation protocol.

Usage (from repo root):
    pip install .
    python -m examples.demo_minimal
"""

from asemantic_protocol import (
    FragmentBuilder,
    FragmentValidator,
    ReceiverState,
    ValidationResult,
    generate_seed,
    generate_domain_tag,
)


def main():
    domain = generate_domain_tag()
    seed = generate_seed()

    print("\n=== Provisionnement ===")
    print("Domain tag (hex, tronque):", domain.hex()[:16], "...")
    print("Seed K0 (hex, tronque):   ", seed.hex()[:16], "...")

    builder = FragmentBuilder.mode_a(domain, seed)
    state = ReceiverState.mode_a(seed)
    validator = FragmentValidator(domain, window_size=7)

    content = b"ALARM_LEVEL_3"
    print("\nContenu applicatif S:", content)

    print("\n=== Emission F0 ===")
    fragment0 = builder.build(content)
    print("F0 (hex, tronque):", fragment0.hex()[:16], "...", fragment0.hex()[-16:])

    print("\n=== Reception F0 ===")
    print("Avant validation: ancre t =", state.anchor)
    result0, idx0 = validator.validate_and_commit(fragment0, state, content)
    print("Resultat validation F0:", result0.value.upper(), "a l'indice j* =", idx0)
    print("Apres validation: ancre t =", state.anchor)

    builder.advance()

    print("\n=== Emission F1 ===")
    fragment1 = builder.build(content)
    print("F1 (hex, tronque):", fragment1.hex()[:16], "...", fragment1.hex()[-16:])

    print("\n=== Reception F1 ===")
    print("Avant validation: ancre t =", state.anchor)
    result1, idx1 = validator.validate_and_commit(fragment1, state, content)
    print("Resultat validation F1:", result1.value.upper(), "a l'indice j* =", idx1)
    print("Apres validation: ancre t =", state.anchor)

    print("\n=== Rejeu de F0 (attaque replay) ===")
    print("F0 (rejoue) hex tronque:", fragment0.hex()[:16], "...", fragment0.hex()[-16:])
    result_replay, idx_replay = validator.validate(fragment0, state, content)
    print("Resultat validation F0 rejoue:", result_replay.value.upper())
    print("Index retourne:", idx_replay)
    print("Ancre t reste =", state.anchor, "(pas de glissement)")


if __name__ == "__main__":
    main()
