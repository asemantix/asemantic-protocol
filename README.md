# Asemantic Fragment Validation Protocol – PoC

Minimal Python implementation (proof-of-concept) of the asemantic fragment
validation protocol described in the patent: validation exclusivement locale de
fragments asémantiques auto-porteurs avec fenêtre bornée et ancre monotone.

## Installation

```bash
pip install .
```

## Demo

```bash
python -m examples.demo_minimal
```

This will:
- provision a random domain tag and seed K0 (shared out-of-band),
- create a sender (FragmentBuilder) and receiver (ReceiverState + FragmentValidator) in Mode A,
- emit and validate two successive fragments (F0, F1),
- attempt to replay F0 and show that it is rejected while the anchor t remains monotonic.
