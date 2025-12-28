# ASEMANTIX™ — Asemantic Protocol PoC

[▶ Try the PoC in Colab](#try-the-poc-in-colab) · [⬇ Install locally](#install) · [▶ Run the demo](#demo)
[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/asemantix/asemantic-protocol/blob/main/ASEMANTIX_PoC_Demo.ipynb)

**The First Asemantic Protocol on Raw Heterogeneous Channels**

[![Website](https://img.shields.io/badge/Website-asemantix.tech-gold?style=for-the-badge)](https://asemantix.tech)
[![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge)](https://python.org)
[![License](https://img.shields.io/badge/License-Proprietary-red?style=for-the-badge)]()

**[Install](#install) • [Demo](#demo) • [Run in Colab](#run-in-google-colab) • [Documentation](https://asemantix.tech)**

---

## What is this?

Proof of Concept Python implementation of the asemantic fragment validation protocol described in the patent:

> *"Procédé de validation exclusivement locale de fragments asémantiques auto-porteurs, avec fenêtre bornée et ancre monotone"*

**Key features:**
- Fragments are **indistinguishable from random noise** (NIST SP 800-22: 100% pass)
- **Zero metadata** transmitted (no index, no timestamp, no headers)
- **Local validation** with bounded window [t, t+ν]
- **Anti-replay** via monotonic anchor
- **Forward secrecy** via KDF seed evolution

---

## Run in Google Colab

**No installation required!** Click the button below to run the demo in your browser:

## Try the PoC in Colab

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/asemantix/asemantic-protocol/blob/main/ASEMANTIX_PoC_Demo.ipynb)

---

## Install
**Prerequisites**: Python 3.8+ and Git installed on your machine. You should be able to run `python --version` and `git --version`.


```bash
# Clone the repository
git clone https://github.com/asemantix/asemantic-protocol.git
cd asemantic-protocol

# Optional: create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate

# Install the package
pip install .
```

### Quick install (without cloning):

```bash
pip install git+https://github.com/asemantix/asemantic-protocol.git
```

---

## Demo

After installation, run the minimal demo:

```bash
python -m examples.demo_minimal
```

### What the demo shows:

| Step | Description | Patent Claim |
|------|-------------|--------------|
| 1 | Provisioning (domain + seed K0) | — |
| 2 | Emit F0, validate → ACCEPT | Claim 1 |
| 3 | Emit F1, validate → ACCEPT | Claim 3 |
| 4 | Replay F0 → REJECT | Claim 9 |
| 5 | Anchor stays monotonic | Claim 9 |

### Expected output:

```
=== Provisionnement ===
Domain tag (hex, tronque): dc6acba57cd926dc ...
Seed K0 (hex, tronque):    a4164e965d600668 ...

=== Emission F0 ===
F0 (hex, tronque): c76566ec7e80ab7d ... 6b0d2de7e8ae7dfd

=== Reception F0 ===
Avant validation: ancre t = 0
Resultat validation F0: ACCEPT a l'indice j* = 0
Apres validation: ancre t = 1

=== Emission F1 ===
F1 (hex, tronque): f4bbce6c03ede07d ... a6b0bceb55ae9669

=== Reception F1 ===
Avant validation: ancre t = 1
Resultat validation F1: ACCEPT a l'indice j* = 1
Apres validation: ancre t = 2

=== Rejeu de F0 (attaque replay) ===
F0 (rejoue) hex tronque: c76566ec7e80ab7d ... 6b0d2de7e8ae7dfd
Resultat validation F0 rejoue: REJECT
Index retourne: None
Ancre t reste = 2 (pas de glissement)
```

---

## API Usage

```python
from asemantic_protocol import (
    FragmentBuilder,
    FragmentValidator,
    ReceiverState,
    generate_seed,
    generate_domain_tag,
)

# Provisioning (shared out-of-band)
domain = generate_domain_tag()  # 128 bits
seed = generate_seed()          # 256 bits

# Emitter side
builder = FragmentBuilder.mode_a(domain, seed)
fragment = builder.build(b"SECRET_MESSAGE")
builder.advance()  # K1 = KDF(K0)

# Receiver side
state = ReceiverState.mode_a(seed)
validator = FragmentValidator(domain, window_size=7)

result, index = validator.validate_and_commit(fragment, state, b"SECRET_MESSAGE")
# result = ValidationResult.ACCEPT
# index = 0
# state.anchor = 1
```

---

## Project Structure

```
asemantic-protocol/
├── README.md
├── pyproject.toml
├── ASEMANTIX_PoC_Demo.ipynb    # Google Colab notebook
├── asemantic_protocol/
│   ├── __init__.py             # Public API
│   ├── crypto.py               # KDF, compute_fragment, constant_time_equal
│   ├── fragment.py             # FragmentBuilder (Mode A / Mode B)
│   ├── state.py                # ReceiverState, monotonic anchor
│   └── validator.py            # FragmentValidator, windowed validation
└── examples/
    └── demo_minimal.py         # Minimal end-to-end demo
```

---

## Patent Claims Demonstrated

| Claim | Description | Implementation |
|-------|-------------|----------------|
| 1 | Windowed recomputation + strict equality | `FragmentValidator.validate()` |
| 3 | Mode A — Secret seed with forward secrecy | `FragmentBuilder.mode_a()` |
| 7 | Early stop on first match | `_validate_mode_a()` loop |
| 8 | Fragment length ℓ ≥ 256 bits | `DEFAULT_FRAGMENT_LENGTH = 256` |
| 9 | Monotonic anchor (anti-replay) | `ReceiverState.advance()` |
| 17 | No persistent list of accepted fragments | State = (anchor, seed) only |
| 18 | Domain separation d ≥ 128 bits | `generate_domain_tag()` |

---

## Performance

| Metric | Value |
|--------|-------|
| Fragment generation | >20,000 /second |
| Fragment validation | >20,000 /second |
| Latency | <50 µs |
| NIST SP 800-22 | 100% pass (6/6 tests) |

---

## License

**Proprietary — All rights reserved.**

This code is provided for demonstration and evaluation purposes only.

**Contact:** [ASEMANTIX@proton.me](mailto:ASEMANTIX@proton.me)

**Website:** [https://asemantix.tech](https://asemantix.tech)

---

<p align="center">
  <strong>Why reveal to the world what is confidential?</strong><br>
  <em>Your message is invisible.</em>
</p>
