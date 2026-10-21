# PUF-F1 research prototype: reproducibility candidate

**Status: Research prototype, not exact wire-conformant frozen-manuscript implementation, not proven secure.**

This repo contains a reassembled snapshot of the Stage 1–4 code developed for the study *Verifiable PUF-Rooted Additive Aggregation for Constrained Wireless Sensor Networks*. It includes equation-level reference aggregation and a separate security-state model. It is not the physically measured PUF implementation. **Do not present passing tests as evidence of capture-collusion resistance or rollback protection.**

## Run on Ubuntu 22.04 / WSL

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pytest hypothesis numpy scipy sympy cryptography
bash scripts/run_validation.sh
```

Test logs, a JUnit report, source checksums, dependency versions and an encoding-conformance probe are written under `results/`. The GitHub Actions workflow runs the suite on Python 3.10 and attaches these results as build artifacts. This package intentionally does not contain a pre-claimed WSL or GitHub CI result.

## Validation results and provenance

The source assembly was executed in a separate Linux environment on 2026-10-22: **43 passed** (13.27 s). The user's directly reported WSL result is **30 passed** for Stages 1–3; no WSL Stage 4 output has been supplied. Identical source hashes and logs must be collected on WSL before those results can be combined as a single user-host run.

## Security limitations

- Test `test_collusion_counterexample_accepted` verifies a successful attack, not resistance.
- Storage-rollback tests expose reuse, not resistance.
- The proof is conditional on PUF extractor entropy, joint pseudorandomness, unrolled-back persistent state, and secrecy of the cluster challenge from actively captured leaves.
- Full aggregate-ciphertext authentication and physical PUF entropy measurements are not established.
- The prototype currently has provisional encoding choices; see `CONFORMANCE_MATRIX.md`.

## GitHub release procedure

Run all 43 tests on WSL, compare source hashes with the intended commit, commit the sources, and allow GitHub Actions to pass. Tag a **pre-release**, not a final conformance certification. Include the conformance matrix and the saved logs in release assets. Do not claim GitHub has been published merely because this ZIP exists.
