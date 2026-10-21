# Frozen F1 Stage 3: equation-level reference implementation

This package provides the **Stage 3 prototype** for Eq. (3)-(14) of Version 3, with no new protocol mechanism. It is **not a certified byte-for-byte implementation of the paper** and **not a security proof**.

## Install into your existing WSL project

In `~/puf_f1_prototype` (with earlier Stage 1 and 2 present):

```sh
unzip -o PUF_F1_Stage3_Aggregation.zip
source .venv/bin/activate
python -m pytest tests/ -v | tee results/stage3_validation.txt
```

Only these files are installed: `protocol.py`, `leaf.py`, `cluster_head.py`, `sink.py`, `tests/test_stage3.py`, `README_STAGE3.md`. Existing `config.py`, `encoding.py`, `kdf.py`, `puf.py`, `sampling.py`, and earlier tests are not overwritten.

## Expected checks

- 10/20/50 leaves, correct aggregation and full packet pack/unpack;
- leaf packet 38 bytes, 50-slot aggregate 62 bytes;
- valid max aggregate 50 * 255 = 12,750;
- modified aggregate rejected by hidden projections;
- forged lineage root rejected;
- 1-scaling-unit bias accepted if period challenge is exposed (known collusion attack);
- noncanonical field elements, invalid bitmap, duplicates rejected.

## Mathematical implementation

- Equation (7): `(a*s)_0 + e_0 + DELTA * reading (mod Q)`, with `(a*s)_0 = a_0*s_0 - sum(a_j*s_{N-j})` in `Z_q[x]/(x^N+1)`.
- Equation (8): tag; `g_j = theta_j*y + omega_j mod Q`.
- Equations (9)-(10): sums mod Q.
- Equations (11)-(14): subtract summed polynomial-mask coefficients, unsigned-offset decode.

## Important conformance gaps

1. **Public polynomial sampling**: manuscript uses an unkeyed XOF for public `a`; Stage 2 `kdf.derive` requires a 32-byte key. This prototype feeds a *public constant zero key* to that API. It is an implementation placeholder, **not** proof of exact unkeyed XOF input-encoding equivalence.
2. **XOF input encoding**: Stage 1 encoding was provisional, never bytewise verified against independent released source. `ID`/cluster/epoch use big endian widths (2/2/8); the manuscript does not fully freeze those byte orders.
3. **Membership bitmap**: bit order is little-endian within bitmap bytes; manuscript does not fix this order. It is a serialization choice, not independently validated.
4. **Merkle lineage**: SHA-256 with `0x00 || ID || tag` leaves and `0x01 || left || right` internal nodes, duplicating the last odd node. The manuscript does not freeze this tree algorithm. Do not claim bytewise compatibility.
5. **Tag derivation**: `k_mac = derive(K_i, 'mac', ...); tag = derive(k_mac, 'tag', ...)` is a plausible interpretation of Eq. (8), not a cryptographically authenticated ciphertext. The tag authenticates only participation context.
6. **Period seed**: this prototype injects the correct 32-byte seed into both leaf and sink simulation. It does not implement authenticated wrapping or validate the periodic seed distribution. Cluster-head `cluster_aggregate` does **not** need or read the seed, but the `Context` object holds it for convenience. A real CH **must not** be given `period_seed`; leaking it is precisely the collusion weakness. Use this only as a test harness.
7. **Freshness**: sink's processed-epoch set is volatile in-process. It does not implement persistent counters, authenticated beacons or rollback protection. Stage 4 remains necessary.
8. **PUF**: test uses deterministic 32-byte keys representing successfully reconstructed PUF keys; does not measure the physical extractor. Stage 2 tests the extractor separately.
9. **One-shot adaptive interface**: `Sink.verify` consumes an epoch before any validation failure, but this is not durable across sink restart.
10. **Aggregate confidentiality**: the trusted sink has per-node keys. The cluster head only sees masked leaf packets in threat model. Do not expose secret `Context.period_seed` to cluster head.
11. This implementation demonstrates the algebraic known-secret forgery; it does not establish QROM pseudorandomness or the full real-to-ideal proof.

## Data integrity of the installation

The archive deliberately contains no replacements for Stage 1 and 2 foundations. If tests fail, record Python traceback and compare installed foundation functions with the Stage 1/2 code; do not silently rewrite the manuscript or the frozen code paths.
