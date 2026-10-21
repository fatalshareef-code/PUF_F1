# Stage 4 — frozen F1 state and wrapping research harness

Install with `unzip -o PUF_F1_Stage4_State_Wrapping.zip` in `~/puf_f1_prototype`.
Run `python -m pytest tests/ -v | tee results/stage4_validation.txt`.

Adds only `stage4_security.py`, `tests/test_stage4.py`, `README_STAGE4.md`. Does not overwrite Stages 1–3.

## Provenance and limits

- This is a **research test harness** for the Stage 4 behaviors, NOT verified byte-for-byte conformance with manuscript Version 3. Exact wrapping MAC construction, beacon MAC (vs specified hash-chain preimages), period-index encoding and authenticated resynchronization packet formats were not frozen to executable bytes in the manuscript. These are explicit model choices. **The test-beacon uses an HMAC and is not the manuscript's hash-chain protocol.**
- Wrapped period seed uses SHAKE256 domain labels `wrap` and `wraptag`, a 32-byte XOR pad, and a domain-separated HMAC-SHA256 16-byte authenticator. It is a *modeled authenticated wrap*, not a claim that manuscript ciphertext/wire encoding was reproduced.
- `LeafPersistent` uses SQLite, commits the epoch before encryption, intentionally burning an epoch if encryption/transmission fails. This assumes non-rolled-back persistent state. Reboot with intact storage rejects replay; physical rollback can reuse an epoch and leak reading differences. Sink rejection cannot prevent what an eavesdropper has already seen.
- `resync_floor(epoch)` deliberately does **not** authenticate its argument. Only invoke it with a separately verified sink message; this model does not implement the manuscript's authenticated resync message. Do not expose the API to untrusted inputs.
- `DurableSink` processes at most one aggregate per `(cluster, epoch)` in surviving SQLite state, including failures; storage rollback or multiple independent sink replicas are not handled.
- `protocol.Context` includes the confidential period seed; in production a cluster head MUST NOT receive this object. Stage 4 does not change the Stage 3 `Context` interface.
- The authenticated beacon and seed wrap here are *example instantiations to test invariants*, not additions to the frozen protocol. A fully conformant reference needs manuscript-defined hash-chain indexing / authentication and byte-level packing and verified source-equation alignment.
- All tests are *behavioral checks*, not proofs of SHAKE256 multi-user pseudorandomness, physical PUF entropy, adaptive aggregate integrity, or active captured-leaf collusion resistance.

## Targeted known attack

`test_rollback_snapshot_reenables_reuse` **passes when rollback succeeds**. It confirms a vulnerability under full storage snapshot restoration. Do not report its PASS status as rollback resistance.
