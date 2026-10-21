# Frozen Version 3 vs available Python prototype — encoding audit

| Element | Version 3 intent | Prototype behavior | Finding | Required before certified conformance |
|---|---|---|---|---|
| `n,q,t,Δ,η,r` | 1024, 1628161, 16384, 99, 2, 3 | Same constants | MATCH as configured | Exhaustively trace each invocation to `config.py` |
| 11 domain labels | `a,s,e,mac,tag,omega,theta,wrap,wraptag,chain,merkle` | Same names | LABELS MATCH | Prove exact input/output transcript domain separation |
| KDF encoding | Length-prefixed fields; byte order not fully frozen | Prefix `PUF-F1`, 2-byte lengths, big-endian node/epoch IDs | PROVISIONAL | Publish normative encoding and test vectors; update manuscript if this becomes canonical |
| Public `a` | Public, unkeyed XOF-derived polynomial | `sample_uniform_poly(bytes(32),'a',...)`, *keyed interface with public zero key* | NOT EQUIVALENT AS SPECIFIED | Freeze true unkeyed encoding; do not claim source equivalence |
| Samplers | 21-bit rejection and CBD η=2 | Little-endian bit consumption, consecutive 21-bit proposals | PARTIAL | Freeze bit order and rejection behavior in manuscript; cross-check test vectors |
| Leaf wire format | 38 bytes | 2 node + 8 epoch + 3 y + 9 g + 16 tag | SIZE MATCH | Freeze byte order and tag definition |
| Aggregate wire | 62 bytes at 50 leaves | 2 cluster + 8 epoch + 1 length + 7 bitmap + 3 y + 9 g + 32 root = 62 | SIZE MATCH | Freeze bitmap bit order and parse rules |
| Merkle lineage | Root of participating tags | SHA-256 tree with `0x00` leaf, `0x01` internal, odd duplication | PROVISIONAL | Manuscript must specify complete tree algorithm or revise implementation |
| Participation tags | Per-node participation | `tag=SHAKE256(k_mac,'tag',context)` | PROVISIONAL | Clarify whether tag binds only context, not ciphertext (currently does not) |
| Challenge seed | Period seed distributed secretly | Context contains `period_seed` and is supplied to aggregation caller | TEST-ONLY SECRET EXPOSURE | Separate CH-public context from leaf/sink secret state in conformant implementation |
| Integrity projections | `g_j=theta_j*y+omega_j mod q` | Equation implemented | EQUATION MATCH | Prove transcript-level challenge hiding under stated restrictions |
| Period-seed wrapping | Wrapped and authenticated once per period | XOR SHAKE pad + HMAC-SHA256 truncated 16-byte tag | MODEL ONLY | Freeze exact message/authentication format; reject forged/replayed wrapping packets |
| Beacon authentication | One-way hash-chain beacon | Per-epoch HMAC beacon | MISMATCH | Implement specified hash-chain or explicitly revise manuscript; do not claim equivalence |
| Freshness | Persistent counter and authenticated resync | SQLite monotonic epoch guard; `resync_floor` accepts preauthenticated parameter | PARTIAL | Specify authenticated resync and hardware trust/rollback boundary |
| Sink one-attempt rule | Once per `(cluster,epoch)` | SQLite `DurableSink`, in-process `Sink` in Stage 3 | MODEL CHECKED | Crash, multi-process, durable-state coverage still limited |
| PUF entropy/BER | SRAM PUF conditional entropy and BCH FE | Software extractor with simulated inputs | NO HARDWARE EVIDENCE | Physical device characterization required for empirical claim |

**Conclusion:** Security invariant and equation-level tests passing do not imply complete manuscript-to-code conformance. This is a blocker list, not evidence that all encoding discrepancies are fixed. Changing any of these would require updated tests, proof assumptions and explicit manuscript revision; do not silently alter the frozen protocol.
