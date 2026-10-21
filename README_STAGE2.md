# Frozen F1 Stage 2 — extractor and samplers

This is a **software reference candidate**, NOT certified as an implementation of every
bit-level convention in the submitted Version 3 manuscript. Do not cite the results as
hardware PUF evidence or as a cryptographic security proof.

## Provenance and frozen choices
- 14 blocks x repetition-5 x BCH(255,155,13) = 17,850 raw PUF bits.
- Binary primitive BCH length 255 over GF(2^8), primitive polynomial 0x11D,
  roots alpha^1..alpha^26, 100 parity bits and 155 data bits.
- Code-offset FE: random codeword, offset = raw XOR repeated(codeword), majority
  decoding followed by BCH correction. The 14 decoded 155-bit messages form
  a 2,170-bit extractor source; public 2,425-bit Toeplitz seed hashes to 256 bits.
- Explicit candidate convention: little-endian bit order within encoded bytes;
  Toeplitz index T[row,col] = seed[row - col + source_bits - 1]. These choices
  must be compared with the manuscript's *actual reference implementation*.
- SHAKE256 sampling uses the pre-existing `kdf.derive` interface from Stage 1,
  consecutive 21-bit rejection proposals (`q=1,628,161`) and consecutive
  4-bit CBD eta=2 draws, with no unused bits silently discarded.

## IMPORTANT review findings
1. The binary helper is 2,232 bytes (code-offset) plus 304 bytes (Toeplitz
   seed) = **2,536 bytes**. Version 3 reports roughly **4.5 kB**; its accounting
   may involve unpacked bits or additional public metadata. Reconcile before
   making a communication/memory claim.
2. The manuscript's 385-bit residual entropy threshold at h=0.90 is an
   *assumption*, not a measurement, and is not established by the tests.
3. BCH correction is guaranteed up to 13 **majority-decoded** bit errors per
   255-bit block. More errors can fail or miscorrect. This implementation does
   not establish a target 10% raw BER reconstruction failure rate.
4. The generated key equals the enrollment key if decoding succeeds. Failed
   correction may raise or yield a *different* key; caller should treat any
   mismatching authentication/verification as a regeneration failure.
5. The SHAKE256 domain/serialization implementation from Stage 1 remains
   **provisional**, and this package does not certify its transcript format.
6. No physical hardware SRAM-PUF, temperature, voltage, aging, or correlated
   noise effects are tested here.

## Installation into WSL
```
cd ~/puf_f1_prototype
# Extract archive content, preserving existing Stage 1 files
unzip -o /path/to/PUF_F1_Stage2_Extractor_Samplers.zip
source .venv/bin/activate
python -m pytest tests/test_environment.py tests/test_foundations.py tests/test_stage2.py -v
```

The ZIP contains only `puf.py`, `sampling.py`, `tests/test_stage2.py`, and this
README; it **does not overwrite** your existing config/encoding/kdf files.

`puf.enroll(raw)` returns `(key, HelperData)`; `puf.reconstruct(raw2,helper)`
returns the same key if correction succeeds. `raw` is 2,232 bytes, with 17,850
meaningful low-order bits.
