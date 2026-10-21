import hashlib

def test_python_sha_ke256():
    output = hashlib.shake_256(b"PUF-F1").digest(32)
    assert len(output) == 32

def test_modular_arithmetic():
    q = 1628161
    assert (q + 5) % q == 5
