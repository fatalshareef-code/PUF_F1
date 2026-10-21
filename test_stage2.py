import random
import secrets
import pytest
import puf
from sampling import XOFStream,uniform_field,sample_cbd,sample_uniform_poly,sample_cbd_poly

def test_bch_design_parameters():
    assert puf.RAW_BITS==17850
    assert puf._G.bit_length()-1==100
    assert puf.MESSAGE_BITS==2170

def test_bch_corrects_13_positions():
    rng=random.Random(24)
    for _ in range(35):
        message=rng.getrandbits(puf.BCH_K)
        c=puf.bch_encode(message)
        for nerr in (0,1,5,13):
            received=c
            for i in rng.sample(range(255),nerr): received ^= 1<<i
            assert puf.bch_decode(received)==message

def test_bch_excess_not_guaranteed():
    # >13 errors are outside guaranteed correction radius; do not assume
    # decoding must throw, since a wrong codeword or miscorrection is possible.
    message=100
    received=puf.bch_encode(message)
    for i in range(14): received ^= 1<<i
    try:out=puf.bch_decode(received)
    except ValueError:return
    assert out !=message

def test_full_reconstruction_no_error():
    raw=bytes([0xAA])*((puf.RAW_BITS+7)//8)
    k,h=puf.enroll(raw)
    assert len(k)==32
    assert puf.reconstruct(raw,h)==k
    assert len(h.offset)==2232
    assert len(h.toeplitz_seed)==304

def test_full_reconstruction_two_flips_per_repetition_group():
    raw=bytes([0x96])*((puf.RAW_BITS+7)//8)
    k,h=puf.enroll(raw)
    corrupted=bytearray(raw)
    for codebit in range(0,puf.CODE_BITS,109):
        for repindex in (0,1):
            idx=codebit*5+repindex
            corrupted[idx//8]^=1<<(idx%8)
    assert puf.reconstruct(bytes(corrupted),h)==k

def test_reconstruction_too_many_errors_can_fail():
    raw=secrets.token_bytes((puf.RAW_BITS+7)//8)
    k,h=puf.enroll(raw)
    corrupted=bytearray(raw)
    # Induce at least 14 distinct majority-vote errors in first BCH block.
    for codebit in range(14):
        for rep in (0,1,2):
            idx=5*codebit+rep
            corrupted[idx//8] ^= 1 <<(idx%8)
    try:bad=puf.reconstruct(bytes(corrupted),h)
    except ValueError:return
    assert bad !=k

def test_uniform_rejection_and_cbd():
    key=bytes(range(32))
    stream=XOFStream(key,'a',b'node',b'epoch')
    outputs=[uniform_field(stream) for _ in range(100)]
    assert all(0<=x<1628161 for x in outputs)
    vals=[sample_cbd(XOFStream(key,'e',i.to_bytes(2,'big'))) for i in range(50)]
    assert all(-2<=x<=2 for x in vals)

def test_context_determinism():
    key=bytes(range(32))
    assert sample_uniform_poly(key,'a',b'node',n=8)==sample_uniform_poly(key,'a',b'node',n=8)
    assert sample_uniform_poly(key,'a',b'node',n=8)!=sample_uniform_poly(key,'a',b'node2',n=8)
    assert all(-2<=x<=2 for x in sample_cbd_poly(key,'e',n=20))
