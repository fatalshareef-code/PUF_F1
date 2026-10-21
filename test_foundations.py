import pytest
from config import Q,N,T,DELTA,R,DOMAIN_LABELS
from encoding import encode_uint,decode_uint,encode_field,decode_field,encode_fields
from kdf import derive

def test_frozen_parameters():
    assert (N,Q,T,DELTA,R)==(1024,1628161,16384,99,3)

def test_integer_roundtrip():
    for value in [0,1,255,65535]:
        assert decode_uint(encode_uint(value,2),2)==value

def test_field_roundtrip():
    for value in [0,1,Q//2,Q-1]:
        assert decode_field(encode_field(value,Q),Q)==value

def test_reject_noncanonical_element():
    with pytest.raises(ValueError):
        decode_field(Q.to_bytes(3,'big'),Q)

def test_unambiguous_field_encoding():
    assert encode_fields(b'ab',b'c')!=encode_fields(b'a',b'bc')

def test_domain_separation():
    key=bytes(range(32))
    assert len({derive(key,label,b'node-1',b'epoch-1') for label in DOMAIN_LABELS})==len(DOMAIN_LABELS)

def test_epoch_separation():
    key=bytes(range(32))
    assert derive(key,'omega',b'epoch-1')!=derive(key,'omega',b'epoch-2')

def test_deterministic_derivation():
    key=bytes(range(32))
    assert derive(key,'mac',b'node-1')==derive(key,'mac',b'node-1')

def test_reject_unknown_label():
    with pytest.raises(ValueError):
        derive(bytes(32),'unknown',b'context')
