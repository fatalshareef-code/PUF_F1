import hashlib
from config import DOMAIN_LABELS
from encoding import encode_fields

def derive(key,label,*context,output_length=32):
    if label not in DOMAIN_LABELS:raise ValueError('unknown label')
    if not isinstance(key,bytes) or len(key)!=32:raise ValueError('32-byte key required')
    if not 1<=output_length<=65535:raise ValueError('output length')
    return hashlib.shake_256(encode_fields(b'PUF-F1',label.encode('ascii'),key,*context)).digest(output_length)
