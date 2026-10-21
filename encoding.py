def encode_uint(value,width):
    if width <= 0 or not 0<=value<1<<(8*width): raise ValueError('integer range')
    return value.to_bytes(width,'big')
def decode_uint(data,width):
    if len(data)!=width: raise ValueError('width')
    return int.from_bytes(data,'big')
def encode_field(value,q):
    if not 0<=value<q:raise ValueError('field range')
    return encode_uint(value,(q.bit_length()+7)//8)
def decode_field(data,q):
    v=decode_uint(data,(q.bit_length()+7)//8)
    if v>=q:raise ValueError('noncanonical field')
    return v
def encode_fields(*fields):
    r=b''
    for f in fields:
        if not isinstance(f,bytes) or len(f)>65535:raise ValueError('invalid field')
        r+=encode_uint(len(f),2)+f
    return r
