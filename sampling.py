"""Deterministic SHAKE256 XOF stream and specified rejection/CBD samplers.
These require a frozen KDF input encoding; import supplied kdf.derive at runtime.
"""
from config import Q, ETA
from kdf import derive

class XOFStream:
    def __init__(self,key,label,*context):
        self.key=key;self.label=label;self.context=context;self.cursor=0
        self._bit_buffer=0
        self._available=0
    def read(self,n):
        if n<0:raise ValueError('negative length')
        # hashlib.shake_256.digest(x) returns a fixed prefix, not streaming state.
        end=self.cursor+n
        prefix=derive(self.key,self.label,*self.context,output_length=end)
        data=prefix[self.cursor:end]
        self.cursor=end
        return data

    def read_bits(self, n):
        if n<=0:raise ValueError("bit count must be positive")
        while self._available<n:
            self._bit_buffer |= self.read(1)[0]<<self._available
            self._available+=8
        mask=(1<<n)-1
        result=self._bit_buffer & mask
        self._bit_buffer >>= n
        self._available -= n
        return result

def uniform_field(stream,q=Q):
    if not (1<q<2**21):raise ValueError('q outside 21-bit rejection range')
    # Consecutive 21-bit proposals, packed without discarding the other 3 bits.
    while True:
        candidate=stream.read_bits(21)
        if candidate<q:return candidate

def sample_cbd(stream,eta=ETA):
    if not 1<=eta<=8:raise ValueError('eta outside supported range')
    word=stream.read_bits(2*eta)
    a=(word&((1<<eta)-1)).bit_count()
    b=((word>>eta)&((1<<eta)-1)).bit_count()
    return a-b

def sample_uniform_poly(key,label,*context,n=1024,q=Q):
    stream=XOFStream(key,label,*context)
    return [uniform_field(stream,q) for _ in range(n)]

def sample_cbd_poly(key,label,*context,n=1024,eta=ETA):
    stream=XOFStream(key,label,*context)
    return [sample_cbd(stream,eta) for _ in range(n)]
