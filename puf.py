"""PUF-F1 software-only code-offset extractor: repetition-5 + BCH(255,155,t=13) x14.

This is an independently implemented reference candidate. Real hardware entropy,
independence, and side-channel properties are NOT established by software tests.
GF(256) uses primitive polynomial 0x11D. The Toeplitz seed is public.
"""
from dataclasses import dataclass
import hashlib
import secrets

BCH_N=255; BCH_K=155; BCH_T=13; BLOCKS=14; REP=5
RAW_BITS=BLOCKS*BCH_N*REP
CODE_BITS=BLOCKS*BCH_N
MESSAGE_BITS=BLOCKS*BCH_K
KEY_BITS=256

# GF(256) using 0x11D.
_EXP=[0]*510; _LOG=[0]*256
_x=1
for _i in range(255):
    _EXP[_i]=_x
    _LOG[_x]=_i
    _x<<=1
    if _x & 256: _x ^= 0x11d
for _i in range(255,510):_EXP[_i]=_EXP[_i-255]
assert _x==1

def gf_mul(a,b): return 0 if not a or not b else _EXP[_LOG[a]+_LOG[b]]
def gf_div(a,b):
    if not b: raise ZeroDivisionError
    return 0 if not a else _EXP[(_LOG[a]-_LOG[b])%255]

def generator():
    visited=set(); g=1
    for start in range(1,2*BCH_T+1):
        if start in visited:continue
        cos=[]; j=start
        while j not in cos:
            cos.append(j);visited.add(j);j=(2*j)%255
        # multiply minimal polynomial coefficients over GF(256), lowest degree first
        poly=[1]
        for j in cos:
            alpha=_EXP[j]; nxt=[0]*(len(poly)+1)
            for k,v in enumerate(poly):
                nxt[k]^=gf_mul(v,alpha)
                nxt[k+1]^=v
            poly=nxt
        assert all(v in (0,1) for v in poly), 'unexpected nonbinary minimal polynomial'
        minimal=sum(v<<i for i,v in enumerate(poly))
        result=0
        for i in range(g.bit_length()):
            if (g>>i)&1: result ^= minimal<<i
        g=result
    assert g.bit_length()-1==BCH_N-BCH_K
    return g
_G=generator()

def int_bits(value, n):return [(value>>i)&1 for i in range(n)]
def to_int(bits):return sum(int(b)<<i for i,b in enumerate(bits))

def _rem(poly,gen=_G):
    while poly.bit_length()>=gen.bit_length():
        poly ^= gen<<(poly.bit_length()-gen.bit_length())
    return poly

def bch_encode(message):
    if not 0<=message<(1<<BCH_K): raise ValueError('message outside BCH message space')
    shifted=message<<(BCH_N-BCH_K)
    return shifted | _rem(shifted)

def bch_decode(word):
    if not 0<=word<(1<<BCH_N):raise ValueError('invalid BCH word')
    # Syndromes S_j = received(alpha^j) for j=1..26
    synd=[]
    for j in range(1,2*BCH_T+1):
        s=0; v=word
        while v:
            bit=v & -v; idx=bit.bit_length()-1
            s ^= _EXP[(idx*j)%255]
            v ^= bit
        synd.append(s)
    if not any(synd):return word>>(BCH_N-BCH_K)
    # Berlekamp--Massey (lowest degree coefficients).
    C=[1]+[0]*(2*BCH_T); B=[1]+[0]*(2*BCH_T)
    L=0; m=1; b=1
    for n in range(2*BCH_T):
        discrepancy=synd[n]
        for i in range(1,L+1):discrepancy ^= gf_mul(C[i],synd[n-i])
        if not discrepancy:
            m+=1;continue
        T=C.copy();coef=gf_div(discrepancy,b)
        for i in range(2*BCH_T+1-m):C[i+m]^=gf_mul(coef,B[i])
        if 2*L<=n:
            L=n+1-L;B=T;b=discrepancy;m=1
        else:m+=1
    if L>BCH_T:raise ValueError('BCH errors exceed correction bound')
    loc=[]
    for position in range(BCH_N):
        # Lambda(alpha^(-position))==0
        x=_EXP[(-position)%255]; acc=0
        for coeff in reversed(C[:L+1]):acc=gf_mul(acc,x)^coeff
        if not acc:loc.append(position)
    if len(loc)!=L:raise ValueError('BCH locator degree mismatch')
    corrected=word
    for i in loc:corrected ^= 1<<i
    if _rem(corrected) != 0:raise ValueError('BCH correction unsuccessful')
    return corrected>>(BCH_N-BCH_K)

def bits_from_bytes(data, count):
    if len(data)*8 < count:raise ValueError('insufficient input bytes')
    return int_bits(int.from_bytes(data,'little'),count)

def bytes_from_bits(bits):return to_int(bits).to_bytes((len(bits)+7)//8,'little')

def repetition_encode(bits):return [b for bit in bits for b in [bit]*REP]
def repetition_decode(bits):
    if len(bits)!=RAW_BITS:raise ValueError('invalid repetition input length')
    return [int(sum(bits[i:i+REP])>=3) for i in range(0,len(bits),REP)]

def _toeplitz_hash(source_bits, seed_bits, out_bits=KEY_BITS):
    # T[row,col] = seed[row-col + (n-1)]; seed length n+out_bits-1
    n=len(source_bits)
    if len(seed_bits)!=n+out_bits-1:raise ValueError('incorrect Toeplitz seed length')
    res=[]
    for row in range(out_bits):
        parity=0
        for col,bit in enumerate(source_bits):
            if bit:parity ^= seed_bits[row-col+n-1]
        res.append(parity)
    return bytes_from_bits(res)

@dataclass(frozen=True)
class HelperData:
    offset:bytes
    toeplitz_seed:bytes


def enroll(raw:bytes, *, rng=secrets.token_bytes):
    """Code-offset Gen. Enrollment samples random codewords; extractor hashes recovered source.

    Data format for prototype: raw is 2232 bytes containing 17850 meaningful bits;
    helper offset uses 2232 bytes, seed 291? Actually 3570+256-1=3825 bits -> 479 bytes.
    Note manuscript's 4.5KB helper accounting requires reconciliation.
    """
    raw_bits=bits_from_bytes(raw,RAW_BITS)
    messages=[]; code_bits=[]
    for _ in range(BLOCKS):
        m=int.from_bytes(rng(20),'little')&((1<<BCH_K)-1)
        messages.extend(int_bits(m,BCH_K))
        code_bits.extend(int_bits(bch_encode(m),BCH_N))
    expanded=repetition_encode(code_bits)
    offset=bytes_from_bits([a^b for a,b in zip(raw_bits,expanded)])
    # Toeplitz extracts from 2170 recovered message bits, not 3570 code bits.
    seed_len=MESSAGE_BITS+KEY_BITS-1
    seed_bytes=rng((seed_len+7)//8)
    seed=bits_from_bytes(seed_bytes,seed_len)
    key=_toeplitz_hash(messages,seed)
    return key, HelperData(offset,bytes_from_bits(seed))

def reconstruct(raw:bytes,helper:HelperData):
    r=bits_from_bytes(raw,RAW_BITS)
    off=bits_from_bytes(helper.offset,RAW_BITS)
    expanded=[a^b for a,b in zip(r,off)]
    code=repetition_decode(expanded)
    messages=[]
    for block in range(BLOCKS):
        word=to_int(code[block*BCH_N:(block+1)*BCH_N])
        msg=bch_decode(word)
        messages.extend(int_bits(msg,BCH_K))
    seed=bits_from_bytes(helper.toeplitz_seed,MESSAGE_BITS+KEY_BITS-1)
    return _toeplitz_hash(messages,seed)
