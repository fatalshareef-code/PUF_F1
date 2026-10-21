"""Frozen-F1 equation-level prototype; see README_STAGE3.md for NOT-YET-VERIFIED encoding choices."""
from dataclasses import dataclass
import hashlib
from config import Q,N,DELTA,R,T
from encoding import encode_uint, decode_uint,encode_field,decode_field
from kdf import derive
from sampling import XOFStream,uniform_field,sample_uniform_poly,sample_cbd_poly

@dataclass(frozen=True)
class Context:
    cluster:int
    epoch:int
    rho:bytes
    period_seed:bytes
    slots:tuple[int,...]
    def __post_init__(self):
        if not 0<=self.cluster<=65535 or not 0<=self.epoch<2**64:raise ValueError('context range')
        if len(self.rho)!=32 or len(self.period_seed)!=32:raise ValueError('context seed length')
        if not self.slots or len(self.slots)>255 or len(self.slots)!=len(set(self.slots)) or tuple(sorted(self.slots))!=self.slots:raise ValueError('slots')
        if any(not 0<=n<65536 for n in self.slots):raise ValueError('IDs')
    def parts(self,node):return (encode_uint(node,2),encode_uint(self.cluster,2),encode_uint(self.epoch,8),self.rho)

def hidden_challenges(ctx):
    return _sample_theta(ctx)
def _sample_theta(ctx):
    st=XOFStream(ctx.period_seed,'theta',encode_uint(ctx.cluster,2),encode_uint(ctx.epoch,8),ctx.rho)
    return tuple(uniform_field(st) for _ in range(R))

def leaf_material(key,node,ctx):
    cp=ctx.parts(node)
    a=sample_uniform_poly(bytes(32),'a',*cp,n=N)  # public, zero-keyed API ONLY; no public-secret separation claim
    s=sample_cbd_poly(key,'s',*cp,n=N)
    e0=sample_cbd_poly(key,'e',*cp,n=N)[0]
    mask=(a[0]*s[0]-sum(a[j]*s[N-j] for j in range(1,N)))%Q
    omega_stream=XOFStream(key,'omega',*cp)
    omega=tuple(uniform_field(omega_stream) for _ in range(R))
    k_mac=derive(key,'mac',*cp)
    tag=derive(k_mac,'tag',*cp,output_length=16)
    return mask,e0,omega,tag

@dataclass(frozen=True)
class LeafPacket:
    node:int
    epoch:int
    y:int
    g:tuple[int,...]
    tag:bytes
    def pack(self):
        if len(self.g)!=R or len(self.tag)!=16:raise ValueError('invalid fields')
        return encode_uint(self.node,2)+encode_uint(self.epoch,8)+encode_field(self.y,Q)+b''.join(encode_field(v,Q) for v in self.g)+self.tag
    @classmethod
    def unpack(cls,b):
        if len(b)!=38:raise ValueError('invalid leaf packet length')
        return cls(decode_uint(b[:2],2),decode_uint(b[2:10],8),decode_field(b[10:13],Q),tuple(decode_field(b[13+3*j:16+3*j],Q) for j in range(R)),b[22:38])

def leaf_report(key,node,reading,ctx):
    if node not in ctx.slots or not 0<=reading<256:raise ValueError('node or reading')
    m,e0,om,tag=leaf_material(key,node,ctx)
    y=(m+e0+DELTA*reading)%Q
    theta=hidden_challenges(ctx)
    return LeafPacket(node,ctx.epoch,y,tuple((theta[j]*y+om[j])%Q for j in range(R)),tag)

def hash_merkle(packets):
    nodes=[hashlib.sha256(b'\x00'+encode_uint(p.node,2)+p.tag).digest() for p in packets]
    while len(nodes)>1:
        if len(nodes)%2:nodes.append(nodes[-1])
        nodes=[hashlib.sha256(b'\x01'+nodes[j]+nodes[j+1]).digest() for j in range(0,len(nodes),2)]
    return nodes[0]

@dataclass(frozen=True)
class Aggregate:
    cluster:int
    epoch:int
    bitmap:bytes
    y:int
    g:tuple[int,...]
    root:bytes
    def pack(self):
        if len(self.g)!=R or len(self.root)!=32:raise ValueError('aggregate fields')
        return encode_uint(self.cluster,2)+encode_uint(self.epoch,8)+bytes([len(self.bitmap)])+self.bitmap+encode_field(self.y,Q)+b''.join(encode_field(x,Q) for x in self.g)+self.root
    @classmethod
    def unpack(cls,b,slot_count):
        width=(slot_count+7)//8
        if len(b)!=2+8+1+width+3+3*R+32 or b[10]!=width:raise ValueError('aggregate length')
        start=11+width
        return cls(decode_uint(b[:2],2),decode_uint(b[2:10],8),b[11:start],decode_field(b[start:start+3],Q),tuple(decode_field(b[start+3+3*j:start+6+3*j],Q) for j in range(R)),b[-32:])

def cluster_aggregate(packets,ctx):
    p=sorted(packets,key=lambda x:x.node)
    if len(p)!=len(set(x.node for x in p)) or any(x.node not in ctx.slots or x.epoch!=ctx.epoch for x in p):raise ValueError('schedule violation')
    bits=sum(1<<ctx.slots.index(x.node) for x in p)
    bitmap=bits.to_bytes((len(ctx.slots)+7)//8,'little')
    return Aggregate(ctx.cluster,ctx.epoch,bitmap,sum(x.y for x in p)%Q,tuple(sum(x.g[j] for x in p)%Q for j in range(R)),hash_merkle(p))

class Sink:
    def __init__(self,keys):self.keys=dict(keys);self.seen=set()
    def verify(self,agg,ctx):
        # Once processed, accepted OR rejected; enforced in-process ONLY.
        ident=(ctx.cluster,ctx.epoch)
        if ident in self.seen:raise ValueError('replay')
        self.seen.add(ident)
        if agg.cluster!=ctx.cluster or agg.epoch!=ctx.epoch:raise ValueError('epoch')
        bits=int.from_bytes(agg.bitmap,'little')
        if len(agg.bitmap)!=(len(ctx.slots)+7)//8 or bits>>len(ctx.slots):raise ValueError('bitmap')
        nodes=[n for j,n in enumerate(ctx.slots) if bits>>j&1]
        if not nodes:raise ValueError('empty')
        if any(n not in self.keys for n in nodes):raise ValueError('unenrolled')
        # Sink derives expected tags from authenticated context: root, not per-packet MAC.
        entries=[]; totalmask=0;totalomega=[0]*R
        for node in nodes:
            mask,e0,omega,tag=leaf_material(self.keys[node],node,ctx)
            entries.append(LeafPacket(node,ctx.epoch,0,(0,)*R,tag))
            totalmask=(totalmask+mask)%Q
            for j in range(R):totalomega[j]=(totalomega[j]+omega[j])%Q
        if hash_merkle(entries)!=agg.root:raise ValueError('lineage mismatch')
        theta=hidden_challenges(ctx)
        if any((agg.g[j]-totalomega[j]-theta[j]*agg.y)%Q for j in range(R)):raise ValueError('projection mismatch')
        z=(agg.y-totalmask)%Q
        decoded=((z+DELTA//2)%Q)//DELTA
        if not 0<=decoded<=255*len(nodes) or decoded>=T:raise ValueError('plaintext out of range')
        return decoded
