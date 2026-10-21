"""Structural probes only; flags provisional choices explicitly."""
import json,hashlib,inspect
from pathlib import Path
from config import N,Q,T,DELTA,R
from protocol import LeafPacket, Aggregate,Context, leaf_report,cluster_aggregate
from kdf import derive
from stage4_security import make_beacon,wrap_seed
key=b'\x01'*32
ctx=Context(1,42,b'\x02'*32,b'\x03'*32,(1,2,3,4,5,6,7,8,9,10))
packets=[leaf_report(bytes([i])*32,i,20,ctx) for i in ctx.slots]
agg=cluster_aggregate(packets,ctx)
report={
 'status':'PROTOTYPE_NOT_BYTE_CONFORMANT',
 'params':{'n':N,'q':Q,'t':T,'delta':DELTA,'r':R},
 'packet_bytes':{'leaf':len(packets[0].pack()),'aggregate_10':len(agg.pack()),'aggregate_50_expected':62},
 'kdf':{'sha256_of_sample':hashlib.sha256(derive(key,'omega',b'node',output_length=32)).hexdigest(), 'context_serialization':'length-prefixed; non-frozen endian'},
 'known_mismatches':['public polynomial uses 32-byte all-zero keyed SHAKE256 placeholder','Merkle SHA256 tree serialization not specified by manuscript','beacon HMAC instead of manuscript hash-chain','wrap HMAC-SHA256 prototype choice','unverified authenticated resynchronization','period seed embedded in shared Context object','no hardware PUF entropy validation'],
 'proof_status':'conditional; not complete standard-model reduction',
 'result_semantics':'passing rollback and collusion attack tests confirm known weaknesses'
}
print(json.dumps(report,indent=2,sort_keys=True))
