"""F1 Stage 4 stateful *model*: keyed wrapping, epoch authentication, SQLite monotonic state.

These operational wire encodings are REFERENCE CHOICES, not independently
verified against manuscript byte-level specifications. No hardware rollback protection.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib, hmac, os, sqlite3
from config import Q
from encoding import encode_uint, encode_fields
from kdf import derive
from protocol import leaf_report, Sink


def _ctx(cluster: int, epoch: int, period: int, node: int = 0) -> bytes:
    return encode_fields(encode_uint(cluster,2), encode_uint(epoch,8), encode_uint(period,8), encode_uint(node,2))

def _xor(a,b): return bytes(x^y for x,y in zip(a,b))

@dataclass(frozen=True)
class WrappedSeed:
    cluster: int
    period: int
    node: int
    ciphertext: bytes
    tag: bytes


def wrap_seed(key:bytes, seed:bytes, cluster:int, period:int, node:int) -> WrappedSeed:
    if len(seed)!=32: raise ValueError('seed must be 32 bytes')
    ctx=_ctx(cluster,0,period,node)
    pad=derive(key,'wrap',ctx,output_length=32)
    ciphertext=_xor(seed,pad)
    tagkey=derive(key,'wraptag',ctx)
    tag=hmac.new(tagkey,encode_fields(b'F1-wrap-v1',ctx,ciphertext),hashlib.sha256).digest()[:16]
    return WrappedSeed(cluster,period,node,ciphertext,tag)


def unwrap_seed(key:bytes,wrapped:WrappedSeed,cluster:int,period:int,node:int)->bytes:
    if (wrapped.cluster,wrapped.period,wrapped.node)!=(cluster,period,node): raise ValueError('wrong wrapping context')
    if len(wrapped.ciphertext)!=32 or len(wrapped.tag)!=16: raise ValueError('bad wrapping format')
    ctx=_ctx(cluster,0,period,node)
    tagkey=derive(key,'wraptag',ctx)
    expected=hmac.new(tagkey,encode_fields(b'F1-wrap-v1',ctx,wrapped.ciphertext),hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(wrapped.tag,expected): raise ValueError('invalid wrapping authentication')
    return _xor(wrapped.ciphertext,derive(key,'wrap',ctx,output_length=32))

@dataclass(frozen=True)
class Beacon:
    cluster:int
    epoch:int
    rho:bytes
    tag:bytes


def make_beacon(key:bytes,cluster:int,epoch:int,rho:bytes)->Beacon:
    if len(rho)!=32: raise ValueError('rho length')
    ctx=_ctx(cluster,epoch,0)
    tagkey=derive(key,'chain',ctx)
    tag=hmac.new(tagkey,encode_fields(b'F1-epoch-v1',ctx,rho),hashlib.sha256).digest()[:16]
    return Beacon(cluster,epoch,rho,tag)


def authenticate_beacon(key:bytes,beacon:Beacon,cluster:int,epoch:int,rho:bytes)->None:
    if (beacon.cluster,beacon.epoch,beacon.rho)!=(cluster,epoch,rho):raise ValueError('beacon context mismatch')
    if len(beacon.tag)!=16:raise ValueError('beacon tag length')
    expected=make_beacon(key,cluster,epoch,rho)
    if not hmac.compare_digest(beacon.tag,expected.tag):raise ValueError('invalid beacon')

class LeafPersistent:
    """Durable, monotonic-on-one-database emission guard; no anti-rollback guarantee.

    Burn the epoch BEFORE computing or transmitting the ciphertext. This trades
    availability for avoiding two different ciphertexts under one context.
    """
    def __init__(self,path:str,node:int,key:bytes,cluster:int):
        self.path=str(path);self.node=node;self.key=key;self.cluster=cluster
        with self._db() as con:
            con.execute('CREATE TABLE IF NOT EXISTS epochs (node INTEGER, cluster INTEGER, last_epoch INTEGER NOT NULL, PRIMARY KEY(node,cluster))')

    def _db(self):
        con=sqlite3.connect(self.path,timeout=10,isolation_level=None)
        con.execute('PRAGMA journal_mode=WAL');con.execute('PRAGMA synchronous=FULL')
        return con

    def emit(self,ctx,reading:int,beacon:Beacon):
        if ctx.cluster!=self.cluster or self.node not in ctx.slots:raise ValueError('wrong leaf context')
        authenticate_beacon(self.key,beacon,ctx.cluster,ctx.epoch,ctx.rho)
        con=self._db()
        try:
            con.execute('BEGIN IMMEDIATE')
            row=con.execute('SELECT last_epoch FROM epochs WHERE node=? AND cluster=?',(self.node,self.cluster)).fetchone()
            if row and ctx.epoch<=row[0]:raise ValueError('used or stale epoch')
            con.execute('INSERT INTO epochs(node,cluster,last_epoch) VALUES (?,?,?) ON CONFLICT(node,cluster) DO UPDATE SET last_epoch=excluded.last_epoch', (self.node,self.cluster,ctx.epoch))
            con.execute('COMMIT')
        except:
            if con.in_transaction:con.execute('ROLLBACK')
            raise
        finally:con.close()
        return leaf_report(self.key,self.node,reading,ctx)

    def resync_floor(self,sink_epoch:int)->None:
        """Advance local floor to sink-authenticated epoch; never decrease it.

        IMPORTANT: caller must independently authenticate sink response; this API
        alone must never be used with attacker-controlled sink_epoch.
        """
        if not 0<=sink_epoch<2**64:raise ValueError('epoch range')
        con=self._db()
        try:
            con.execute('BEGIN IMMEDIATE')
            row=con.execute('SELECT last_epoch FROM epochs WHERE node=? AND cluster=?',(self.node,self.cluster)).fetchone()
            floor=max(sink_epoch,row[0] if row else -1)
            con.execute('INSERT INTO epochs(node,cluster,last_epoch) VALUES (?,?,?) ON CONFLICT(node,cluster) DO UPDATE SET last_epoch=excluded.last_epoch',(self.node,self.cluster,floor))
            con.execute('COMMIT')
        except:
            if con.in_transaction: con.execute('ROLLBACK')
            raise
        finally:con.close()

class DurableSink:
    """Persist a processed epoch *before* calling the unchanged Stage 3 verifier."""
    def __init__(self,path:str,keys:dict):
        self.path=str(path);self.keys=dict(keys)
        with self._db() as con:
            con.execute('CREATE TABLE IF NOT EXISTS consumed(cluster INTEGER,epoch INTEGER,PRIMARY KEY(cluster,epoch))')
    def _db(self):
        con=sqlite3.connect(self.path,timeout=10,isolation_level=None)
        con.execute('PRAGMA journal_mode=WAL');con.execute('PRAGMA synchronous=FULL')
        return con
    def verify(self,agg,ctx):
        con=self._db()
        try:
            con.execute('BEGIN IMMEDIATE')
            con.execute('INSERT INTO consumed(cluster,epoch) VALUES (?,?)',(ctx.cluster,ctx.epoch))
            con.execute('COMMIT')
        except sqlite3.IntegrityError as e:
            if con.in_transaction:con.execute('ROLLBACK')
            raise ValueError('already processed epoch') from e
        except:
            if con.in_transaction:con.execute('ROLLBACK')
            raise
        finally:con.close()
        return Sink(self.keys).verify(agg,ctx)
