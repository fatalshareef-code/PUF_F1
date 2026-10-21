from dataclasses import replace
import pytest
from stage4_security import wrap_seed,unwrap_seed,make_beacon,authenticate_beacon,LeafPersistent,DurableSink
from protocol import Context, cluster_aggregate, leaf_report
from config import Q

def ctx(epoch=17, n=3, rho=None):
    return Context(4,epoch,rho or bytes([epoch%256])*32,b'\x27'*32,tuple(range(1,n+1)))
def keys(n=3):return {i:i.to_bytes(32,'big') for i in range(1,n+1)}

def test_wrap_round_trip():
    key=keys()[1];seed=b'Z'*32
    w=wrap_seed(key,seed,4,3,1)
    assert unwrap_seed(key,w,4,3,1)==seed

def test_wrap_wrong_node_or_period_rejected():
    key=keys()[1];w=wrap_seed(key,b'Z'*32,4,3,1)
    with pytest.raises(ValueError):unwrap_seed(key,w,4,4,1)
    with pytest.raises(ValueError):unwrap_seed(keys()[2],w,4,3,1)

def test_wrap_tamper_rejected():
    key=keys()[1];w=wrap_seed(key,b'Z'*32,4,3,1)
    with pytest.raises(ValueError,match='authentication'):
        unwrap_seed(key,replace(w,ciphertext=b'A'*32),4,3,1)
    with pytest.raises(ValueError):unwrap_seed(key,replace(w,tag=b'\0'*16),4,3,1)

def test_beacon_alteration_and_forgery():
    c=ctx();key=keys()[1];b=make_beacon(key,c.cluster,c.epoch,c.rho)
    authenticate_beacon(key,b,c.cluster,c.epoch,c.rho)
    for changed in [replace(b,epoch=c.epoch+1),replace(b,rho=b'Q'*32),replace(b,tag=b'\0'*16)]:
        with pytest.raises(ValueError):authenticate_beacon(key,changed,c.cluster,c.epoch,c.rho)

def test_durable_leaf_rejects_reuse_after_restart(tmp_path):
    c=ctx();k=keys()[1];db=tmp_path/'leaf.db';b=make_beacon(k,c.cluster,c.epoch,c.rho)
    p=LeafPersistent(db,1,k,4).emit(c,19,b)
    assert len(p.pack())==38
    with pytest.raises(ValueError,match='used'):
        LeafPersistent(db,1,k,4).emit(c,20,b)

def test_stale_replayed_beacon(tmp_path):
    c=ctx();k=keys()[1];db=tmp_path/'leaf.db';b=make_beacon(k,4,17,c.rho)
    leaf=LeafPersistent(db,1,k,4);leaf.emit(c,10,b)
    newer=ctx(18);leaf.emit(newer,11,make_beacon(k,4,18,newer.rho))
    with pytest.raises(ValueError):leaf.emit(c,12,b)

def test_tampered_beacon_does_not_burn_epoch(tmp_path):
    c=ctx();k=keys()[1];leaf=LeafPersistent(tmp_path/'leaf.db',1,k,4)
    forged=replace(make_beacon(k,4,17,c.rho),tag=b'\0'*16)
    with pytest.raises(ValueError):leaf.emit(c,11,forged)
    assert leaf.emit(c,12,make_beacon(k,4,17,c.rho)).node==1

def test_durable_sink_consumes_invalid_attempt(tmp_path):
    c=ctx();ks=keys();agg=cluster_aggregate([leaf_report(ks[i],i,10,c) for i in ks],c)
    db=tmp_path/'sink.db';sink=DurableSink(db,ks)
    with pytest.raises(ValueError,match='projection'):sink.verify(replace(agg,y=(agg.y+1)%Q),c)
    with pytest.raises(ValueError,match='already processed'):
        DurableSink(db,ks).verify(agg,c)

def test_durable_sink_success_rejects_replay(tmp_path):
    c=ctx();ks=keys();agg=cluster_aggregate([leaf_report(ks[i],i,10,c) for i in ks],c)
    db=tmp_path/'sink.db';assert DurableSink(db,ks).verify(agg,c)==30
    with pytest.raises(ValueError,match='already processed'):
        DurableSink(db,ks).verify(agg,c)

def test_resync_floor_never_moves_backward(tmp_path):
    k=keys()[1];leaf=LeafPersistent(tmp_path/'leaf.db',1,k,4)
    leaf.resync_floor(42);leaf.resync_floor(40)
    c=ctx(42)
    with pytest.raises(ValueError,match='used'):leaf.emit(c,5,make_beacon(k,4,42,c.rho))
    c=ctx(43);assert leaf.emit(c,5,make_beacon(k,4,43,c.rho)).epoch==43

def test_rollback_snapshot_reenables_reuse(tmp_path):
    # Model: an attacker restores an older database snapshot, defeating local monotonicity.
    c=ctx();k=keys()[1];db=tmp_path/'leaf.db';b=make_beacon(k,4,17,c.rho)
    leaf=LeafPersistent(db,1,k,4);leaf.resync_floor(16)
    import shutil
    # WAL is checkpointed only once all connections close; use SQLite backup for snapshot.
    import sqlite3
    with sqlite3.connect(db) as src, sqlite3.connect(tmp_path/'snapshot.db') as dest:src.backup(dest)
    leaf.emit(c,10,b)
    # Restore a database snapshot using the SQLite backup API to avoid
    # corrupting a live WAL database during the attack simulation.
    with sqlite3.connect(tmp_path/'snapshot.db') as src, sqlite3.connect(db) as dest:
        src.backup(dest)
    reused=LeafPersistent(db,1,k,4).emit(c,11,b)
    assert reused.y!=leaf_report(k,1,10,c).y

def test_reboot_packet_loss_advances_epoch(tmp_path):
    k=keys()[1];db=tmp_path/'leaf.db';a=ctx(17);b=ctx(20)
    leaf=LeafPersistent(db,1,k,4)
    leaf.emit(a,10,make_beacon(k,4,17,a.rho))
    assert LeafPersistent(db,1,k,4).emit(b,10,make_beacon(k,4,20,b.rho)).epoch==20

def test_invalid_ctx_prevents_output(tmp_path):
    c=ctx();k=keys()[1];leaf=LeafPersistent(tmp_path/'leaf.db',1,k,4)
    with pytest.raises(ValueError):leaf.emit(c,0,make_beacon(k,4,18,c.rho))
