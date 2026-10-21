import pytest
from protocol import Context,LeafPacket,Aggregate,leaf_report,cluster_aggregate,Sink,hidden_challenges
from config import Q

def ctx(k):return Context(4,17,b'\x13'*32,b'\x27'*32,tuple(range(1,k+1)))
def keys(k):return {i:i.to_bytes(32,'big') for i in range(1,k+1)}
@pytest.mark.parametrize('n',[10,20,50])
def test_end_to_end(n):
    c=ctx(n);ks=keys(n);readings={i:(i*7)%256 for i in ks}
    packets=[leaf_report(ks[i],i,readings[i],c) for i in ks]
    assert all(len(p.pack())==38 and LeafPacket.unpack(p.pack())==p for p in packets)
    agg=cluster_aggregate(packets,c)
    assert Aggregate.unpack(agg.pack(),n)==agg
    assert len(agg.pack())==2+8+1+(n+7)//8+12+32
    assert Sink(ks).verify(agg,c)==sum(readings.values())
def test_aggregate_50_62_bytes():
    c=ctx(50);ks=keys(50)
    a=cluster_aggregate([leaf_report(ks[i],i,1,c) for i in ks],c)
    assert len(a.pack())==62
def test_modified_aggregate_rejected():
    c=ctx(10);ks=keys(10);a=cluster_aggregate([leaf_report(ks[i],i,10,c) for i in ks],c)
    from dataclasses import replace
    with pytest.raises(ValueError,match='projection'):
        Sink(ks).verify(replace(a,y=(a.y+1)%Q),c)
def test_merkle_tampering_rejected():
    c=ctx(10);ks=keys(10);a=cluster_aggregate([leaf_report(ks[i],i,10,c) for i in ks],c)
    from dataclasses import replace
    with pytest.raises(ValueError,match='lineage'):
        Sink(ks).verify(replace(a,root=b'\x00'*32),c)
def test_collusion_counterexample_accepted():
    c=ctx(10);ks=keys(10);a=cluster_aggregate([leaf_report(ks[i],i,10,c) for i in ks],c)
    from dataclasses import replace
    theta=hidden_challenges(c); delta=99
    forged=replace(a,y=(a.y+delta)%Q,g=tuple((a.g[j]+theta[j]*delta)%Q for j in range(3)))
    assert Sink(ks).verify(forged,c)==101  # original 100 plus bias 1

def test_duplicate_sink_rejected():
    c=ctx(10);ks=keys(10);a=cluster_aggregate([leaf_report(ks[i],i,10,c) for i in ks],c)
    sink=Sink(ks)
    assert sink.verify(a,c)==100
    with pytest.raises(ValueError,match='replay'):sink.verify(a,c)

def test_noncanonical_leaf_rejected():
    c=ctx(10);ks=keys(10);p=leaf_report(ks[1],1,10,c)
    b=bytearray(p.pack());b[10:13]=Q.to_bytes(3,'big')
    with pytest.raises(ValueError):LeafPacket.unpack(bytes(b))

def test_max_50_node_plaintext_no_wrap():
    c=ctx(50);ks=keys(50)
    a=cluster_aggregate([leaf_report(ks[i],i,255,c) for i in ks],c)
    assert Sink(ks).verify(a,c)==12750

def test_bad_member_bitmap_rejected():
    c=ctx(10);ks=keys(10)
    a=cluster_aggregate([leaf_report(ks[i],i,3,c) for i in ks],c)
    from dataclasses import replace
    with pytest.raises(ValueError,match='bitmap'):
        Sink(ks).verify(replace(a,bitmap=b'\xff\xff'),c)
