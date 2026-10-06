import zlib
from coebot import sfs
from coebot.sfs import Typed


def test_roundtrip():
    obj = {"c": "heart_beat", "n": 5, "big": 1791215027804, "b": True,
           "arr": [1, "x", {"k": None}], "ba": bytes(range(31)), "f": 1.5}
    assert sfs.decode(sfs.encode(obj)) == obj


def test_typed():
    assert sfs.encode({"a": Typed(sfs.SHORT, 13)}) == b"\x12\x00\x01\x00\x01a\x03\x00\x0d"


def test_frame_stream_and_compress():
    big = {"s": "x" * 2000}
    raw = sfs.frame({"a": 1}) + sfs.frame(big)
    p = sfs.PacketParser()
    out = []
    for i in range(0, len(raw), 7):  # fragmented delivery
        out += p.feed(raw[i:i + 7])
    assert out == [{"a": 1}, big]
    assert sfs.frame(big)[0] & sfs.COMPRESSED


def test_bigsize():
    big = {"s": "y" * 70000}
    assert sfs.PacketParser().feed(sfs.frame(big, compress=False)) == [big]
