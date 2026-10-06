"""Bidirectional SFS2X codec: SFSObject/SFSArray values and packet framing."""
import struct
import zlib

NULL, BOOL, BYTE, SHORT, INT, LONG, FLOAT, DOUBLE, STRING = range(9)
BOOL_ARR, BYTE_ARR, SHORT_ARR, INT_ARR, LONG_ARR, FLOAT_ARR, DOUBLE_ARR, STRING_ARR = range(9, 17)
SFS_ARRAY, SFS_OBJECT, CLASS, TEXT = 17, 18, 19, 20

_NUM = {BYTE: ">b", SHORT: ">h", INT: ">i", LONG: ">q", FLOAT: ">f", DOUBLE: ">d"}
_NUM_ARR = {SHORT_ARR: SHORT, INT_ARR: INT, LONG_ARR: LONG, FLOAT_ARR: FLOAT, DOUBLE_ARR: DOUBLE}


class Typed:
    """Force an explicit SFS type, e.g. Typed(BYTE, 13) or Typed(LONG, ts)."""
    def __init__(self, t, v):
        self.t, self.v = t, v

    def __repr__(self):
        return f"Typed({self.t}, {self.v!r})"


class Reader:
    def __init__(self, data):
        self.d, self.i = data, 0

    def take(self, n):
        if self.i + n > len(self.d):
            raise ValueError("truncated SFS data")
        b = self.d[self.i:self.i + n]
        self.i += n
        return b

    def u16(self):
        return struct.unpack(">H", self.take(2))[0]

    def i32(self):
        return struct.unpack(">i", self.take(4))[0]


def _read_value(r, t=None):
    if t is None:
        t = r.take(1)[0]
    if t == NULL:
        return None
    if t == BOOL:
        return r.take(1)[0] != 0
    if t in _NUM:
        return struct.unpack(_NUM[t], r.take(struct.calcsize(_NUM[t])))[0]
    if t == STRING:
        return r.take(r.u16()).decode("utf-8", "replace")
    if t == TEXT:
        return r.take(r.i32()).decode("utf-8", "replace")
    if t == BOOL_ARR:
        return [r.take(1)[0] != 0 for _ in range(r.u16())]
    if t == BYTE_ARR:
        return bytes(r.take(r.i32()))
    if t in _NUM_ARR:
        return [_read_value(r, _NUM_ARR[t]) for _ in range(r.u16())]
    if t == STRING_ARR:
        return [_read_value(r, STRING) for _ in range(r.u16())]
    if t == SFS_ARRAY:
        return [_read_value(r) for _ in range(r.u16())]
    if t == SFS_OBJECT:
        out = {}
        for _ in range(r.u16()):
            k = r.take(r.u16()).decode("utf-8", "replace")
            out[k] = _read_value(r)
        return out
    raise ValueError(f"unsupported SFS type {t}")


def decode(data):
    return _read_value(Reader(data))


def _enc_typed(t, v):
    if t == NULL:
        return b"\x00"
    if t == BOOL:
        return bytes([BOOL, 1 if v else 0])
    if t in _NUM:
        return bytes([t]) + struct.pack(_NUM[t], v)
    if t == STRING:
        b = v.encode("utf-8")
        return bytes([STRING]) + struct.pack(">H", len(b)) + b
    if t == TEXT:
        b = v.encode("utf-8")
        return bytes([TEXT]) + struct.pack(">i", len(b)) + b
    if t == BYTE_ARR:
        return bytes([BYTE_ARR]) + struct.pack(">i", len(v)) + bytes(v)
    raise ValueError(f"cannot encode explicit type {t}")


def _enc_value(v):
    if isinstance(v, Typed):
        return _enc_typed(v.t, v.v)
    if v is None:
        return b"\x00"
    if isinstance(v, bool):
        return _enc_typed(BOOL, v)
    if isinstance(v, int):
        if -2**31 <= v < 2**31:
            return _enc_typed(INT, v)
        return _enc_typed(LONG, v)
    if isinstance(v, float):
        return _enc_typed(DOUBLE, v)
    if isinstance(v, str):
        return _enc_typed(STRING if len(v.encode("utf-8")) < 65536 else TEXT, v)
    if isinstance(v, (bytes, bytearray)):
        return _enc_typed(BYTE_ARR, v)
    if isinstance(v, dict):
        return bytes([SFS_OBJECT]) + _enc_obj_body(v)
    if isinstance(v, (list, tuple)):
        return bytes([SFS_ARRAY]) + struct.pack(">H", len(v)) + b"".join(_enc_value(x) for x in v)
    raise TypeError(f"cannot encode {type(v)}")


def _enc_obj_body(d):
    out = [struct.pack(">H", len(d))]
    for k, v in d.items():
        kb = k.encode("utf-8")
        out.append(struct.pack(">H", len(kb)) + kb + _enc_value(v))
    return b"".join(out)


def encode(obj):
    return _enc_value(obj)


# ---- packet framing -------------------------------------------------------
BINARY, ENCRYPTED, COMPRESSED, BIGSIZE = 0x80, 0x40, 0x20, 0x08
COMPRESS_THRESHOLD = 512


def frame(obj, compress=True):
    body = encode(obj)
    hdr = BINARY
    if compress and len(body) > COMPRESS_THRESHOLD:
        body, hdr = zlib.compress(body), hdr | COMPRESSED
    if len(body) > 0xFFFF:
        return bytes([hdr | BIGSIZE]) + struct.pack(">I", len(body)) + body
    return bytes([hdr]) + struct.pack(">H", len(body)) + body


class PacketParser:
    """Feed raw TCP bytes, get decoded packets back."""
    def __init__(self):
        self.buf = b""

    def feed(self, data):
        self.buf += data
        out = []
        while True:
            if len(self.buf) < 3:
                break
            h = self.buf[0]
            ls = 4 if h & BIGSIZE else 2
            if len(self.buf) < 1 + ls:
                break
            n = int.from_bytes(self.buf[1:1 + ls], "big")
            if len(self.buf) < 1 + ls + n:
                break
            body = self.buf[1 + ls:1 + ls + n]
            self.buf = self.buf[1 + ls + n:]
            if h & ENCRYPTED:
                raise ValueError("encrypted packets are not supported")
            if h & COMPRESSED:
                body = zlib.decompress(body)
            out.append(decode(body))
        return out


def gunzip_field(pkt_params, key="gZip"):
    """Large responses carry a gzip'd SFSObject in `gZip`; return it decoded."""
    import gzip
    raw = pkt_params.get(key)
    return decode(gzip.decompress(raw)) if raw else None
