import hashlib
import itertools

NIL = b""


class Database:
    def __init__(self):
        self.reads = 0
        self.writes = 0
        self.db = {}

    def get(self, k):
        self.reads += 1
        return self.db.get(k, None)

    def put(self, k, v):
        self.writes += 1
        self.db[k] = v

    def delete(self, k):
        del self.db[k]


def blake2b(nbyte=32):
    def f(x):
        return hashlib.blake2b(x, digest_size=nbyte).digest()

    return f


def bytes_to_int(x):
    return int.from_bytes(x, "big")


def int_to_bytes(x, byte=32):
    return x.to_bytes(byte, "big")


def chunk_iterable(iterable, size):
    it = iter(iterable)
    while True:
        chunk = tuple(itertools.islice(it, size))
        if not chunk:
            break
        yield chunk


def bytes_to_binstring(x, bit=256):
    return format(bytes_to_int(x), f"0{bit}b")


def binstring_to_bytes(x, byte=32):
    return int_to_bytes(int(x, 2), byte)
