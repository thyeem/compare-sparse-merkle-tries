import hashlib
import itertools

from database import RocksDB


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


class CachedSMT(object):
    """A pure-python implementation of Modified Sparse Merkle Tree (SMT).

    Based on the Vanilla SMT, a modification for reading DB as few as possible
    using cached objects was made.
    """

    def __init__(self, hash_bytes=32, db=None, hash_fn=None):
        """ RocksDB will be used when not provided keyword 'db' """

        self.db = db or RocksDB()
        self.HASH_BYTES = hash_bytes
        self.HASH_BITS = hash_bytes << 3
        self.hash = hash_fn or blake2b(hash_bytes)
        self.nil = b"" * hash_bytes
        self.nilproof = [self.nil]

    def new_tree(self):
        h = self.nil
        for _ in range(self.HASH_BITS):
            hh = h + h
            h = self.hash(hh)
            self.nilproof.insert(0, h)
            self.db.put(h, hh)
        return h

    def get(self, root, key):
        nshift = self.HASH_BITS - 1
        h = root
        bits = bytes_to_int(key)
        for i in range(self.HASH_BITS):
            hh = self.db.get(h)
            if hh == self.nilproof[i] * 2:
                return self.nil
            if (bits >> nshift) & 1:
                h = hh[self.HASH_BYTES :]
            else:
                h = hh[: self.HASH_BYTES]
            bits <<= 1
        return h

    def get_merkle_proof(self, root, key):
        nshift = self.HASH_BITS - 1
        bits = bytes_to_int(key)
        h = root
        proof = []
        for i in range(self.HASH_BITS):
            if h == self.nilproof[i]:
                return proof
            hh = self.db.get(h)
            if (bits >> nshift) & 1:
                h = hh[self.HASH_BYTES :]
                proof.append(hh[: self.HASH_BYTES])
            else:
                h = hh[: self.HASH_BYTES]
                proof.append(hh[self.HASH_BYTES :])
            bits <<= 1
        return proof

    def update(self, root, key, leaf):
        proof = self.get_merkle_proof(root, key)
        iNIL = len(proof)
        bits = bytes_to_int(key)
        h = leaf
        for i in reversed(range(self.HASH_BITS)):
            if i < iNIL:
                pf = proof[i]
            else:
                pf = self.nilproof[i + 1]
            if bits & 1:
                hh = pf + h
            else:
                hh = h + pf
            h = self.hash(hh)
            self.db.put(h, hh)
            bits >>= 1
        return h

    def updates(self, root, keys, leaves, batch_size=20):
        """method prepared for RocksDB-batch-mode

        Just give lists of key and leaf, regardless the size of key/leaf size
        They would be appropriately chunked
        """
        chunks = zip(
            chunk_iterable(keys, batch_size), chunk_iterable(leaves, batch_size)
        )
        for keys, leaves in chunks:
            self.db.init_batch()
            for key, leaf in zip(keys, leaves):
                root = self.update(root, key, leaf)
            self.db.write_batch()
        return root

    def verify_proof(self, root, key, leaf, proof):
        iNIL = len(proof)
        bits = bytes_to_int(key)
        h = leaf
        for i in reversed(range(self.HASH_BITS)):
            if i < iNIL:
                pf = proof[i]
            else:
                pf = self.nilproof[i + 1]
            if bits & 1:
                hh = pf + h
            else:
                hh = h + pf
            h = self.hash(hh)
            bits >>= 1
        return root == h
