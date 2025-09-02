from utils import *


class VanillaSMT:
    """A pure-python implementation of Vanilla Sparse Merkle Tree (SMT).

    This is a straightforward standard Sparse Merkle Tree without any optimizations.
    """

    def __init__(self, hash_bytes=32, hash_fn=None):
        self.HASH_BYTES = hash_bytes
        self.HASH_BITS = hash_bytes << 3
        self.hash = hash_fn or blake2b(hash_bytes)
        self.new()

    def new(self):
        self.db = Database()
        h = NIL
        for _ in range(self.HASH_BITS):
            hh = h + h
            h = self.hash(hh)
            self.db.put(h, hh)
        return h

    def get(self, root, key):
        nshift = self.HASH_BITS - 1
        h = root
        bits = bytes_to_int(key)
        for _ in range(self.HASH_BITS):
            hh = self.db.get(h)
            if (bits >> nshift) & 1:
                h = hh[self.HASH_BYTES :]
            else:
                h = hh[: self.HASH_BYTES]
            bits <<= 1
        return h

    def get_merkle_proof(self, root, key):
        bits = bytes_to_int(key)
        nshift = self.HASH_BITS - 1
        h = root
        proof = []
        for _ in range(self.HASH_BITS):
            hh = self.db.get(h)
            if (bits >> nshift) & 1:
                h = hh[self.HASH_BYTES :]
                proof.append(hh[: self.HASH_BYTES])
            else:
                h = hh[: self.HASH_BYTES]
                proof.append(hh[self.HASH_BYTES :])
            bits <<= 1
        return proof

    def insert(self, root, key, leaf):
        proof = self.get_merkle_proof(root, key)
        bits = bytes_to_int(key)
        h = leaf
        for i in range(self.HASH_BITS):
            if bits & 1:
                hh = proof[-1 - i] + h
            else:
                hh = h + proof[-1 - i]
            h = self.hash(hh)
            self.db.put(h, hh)
            bits >>= 1
        return h

    def verify_proof(self, root, key, leaf, proof):
        bits = bytes_to_int(key)
        h = leaf
        for i in range(self.HASH_BITS):
            if bits & 1:
                hh = proof[-1 - i] + h
            else:
                hh = h + proof[-1 - i]
            h = self.hash(hh)
            bits >>= 1
        return root == h
