from utils import *


class CachedSMT:
    """A pure-python implementation of Modified Sparse Merkle Tree (SMT).

    Based on the Vanilla SMT, a modification for reading DB as few as possible
    using cached objects was made.
    """

    def __init__(self, hash_bytes=32, hash_fn=None):
        self.HASH_BYTES = hash_bytes
        self.HASH_BITS = hash_bytes << 3
        self.hash = hash_fn or blake2b(hash_bytes)
        self.cache = [NIL]
        self.new()

    def new(self):
        self.db = Database()
        h = NIL
        for _ in range(self.HASH_BITS):
            hh = h + h
            h = self.hash(hh)
            self.cache.insert(0, h)
            self.db.put(h, hh)
        return h

    def get(self, root, key):
        nshift = self.HASH_BITS - 1
        h = root
        bits = bytes_to_int(key)
        for i in range(self.HASH_BITS):
            hh = self.db.get(h)
            if hh == self.cache[i] * 2:
                return NIL
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
            if h == self.cache[i]:
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

    def insert(self, root, key, leaf):
        proof = self.get_merkle_proof(root, key)
        size_proof = len(proof)
        bits = bytes_to_int(key)
        h = leaf
        for i in reversed(range(self.HASH_BITS)):
            if i < size_proof:
                pf = proof[i]
            else:
                pf = self.cache[i + 1]
            if bits & 1:
                hh = pf + h
            else:
                hh = h + pf
            h = self.hash(hh)
            self.db.put(h, hh)
            bits >>= 1
        return h

    def verify_proof(self, root, key, leaf, proof):
        size_proof = len(proof)
        bits = bytes_to_int(key)
        h = leaf
        for i in reversed(range(self.HASH_BITS)):
            if i < size_proof:
                pf = proof[i]
            else:
                pf = self.cache[i + 1]
            if bits & 1:
                hh = pf + h
            else:
                hh = h + pf
            h = self.hash(hh)
            bits >>= 1
        return root == h
