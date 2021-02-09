import hashlib
import itertools

from database import RocksDB


def bytes_to_int(x):
    return int.from_bytes(x, "big")


def int_to_bytes(x, byte=32):
    return x.to_bytes(byte, "big")


def blake2b(nbyte=32):
    def f(x):
        return hashlib.blake2b(x, digest_size=nbyte).digest()

    return f


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


def len_lcp(X, Y):
    """length of the longest common prefix for a set of two strings"""
    n = 0
    for x, y in zip(X, Y):
        if x != y:
            break
        n += 1
    return n


def is_right(bits):
    return int(bits[0]) & 1


def encode_node(h, bits, R=False):
    nbit = len(bits)
    nbyte = nbit % 8 == 0 and nbit // 8 or nbit // 8 + 1
    nbit = int_to_bytes(nbit, 2)
    path = binstring_to_bytes(bits, nbyte)
    node = R and nbit + path + h or h + nbit + path
    return node


def decode_node(node, N, R=False):
    h = R and node[-N - 1 : -1] or node[:N]
    N = not R and N or 0
    nbit = bytes_to_int(node[N : N + 2])
    nbyte = nbit % 8 == 0 and nbit // 8 or nbit // 8 + 1
    path = node[N + 2 : N + 2 + nbyte]
    return h, bytes_to_binstring(path, nbit), N + 2 + nbyte


def verify_proof(root, key, leaf, proof, hash_fn=blake2b(32)):
    h = leaf
    for prefix, cut in proof[::-1]:
        if prefix == b"\x00":
            h = hash_fn(h + cut)
        elif prefix == b"\x01":
            h = hash_fn(cut[:-1] + h + cut[-1:])
        else:
            return False
    return root == h


class Monotree(object):
    """A pure-python implementation of Monotree (https://github.com/thyeem/monotree).

    Optimization in `monotree` is mainly to compress the path as much as possible
    while reducing the number of db access.
    As a result, compared to the standard Sparse Merkle Tree,
    this reduces the number of DB access from `N` to `log2(N)` in both reads and writes.

    merkle-proof prefix:
    00  \x00  [soft | hard] L
    01  \x01  [soft | hard] R
    """

    def __init__(self, hash_bytes=32, db=None, hash_fn=None):
        """RocksDB will be used when not provided 'db' keyword."""

        self.db = db or RocksDB()
        self.HASH_BYTES = hash_bytes
        self.HASH_BITS = hash_bytes << 3
        self.hash_fn = hash_fn or blake2b(hash_bytes)
        self.nil = b""

    def hash(self, x):
        return x != self.nil and self.hash_fn(x) or self.nil

    def new_tree(self):
        self.db.put(self.nil, self.nil)
        return self.nil

    def is_soft_node(self, node):
        return node[-1:] == b"\x00"

    def is_hard_node(self, node):
        return node[-1:] == b"\x01"

    def encode_soft_node(self, h, b):
        return encode_node(h, b) + b"\x00"

    def decode_soft_node(self, node):
        return decode_node(node, self.HASH_BYTES)[:-1]

    def encode_hard_node(self, h, b, H, B):
        Lnode = encode_node(h, b)
        Rnode = encode_node(H, B, True)
        return Lnode + Rnode + b"\x01"

    def decode_hard_node(self, node):
        Lh, Lb, size = decode_node(node, self.HASH_BYTES)
        Rh, Rb, _ = decode_node(node[size:], self.HASH_BYTES, True)
        return Lh, Lb, Rh, Rb

    def gen_node(self, h, b, H, B):
        if H == self.nil and B == self.nil:
            node = self.encode_soft_node(h, b)
        else:
            Lh, Rh = is_right(b) and (H, h) or (h, H)
            Lb, Rb = is_right(b) and (B, b) or (b, B)
            node = self.encode_hard_node(Lh, Lb, Rh, Rb)
        return node

    def put_node(self, h, b, H, B):
        node = self.gen_node(h, b, H, B)
        h = self.hash(node)
        self.db.put(h, node)
        return h

    def get_node(self, root, bits):
        node = self.db.get(root)
        if self.is_soft_node(node):
            h, b = self.decode_soft_node(node)
            return h, b, self.nil, self.nil
        if self.is_hard_node(node):
            Lh, Lb, Rh, Rb = self.decode_hard_node(node)
            return is_right(bits) and (Rh, Rb, Lh, Lb) or (Lh, Lb, Rh, Rb)
        assert False

    def put(self, root, bits, leaf):
        h, b, H, B = self.get_node(root, bits)
        n = len_lcp(b, bits)
        if n == 0:
            return self.put_node(h, b, leaf, bits)
        if n == len(bits):
            h = leaf
        elif n == len(b):
            h = self.put(h, bits[n:], leaf)
        else:
            sub_b, sub_B = b[n:], bits[n:]
            h, b = self.put_node(h, sub_b, leaf, sub_B), b[:n]
        return self.put_node(h, b, H, B)

    def update(self, root, key, leaf):
        bits = bytes_to_binstring(key, self.HASH_BITS)
        if root == self.nil:
            return self.put_node(leaf, bits, self.nil, self.nil)
        else:
            return self.put(root, bits, leaf)

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

    def get_leaf(self, root, key):
        bits = bytes_to_binstring(key, self.HASH_BITS)
        return self.get(root, bits)

    def get(self, root, bits):
        h, b, *_ = self.get_node(root, bits)
        n = len_lcp(b, bits)
        if n == len(bits):
            return h
        if n == len(b):
            return self.get(h, bits[n:])
        return

    def encode_proof(self, node, bits):
        N = self.HASH_BYTES
        if self.is_soft_node(node):
            prefix = b"\x00"
            cut = node[N:]
        elif self.is_hard_node(node):
            if is_right(bits):
                prefix = b"\x01"
                cut = node[: -N - 1] + b"\x01"
            else:
                prefix = b"\x00"
                cut = node[N:]
        else:
            assert False
        return prefix, cut

    def get_merkle_proof(self, root, key):
        proof = []
        if root == self.nil:
            return proof
        bits = bytes_to_binstring(key, self.HASH_BITS)
        return self.get_proof(root, bits, proof)

    def get_proof(self, root, bits, proof):
        h, b, H, B = self.get_node(root, bits)
        n = len_lcp(b, bits)
        if n == len(bits):
            node = self.gen_node(h, bits, H, B)
            e = self.encode_proof(node, bits)
            proof.append(e)
            return proof
        if n == len(b):
            node = self.gen_node(h, b, H, B)
            e = self.encode_proof(node, bits)
            proof.append(e)
            return self.get_proof(h, bits[n:], proof)
        return proof
