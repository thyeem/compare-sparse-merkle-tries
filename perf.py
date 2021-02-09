import os
import time

from cached_smt import CachedSMT
from database import MemoryDB, RocksDB
from monotree import Monotree, blake2b, verify_proof
from vanilla_smt import VanillaSMT


def gen_keys(size, hash_fn=blake2b(32), static=False):
    if static:
        return [hash_fn(bytes([(i // 256) % 256, i % 256])) for i in range(size)]
    else:
        return [hash_fn(os.urandom(16)) for _ in range(size)]


def start_perf(*args):
    print(f'\n{"-" * 80}\n{args[0]}\n{"-" * 80}\n')


def timeit(comment=""):
    def fmt(t):
        return (
            t > 1
            and f"{t:.4f} s"
            or 1e3 * t > 1
            and f"{1e3*t:.4f} ms"
            or 1e6 * t > 1
            and f"{1e6*t:.4f} us"
            or f"{1e9*t:.4f} ns"
        )

    def _(f):
        def __(*args, **kwargs):
            tick = time.perf_counter()
            res = f(*args, **kwargs)
            tock = time.perf_counter()
            desc = comment or f.__name__
            print(f"{desc}  {fmt(tock-tick)}")
            return res

        return __

    return _


def unit_test(name, tree, keys, size, batch=False, DBcount=False):
    root = tree.new_tree()
    print(f"{name}")

    @timeit(f"time for updating {size} keys:")
    def fn_batch():
        return tree.updates(root, keys, keys)

    @timeit(f"time for updating {size} keys:")
    def fn_non_batch():
        r = root
        for key in keys:
            r = tree.update(r, key, key)
        return r

    root = batch and fn_batch() or fn_non_batch()
    if DBcount:
        print(f"writes: {tree.db.writes}, reads: {tree.db.reads}")
    print(f"root: {root.hex()}")
    print()


def vsmtMemory_vs_csmtMemory_vs_monoMemory(nbyte, size):
    start_perf("Vanilla SMT vs. Cached SMT vs. Monotree")
    hash_fn = blake2b(nbyte)
    keys = gen_keys(size, hash_fn)
    keys_in_order = sorted(keys)
    unit_test(
        name="Vanilla-SMT with MemoryDB",
        tree=VanillaSMT(nbyte, db=MemoryDB()),
        keys=keys,
        size=size,
        batch=False,
        DBcount=True,
    )
    unit_test(
        name="Vanilla-SMT with MemoryDB (keys-sorted)",
        tree=VanillaSMT(nbyte, db=MemoryDB()),
        keys=keys_in_order,
        size=size,
        batch=False,
        DBcount=True,
    )
    unit_test(
        name="Cached-SMT with MemoryDB",
        tree=CachedSMT(nbyte, db=MemoryDB()),
        keys=keys,
        size=size,
        batch=False,
        DBcount=True,
    )
    unit_test(
        name="Cached-SMT with MemoryDB (keys-sorted)",
        tree=CachedSMT(nbyte, db=MemoryDB()),
        keys=keys_in_order,
        size=size,
        batch=False,
        DBcount=True,
    )
    unit_test(
        name="Monotree with MemoryDB",
        tree=Monotree(nbyte, db=MemoryDB()),
        keys=keys,
        size=size,
        batch=False,
        DBcount=True,
    )
    unit_test(
        name="Monotree with MemoryDB (keys-sorted)",
        tree=Monotree(nbyte, db=MemoryDB()),
        keys=keys_in_order,
        size=size,
        batch=False,
        DBcount=True,
    )


def csmtMemory_vs_csmtRocksDB(nbyte, size):
    start_perf("Cached SMT MemoryDB vs. Cached SMT RocksDB")
    hash_fn = blake2b(nbyte)
    keys = gen_keys(size, hash_fn)
    unit_test(
        name="Cached-SMT with MemoryDB",
        tree=CachedSMT(nbyte, db=MemoryDB()),
        keys=keys,
        size=size,
        batch=False,
    )
    unit_test(
        name="Cached-SMT with RocksDB (batch)",
        tree=CachedSMT(nbyte, db=RocksDB()),
        keys=keys,
        size=size,
        batch=True,
    )


def monoMemory_vs_monoRocksDB(nbyte, size):
    start_perf("Monotree-MemoryDB vs. Monotree-RocksDB")
    hash_fn = blake2b(nbyte)
    keys = gen_keys(size, hash_fn)
    unit_test(
        name="Monotree-MemoryDB",
        tree=Monotree(nbyte, db=MemoryDB()),
        keys=keys,
        size=size,
        batch=False,
    )
    unit_test(
        name="Monotree-RocksDB (batch)",
        tree=Monotree(nbyte, db=RocksDB()),
        keys=keys,
        size=size,
        batch=True,
    )


def monoRocksDB_monoRocksDBbatch(nbyte, size):
    start_perf("Monotree-RocksDB vs. Monotree-RocksDB-batch-mode")
    hash_fn = blake2b(nbyte)
    keys = gen_keys(size, hash_fn)
    unit_test(
        name="Monotree-RocksDB (non-batch)",
        tree=Monotree(nbyte, db=RocksDB()),
        keys=keys,
        size=size,
        batch=False,
    )
    unit_test(
        name="Monotree-RocksDB (batch)",
        tree=Monotree(nbyte, db=RocksDB()),
        keys=keys,
        size=size,
        batch=True,
    )


def test_mono_get_leaf(nbyte, size, dump=False):
    start_perf("Monotree get-leaf test")
    hash_fn = blake2b(nbyte)
    keys = gen_keys(size, hash_fn)
    tree = Monotree(hash_bytes=nbyte, db=MemoryDB())
    root = tree.new_tree()
    for key in keys:
        root = tree.update(root, key, key)
    if dump:
        print(f"root: {root.hex()}")
        print(f"keys: {[key.hex() for key in keys]}")
    for key in keys:
        leaf = tree.get_leaf(root, key)
        if dump:
            print(f"key {key.hex()}  leaf {leaf.hex()}")
        assert leaf == key, f"{leaf}=={key}?"


def test_mono_merkle_proof(nbyte, size, dump=False):
    start_perf("Monotree merkle-proof test")
    hash_fn = blake2b(nbyte)
    keys = gen_keys(size, hash_fn)
    tree = Monotree(hash_bytes=nbyte, db=MemoryDB())
    root = tree.new_tree()
    for key in keys:
        root = tree.update(root, key, key)
    if dump:
        print(f"root: {root.hex()}")
        print(f"keys: {[key.hex() for key in keys]}")
    for key in keys:
        proof = tree.get_merkle_proof(root, key)
        verified = verify_proof(root, key, key, proof, hash_fn=hash_fn)
        assert verified
        if dump:
            print(
                f"{verified}  key {key.hex()}  ",
                f"proof {[(a.hex(), b.hex()) for a, b in proof]}",
            )


if __name__ == "__main__":
    vsmtMemory_vs_csmtMemory_vs_monoMemory(nbyte=32, size=10000)
    csmtMemory_vs_csmtRocksDB(nbyte=32, size=10000)
    monoMemory_vs_monoRocksDB(nbyte=32, size=10000)
    monoRocksDB_monoRocksDBbatch(nbyte=32, size=10000)
    test_mono_get_leaf(nbyte=4, size=20, dump=True)
    test_mono_merkle_proof(nbyte=4, size=20, dump=True)
