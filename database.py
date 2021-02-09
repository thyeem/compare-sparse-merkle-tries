# pylint: disable=no-member
import os
from collections import defaultdict

import rocksdb


class MemoryDB(object):
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


class RocksDB(object):
    def __init__(self, dbfile=None):
        dbfile = dbfile or f"/tmp/{os.urandom(8).hex()}"
        self.db = rocksdb.DB(dbfile, self.config_rocksdb())
        self.meta = set()
        self.cache = defaultdict(lambda: None)
        self.batch = rocksdb.WriteBatch()
        self.batch_mode = False

    def config_rocksdb(self):
        """tunes RocksDB based on 'the fastest way to insert data into rocksdb'
        https://github.com/facebook/rocksdb/wiki/RocksDB-FAQ
        """
        opt = rocksdb.Options()
        opt.create_if_missing = True
        opt.disable_auto_compactions = True
        opt.write_buffer_size = 1 << 26
        opt.max_write_buffer_number = 3
        opt.target_file_size_base = 1 << 26
        # opt.table_factory = rocksdb.BlockBasedTableFactorsy(
        #     filter_policy=rocksdb.BloomFilterPolicy(10),
        #     block_cache=rocksdb.LRUCache(2 * (1 << 30)))
        opt.max_background_flushes = 4
        opt.level0_file_num_compaction_trigger = True
        opt.level0_slowdown_writes_trigger = True
        opt.level0_stop_writes_trigger = 32
        return opt

    def init_batch(self):
        self.batch_mode = True
        self.batch.clear()
        self.meta = set()
        self.cache = defaultdict(lambda: None)

    def write_batch(self):
        self.db.write(self.batch)
        self.batch_mode = False

    def get(self, k):
        if self.batch_mode:
            if k in self.meta or k in self.cache:
                v = self.cache[k]
            else:
                v = self.db.get(k)
                if v:
                    self.cache[k] = v
        else:
            v = self.db.get(k)
        return v

    def put(self, k, v):
        if self.batch_mode:
            self.cache[k] = v
            self.batch.put(k, v)
        else:
            self.db.put(k, v)

    def delete(self, k):
        if self.batch_mode:
            if self.cache[k]:
                del self.cache[k]
            self.meta.add(k)
            self.batch.delete(k)
        else:
            self.db.delete(k)
