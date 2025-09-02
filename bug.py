from ouch import randbytes

from monotree import *
from utils import *

t1 = Monotree()
t2 = Monotree()
r1 = b""
r2 = b""
hash_fn = blake2b(32)

one = randbytes(32)
two = randbytes(32)

r1 = t1.insert(r1, one, one)
r1 = t1.insert(r1, two, two)

r2 = t2.insert(r2, two, two)
r2 = t2.insert(r2, one, one)


print(r1)
print(r2)
assert r1 == r2
