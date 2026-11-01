# -*- coding: utf-8 -*-
import sys
print("sys.path[0:3]:", sys.path[:3])
try:
    import rot
    print("ROT FILE:", rot.__file__)
except Exception as e:
    print("ROT IMPORT FAILED:", type(e).__name__, e)
try:
    import rot.invariants as i
    print("INV FILE:", i.__file__)
    print("KINDS:", i.names())
except Exception as e:
    print("INV IMPORT FAILED:", type(e).__name__, e)
