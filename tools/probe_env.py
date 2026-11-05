# -*- coding: utf-8 -*-
"""Probe the local environment for the GAP-4 repro (stdlib only)."""
import importlib
import sys

print("python:", sys.version.split()[0])
for mod in ("botocore", "boto3", "requests"):
    try:
        m = importlib.import_module(mod)
        print("%-10s OK %s" % (mod, getattr(m, "__version__", "?")))
    except Exception as e:
        print("%-10s MISSING (%s)" % (mod, type(e).__name__))
