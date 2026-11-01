# -*- coding: utf-8 -*-
"""Locate PROPS constants and _REGISTRY target keys in HEAD targets file."""
import io
import re

t = io.open("tmp_targets_head.py", encoding="utf-16").read()
lines = t.splitlines()

for i, l in enumerate(lines):
    if re.match(r"^[A-Z_0-9]*_PROPS\s*=", l):
        print("PROPS  L%-4d %s" % (i + 1, l.strip()[:70]))
    if re.match(r'^\s*"[a-z][a-z0-9-]*":\s*_spec', l):
        print("TARGET L%-4d %s" % (i + 1, l.strip()[:70]))
    if l.startswith("_REGISTRY") or l.strip() == "}":
        print("BOUND  L%-4d %s" % (i + 1, l.strip()[:70]))

