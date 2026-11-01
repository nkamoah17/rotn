# -*- coding: utf-8 -*-
"""Verify __main__.py dispatch is clean + syntax is valid."""
import io
import py_compile

t = io.open("rot/__main__.py", encoding="utf-8").read()
lines = t.splitlines()
print("== dispatch / NOTE lines ==")
for i, l in enumerate(lines):
    if "cmd_doctor}[args" in l or 'NOTE: the' in l or '"ladder"' in l or '"ab"' in l:
        print("L%-4d %s" % (i + 1, l))

# syntax check
try:
    py_compile.compile("rot/__main__.py", doraise=True)
    print("\nSYNTAX OK")
except py_compile.PyCompileError as e:
    print("\nSYNTAX ERROR:", e)
