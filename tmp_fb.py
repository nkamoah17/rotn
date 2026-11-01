# -*- coding: utf-8 -*-
import io
import re

t = io.open("suite_err.txt", encoding="utf-8", errors="replace").read()
i = t.find("test_falseblock")
while i != -1:
    # find the block start (the ====== line before this)
    s = t.rfind("====", 0, i)
    e = t.find("====", i + 10)
    print(t[s:e if e != -1 else s + 2000])
    print("\n\n##########\n")
    i = t.find("test_falseblock", i + 1)
    if i > 200000:
        break
