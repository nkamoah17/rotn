# -*- coding: utf-8 -*-
"""Verify the repro's common.py resolves both CLIs and a region."""
import sys
import common as C

print("python   :", sys.version.split()[0])
try:
    print("aws cli  :", C.aws_exe())
except Exception as e:
    print("aws cli  : FAIL ->", e)
try:
    print("agentcore:", C.ac_cmd())
except Exception as e:
    print("agentcore: FAIL ->", e)
try:
    print("region   :", C.region())
except Exception as e:
    print("region   : FAIL ->", e)