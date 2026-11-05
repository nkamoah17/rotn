import os
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.abspath(__file__)), os.pardir, "agentcore_repro"))
import common as C

cases = [
    ("connect blip", "Could not connect to the endpoint URL: \"https://x/\"", True),
    ("503", "An error occurred (ServiceUnavailableException) when calling ...", True),
    ("throttling", "An error occurred (ThrottlingException): rate exceeded", True),
    ("timeout", "command timed out after 300s: aws ...", True),
    ("access denied", "An error occurred (AccessDeniedException): ... not authorized", False),
    ("param validation", "An error occurred (ParamValidation): invalid", False),
    ("not found", "An error occurred (ResourceNotFoundException)", False),
    ("empty", "", False),
]
ok = True
for label, msg, want in cases:
    got = C._is_transient(msg)
    mark = "OK " if got == want else "BAD"
    if got != want:
        ok = False
    print("%s  %-16s want=%-5s got=%-5s  %s" % (mark, label, want, got, msg[:50]))
print("ALL_OK" if ok else "SOME_FAILED")
print("default retries =", C._aws_retries())