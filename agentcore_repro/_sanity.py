# -*- coding: utf-8 -*-
"""_sanity.py -- offline checks of the GAP-4 repro (no AWS calls)."""
import importlib.util
import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))
import common as C  # noqa: E402

# 1) transfer handler
spec = importlib.util.spec_from_file_location("th", "lambda/transfer_handler.py")
th = importlib.util.module_from_spec(spec)
spec.loader.exec_module(th)
r = th.handler({"amount": 100}, None)
assert r["amount"] == 100 and r["status"] == "SETTLED", r
r2 = th.handler({"params": {"arguments": {"amount": 50}}}, None)
assert r2["amount"] == 50
try:
    th.handler({}, None)
    raise SystemExit("handler should have raised on missing amount")
except ValueError:
    pass
print("handler OK")

# 2) render template on the real buggy policy
src = open("policies/spendcap-buggy-agentcore.dw").read()
out = C.render_template(src, {"GATEWAY_ARN":
    "arn:aws:bedrock-agentcore:us-east-1:123:gateway/xyz"})
assert "arn:aws:bedrock-agentcore:us-east-1:123:gateway/xyz" in out
assert "{{" not in out
print("render OK")

# 3) classify
spec2 = importlib.util.spec_from_file_location("f30", "30_fire_parallel.py")
f30 = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(f30)
C.ensure_out()
t1 = os.path.join(C.OUT_DIR, "_t1.json")
t2 = os.path.join(C.OUT_DIR, "_t2.json")
open(t1, "w").write('{"txId": "rot-abc", "status": "SETTLED"}')
open(t2, "w").write('{"error": "PolicyDenied"}')
assert f30.classify(0, t1, "", "") == "ADMITTED"
assert f30.classify(1, t2, "", "") == "DENIED"
assert f30.classify(1, t1, "", "") == "UNKNOWN"
print("classify OK")

# 4) settle regex
spec3 = importlib.util.spec_from_file_location("e40", "40_capture_evidence.py")
e40 = importlib.util.module_from_spec(spec3)
spec3.loader.exec_module(e40)
lines = ("noise\nSETTLE txId=rot-1 amount=100 status=SETTLED\n"
         "SETTLE txId=rot-2 amount=100 status=SETTLED\n")
ms = list(e40.SETTLE_RE.finditer(lines))
assert len(ms) == 2 and ms[0].group(2) == "100", ms
print("settle regex OK")

# 5) names + state round-trip
assert C.names()["gateway"] == "rot-spendcap-gw"
st = C.save_state({"phase": "test"})
assert C.load_state()["phase"] == "test"
print("names/state OK")

print("ALL_SANITY_OK")