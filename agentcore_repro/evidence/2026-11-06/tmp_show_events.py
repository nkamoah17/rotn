# -*- coding: utf-8 -*-
"""tmp: show SETTLE lines from the raw lambda log events with timestamps."""
import datetime
import json

d = json.load(open(r"<REPO_ROOT>\tmp_lambda_events.json"))
evs = [e for e in d.get("events", []) if "SETTLE" in e.get("message", "")]
print("total SETTLE:", len(evs))
for e in evs:
    ts = datetime.datetime.utcfromtimestamp(e["timestamp"] / 1000.0)
    print(ts.strftime("%H:%M:%S.%f")[:-3], e["message"])
