# -*- coding: utf-8 -*-
"""Extract exactly the 12 research invariants (by name) from UTF-16 HEAD."""
import io
import re

t = io.open("tmp_head_invariants.py", encoding="utf-16", errors="replace").read()
lines = t.splitlines()

RESEARCH = [
    "zab_no_premature_apply", "zab_apply_persisted", "pbft_quorum",
    "pbft_prepare_before_commit", "no_double_charge", "charge_requires_order",
    "settle_requires_charge", "no_unapproved_irreversible",
    "no_privilege_escalation", "no_deadlock", "task_ends_or_escalates",
    "no_runaway_budget",
]

bounds = [i for i, l in enumerate(lines)
          if re.match(r"^def [a-z_0-9]+\(", l) or l.startswith("_REGISTRY")]

pieces = []
for name in RESEARCH:
    start = None
    for i, l in enumerate(lines):
        if re.match(r"^def %s\(" % name, l):
            start = i
            break
    if start is None:
        raise SystemExit("NOT FOUND: %s" % name)
    ends = [b for b in bounds if b > start]
    end = ends[0] if ends else len(lines)
    block = lines[start:end]
    while block and not block[-1].strip():
        block.pop()
    pieces.append("\n".join(block))

out = "\n\n\n".join(pieces) + "\n"
io.open("tmp_research_invariants_block.py", "w", encoding="utf-8",
        newline="\n").write(out)

got = re.findall(r"^def ([a-z_0-9]+)\(", out, re.M)
print("extracted %d functions:" % len(got))
print(got)
print("missing:", (set(RESEARCH) - set(got)) or "none",
      " extra:", (set(got) - set(RESEARCH)) or "none")
