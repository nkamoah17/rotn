# -*- coding: utf-8 -*-
"""Assemble rotn-research/rotn_research/targets.py from the HEAD targets file.

Extracts the research PROPS constants + research target entries (2PC, ZAB,
PBFT, payment, approval/delegation/orchestration/budget, livelock, deadlock)
and re-registers them into the shared ``rot.targets`` registry.
"""
import io
import re

t = io.open("tmp_targets_head.py", encoding="utf-16").read()
lines = t.splitlines()

RESEARCH_TARGETS = [
    "correct", "buggy",
    "zab-correct", "zab-buggy",
    "pbft-correct", "pbft-buggy",
    "payment-correct", "payment-buggy",
    "approval-correct", "approval-buggy",
    "delegation-correct", "delegation-buggy",
    "orchestration-correct", "orchestration-buggy",
    "budget-correct", "budget-buggy",
    "livelock-correct", "livelock-buggy",
    "deadlock-correct", "deadlock-buggy",
]
RESEARCH_PROPS = [
    "TWOPC_PROPS", "ZAB_PROPS", "PBFT_PROPS", "PAYMENT_PROPS",
    "APPROVAL_PROPS", "DELEGATION_PROPS", "ORCHESTRATION_PROPS",
    "BUDGET_PROPS", "LIVELOCK_PROPS",
]

# --- extract PROPS constants (may span multiple lines) -----------------
props_lines = []
i = 0
while i < len(lines):
    m = re.match(r"^([A-Z_0-9]*_PROPS)\s*=\s*(.*)$", lines[i])
    if m and m.group(1) in RESEARCH_PROPS:
        # collect until the line ends with ']'
        buf = [lines[i]]
        j = i
        while not buf[-1].rstrip().endswith("]") and j + 1 < len(lines):
            j += 1
            buf.append(lines[j])
        props_lines.extend(buf)
        i = j + 1
    else:
        i += 1
props_block = "\n".join(props_lines)

# --- extract target entries ------------------------------------------
entries = []
for name in RESEARCH_TARGETS:
    start = None
    for i, l in enumerate(lines):
        if re.match(r'^\s*"%s":\s*_spec\(' % re.escape(name), l):
            start = i
            break
    if start is None:
        raise SystemExit("target not found: %s" % name)
    # end = the line that closes the _spec( call with '),'
    depth = 0
    end = start
    for j in range(start, len(lines)):
        depth += lines[j].count("(") - lines[j].count(")")
        if depth == 0 and j > start:
            end = j
            break
    block = lines[start:end + 1]
    entries.append("\n".join(block))

registry_block = "_REGISTRY = {\n" + "\n".join(entries) + "\n}\n"

# --- assemble ---------------------------------------------------------
HEADER = '''# -*- coding: utf-8 -*-
"""Research protocol targets (2PC / ZAB / PBFT / payment / approval family).

These targets were previously defined in ``rot.targets``; after the
product/research split they live here and are re-registered into the shared
``rot.targets`` registry via ``register`` so that ``targets.build("zab-buggy")``
and friends resolve exactly as before.

The product never imports this module.  Research targets reference research
modules (``rotn_research.{twopc,zab,pbft,payment,approval}``) and the product
``TargetSpec`` / ``invariants``.
"""
from rot.targets import TargetSpec          # product (data model)
import rot.invariants as invariants         # product (named invariants)
import rotn_research.twopc as twopc         # research
import rotn_research.zab as zab             # research
import rotn_research.pbft as pbft           # research
import rotn_research.payment as payment     # research
import rotn_research.approval as approval   # research


def _spec(name, description, buggy, build, properties, default_property,
          protocol="2PC"):
    return TargetSpec(
        name=name,
        description=description,
        build=lambda n: build(n=n, buggy=buggy),
        properties=list(properties),
        default_property=default_property,
        protocol=protocol,
    )


'''

REG = ("\n\n# --- register into the shared product registry "
       "---------------------\n"
       "import rot.targets as _targets\n")
for n in RESEARCH_TARGETS:
    REG += '_targets.register("%s", _REGISTRY["%s"])\n' % (n, n)
REG += "\n__all__ = %r\n" % (RESEARCH_TARGETS + RESEARCH_PROPS)

out = HEADER + props_block + "\n\n\n" + registry_block + REG
io.open("rotn-research/rotn_research/targets.py", "w", encoding="utf-8",
        newline="\n").write(out)
print("wrote rotn-research/rotn_research/targets.py (%d lines)"
      % len(out.splitlines()))
print("props:", RESEARCH_PROPS)
print("targets:", RESEARCH_TARGETS)
