# -*- coding: utf-8 -*-
"""Phase A helper: extract the research-plane invariant factories from
rot/invariants.py (verbatim) and splice them out of the product file.

Run from the repo root:  python scripts_phase_a_extract.py
"""
import io
import re

PATH = "rot/invariants.py"
lines = io.open(PATH, encoding="utf-8").read().splitlines(True)


def find_line(pattern, what=""):
    rx = re.compile(pattern)
    for i, ln in enumerate(lines):
        if rx.search(ln):
            return i
    raise SystemExit("NOT FOUND (%s): %s" % (what, pattern))


def block_start(def_idx):
    """If a '# ---' / '# Gx' comment block immediately precedes the def at
    ``def_idx``, return the index of the block's first line; else the def's
    own index (no header)."""
    j = def_idx
    if j > 0 and lines[j - 1].lstrip().startswith("#"):
        while j > 0 and lines[j - 1].lstrip().startswith("#"):
            j -= 1
    return j


i_zab = find_line(r"^def zab_no_premature_apply", "zab def")
i_spend = find_line(r"^def spendcap_within_cap", "spendcap def")
i_app = find_line(r"^def no_unapproved_irreversible", "approval def")
i_g6 = find_line(r"^# G6: over-privileged", "G6 header")

# Region 1 = zab/pbft/payment factories: from the zab def (or its header) to
# the two blank lines just before `def spendcap_within_cap` (exclusive).
r1s = block_start(i_zab)
r1e = i_spend - 2
assert lines[r1e].strip() == "" and lines[r1e + 1].strip() == "", "seam A"
assert lines[r1s - 1].strip() == "", "seam A0"

# Region 2 = the G4 approval block: from its header to (exclusive) the two
# blank lines just before the G6 header block.
r2s = block_start(i_app)
r2e = i_g6 - 1
assert lines[r2e - 2].strip() == "" and lines[r2e - 1].strip() == "", "seam B"

region1 = "".join(lines[r1s:r1e])
region2 = "".join(lines[r2s:r2e])


def names_in(region):
    return re.findall(r"^def (\w+)\(", region, re.M)


exp1 = ["zab_no_premature_apply", "zab_apply_persisted", "pbft_quorum",
        "pbft_prepare_before_commit", "no_double_charge",
        "charge_requires_order", "settle_requires_charge"]
exp2 = ["no_unapproved_irreversible", "no_privilege_escalation", "no_deadlock",
        "task_ends_or_escalates", "no_runaway_budget"]
got1, got2 = names_in(region1), names_in(region2)
assert got1 == exp1, "region1 mismatch: %r" % got1
assert got2 == exp2, "region2 mismatch: %r" % got2

# Verbatim research body (for rotn_research/invariants.py)
io.open("research_invariants_body.py.txt", "w", encoding="utf-8").write(
    region1.rstrip("\n") + "\n\n\n" + region2.rstrip("\n") + "\n")

# Spliced product file with exactly two blank lines at each seam.
prefix = "".join(lines[:r1s]).rstrip("\n")
middle = "".join(lines[r1e:r2s]).strip("\n")
tail = "".join(lines[r2e:])
new = prefix + "\n\n\n" + middle + "\n\n" + tail
io.open(PATH, "w", encoding="utf-8").write(new)
print("OK: region1=%d lines, region2=%d lines; product now %d lines"
      % (r1e - r1s, r2e - r2s, len(new.splitlines())))
