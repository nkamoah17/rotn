# -*- coding: utf-8 -*-
"""Move research modules rot/*.py -> rotn-research/rotn_research/*.py with
import rewriting: research cross-refs rot.X -> rotn_research.X; product refs
(rot.ir, rot.invariants, ...) stay rot.*."""
import io
import os
import re

RESEARCH = {
    "twopc", "zab", "pbft", "payment", "order_service", "env",
    "composition", "zk_bugs", "ladder", "approval", "ab", "empirical",
    "llm_baseline", "cpg_reader", "classify",
}

DEST_PKG = os.path.join("rotn-research", "rotn_research")
os.makedirs(DEST_PKG, exist_ok=True)


def _rewrite_relative(line):
    """Handle relative imports in a moved research module.

    ``from . import X`` / ``from .X import ...`` resolve against the package
    the module now lives in (``rotn_research``).  Product modules must be
    re-anchored to ``rot``; research modules to ``rotn_research``.
    """
    # from ..X import ...  /  from .X import ...
    m = re.match(r"^(\s*)from\s+\.([a-z_0-9]+)\s+import\b(.*)$", line)
    if m:
        x = m.group(2)
        pkg = "rotn_research" if x in RESEARCH else "rot"
        return "%sfrom %s.%s import%s" % (m.group(1), pkg, x, m.group(3))
    # from .. import X  /  from . import X
    m = re.match(r"^(\s*)from\s+\.\.?\s+import\s+(.+)$", line)
    if m:
        names = [x.strip() for x in m.group(2).split(",")]
        res, prod = [], []
        for nm in names:
            base = nm.split(" as ")[0].strip()
            (res if base in RESEARCH else prod).append(nm)
        parts = []
        if prod:
            parts.append("%sfrom rot import %s" % (m.group(1), ", ".join(prod)))
        if res:
            parts.append("%sfrom rotn_research import %s"
                         % (m.group(1), ", ".join(res)))
        return "\n".join(parts)
    return None


def rewrite(src):
    out = []
    for line in src.splitlines():
        # import rot.X  (X research)  ->  import rotn_research.X
        m = re.match(r"^(\s*)import\s+rot\.([a-z_0-9]+)(\s*as\s+\w+)?\s*$", line)
        if m and m.group(2) in RESEARCH:
            line = "%simport rotn_research.%s%s" % (m.group(1), m.group(2),
                                                    m.group(3) or "")
            out.append(line)
            continue
        # from rot.X import ...  (X research)  ->  from rotn_research.X import
        m = re.match(r"^(\s*)from\s+rot\.([a-z_0-9]+)\s+import\b(.*)$", line)
        if m and m.group(2) in RESEARCH:
            line = "%sfrom rotn_research.%s import%s" % (m.group(1),
                                                         m.group(2), m.group(3))
            out.append(line)
            continue
        # from rot import X, Y  -> split research names to rotn_research
        m = re.match(r"^(\s*)from\s+rot\s+import\s+(.+)$", line)
        if m:
            names = [x.strip() for x in m.group(2).split(",")]
            res, prod = [], []
            for nm in names:
                base = nm.split(" as ")[0].strip()
                (res if base in RESEARCH else prod).append(nm)
            parts = []
            if prod:
                parts.append("%sfrom rot import %s" % (m.group(1),
                                                       ", ".join(prod)))
            if res:
                parts.append("%sfrom rotn_research import %s" % (m.group(1),
                                                                 ", ".join(res)))
            out.extend(parts)
            continue
        # relative imports -> re-anchor product vs research
        r = _rewrite_relative(line)
        if r is not None:
            out.extend(r.splitlines())
            continue
        out.append(line)
    return "\n".join(out) + "\n"


moved = []
for name in sorted(RESEARCH):
    src_path = os.path.join("rot", name + ".py")
    if not os.path.exists(src_path):
        print("MISSING (skip): %s" % src_path)
        continue
    src = io.open(src_path, encoding="utf-8").read()
    dst_path = os.path.join(DEST_PKG, name + ".py")
    io.open(dst_path, "w", encoding="utf-8", newline="\n").write(rewrite(src))
    moved.append(name)

io.open(os.path.join(DEST_PKG, "__init__.py"), "w", encoding="utf-8",
        newline="\n").write(
    '# -*- coding: utf-8 -*-\n'
    '"""rotn_research: the ROTN research plane (ZAB/PBFT/2PC/payment/approval\n'
    'research, CPG-4, A/B frontends, ladders, empirical baselines).\n'
    '\n'
    'This package DEPENDS on the product (``pip install rotn``); it is never\n'
    'imported by the product.  Importing it registers its research invariants\n'
    'and targets into the shared ``rot.invariants`` / ``rot.targets``\n'
    'registries (via ``register``), so research targets resolve the same way\n'
    'they did before the split.\n'
    '"""\n'
    'from rotn_research import invariants  # noqa: F401  (registers invariants)\n'
    'from rotn_research import targets    # noqa: F401  (registers targets)\n'
    '\n'
    '__all__ = ["invariants", "targets"]\n'
)

print("moved %d research modules:" % len(moved))
print(moved)
