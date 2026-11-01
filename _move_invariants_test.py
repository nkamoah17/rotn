# -*- coding: utf-8 -*-
"""Move test_invariants.py to research, splitting product/research invariant imports."""
import io, os

RESEARCH_TESTS = os.path.join('rotn-research', 'tests')
os.makedirs(RESEARCH_TESTS, exist_ok=True)

with io.open('tests/test_invariants.py', encoding='utf-8') as fh:
    text = fh.read()

OLD = """from rot.invariants import (
    Invariant,
    LABEL_INDUCTIVE,
    LABEL_BOUNDED,
    LABEL_LIKELY,
    LABEL_EVENTUALLY,
    BLOCKING_LABELS,
    PERM_ALERT,
    PERM_WARN,
    PERM_BLOCK,
    RUNG_STRUCTURAL,
    RUNG_LOCAL,
    RUNG_PROTOCOL,
    RUNG_E2E,
    ALL_RUNGS,
    RUNG_CEILING,
    PERMISSION_NAMES,
    agreement,
    validity,
    no_spurious_abort,
    zab_no_premature_apply,
    zab_apply_persisted,
    pbft_quorum,
    pbft_prepare_before_commit,
    no_double_charge,
    charge_requires_order,
    settle_requires_charge,
    names,
    get,
)"""

NEW = """from rot.invariants import (
    Invariant,
    LABEL_INDUCTIVE,
    LABEL_BOUNDED,
    LABEL_LIKELY,
    LABEL_EVENTUALLY,
    BLOCKING_LABELS,
    PERM_ALERT,
    PERM_WARN,
    PERM_BLOCK,
    RUNG_STRUCTURAL,
    RUNG_LOCAL,
    RUNG_PROTOCOL,
    RUNG_E2E,
    ALL_RUNGS,
    RUNG_CEILING,
    PERMISSION_NAMES,
    agreement,
    validity,
    no_spurious_abort,
    names,
    get,
)
from rotn_research.invariants import (
    zab_no_premature_apply,
    zab_apply_persisted,
    pbft_quorum,
    pbft_prepare_before_commit,
    no_double_charge,
    charge_requires_order,
    settle_requires_charge,
)"""

assert OLD in text, "could not find the import block"
text = text.replace(OLD, NEW)

dst = os.path.join(RESEARCH_TESTS, 'test_invariants.py')
with io.open(dst, 'w', encoding='utf-8') as fh:
    fh.write(text)
os.remove('tests/test_invariants.py')
print('moved tests/test_invariants.py ->', dst)