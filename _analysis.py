# -*- coding: utf-8 -*-
import os, io, re
print('rot/ (product) has twopc.py:', os.path.exists('rot/twopc.py'))
print('research has twopc.py:', os.path.exists('rotn-research/rotn_research/twopc.py'))
print()
print('== research rotn_research/ modules ==')
for f in sorted(os.listdir('rotn-research/rotn_research')):
    print('  ', f)
print()
prod_tests = sorted(f for f in os.listdir('tests') if f.endswith('.py'))
use_cb, use_other = [], []
for f in prod_tests:
    t = io.open(os.path.join('tests', f), encoding='utf-8', errors='replace').read()
    uses_cb = bool(re.search(r"build\s*\(\s*['\"](correct|buggy)['\"]", t)) or bool(re.search(r"get\s*\(\s*['\"](correct|buggy)['\"]", t))
    uses_other = bool(re.search(r'\b(zab|pbft|payment|order[_-]|no_double_charge|charge_requires|settle_requires|no_deadlock|task_ends_or_escalates|approval_before|delegation_within)\b', t))
    if uses_cb:
        use_cb.append(f)
    if uses_other:
        use_other.append(f)
print('Product tests referencing 2PC correct/buggy via build/get: %d' % len(use_cb))
print('Product tests referencing other research protocols: %d' % len(use_other))
print('  other:', use_other)