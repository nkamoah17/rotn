# -*- coding: utf-8 -*-
import os, io, re
files = ['test_composition.py', 'test_emitter_spec.py', 'test_liveness_binds.py',
         'test_phase4_default.py', 'test_zk_bug_replay.py', 'test_invariants.py']
for f in files:
    p = os.path.join('tests', f)
    t = io.open(p, encoding='utf-8', errors='replace').read()
    print('=== %s ===' % f)
    for m in re.finditer(r'^(import|from)\s+([a-zA-Z_.]+)', t, re.M):
        mod = m.group(2)
        if any(k in mod for k in ['rot', 'research', 'twopc', 'zab', 'pbft', 'payment', 'approval', 'empirical']):
            print('  import:', m.group(0).strip())
    names = set()
    for x in ['no_double_charge', 'charge_requires', 'settle_requires', 'no_deadlock',
              'task_ends_or_escalates', 'no_runaway', 'no_privilege', 'zab_no_premature',
              'zab_apply', 'pbft_quorum', 'pbft_prepare', 'no_unapproved',
              'payment-correct', 'payment-buggy', 'zab-correct', 'zab-buggy',
              'orch-correct', 'orch-buggy', 'live-correct', 'live-buggy']:
        if re.search(r'\b' + x, t):
            names.add(x)
    print('  research names:', sorted(names))
    print()