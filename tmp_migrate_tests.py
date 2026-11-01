# -*- coding: utf-8 -*-
"""One-shot migration: make the 14 product research-tests + 2 existing
research tests import the rotn_research package instead of rot.<research>.

Only the 15 A1-research modules are rewritten.  Product modules (rot.ir,
rot.invariants, rot.cpg4, rot.emitter, ...) are left untouched.
"""
import io
import os
import re
import shutil

ROOT = r'c:\Users\jeren\Documents\KAMANU\ROTN'
RR_TESTS = os.path.join(ROOT, 'rotn-research', 'tests')
PROD_TESTS = os.path.join(ROOT, 'tests')

RESEARCH = ['twopc', 'zab', 'pbft', 'payment', 'order_service', 'env',
            'composition', 'zk_bugs', 'ladder', 'approval', 'ab', 'empirical',
            'llm_baseline', 'cpg_reader', 'classify']
RESEARCH_SET = set(RESEARCH)
# rot.<research>  (module attr / import / from-import) -> rotn_research.<research>
ATTR = re.compile(r'\brot\.(' + '|'.join(RESEARCH) + r')\b')
# from rot import <names>
FROM_ROT = re.compile(r'^(\s*)from\s+rot\s+import\s+(.+?)\s*$')


def rewrite(src):
    out_lines = []
    for line in src.splitlines():
        m = FROM_ROT.match(line)
        if m:
            indent, rest = m.group(1), m.group(2)
            comment = ''
            if '#' in rest:
                i = rest.index('#')
                comment = '  #' + rest[i + 1:]
                rest = rest[:i].strip()
            rest = rest.replace('(', ' ').replace(')', ' ')
            names = [n.strip() for n in rest.split(',') if n.strip()]
            res = [n for n in names
                   if n.split(' as ')[0].strip() in RESEARCH_SET]
            prod = [n for n in names
                    if n.split(' as ')[0].strip() not in RESEARCH_SET]
            new = []
            if res:
                new.append(indent + 'from rotn_research import '
                           + ', '.join(res))
            if prod:
                new.append(indent + 'from rot import ' + ', '.join(prod))
            if not new:  # nothing imported (rare)
                new.append(line)
            out_lines.extend(new)
            if comment:
                out_lines[-1] += comment
            continue
        out_lines.append(ATTR.sub(r'rotn_research.\1', line))
    return '\n'.join(out_lines) + '\n'


def process(path, dest, in_place=False):
    src = io.open(path, encoding='utf-8').read()
    new = rewrite(src)
    changed = (new != src)
    if in_place:
        io.open(path, 'w', encoding='utf-8', newline='').write(new)
    else:
        shutil.copyfile(path, dest)
        io.open(dest, 'w', encoding='utf-8', newline='').write(new)
    return changed


# 1) existing research tests: fix in place
print('== existing research tests (in place) ==')
for f in ('test_invariants.py', 'test_phase4_default.py'):
    p = os.path.join(RR_TESTS, f)
    print('   %-28s changed=%s' % (f, process(p, None, in_place=True)))

# 2) the 14 product research tests: copy into rotn_research/tests/
print('\n== product research tests (moved) ==')
MOVED = ['test_cpg_model.py', 'test_env.py', 'test_general_state_space.py',
         'test_heldout_spec.py', 'test_impact.py', 'test_incremental.py',
         'test_java_model.py', 'test_liveness_enforcement.py',
         'test_llm_baseline.py', 'test_mr_gate.py', 'test_phase6_tla.py',
         'test_phase7_evidence.py', 'test_source_pipeline.py',
         'test_verdicts_liveness.py']
for f in MOVED:
    src = os.path.join(PROD_TESTS, f)
    dst = os.path.join(RR_TESTS, f)
    print('   %-32s changed=%s  -> %s' % (f, process(src, dst), dst))

print('\ndone')
