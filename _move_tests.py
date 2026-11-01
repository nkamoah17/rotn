# -*- coding: utf-8 -*-
"""Move research-coupled product tests into the research repo and fix imports."""
import io, os, re

RESEARCH = os.path.join('rotn-research', 'tests')
os.makedirs(RESEARCH, exist_ok=True)

# research modules that moved to rotn_research
RESEARCH_MODULES = [
    'payment', 'composition', 'approval', 'ab', 'zk_bugs',
    'zab', 'pbft', 'order_service', 'env', 'ladder', 'empirical',
    'llm_baseline', 'cpg_reader', 'classify', 'twopc',
]

FILES = [
    'test_composition.py',
    'test_emitter_spec.py',
    'test_liveness_binds.py',
    'test_phase4_default.py',
    'test_zk_bug_replay.py',
]

def fix_imports(text):
    # import rot.<mod> as <name>  ->  import rotn_research.<mod> as <name>
    for m in RESEARCH_MODULES:
        text = re.sub(
            r'import\s+rot\.' + m + r'\b',
            'import rotn_research.' + m,
            text)
        # from rot.<mod> import ...  ->  from rotn_research.<mod> import ...
        text = re.sub(
            r'from\s+rot\.' + m + r'\b',
            'from rotn_research.' + m,
            text)
    return text

for f in FILES:
    src = os.path.join('tests', f)
    dst = os.path.join(RESEARCH, f)
    with io.open(src, encoding='utf-8') as fh:
        text = fh.read()
    text = fix_imports(text)
    with io.open(dst, 'w', encoding='utf-8') as fh:
        fh.write(text)
    os.remove(src)
    print('moved', f, '->', dst)
print('done')