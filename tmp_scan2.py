import os, re, io

ROOT = r'c:\Users\jeren\Documents\KAMANU\ROTN'
TESTS = os.path.join(ROOT, 'tests')
RR = os.path.join(ROOT, 'rotn-research')

RESEARCH = set(['twopc', 'zab', 'pbft', 'payment', 'order_service',
                'composition', 'zk_bugs', 'ladder', 'approval', 'ab',
                'empirical', 'llm_baseline', 'classify', 'cpg_reader',
                'emitter', 'env'])

def research_imports(src):
    hits = set()
    for m in re.finditer(
            r'(?:import\s+rot\.([A-Za-z0-9_]+)'
            r'|from\s+rot\s+import\s+([A-Za-z0-9_,\s\*]+)'
            r'|import\s+rot\.([A-Za-z0-9_]+)\.)', src):
        for g in (m.group(1), m.group(3)):
            if g in RESEARCH:
                hits.add(g)
        if m.group(2):
            for n in (x.strip() for x in m.group(2).split(',')):
                if n in RESEARCH:
                    hits.add(n)
    return hits

print('===== PRODUCT tests/ importing research modules =====')
for f in sorted(os.listdir(TESTS)):
    if not f.endswith('.py') or f == 'conftest.py':
        continue
    p = os.path.join(TESTS, f)
    src = io.open(p, encoding='utf-8', errors='replace').read()
    # only count real import lines, not docstrings
    real = set()
    for ln, line in enumerate(src.splitlines(), 1):
        s = line.strip()
        if s.startswith('import ') or s.startswith('from '):
            real |= research_imports(line)
    if real:
        print('   %-32s -> %s' % (f, ', '.join(sorted('rot.' + r for r in real))))

print('\n===== rotn-research/ contents =====')
def listdir(base, label):
    print('  %s:' % label)
    if not os.path.isdir(base):
        print('    (MISSING)')
        return
    for f in sorted(os.listdir(base)):
        print('    ' + f)
listdir(RR, 'rotn-research/')
listdir(os.path.join(RR, 'rotn_research'), 'rotn_research/')
listdir(os.path.join(RR, 'tests'), 'tests/')
listdir(os.path.join(RR, 'bench'), 'bench/')
listdir(os.path.join(RR, 'twopc-java'), 'twopc-java/')
listdir(os.path.join(RR, 'docs'), 'docs/')
listdir(os.path.join(RR, '.github', 'workflows'), '.github/workflows/')

print('\n===== rotn_research modules MISSING from research copy =====')
prod_rot = os.path.join(ROOT, 'rot')
rr_pkg = os.path.join(RR, 'rotn_research')
for m in sorted(RESEARCH):
    prod = os.path.join(prod_rot, m + '.py')
    res = os.path.join(rr_pkg, m + '.py')
    print('   %-16s product=%s  research_copy=%s' % (
        m, 'Y' if os.path.exists(prod) else '-',
        'Y' if os.path.exists(res) else 'MISSING!'))
