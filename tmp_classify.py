import os, re, io

ROOT = r'c:\Users\jeren\Documents\KAMANU\ROTN'
ROT = os.path.join(ROOT, 'rot')

# Candidate RESEARCH modules (to move to rotn_research).
RESEARCH = set(['twopc', 'zab', 'pbft', 'payment', 'order_service',
                'composition', 'zk_bugs', 'ladder', 'approval', 'ab',
                'empirical', 'llm_baseline', 'classify', 'cpg_reader',
                'emitter', 'env'])

mods = sorted(f[:-3] for f in os.listdir(ROT)
              if f.endswith('.py') and f != '__init__.py'
              and f != '__main__.py')
print('ALL rot/ modules (%d):' % len(mods))
for m in mods:
    tag = 'RESEARCH?' if m in RESEARCH else 'product  '
    print('   %-20s %s' % (m, tag))

# import-edge detector: does module X import a research module?
def research_imports(path):
    hits = []
    try:
        src = io.open(path, encoding='utf-8', errors='replace').read()
    except Exception:
        return hits
    for m in re.finditer(
            r'(?:import\s+(?:rot\.([A-Za-z0-9_]+))'
            r'|from\s+rot\s+import\s+([A-Za-z0-9_,\s\*]+))', src):
        names = []
        if m.group(1):
            names.append(m.group(1))
        else:
            names = [n.strip() for n in m.group(2).split(',') if n.strip()]
        for n in names:
            if n in RESEARCH:
                line = src[:m.start()].count('\n') + 1
                hits.append((line, n))
    return hits

print('\n===== PRODUCT modules (not in RESEARCH) that IMPORT research =====')
found = False
for m in mods:
    if m in RESEARCH:
        continue
    p = os.path.join(ROT, m + '.py')
    h = research_imports(p)
    if h:
        found = True
        print('\n-- rot/%s.py' % m)
        for ln, n in sorted(set(h))[:20]:
            print('     line %4d -> rot.%s' % (ln, n))
if not found:
    print('   (none -- product core is already research-free)')

print('\n===== RESEARCH modules importing OTHER research modules =====')
for m in sorted(RESEARCH):
    p = os.path.join(ROT, m + '.py')
    if not os.path.exists(p):
        continue
    h = research_imports(p)
    if h:
        print('   rot/%-14s -> %s' % (m, ', '.join('rot.' + n
              for _, n in sorted(set(h)))))
