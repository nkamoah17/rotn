import os, re, io

ROOT = r'c:\Users\jeren\Documents\KAMANU\ROTN'
RESEARCH = ['twopc', 'zab', 'pbft', 'payment', 'order_service', 'env',
            'composition', 'zk_bugs', 'ladder', 'approval', 'ab', 'empirical',
            'llm_baseline', 'cpg_reader', 'classify']
pat = re.compile(r'\b(rot|rotn_research)\.(%s)\b' % '|'.join(RESEARCH))
pat2 = re.compile(r'from\s+rot\s+import\s+[^#]*\b(%s)\b' % '|'.join(RESEARCH))


def scan(base, label):
    print('\n===== %s =====' % label)
    found = False
    for dp, dn, fn in os.walk(base):
        dn[:] = [d for d in dn if d not in ('.git', '__pycache__', 'build',
                                            'site-packages', '.venv', 'out')]
        for f in sorted(fn):
            if not f.endswith(('.py', '.md')):
                continue
            p = os.path.join(dp, f)
            try:
                lines = io.open(p, encoding='utf-8',
                                errors='replace').read().splitlines()
            except Exception:
                continue
            hits = [(i + 1, l.strip()) for i, l in enumerate(lines)
                    if (pat.search(l) or pat2.search(l))
                    and ('import' in l or 'rot.' in l
                         or 'rotn_research.' in l)]
            if hits:
                found = True
                print('\n-- %s' % os.path.relpath(p, ROOT))
                for ln, txt in hits[:14]:
                    print('   %4d: %s' % (ln, txt[:105]))
    if not found:
        print('   (no research-module references)')


scan(os.path.join(ROOT, 'rot'), 'PRODUCT rot/')
scan(os.path.join(ROOT, 'tests'), 'PRODUCT tests/')
scan(os.path.join(ROOT, 'rotn-research'), 'RESEARCH rotn-research/')
