import os, ast, io

ROOT = r'c:\Users\jeren\Documents\KAMANU\ROTN'
RESEARCH = {'twopc', 'zab', 'pbft', 'payment', 'order_service', 'composition',
            'zk_bugs', 'ladder', 'approval', 'ab', 'empirical', 'llm_baseline',
            'classify', 'cpg_reader', 'env'}


def imported_research(path):
    """Return the set of research module names actually imported (ast-based)."""
    hits = set()
    try:
        tree = ast.parse(io.open(path, encoding='utf-8',
                                 errors='replace').read())
    except Exception as e:
        return {'<PARSE_ERROR:%s>' % type(e).__name__}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                # rot.twopc / rot.env / rotn_research.x
                parts = a.name.split('.')
                if len(parts) >= 2 and parts[0] == 'rot' and parts[1] in RESEARCH:
                    hits.add('rot.' + parts[1])
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ''
            parts = mod.split('.')
            if parts and parts[0] == 'rot':
                if len(parts) >= 2 and parts[1] in RESEARCH:
                    hits.add('rot.' + parts[1])
                for a in node.names:
                    if a.name in RESEARCH:
                        hits.add('rot.' + a.name)
    return hits


def scan_dir(base, label, only_real=True):
    print('\n===== %s =====' % label)
    anyhit = False
    for f in sorted(os.listdir(base)):
        if not f.endswith('.py') or f in ('conftest.py', '__init__.py'):
            continue
        p = os.path.join(base, f)
        h = imported_research(p)
        if h:
            anyhit = True
            print('   %-34s -> %s' % (f, ', '.join(sorted(h))))
    if not anyhit:
        print('   (none)')


scan_dir(os.path.join(ROOT, 'tests'), 'PRODUCT tests/ importing research')
scan_dir(os.path.join(ROOT, 'rot'), 'PRODUCT rot/ modules importing research')
scan_dir(os.path.join(ROOT, 'rotn-research', 'rotn_research'),
         'RESEARCH pkg: files importing rot.<research> (need rewrite to rotn_research)')
scan_dir(os.path.join(ROOT, 'rotn-research', 'tests'),
         'RESEARCH tests importing rot.<research> (need rewrite)')
