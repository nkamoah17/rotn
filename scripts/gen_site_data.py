# -*- coding: utf-8 -*-
"""gen_site_data.py -- CLI wrapper for the site registry generator.

The registry-generation logic lives in :mod:`rot.sitegen` (part of the
installed ``rot`` package, so ``rot site`` can use it from a
``pip install .`` environment where ``scripts/`` is not on the import path).
This script is the standalone entry point for regenerating the committed
registry by hand:

    python scripts/gen_site_data.py [SITE_DIR]     # default: <repo>/site

The generated ``data/traces.js`` is byte-identical to what ``rot site``
produces (single source of truth in :mod:`rot.sitegen`).
"""

from __future__ import print_function

import os
import sys

# When run standalone (`python scripts/gen_site_data.py`), only scripts/ is
# sys.path[0] -- not the repo root -- so make the repo root importable first.
# This lets `rot` (and thus rot.sitegen) resolve from the source tree.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from rot.sitegen import generate, generate_data  # noqa: E402,F401  (re-export)

__all__ = ["generate", "generate_data"]


def _repo_root():
    """Absolute path of the repository root (parent of scripts/)."""
    return _REPO_ROOT


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    site_dir = argv[0] if argv else os.path.join(_repo_root(), "site")
    out_path, ids = generate(site_dir)
    print("  registry  : %s" % out_path)
    print("  traces    : %s" % (", ".join(ids) if ids else "(none)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())

