# -*- coding: utf-8 -*-
"""pytest path setup for the research repo.

The research package (``rotn_research``) lives in this repo; the product
package (``rot``) lives in the parent directory.  Both must be importable so
that the research tests can use the shared product registry (``rot.invariants``,
``rot.targets``) alongside the research modules (``rotn_research.*``).
"""
import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))          # .../rotn-research
_product_root = os.path.dirname(_here)                       # .../ROTN (product)
for _p in (_here, _product_root):
    if _p not in sys.path:
        sys.path.insert(0, _p)
