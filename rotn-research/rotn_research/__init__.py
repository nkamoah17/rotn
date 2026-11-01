# -*- coding: utf-8 -*-
"""rotn_research: the ROTN research plane (ZAB/PBFT/2PC/payment/approval
research, CPG-4, A/B frontends, ladders, empirical baselines).

This package DEPENDS on the product (``pip install rotn``); it is never
imported by the product.  Importing it registers its research invariants
and targets into the shared ``rot.invariants`` / ``rot.targets``
registries (via ``register``), so research targets resolve the same way
they did before the split.
"""
from rotn_research import invariants  # noqa: F401  (registers invariants)
from rotn_research import targets    # noqa: F401  (registers targets)

__all__ = ["invariants", "targets"]
