# -*- coding: utf-8 -*-
"""spendcap_display.py -- make the policy -> model abstraction explicit and auditable.

The spend-cap demo's honest claim is that ROTN *discriminates* a documented
anti-pattern (the response-sum vs request-sum spend cap) through a distilled,
bounded transition system that three independent engines (Z3, TLC, and
policy-direct) check.
For that to be credible, the audience must see *exactly* which policy was parsed,
*exactly* which bounded model was built from it, and *exactly* what the model
assumes that the raw policy does not say.

This module renders that block. It imports the real front-end (rot.dw) and the
real model builder (rot.spendcap), so the text it prints is the same text the
engines verify -- a single source of truth, with no drift.  Pure stdlib,
Python 3.6-compatible, and deterministic (no engine, no network).

Invoked by demo.ps1 / demo.sh before the checking phases:

    python -m rot.spendcap_display <policy.dw> --max-inflight 3
"""

from __future__ import print_function

import argparse

from rot import invariants
from rot import spendcap
from rot.design_view import domain_to_str, expr_to_str
from rot.dw import parse_file

__all__ = ["render", "main"]

INVARIANT_NAME = "spendcap_within_cap"
_BAR = "=" * 74


def _raw_text(path):
    with open(path, "r") as f:
        return f.read().rstrip("\n")


def render(policy_path, max_inflight=None):
    """Render the policy -> model abstraction block for one spend-cap .dw policy."""
    policy = parse_file(policy_path)
    ir = policy.to_ir(max_inflight=max_inflight)
    inv = invariants.get(INVARIANT_NAME)
    md = ir.metadata

    print(_BAR)
    print("POLICY -> MODEL ABSTRACTION")
    print("policy file : %s" % policy_path)
    print(_BAR)
    print("[1] RAW POLICY TEXT  (what a human wrote in Dogwood)")
    for line in _raw_text(policy_path).splitlines():
        print("      " + line)
    print("[2] PARSED SEMANTIC FINGERPRINT  (what the .dw front-end extracted)")
    print("      id=%r  action=%r  event_kind=%r  cap=%d  window=%r"
          % (policy.policy_id, policy.action, policy.event_kind,
             policy.cap, policy.window))
    print("      -> selects model variant : %s"
          % ("BUGGY (response-sum)" if policy.is_buggy else "CORRECT (request-sum)"))
    print("[3] BOUNDED IR MODEL  (what ROTN actually checks -- one source of truth)")
    for v in ir.variables:
        print("      %-10s : %-12s   %s" % (v.name, domain_to_str(v.domain), v.desc))
    print("      spend_ok.guard   : %s" % expr_to_str(ir.action("spend_ok").guard))
    print("      spend_deny.guard : %s" % expr_to_str(ir.action("spend_deny").guard))
    print("      invariant %-19s: %s" % (inv.name, expr_to_str(inv.expression)))
    print("[4] EXPLICIT ASSUMPTIONS  (modelled, but NOT written in the policy)")
    print("      uniform amount : AMOUNT = %d  (every request is the same size)"
          % md.get("amount", spendcap.AMOUNT))
    print("      spend cap      : CAP    = %d  (the policy limit)"
          % md.get("cap", spendcap.CAP))
    print("      bounded pool   : K      = %d  (max concurrent in-flight requests)"
          % md.get("max_inflight", spendcap.MAX_INFLIGHT))
    print("      single service : n      = 1  (one decision plane)")
    print("[5] CORRESPONDENCE ARGUMENT  (policy obligation -> invariant)")
    print("      policy clause : %s" % inv.policy_clause)
    print("      obligation    : in-flight (issued, unsettled) requests count against the cap")
    print("      modelled as   : spend_ok admits a request only if the cap still fits it")
    if policy.is_buggy:
        print("      THIS VARIANT  : guard charges 'completed' only -> in-flight is invisible -> VIOLATED")
    else:
        print("      THIS VARIANT  : guard charges 'completed + inflight*AMOUNT' -> in-flight counts -> PROVEN")
    print(_BAR)
    print("")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Render the spend-cap policy -> model abstraction block.")
    parser.add_argument("policy", help="path to a spend-cap .dw policy")
    parser.add_argument("--max-inflight", type=int, default=None,
                        help="K = bounded in-flight pool (default: rot.spendcap.MAX_INFLIGHT)")
    args = parser.parse_args(argv)
    render(args.policy, max_inflight=args.max_inflight)


if __name__ == "__main__":
    main()
