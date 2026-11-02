# -*- coding: utf-8 -*-
"""rot.frontends.code -- Code-to-TLA+ extraction (spec §7, D3).

A **narrow-waist** Ingest front-end (WP1): its only job is to read legacy
source and produce ``ProtocolIR`` *candidates* -- one pinned property per
extracted control -- so the Verify plane can PROVE each or hand back the exact
bypass witness.  It never infers intent (E1) and reports anything outside the
declared pattern class as ``OUT_OF_SCOPE`` (E2), never a silent ``UNKNOWN``.

Pattern class **P1** (the first to ship; D3) has two lighthouse shapes:

* **budget**  (lighthouse ``SpendCap``): a spend/charge decision that
  compares a sum to a cap.  *enforced* accounts for in-flight requests
  (``settled + inflight*amount + amount <= cap``); *bypassable* charges
  settled-only (``settled + amount <= cap``) and is bypassable by a
  parallel-fire burst.
* **label_flow** (lighthouse ``NoExfiltration``): an egress decision that
  guards on a data label.  *enforced* lets labeled data reach only the
  allowed channels; *bypassable* lets it go anywhere (an exfiltration).

Honesty rules (locked, spec §7):
* **E1 -- candidate, not intent.** Every extracted control is labeled
  ``candidate`` in the IR metadata; extraction finds what the code *enforces*,
  never what it *meant*.
* **E2 -- pattern-class scope.** Code outside P1 is ``OUT_OF_SCOPE``.
* **E4 -- per-instance.** A claim is scoped to the extracted shape + the
  instantiation bounds, never a universal statement about the codebase.

This module depends only on ``rot.ir`` and the stdlib (the narrow waist).  The
concrete ``ProtocolIR`` (state + actions + the pinned property) is materialized
by :func:`rot.lower.lower_candidate`, which reuses the existing shape-lowering.
Pure stdlib, Python 3.6 compatible (no f-strings, no dataclasses).
"""

import ast

import rot.ir as ir

__all__ = [
    "PATTERN_CLASS",
    "PATTERN_BUDGET",
    "PATTERN_LABEL_FLOW",
    "CANDIDATE_TAG",
    "Candidate",
    "extract",
    "extract_file",
]

#: The declared pattern class this front-end extracts (spec §7, D3).
PATTERN_CLASS = "P1"
#: P1 shape: a budget control (sum <= cap; in-flight vs. settled).
PATTERN_BUDGET = "budget"
#: P1 shape: a label/flow control (labeled data => allowed channels).
PATTERN_LABEL_FLOW = "label_flow"
#: E1: the candidate tag stamped on every extracted control's IR metadata.
CANDIDATE_TAG = "candidate"

# ---------------------------------------------------------------------------
# Name heuristics (honest, E2: a control is only claimed on the precise shape).
# ---------------------------------------------------------------------------
_INFLIGHT_NAMES = ("inflight", "in_flight", "pending", "open", "inprocess",
                   "in_process", "unresolved")
_AMOUNT_NAMES = ("amount", "per_request", "unit", "cost", "value")
_CAP_NAMES = ("cap", "limit", "budget", "ceiling", "max_spend", "quota")
_SETTLED_NAMES = ("settled", "completed", "spent", "used", "consumed")
_LABEL_NAMES = ("private", "secret", "confidential", "label", "flagged",
                "tainted", "sensitive", "holding_private")
_ALLOWED_NAMES = ("allowed", "allowed_channels", "whitelist", "permitted",
                  "approved", "authorized")

# Canonical lighthouse state-variable names (the front-end emits the pinned
# property against these; the lowering materializes state with the same names).
_BUDGET_COMPLETED = "completed"
_BUDGET_INFLIGHT = "inflight"
_LABEL_EXFILTRATED = "exfiltrated"

#: Lighthouse SpendCap fixture defaults (used only when the source does not pin
#: its own ``amount`` / ``cap`` literals).
_DEFAULT_AMOUNT = 100
_DEFAULT_CAP = 200


class Candidate(object):
    """A *ProtocolIR candidate*: one extracted P1 control (spec §7, D3).

    This is the front-end's output -- the control the code *enforces* (E1),
    scoped to one function (E4), with its pinned property.  It is NOT a claim:
    the Verify plane discharges it (E3).  If no P1 control is present, the
    candidate is ``out_of_scope`` (E2) and the Verify plane reports
    ``OUT_OF_SCOPE``.
    """

    def __init__(self, pattern, enforced, params, provenance,
                 pinned_property=None, candidate=True, out_of_scope=False,
                 reason=""):
        self.pattern = pattern                  # "budget" | "label_flow" | None
        self.enforced = bool(enforced)          # enforced (safe) vs. bypassable
        self.params = dict(params or {})        # amount/cap or label/allowed
        self.provenance = dict(provenance or {})
        self.pinned_property = pinned_property  # rot.ir Expr (one per control)
        self.candidate = bool(candidate)        # E1: candidate, not intent
        self.out_of_scope = bool(out_of_scope)  # E2: outside the pattern class
        self.reason = reason                    # why (esp. for out-of-scope)

    @classmethod
    def out_of_scope_candidate(cls, reason, provenance=None, filename=""):
        """E2: an honest out-of-scope candidate (no P1 control detected)."""
        return cls(pattern=None, enforced=False, params={},
                   provenance=dict(provenance or {"filename": filename}),
                   pinned_property=None, candidate=False, out_of_scope=True,
                   reason=reason)

    @property
    def is_control(self):
        """True iff this candidate names a P1 control (not out-of-scope)."""
        return not self.out_of_scope and self.pattern is not None

    def to_dict(self):
        d = {
            "pattern_class": PATTERN_CLASS,
            "pattern": self.pattern,
            "enforced": self.enforced,
            "params": dict(self.params),
            "provenance": dict(self.provenance),
            "candidate": self.candidate,       # E1
            "out_of_scope": self.out_of_scope,  # E2
            "reason": self.reason,
        }
        if self.pinned_property is not None:
            d["pinned_property"] = self.pinned_property.to_dict()
        return d

    def __repr__(self):
        if self.out_of_scope:
            return "Candidate(out_of_scope=%r)" % self.reason
        return "Candidate(pattern=%s, enforced=%s, params=%r)" % (
            self.pattern, self.enforced, self.params)


# ---------------------------------------------------------------------------
# AST helpers (stdlib only).
# ---------------------------------------------------------------------------
def _is_name(node, names):
    return isinstance(node, ast.Name) and node.id in names


def _literal_value(node):
    if isinstance(node, ast.Num):
        return node.n
    if isinstance(node, ast.NameConstant):
        return node.value
    if isinstance(node, ast.Constant):
        return node.value
    return None


def _func_defaults(func):
    """Map function parameter name -> default literal value (if any)."""
    out = {}
    try:
        args = func.args
    except AttributeError:
        return out
    defaults = list(args.defaults)
    for k, v in (args.kw_defaults or {}).items():
        if v is not None:
            defaults.append(v)
    positional = list(getattr(args, "posonlyargs", [])) + list(args.args or [])
    for arg, default in zip(positional[-len(defaults):], defaults):
        val = _literal_value(default)
        if isinstance(val, int):
            out[arg.arg] = val
    return out


def _flatten_sum(node):
    """Split a top-level ``a + b + c`` into its additive terms."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _flatten_sum(node.left) + _flatten_sum(node.right)
    return [node]


def _term_is_inflight(term):
    """True iff ``term`` charges an in-flight quantity: a product
    ``X * amount`` (e.g. ``inflight * amount``) or a bare in-flight counter."""
    if _is_name(term, _INFLIGHT_NAMES):
        return True
    if isinstance(term, ast.BinOp) and isinstance(term.op, ast.Mult):
        for part in (term.left, term.right):
            if _is_name(part, _INFLIGHT_NAMES):
                return True
    return False


def _is_cap_like(node):
    return (_is_name(node, _CAP_NAMES)
            or isinstance(node, (ast.Num, ast.Constant, ast.NameConstant)))


# ---------------------------------------------------------------------------
# P1 detectors -- each returns a small dict, or None (=> OUT_OF_SCOPE, E2).
# ---------------------------------------------------------------------------
def _detect_budget(func):
    """Detect a **budget** control (lighthouse ``SpendCap``).

    Returns ``{enforced, amount, cap}`` on a precise match, else ``None``.
    *enforced* iff the sum charges an in-flight term (parallel-fire safe);
    *bypassable* iff it is settled-only.
    """
    for node in ast.walk(func):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1:
            continue
        op = node.ops[0]
        left, right = node.left, node.comparators[0]
        # Within-cap orientation: ``sum <= cap`` / ``sum < cap`` (left=sum) or
        # ``cap >= sum`` / ``cap > sum`` (right=sum).
        if isinstance(op, (ast.LtE, ast.Lt)):
            sum_node, cap_node = left, right
        elif isinstance(op, (ast.GtE, ast.Gt)):
            sum_node, cap_node = right, left
        else:
            continue
        if not (isinstance(sum_node, ast.BinOp)
                and isinstance(sum_node.op, ast.Add)):
            continue
        if not _is_cap_like(cap_node):
            continue
        terms = _flatten_sum(sum_node)
        enforced = any(_term_is_inflight(t) for t in terms)
        amount, cap = _DEFAULT_AMOUNT, _DEFAULT_CAP
        for t in terms:
            v = _literal_value(t)
            if isinstance(v, int) and v > 0:
                amount = v
        v = _literal_value(cap_node)
        if isinstance(v, int) and v > 0:
            cap = v
        # Prefer explicit source literals over the lighthouse defaults.
        defaults = _func_defaults(func)
        if "amount" in defaults:
            amount = defaults["amount"]
        if "cap" in defaults:
            cap = defaults["cap"]
        return {"enforced": enforced, "amount": amount, "cap": cap}
    return None


def _return_values(func):
    vals = []
    for node in ast.walk(func):
        if isinstance(node, ast.Return) and node.value is not None:
            vals.append(node.value)
    return vals


def _expr_names(node):
    names = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            names.add(n.id)
    return names


def _find_allowed(param_names):
    for p in param_names:
        if p in _ALLOWED_NAMES:
            return p
    return None


def _detect_label_flow(func):
    """Detect a **label/flow** control (lighthouse ``NoExfiltration``).

    *enforced* iff the egress decision references a data label (labeled data
    may reach only the allowed channels); *bypassable* iff it returns an
    unconditional allow (bare ``True``), ignoring the label.  Returns
    ``{enforced, label, allowed}`` on a precise match, else ``None``.
    """
    param_names = [a.arg for a in (func.args.args or [])]
    label = next((p for p in param_names if p in _LABEL_NAMES), None)
    if label is None:
        return None
    returns = _return_values(func)
    if not returns:
        return None
    # Bypassable: every return is a bare, unconditional allow.
    if all(isinstance(r, (ast.NameConstant, ast.Constant))
           and _literal_value(r) is True for r in returns):
        return {"enforced": False, "label": label,
                "allowed": _find_allowed(param_names)}
    # Enforced: the allow decision depends on the label.
    if any(label in _expr_names(r) for r in returns):
        return {"enforced": True, "label": label,
                "allowed": _find_allowed(param_names)}
    return None


# ---------------------------------------------------------------------------
# Pinned-property emission (rot.ir only -- the front-end is a genuine IR
# producer; the lowering reuses these canonical lighthouse names).
# ---------------------------------------------------------------------------
def _budget_pinned_property(amount, cap):
    """``completed + inflight * amount <= cap`` (the parallel-fire guarantee)."""
    return ir.BinOp(
        "<=",
        ir.BinOp("+", ir.V(_BUDGET_COMPLETED),
                 ir.BinOp("*", ir.V(_BUDGET_INFLIGHT), ir.C(amount))),
        ir.C(cap))


def _label_flow_pinned_property():
    """``NOT exfiltrated`` (labeled data never leaves to an unapproved channel)."""
    return ir.Not(ir.V(_LABEL_EXFILTRATED))


def _provenance(func, filename=""):
    return {
        "function": func.name,
        "start_line": getattr(func, "lineno", None),
        "end_line": getattr(func, "end_lineno", None),
        "filename": filename,
        # Phase 0 IR contract: the producer self-identifies in its own
        # provenance (mirrors rot.frontends.cpg), so lower_candidate can stamp
        # the IR's "source" metadata with the real producer.
        "source": "rot.frontends.code",
    }


def _functions(module):
    for node in getattr(module, "body", []):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


# ---------------------------------------------------------------------------
# Public API.
# ---------------------------------------------------------------------------
def extract(source, filename=""):
    """Extract the first P1 control from ``source`` into a :class:`Candidate`.

    * **E1** -- the result is a *candidate* (``candidate=True``), not intent.
    * **E2** -- if no P1 control is present, the candidate is ``out_of_scope``
      (never a silent ``UNKNOWN``, never claimed).
    * **E4** -- the candidate is scoped to the specific function it came from.
    """
    module = ast.parse(source)
    for func in _functions(module):
        budget = _detect_budget(func)
        if budget is not None:
            return Candidate(
                pattern=PATTERN_BUDGET,
                enforced=budget["enforced"],
                params={"amount": budget["amount"], "cap": budget["cap"]},
                provenance=_provenance(func, filename),
                pinned_property=_budget_pinned_property(
                    budget["amount"], budget["cap"]),
                candidate=True, out_of_scope=False,
                reason="budget control (lighthouse SpendCap)")
        label = _detect_label_flow(func)
        if label is not None:
            return Candidate(
                pattern=PATTERN_LABEL_FLOW,
                enforced=label["enforced"],
                params={"label": label["label"], "allowed": label["allowed"]},
                provenance=_provenance(func, filename),
                pinned_property=_label_flow_pinned_property(),
                candidate=True, out_of_scope=False,
                reason="label/flow control (lighthouse NoExfiltration)")
    # E2: no P1 control anywhere in the source -> honest OUT_OF_SCOPE.
    return Candidate.out_of_scope_candidate(
        "no P1 control (budget / label-flow) detected in %s"
        % (filename or "<source>"),
        provenance={"filename": filename})


def extract_file(path):
    """Read ``path`` and :func:`extract` it."""
    with open(path, "r") as fh:
        return extract(fh.read(), filename=path)