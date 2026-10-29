# -*- coding: utf-8 -*-
"""aggregate.py -- ``rot coach --aggregate`` (B5): coach the *rules* from the ledger.

The offline coach (``rot.coach``) coaches a *policy* back in bounds, with a
proof.  The runtime coach (this module) does the dual job on the *live*
record: given the decision ledger the adapters appended, it surfaces

  1. **which prompts / tool-descriptions cause blocks** -- the blocked
     decisions grouped by tool (``blocked_by.by_tool``);
  2. **which rules block legitimate work** -- the blocked decisions grouped
     by rule, each with its ``why`` / ``to_proceed`` (``legitimate_work``)
     and the top blockers (``top_blockers``); and
  3. **a re-proof that any relaxation stays safe** -- the ``relaxation``
     section: the "admit the blocked calls" relaxation is re-proved (or
     refuted) with the *same* bounded-exhaustive engine the offline proof
     used -- no new engine -- and is **fail-closed** (an unverifiable
     relaxation is never read as safe).

The relaxation re-proof
-----------------------

A *relaxation* of a runtime rule admits the calls the rule blocked.  That is
safe iff admitting those calls cannot leave the pinned property unsatisfied.
The check has two halves, both over the ``ProtocolIR`` (the spec):

  * **the recorded breaches** -- for each distinct state at which the rule
    blocked, apply the decision action's *effects* (what the admitted call
    would do) and require the pinned property to hold in the resulting state;
  * **the whole space** -- require that every reachable state the guard
    admits satisfies the pinned property (guard-implies-property).

If either half fails, the report carries the violating state as the
``witness`` (``status: "unsafe"``) -- the relaxation must not be made.  If
both hold within the bound, ``status: "safe"`` with the bound recorded.
Without a rule (or with an un-evaluable effect) the relaxation is
``"unverified"`` -- fail-closed, mirroring the coaching loop's rule that only
a *re-proven* correction closes.

The result is a deterministic, hashable artifact (``caravel.aggregate/v1``)
-- the same discipline as the RTF trace and the coaching artifact -- and
maps the live "Overly Restrictive" evidence to the SOC 2 / AIUC controls via
:mod:`rot.compliance`.

Pure stdlib, Python 3.6 compatible (no f-strings).
"""

from __future__ import print_function

import rot
import rot.compliance as compliance
from .refusal import Refusal, canonical_json, refusal_hash
from .core import Decision
from . import ledger as _ledger

__all__ = [
    "SCHEMA",
    "SAFE",
    "UNSAFE",
    "UNVERIFIED",
    "NOT_APPLICABLE",
    "AggregateResult",
    "aggregate_ledger",
]

#: The aggregate artifact schema tag (stable; bump on shape changes).
SCHEMA = "caravel.aggregate/v1"

#: Relaxation re-proof statuses (stable; fail-closed).
SAFE = "safe"            # both halves re-proved within the bound.
UNSAFE = "unsafe"        # a witness state violates the pinned property.
UNVERIFIED = "unverified"  # could not be re-proven (never read as safe).
NOT_APPLICABLE = "not_applicable"  # nothing was blocked; nothing to relax.


class AggregateResult(object):
    """A deterministic, hashable ``caravel.aggregate/v1`` artifact.

    The body is the full aggregate report (ledger stats, blocked_by,
    legitimate_work, top_blockers, relaxation, compliance); the top-level
    ``hash`` pins the exact report, so it can be referenced, compared, and
    re-verified byte-for-byte -- the same contract as the RTF trace.
    """

    def __init__(self, body):
        self.body = body
        self.hash = refusal_hash(body)

    def to_dict(self):
        """The report body plus the top-level ``hash``."""
        d = dict(self.body)
        d["hash"] = self.hash
        return d

    def to_json(self, indent=2):
        """Deterministic JSON (sorted keys, stable separators)."""
        return canonical_json(self.to_dict(), indent=indent)

    def __repr__(self):
        return "AggregateResult(blocks=%d, relaxation=%r, hash=%s...)" % (
            self.body["ledger"]["blocked"],
            self.body["relaxation"]["status"], self.hash[:12])


def _refusal_of(entry):
    """The refusal dict of a ledger entry (or a raw dict entry)."""
    refusal = getattr(entry, "refusal", entry)
    if isinstance(refusal, Decision):
        refusal = refusal.refusal
    if isinstance(refusal, Refusal):
        return refusal.to_dict()
    if isinstance(refusal, dict):
        return refusal
    raise ValueError(
        "an aggregate entry must carry a refusal (got %r)"
        % type(entry).__name__)


def _context_of(entry):
    """The context dict of a ledger entry (``{}`` for raw dicts)."""
    context = getattr(entry, "context", None)
    return context if isinstance(context, dict) else {}


def _tool_of(entry, refusal):
    """The tool name a decision was about (context first, then the refusal)."""
    context = _context_of(entry)
    for key in ("tool", "name", "action"):
        v = context.get(key)
        if isinstance(v, str) and v:
            return v
    action = refusal.get("action")
    if isinstance(action, str) and action:
        return action
    return "<unknown>"


def _apply_effects(action, state):
    """The state after ``action``'s effects, applied to ``state``.

    The effect expressions are evaluated on the pre-state (simultaneous
    assignment, the TLA semantics the linearizer uses).  Returns ``None``
    when an effect is undefined (``UNDEF``) -- the caller then cannot
    re-prove that step (fail-closed).
    """
    import rot.ir as ir

    updates = {}
    for effect in action.effects:
        value = effect.expr.eval(state)
        if value is ir.Expr.UNDEF:
            return None
        updates[effect.var] = value
    out = dict(state)
    out.update(updates)
    return out


def _reachable_states(ir, max_states):
    """The reachable concrete states (deterministic order), bounded.

    Reuses :func:`rot.trace._reachable_states` (the RTF's own state-space
    enumeration) -- the same bounded-exhaustive engine, no new engine.
    """
    from rot.trace import _reachable_states as _states
    return _states(ir, max_states=max_states)


def _compliance(n_blocked, n_total):
    """Map the live "Overly Restrictive" evidence to SOC 2 / AIUC controls."""
    return {
        "profile": compliance.COMPLIANCE_PROFILE,
        "frameworks": list(compliance.FRAMEWORKS),
        "finding": "Overly Restrictive",
        "controls": compliance.controls_for("Overly Restrictive"),
        "evidence": {
            "blocked_decisions": n_blocked,
            "total_decisions": n_total,
        },
        "note": "runtime blocks are the 'Overly Restrictive' finding "
                "observed live: the policy denied work the agent "
                "(legitimately) proposed",
    }


def _relaxation(blocked, rule, state_space, max_states):
    """The "admit the blocked calls" relaxation, re-proved (or refuted).

    See the module docstring for the two halves of the check.  Returns the
    deterministic ``relaxation`` section of the report.  Fail-closed: without
    a rule -- or with an un-evaluable effect -- the relaxation is
    :data:`UNVERIFIED`, never read as safe.
    """
    if not blocked:
        return {
            "status": NOT_APPLICABLE,
            "safe": True,
            "rule": None,
            "witness": None,
            "bound": None,
            "explanation": "no blocked decisions in the ledger: there is "
                           "nothing to relax",
        }
    if rule is None:
        return {
            "status": UNVERIFIED,
            "safe": False,
            "rule": None,
            "witness": None,
            "bound": None,
            "explanation": "no rule supplied: a relaxation cannot be "
                           "re-proven without the guard it relaxes "
                           "(fail-closed)",
        }

    ir = rule.ir
    action = ir.action(rule.action)
    guard = rule.guard()
    prop = ir.pinned_property

    # Half 1: the recorded breaches.  Admit the blocked call at each distinct
    # recorded blocked state (apply the decision action's effects) and require
    # the pinned property to hold in the resulting state.
    seen = set()
    unverified = None
    for entry in blocked:
        state = _refusal_of(entry).get("state") or {}
        key = tuple(sorted((k, repr(v)) for k, v in state.items()))
        if key in seen:
            continue
        seen.add(key)
        if action is None or not action.effects:
            continue  # a no-op admission cannot break the property
        after = _apply_effects(action, state)
        if after is None:
            unverified = dict(state)
            continue
        if prop.eval(after) is not True:
            return {
                "status": UNSAFE,
                "safe": False,
                "rule": rule.rule_id,
                "witness": after,
                "bound": None,
                "n_states_checked": 1,
                "explanation": "admitting the blocked call at %r leaves the "
                               "state %r, where the pinned property fails: "
                               "the relaxation is UNSAFE" % (state, after),
            }

    # Half 2: the whole space.  Every reachable state the guard admits must
    # satisfy the pinned property (guard-implies-property), checked with the
    # same bounded-exhaustive engine the offline proof used.
    states = []
    seen_states = set()
    for state in (state_space if state_space is not None
                  else _reachable_states(ir, max_states)):
        key = tuple(sorted((k, repr(v)) for k, v in state.items()))
        if key not in seen_states:
            seen_states.add(key)
            states.append(dict(state))
    n_checked = 0
    for state in states:
        n_checked += 1
        if guard.eval(state) is True and prop.eval(state) is False:
            return {
                "status": UNSAFE,
                "safe": False,
                "rule": rule.rule_id,
                "witness": dict(state),
                "bound": n_checked,
                "n_states_checked": n_checked,
                "explanation": "the guard admits %r, where the pinned "
                               "property fails: the relaxation is UNSAFE"
                               % (state,),
            }

    if unverified is not None:
        return {
            "status": UNVERIFIED,
            "safe": False,
            "rule": rule.rule_id,
            "witness": unverified,
            "bound": n_checked,
            "n_states_checked": n_checked,
            "explanation": "the blocked call at %r has an un-evaluable "
                           "effect: the relaxation could not be re-proven "
                           "(fail-closed)" % (unverified,),
        }
    return {
        "status": SAFE,
        "safe": True,
        "rule": rule.rule_id,
        "witness": None,
        "bound": n_checked,
        "n_states_checked": n_checked,
        "explanation": "admitting every recorded blocked call (and every "
                       "state the guard admits) satisfies the pinned "
                       "property within the bound (%d states): the "
                       "relaxation is SAFE" % n_checked,
    }


def aggregate_ledger(ledger, rule=None, state_space=None, max_states=100000):
    """Aggregate a decision ledger into the ``caravel.aggregate/v1`` report.

    This is the body of ``rot coach --aggregate``: it answers (1) which
    prompts / tool-descriptions cause blocks, (2) which rules block
    legitimate work, and (3) re-proves (or refutes) that admitting the
    blocked calls -- any relaxation -- stays safe.

    Parameters
    ----------
    ledger : DecisionLedger | list
        The decisions to aggregate.  A
        :class:`~rot.runtime.ledger.DecisionLedger` is verified (its hash
        chain) before aggregation; a plain list of entries / dicts skips the
        chain check.
    rule : rot.runtime.core.Rule, optional
        The rule whose relaxation is re-proved (e.g.
        ``rot.runtime.rules.get_rule("spendcap_within_cap")``).  Without it
        the relaxation is :data:`UNVERIFIED` (fail-closed).
    state_space : list of dict, optional
        The states to check the relaxation over (defaults to the rule IR's
        reachable state space, bounded by ``max_states``).
    max_states : int, optional
        The state budget for the relaxation re-proof (default 100000).

    Returns
    -------
    AggregateResult
        The deterministic, hashable aggregate report.
    """
    entries = list(ledger) if ledger is not None else []
    if isinstance(ledger, _ledger.DecisionLedger):
        ledger.verify()  # tamper-evident: refuse to aggregate a broken chain
    total = len(entries)
    refusals = [_refusal_of(e) for e in entries]
    blocked_idx = [i for i, r in enumerate(refusals) if r.get("blocked") is True]
    n_blocked = len(blocked_idx)
    n_allowed = total - n_blocked

    # (2) which rules block legitimate work (per-rule blocked/allowed).
    by_rule = {}
    for r in refusals:
        rid = r.get("rule") or "<unknown>"
        slot = by_rule.setdefault(rid, {"blocked": 0, "allowed": 0})
        if r.get("blocked") is True:
            slot["blocked"] += 1
        else:
            slot["allowed"] += 1
    by_rule_out = {}
    for rid in sorted(by_rule):
        slot = by_rule[rid]
        by_rule_out[rid] = {
            "blocked": slot["blocked"],
            "allowed": slot["allowed"],
            "total": slot["blocked"] + slot["allowed"],
        }

    # (1) which prompts / tool-descriptions cause blocks.
    by_tool = {}
    for i in blocked_idx:
        tool = _tool_of(entries[i], refusals[i])
        by_tool[tool] = by_tool.get(tool, 0) + 1

    # (2) the blocked decisions themselves (the legitimate work denied).
    legitimate_work = []
    for i in blocked_idx:
        entry = entries[i]
        context = _context_of(entry)
        r = refusals[i]
        item = {
            "seq": getattr(entry, "seq", i),
            "tool": _tool_of(entry, r),
            "rule": r.get("rule"),
            "why": r.get("why"),
            "to_proceed": r.get("to_proceed"),
            "state": r.get("state"),
        }
        if context.get("prompt"):
            item["prompt"] = context["prompt"]
        if context.get("args"):
            item["args"] = context["args"]
        legitimate_work.append(item)

    top_blockers = sorted(
        [{"rule": rid, "count": slot["blocked"]}
         for rid, slot in by_rule.items() if slot["blocked"]],
        key=lambda x: (-x["count"], x["rule"]))[:5]

    # (3) the re-proof that any relaxation stays safe (fail-closed).
    blocked_entries = [entries[i] for i in blocked_idx]
    relaxation = _relaxation(blocked_entries, rule, state_space, max_states)

    body = {
        "schema": SCHEMA,
        "rot_version": rot.__version__,
        "ledger": {
            "entries": total,
            "allowed": n_allowed,
            "blocked": n_blocked,
            "block_share": (round(float(n_blocked) / total, 4)
                            if total else None),
            "last_entry_hash": (ledger.last_entry_hash()
                                if isinstance(ledger, _ledger.DecisionLedger)
                                else None),
        },
        "blocked_by": {
            "by_rule": by_rule_out,
            "by_tool": dict(sorted(by_tool.items())),
        },
        "legitimate_work": legitimate_work,
        "top_blockers": top_blockers,
        "relaxation": relaxation,
        "compliance": _compliance(n_blocked, total),
    }
    return AggregateResult(body)