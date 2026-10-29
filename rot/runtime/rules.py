# -*- coding: utf-8 -*-
"""rot.runtime.rules -- the concrete runtime rules (the "genuinely reusable" rules).

A :class:`~rot.runtime.core.Rule` is the *meaning* the :class:`RuntimeGuard`
applies the *mechanism* to: a ``ProtocolIR`` decision action plus the canonical
``why`` / ``to_proceed`` strings for that shape.  This module defines the
concrete rules.  The **spend-cap rule** is the canonical example and shows the
rule is *genuinely reusable*: it is the *same predicate* the offline proof
discharged (``completed + inflight * AMOUNT + AMOUNT <= CAP``), now applied
live on each transfer.

The spend-cap rule
------------------

Before admitting a transfer, the guard computes ``(completed, inflight)`` from
the request history and evaluates the ``spend_ok`` guard predicate.  On a
breach the refusal is exactly::

    {
      "blocked":    true,
      "rule":       "spendcap_within_cap",
      "why":        "3 in-flight requests are invisible to the settled-trace monitor",
      "to_proceed": "complete 1 in-flight (or cap inflight at 1)",
      "allowed_now": false
    }

``why`` is canonical for the shape and names the *state-dependent* quantity
(the in-flight count, read from the state) -- the in-flight set is exactly what
the settled-trace (the offline monitor) does not see, which is the root cause
of the parallel-fire race.  ``to_proceed`` is the remediation.  The *decision*
itself is the guard predicate -- the core decides; the rule only supplies the
human-facing strings, so the core stays shape-agnostic.

The exfiltration rule
---------------------

The :class:`~rot.agent_harness` NoExfiltration shape, built the same way: the
decision action is ``agent_take_send_unapproved``, blocked when the agent is
holding private data.  ``why`` / ``to_proceed`` are the canonical strings for
that shape.

Both rules are built from the *existing* ``ProtocolIR`` builders
(:mod:`rot.spendcap`, :mod:`rot.agent_harness`) -- no new IR, no new engine.
Pure stdlib, Python 3.6 compatible (no f-strings).
"""

from __future__ import print_function

from .core import Rule

__all__ = [
    "RULES",
    "spendcap_rule",
    "exfiltration_rule",
    "get_rule",
]


def _int_state(state, key, default=0):
    """Read an integer from ``state`` (tolerating ``None`` / non-ints)."""
    v = (state or {}).get(key, default)
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def spendcap_rule(max_inflight=4, amount=100, cap=200):
    """The spend-cap runtime rule (the canonical, "genuinely reusable" rule).

    Builds the rule from the **correct** spend-cap ``ProtocolIR`` (the
    ``spend_ok`` guard charges in-flight requests against the cap -- the
    predicate the offline proof discharged), and attaches the canonical
    ``why`` / ``to_proceed`` strings.

    Parameters mirror :func:`rot.spendcap.build_ir` so the rule's predicate is
    identical to the proven one: ``amount`` / ``cap`` are the per-request
    amount and spend cap, ``max_inflight`` (``K``) the request-pool bound.

    Returns
    -------
    rot.runtime.core.Rule
        A rule whose guard is ``completed + inflight * amount + amount <= cap
        and inflight < K`` (the ``spend_ok`` guard), ``why`` names the
        in-flight count, and ``to_proceed`` is the remediation.
    """
    import rot.spendcap as _sp

    ir = _sp.build_ir(buggy=False, max_inflight=max_inflight,
                      amount=amount, cap=cap)

    def _why(state):
        # The in-flight set is what the settled-trace monitor cannot see --
        # the root cause of the parallel-fire race.  Name the count from the
        # state so the refusal is specific to the breach it is refusing.
        inflight = _int_state(state, "inflight")
        return ("%d in-flight requests are invisible to the settled-trace "
                "monitor" % inflight)

    return Rule(
        ir=ir,
        action="spend_ok",
        rule_id="spendcap_within_cap",
        why=_why,
        to_proceed="complete 1 in-flight (or cap inflight at 1)",
        description="spend-cap: settled + in-flight amount never exceeds the "
                    "cap (completed + inflight * AMOUNT + AMOUNT <= CAP)",
    )


def exfiltration_rule():
    """The NoExfiltration runtime rule (the exfiltration shape).

    Builds the rule from the **correct** agent-harness IR (the
    ``agent_take_send_unapproved`` guard is ``not holding_private``), and
    attaches the canonical ``why`` / ``to_proceed`` strings.
    """
    import rot.agent_harness as _ah

    ir = _ah.exfiltrate_build_ir(buggy=False)
    return Rule(
        ir=ir,
        action="agent_take_send_unapproved",
        rule_id="no_exfiltration",
        why="the agent is holding private data it must not send",
        to_proceed="stop holding the private data (drop or release it) before "
                   "the send",
        description="NoExfiltration: the agent must not send unapproved data "
                    "while holding private data",
    )


#: The registry of concrete rules, by rule id (the "genuinely reusable" rules).
#: ``get_rule`` returns a rule from this registry; ``spendcap_rule`` /
#: ``exfiltration_rule`` are the canonical, parameterized builders.
RULES = {
    "spendcap_within_cap": "spendcap",
    "no_exfiltration": "exfiltration",
}


def get_rule(name, **kwargs):
    """Look up a concrete rule by id (e.g. ``"spendcap_within_cap"``).

    ``kwargs`` are threaded to the rule builder (e.g. ``amount`` / ``cap`` /
    ``max_inflight`` for the spend-cap rule).  Unknown names raise
    ``KeyError``.
    """
    shape = RULES.get(name)
    if shape == "spendcap":
        return spendcap_rule(**kwargs)
    if shape == "exfiltration":
        return exfiltration_rule()
    raise KeyError("unknown rule %r (known: %s)"
                   % (name, ", ".join(sorted(RULES))))
