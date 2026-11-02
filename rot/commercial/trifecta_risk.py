# -*- coding: utf-8 -*-
"""trifecta_risk.py -- the D6 "Lethal Trifecta" risk flag + checkable property.

This module has two layers, deliberately distinct:

1. **Design-time heuristic** (:func:`detect`, :class:`TrifectaRisk`) -- a
   *static* check over the policy's **action set** (``allowed ∪ denied``).
   It inspects only action *names* for the three lethal facets and makes NO
   soundness claim. It is a *fast pre-filter*: it tells you *whether* the
   lethal combination is exposed, so you know *when* to run the real check.

2. **Checkable property** (:func:`checkable_property`,
   :class:`ExfiltrationCheck`) -- the G3 upgrade. When the heuristic fires
   (all three facets present), the *egress* facet is the one that must be
   policy-enforced. This layer runs a **real bounded model check** over the
   :mod:`rot.agent_harness` exfiltration IR (labels + channels on the state)
   for the *policy-named* egress action and proves or refutes
   ``NoExfiltration`` (private data never reaches the unapproved channel).
   The heuristic is the applicability pre-filter; the model check is the
   soundness claim.

The "Lethal Trifecta" (a.k.a. the "Lethal Triad") is the canonical
agentic-AI risk combination: an agent that can simultaneously

1. **private-data-access** -- read / access private or sensitive data, and
2. **untrusted-content-intake** -- ingest content from outside the trust
   boundary (a prompt-injection surface), and
3. **egress** -- send data out to an external destination

is the maximally dangerous shape: it can be steered by untrusted content into
reading private data and exfiltrating it.  The flag fires (``detected``) when
the policy's action set *contains* actions covering **all three** facets;
otherwise it is ``clear``.

Why the *full* action set (``allowed ∪ denied``)?  The flag is a *capability
surface* check, not an "is it permitted?" check.  A capability that is merely
*denied* is still a capability the agent's action space exposes -- it is one
policy-enforcement step (or one compromised guard) from being exercised.  So a
policy that lists ``exfiltrate_secret`` in ``denied`` still counts as exposing
the **egress** facet.  This is exactly what makes the spend-cap vertical slice
a good demo: its default policy already names ``exfiltrate_secret``.

Soundness / determinism contract
--------------------------------
* **Heuristic: no engine, no state space.**  :func:`detect` is a pure
  function of the policy's action names; it never touches
  :mod:`rot.modelfind` / :mod:`rot.symbolic`.  It is a *design-time
  heuristic flag*, not a proof.
* **Checkable property: bounded model check.**  :func:`checkable_property`
  builds the exfiltration IR for the policy-named egress action and runs the
  bounded exhaustive model finder over it.  A ``proven`` verdict is a genuine
  proof over the bounded model (the harness denies the egress while private
  data is held, so the exfiltration is unreachable); a ``violated`` verdict is
  a genuine counterexample (the harness admits the egress while private data
  is held, so the exfiltration is reachable) with the attack path as witness.
* **Deterministic.**  The same policy always yields the same flag, the same
  facet witnesses, and the same message.  Facets and their witness actions
  are reported in a stable (sorted / canonical) order.  The checkable
  property is deterministic over the bounded state space.
* **Over-flagging is preferred to under-flagging.**  The taxonomy is a
  deliberately broad set of name indicators; a facet is present if *any*
  action in the set indicates it.  A ``clear`` verdict means "we did not see
  all three capability facets in the action names", not "the agent is safe".

Pure stdlib, Python 3.6 compatible.
"""

__all__ = [
    "FACETS",
    "FACET_INDICATORS",
    "TrifectaRisk",
    "classify_action",
    "detect",
    "ExfiltrationCheck",
    "checkable_property",
]

# The three lethal facets, in canonical (stable, report) order.  These names
# are the stable contract for the emitted message and for reports.
FACETS = (
    "private-data-access",
    "untrusted-content-intake",
    "egress",
)

# Per-facet name indicators.  An action (lower-cased) indicates a facet when
# any of the facet's indicator tokens occurs as a substring of the action
# name.  The sets are intentionally broad (over-flag > under-flag) but avoid
# single generic verbs (e.g. bare "read"/"send") that would make almost every
# action hit every facet.  Tokens are matched case-insensitively.
FACET_INDICATORS = {
    # 1. private-data-access: reading / touching private or sensitive data.
    "private-data-access": (
        "secret", "credential", "passwd", "password", "token",
        "api_key", "secret_key", "pii", "ledger", "balance", "account",
        "record", "customer", "profile", "history", "statement", "invoice",
        "read_private", "read_secret", "read_ledger", "read_account",
        "read_record", "read_log", "read_logs", "read_credential",
        "read_password", "read_token", "read_pii",
        "get_private", "get_secret", "get_credential", "get_password",
        "get_token", "get_ledger", "get_account", "get_record",
        "get_balance", "get_profile", "get_history", "get_pii",
        "access_private", "access_secret", "access_credential",
        "access_record", "access_account",
        "view_private", "view_secret", "view_credential", "view_record",
        "view_account", "view_profile",
        "query_record", "query_account", "query_ledger",
        "fetch_private", "fetch_secret", "fetch_credential",
        "fetch_ledger", "fetch_account", "fetch_record",
        "dump_private", "dump_secret", "dump_record",
    ),
    # 2. untrusted-content-intake: ingesting content from outside the trust
    #    boundary (the prompt-injection surface).
    "untrusted-content-intake": (
        "fetch_external", "fetch_web", "fetch_url", "fetch_remote",
        "fetch_inbound", "fetch_untrusted",
        "get_external", "get_web", "get_url", "get_remote",
        "get_inbound", "get_untrusted",
        "ingest", "parse", "scrape", "crawl", "download_external",
        "download_untrusted",
        "email_in", "read_email", "read_inbox", "read_message",
        "read_comment", "read_inbound", "read_untrusted",
        "process_inbound", "process_message", "process_email",
        "process_comment", "process_payload", "process_request_body",
        "handle_inbound", "handle_message", "handle_email",
        "receive_message", "receive_email", "receive_inbound",
        "untrusted", "inbound", "external_quote", "external_rate",
        "external_feed", "web_page", "web_content", "web_input",
        "rss_feed", "api_inbound",
    ),
    # 3. egress: sending / publishing data out to an external destination.
    "egress": (
        "exfiltrate", "egress", "outbound",
        "send", "post_external", "post_webhook", "post_remote",
        "push", "push_external", "push_remote",
        "emit", "transmit", "export", "publish",
        "upload", "upload_external", "upload_remote",
        "forward", "dispatch", "webhook", "notify", "stream_out",
        "write_external", "write_remote", "put_external", "put_remote",
        "send_to", "send_email", "send_webhook", "send_external",
        "send_remote", "send_funds", "send_payment",
        "share_external", "share_out",
    ),
}

# The exact emitted strings (the D6 contract).
_DETECTED_TEMPLATE = "TRIFECTA: detected (facets: %s)"
_CLEAR = "TRIFECTA: clear"


def classify_action(action):
    """Return the tuple of lethal facets that ``action`` indicates.

    The action name is lower-cased and each facet's indicator tokens are
    substring-matched against it.  The result is in canonical :data:`FACETS`
    order (so it is stable and comparable).  An action may indicate several
    facets (e.g. ``exfiltrate_secret`` is both **egress** and
    **private-data-access**); an action may indicate none.

    Parameters
    ----------
    action : str
        The action name (e.g. ``"exfiltrate_secret"``).

    Returns
    -------
    tuple of str
        The indicated facet names in canonical order (possibly empty).
    """
    name = str(action).lower()
    hits = []
    for facet in FACETS:
        for token in FACET_INDICATORS[facet]:
            if token in name:
                hits.append(facet)
                break
    return tuple(hits)


class TrifectaRisk(object):
    """The result of the D6 Lethal-Trifecta design-time risk check.

    Attributes
    ----------
    detected : bool
        ``True`` iff the policy's action set spans **all three** lethal
        facets; ``False`` otherwise.
    facets : dict
        Maps each *present* facet name to the sorted list of actions in the
        policy that indicate it (the witnesses).  Facets not present are
        absent from this dict.
    present : tuple
        The present facet names, in canonical :data:`FACETS` order.
    missing : tuple
        The absent facet names, in canonical :data:`FACETS` order.
    actions : tuple
        The full action set that was checked (``allowed ∪ denied``), sorted.
    message : str
        The exact emitted flag string:
        ``"TRIFECTA: detected (facets: ...)"`` or ``"TRIFECTA: clear"``.
    """

    def __init__(self, detected, facets, present, missing, actions,
                 message):
        self.detected = bool(detected)
        self.facets = dict(facets)
        self.present = tuple(present)
        self.missing = tuple(missing)
        self.actions = tuple(actions)
        self.message = message

    def present_facet(self, facet):
        """``True`` iff ``facet`` is one of the present facets."""
        return facet in self.facets

    def to_dict(self):
        """A JSON-serialisable, deterministic dict form."""
        return {
            "detected": self.detected,
            "facets": {k: list(self.facets[k]) for k in self.facets},
            "present": list(self.present),
            "missing": list(self.missing),
            "actions": list(self.actions),
            "n_actions": len(self.actions),
            "message": self.message,
        }

    def to_json(self, indent=2):
        """A deterministic (sorted-key) JSON string form."""
        import json
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def __repr__(self):
        return ("TrifectaRisk(detected=%s, present=%r, missing=%r)"
                % (self.detected, list(self.present), list(self.missing)))


def _action_set(policy):
    """The policy's full action set (``allowed ∪ denied``), sorted.

    Accepts an :class:`rot.ir.AdversarialPolicy` (via ``.actions()``) or any
    object exposing ``.allowed`` / ``.denied``.
    """
    if hasattr(policy, "actions"):
        return tuple(sorted(policy.actions()))
    allowed = getattr(policy, "allowed", ()) or ()
    denied = getattr(policy, "denied", ()) or ()
    return tuple(sorted(set(allowed) | set(denied)))


def detect(policy):
    """Run the D6 Lethal-Trifecta design-time risk check on ``policy``.

    Checks the policy's **full** action set (``allowed ∪ denied``) for the
    three capability facets -- **private-data-access**,
    **untrusted-content-intake**, **egress** -- and reports whether the
    lethal combination (all three present) is exposed.

    Parameters
    ----------
    policy : rot.ir.AdversarialPolicy
        The agent policy whose action set to inspect.

    Returns
    -------
    TrifectaRisk
        The flag result.  ``.detected`` is ``True`` iff all three facets are
        present; ``.message`` is the exact ``TRIFECTA: ...`` string.

    Raises
    ------
    TypeError
        If ``policy`` is not a policy-like object (no action set).
    """
    if policy is None:
        raise TypeError("detect() requires a policy (allowed/denied sets)")

    actions = _action_set(policy)

    # Tally, per facet, the (sorted) actions that indicate it.
    witness = {facet: [] for facet in FACETS}
    for action in actions:
        for facet in classify_action(action):
            witness[facet].append(action)

    present = tuple(f for f in FACETS if witness[f])
    missing = tuple(f for f in FACETS if not witness[f])
    detected = (len(missing) == 0)

    facets = {f: sorted(witness[f]) for f in present}

    if detected:
        message = _DETECTED_TEMPLATE % ", ".join(FACETS)
    else:
        message = _CLEAR

    return TrifectaRisk(
        detected=detected,
        facets=facets,
        present=present,
        missing=missing,
        actions=actions,
        message=message,
    )


# ---------------------------------------------------------------------------
# Checkable property: the G3 "NoExfiltration" upgrade
# ---------------------------------------------------------------------------
# Verdict statuses for the checkable property (distinct from the three-facet
# audit's proven/violated/unknown because it also has an "applicable" axis).
PROVEN = "proven"          # heuristic fired; model proves NoExfiltration holds
VIOLATED = "violated"      # heuristic fired; model finds an exfiltration path
NOT_APPLICABLE = "not_applicable"  # heuristic did not fire (no lethal combo)
UNKNOWN = "unknown"        # the model check was inconclusive (budget)


class ExfiltrationCheck(object):
    """The result of the G3 *checkable* Lethal-Trifecta property.

    This is the upgrade of the D6 name heuristic into a *checkable* property:
    the heuristic is the applicability pre-filter (does the policy's action
    set span all three lethal facets?), and when it fires the *egress* facet
    is the one that must be policy-enforced.  We then run a real bounded model
    check over the :mod:`rot.agent_harness` exfiltration IR for the
    policy-named egress action and prove or refute ``NoExfiltration``.

    Attributes
    ----------
    status : str
        One of :data:`PROVEN`, :data:`VIOLATED`, :data:`NOT_APPLICABLE`, or
        :data:`UNKNOWN`.
    risk : TrifectaRisk
        The underlying heuristic flag (the pre-filter result).
    egress_action : str or None
        The policy-named egress action that was model-checked (``None`` when
        the property is not applicable).
    harness_denies : bool or None
        ``True`` iff the policy *denies* the egress action (so the harness
        blocks it while private data is held); ``False`` iff the policy
        *allows* it; ``None`` when not applicable.
    witness : dict or None
        A counterexample state (``exfiltrated=True``) when violated.
    attack_path : list or None
        The witness attack path (list of ``(pre_state, action, effects)``)
        when violated.
    n_states : int
        The number of reachable states explored (0 when not applicable).
    message : str
        A human-readable one-line summary.
    """

    def __init__(self, status, risk, egress_action=None, harness_denies=None,
                 witness=None, attack_path=None, n_states=0, message="",
                 tlc_status=None, tlc_n_states=None, crosscheck=None):
        self.status = status
        self.risk = risk
        self.egress_action = egress_action
        self.harness_denies = harness_denies
        self.witness = witness
        self.attack_path = attack_path
        self.n_states = int(n_states)
        self.message = message
        # Two-engine (SMT + TLC) cross-check evidence, present only when a TLC
        # jar was supplied to :func:`checkable_property`.  ``crosscheck`` is a
        # dict: {"smt": <status>, "tlc": <status>, "joined": <status>} where
        # ``joined`` is the conservative two-engine join (PROVEN only if both
        # agree on PROVEN; VIOLATED only if both agree on VIOLATED; anything
        # else -> UNKNOWN).  ``tlc_status`` is the raw TLC verdict
        # (proven/violated/unknown/error) and ``tlc_n_states`` its state count.
        self.tlc_status = tlc_status
        self.tlc_n_states = tlc_n_states
        self.crosscheck = crosscheck

    def is_proven(self):
        return self.status == PROVEN

    def is_violated(self):
        return self.status == VIOLATED

    def is_proven_two_engine(self):
        """``True`` iff BOTH the SMT and TLC engines agree the rule holds.

        The stronger, thesis-grade assurance: two independent model checkers
        (different engines over the same IR state machine) both prove
        ``NoExfiltration``.  Requires a TLC confirmation to have been run.
        """
        return bool(self.crosscheck) and self.crosscheck.get("joined") == PROVEN

    def is_violated_two_engine(self):
        """``True`` iff BOTH the SMT and TLC engines agree the rule is violated."""
        return bool(self.crosscheck) and self.crosscheck.get("joined") == VIOLATED

    def to_dict(self):
        """A JSON-serialisable, deterministic dict form."""
        d = {
            "status": self.status,
            "risk": self.risk.to_dict() if self.risk is not None else None,
            "egress_action": self.egress_action,
            "harness_denies": self.harness_denies,
            "n_states": self.n_states,
            "message": self.message,
        }
        if self.tlc_status is not None:
            d["tlc_status"] = self.tlc_status
            d["tlc_n_states"] = int(self.tlc_n_states) if self.tlc_n_states is not None else None
        if self.crosscheck is not None:
            d["crosscheck"] = dict(self.crosscheck)
        if self.witness is not None:
            d["witness"] = dict(self.witness)
        if self.attack_path is not None:
            d["attack_path"] = [
                {
                    "pre": dict(step[0]),
                    "action": (step[1].name if hasattr(step[1], "name")
                               else step[1]),
                    "delta": dict(step[2]),
                }
                for step in self.attack_path
            ]
        return d

    def to_json(self, indent=2):
        """A deterministic (sorted-key) JSON string form."""
        import json
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def __repr__(self):
        return ("ExfiltrationCheck(status=%r, egress=%r, n_states=%d)"
                % (self.status, self.egress_action, self.n_states))


def _crosscheck_two(smt_status, tlc_status):
    """Conservative two-engine join for the G3 exfiltration property.

    ``PROVEN`` requires both engines to say ``PROVEN``; ``VIOLATED`` requires
    both to say ``VIOLATED``; any disagreement or non-decisive answer
    (unknown / error) collapses to ``UNKNOWN``.  No single engine can mint a
    two-engine decision alone.  This mirrors :func:`rot.crosscheck.join_status`
    so the G3 property shares the same join semantics as the spend-cap
    property, applied to the two independent engines (SMT + TLC) over the same
    IR state machine.
    """
    from rot import crosscheck
    joined = crosscheck.join_status(smt_status, tlc_status)
    return {"smt": smt_status, "tlc": tlc_status, "joined": joined}


def _run_tlc(model_ir, prop, tlc_jar, tlc_timeout):
    """Run TLC (a genuinely independent TLA+ model checker) over ``model_ir``.

    Returns ``(status, n_states)`` where ``status`` is one of
    ``proven`` / ``violated`` / ``unknown`` / ``error`` (the raw engine
    vocabulary) and ``n_states`` the number of states TLC explored.  If the
    jar cannot be resolved, returns ``(None, 0)`` so the caller can skip the
    cross-check gracefully (the single-engine verdict still stands).
    """
    from rot import linearization
    from rot.tlc import TlcEngine
    from rot.config import Config

    cfg = Config(tlc_jar=tlc_jar, tlc_timeout=tlc_timeout)
    if cfg.tlc_jar_path() is None:
        return None, 0
    linear_model = linearization.linearize(model_ir)
    result = TlcEngine(cfg).check(linear_model, prop, target="exfil")
    return result.status, int(result.n_states or 0)


def checkable_property(policy, max_states=200000, tlc_jar=None, tlc_timeout=120):
    """Run the G3 *checkable* Lethal-Trifecta property on ``policy``.

    The heuristic (:func:`detect`) is the applicability pre-filter: it fires
    only when the policy's action set spans all three lethal facets.  When it
    fires, the *egress* facet is the one that must be policy-enforced, so we
    model-check ``NoExfiltration`` over the :mod:`rot.agent_harness`
    exfiltration IR for the policy-named egress action:

    * the egress action is in the policy's ``denied`` set  -> the harness
      denies it while the agent holds private data  -> ``NoExfiltration`` is
      **proven** (the exfiltration is unreachable);
    * the egress action is in the policy's ``allowed`` set -> the harness
      admits it unconditionally -> ``NoExfiltration`` is **violated** (the
      exfiltration is reachable, with the attack path as witness).

    When the heuristic does not fire (the lethal combination is not exposed),
    the property is **not applicable** (there is no egress channel to police).

    Two-engine confirmation
    -----------------------
    Pass ``tlc_jar`` to also run **TLC** (a genuinely independent TLA+ model
    checker) over the *same* IR state machine and record the conservative
    two-engine join on the result: ``PROVEN`` only when both SMT and TLC agree
    the rule holds, ``VIOLATED`` only when both agree it is violated, and
    ``UNKNOWN`` on any disagreement.  This is the thesis's model-independence
    axis applied to the exfiltration property (see :mod:`rot.crosscheck`).
    Without a jar, the result is the single-engine (SMT / bounded model
    finder) verdict and ``crosscheck`` is ``None``.

    Parameters
    ----------
    policy : rot.ir.AdversarialPolicy
        The agent policy whose action set to inspect and whose egress decision
        to model-check.
    max_states : int
        The bounded model finder's state budget (the exfiltration model is
        tiny; this is a safety bound only).
    tlc_jar : str, optional
        Path to ``tla2tools.jar``.  When given, TLC is run as a second
        independent engine and the two-engine join is recorded.
    tlc_timeout : int
        TLC wall-clock timeout (seconds) for the confirmation run.

    Returns
    -------
    ExfiltrationCheck
        The checkable-property result.

    Raises
    ------
    TypeError
        If ``policy`` is not a policy-like object (no action set).
    """
    if policy is None:
        raise TypeError("checkable_property() requires a policy "
                        "(allowed/denied sets)")

    # 1. the heuristic pre-filter (does the lethal combination exist?).
    risk = detect(policy)
    if not risk.detected:
        return ExfiltrationCheck(
            status=NOT_APPLICABLE,
            risk=risk,
            message="EXFIL: not applicable (lethal trifecta not detected "
                    "in the action set)",
        )

    # 2. the egress facet is present; pick its (deterministic) witness action.
    egress_actions = sorted(risk.facets.get("egress", ()))
    if not egress_actions:
        # detected implies the egress facet is present, but be defensive.
        return ExfiltrationCheck(
            status=NOT_APPLICABLE,
            risk=risk,
            message="EXFIL: not applicable (no egress action named)",
        )
    egress_action = egress_actions[0]

    # 3. is the harness policy *denying* the egress action? (The thing under
    #    test is the harness decision on that action.)
    allowed = tuple(getattr(policy, "allowed", ()) or ())
    denied = tuple(getattr(policy, "denied", ()) or ())
    harness_denies = egress_action in denied and egress_action not in allowed

    # 4. build the exfiltration IR for this egress action + harness decision,
    #    and run the bounded model check over NoExfiltration.
    import rot.ir as ir
    import rot.agent_harness as agent_harness
    import rot.modelfind as modelfind

    model_ir = agent_harness.exfil_ir_for_egress(
        egress_action=egress_action, harness_denies=harness_denies)
    model = modelfind.ModelFinder.from_ir(
        model_ir, max_states=max_states)

    # NoExfiltration holds iff no reachable state has exfiltrated == True.
    def _exfiltrated(state):
        v = state.get("exfiltrated")
        if v is None:
            return ir.Expr.UNDEF
        return bool(v)

    def _holds(state):
        # the invariant: exfiltrated is False (i.e. not holding-then-sent).
        e = _exfiltrated(state)
        if e is ir.Expr.UNDEF:
            return ir.Expr.UNDEF
        return (not e)

    verdict, witness = model.forall_reachable(_holds, max_states=max_states)

    # Count reachable states for the report (bounded).
    try:
        n_states = len(model.reachable_states(max_states=max_states))
    except Exception:
        n_states = 0

    # The single-engine (SMT / bounded model finder) status.
    if verdict is True:
        smt_status = PROVEN
    elif verdict is False and witness is not None:
        smt_status = VIOLATED
    else:
        smt_status = UNKNOWN

    # Optional second engine: TLC (TLA+), a genuinely independent model
    # checker over the SAME IR state machine.  When a jar is supplied we run
    # the ``no_exfiltration`` invariant under TLC and record the conservative
    # two-engine join (PROVEN only if both agree on PROVEN; VIOLATED only if
    # both agree on VIOLATED; anything else -> UNKNOWN).
    tlc_status = None
    tlc_n_states = 0
    crosscheck = None
    if tlc_jar:
        import rot.invariants as invariants
        prop = invariants.no_exfiltration(n=1)
        tlc_status, tlc_n_states = _run_tlc(
            model_ir, prop, tlc_jar=tlc_jar, tlc_timeout=tlc_timeout)
        if tlc_status is not None:
            crosscheck = _crosscheck_two(smt_status, tlc_status)

    def _two_engine_suffix():
        if crosscheck is None:
            return ""
        return (" [two-engine: SMT=%s, TLC=%s -> %s]"
                % (crosscheck["smt"], crosscheck["tlc"], crosscheck["joined"]))

    if smt_status is PROVEN:
        message = ("EXFIL: proven (harness denies %r while private data is "
                   "held; NoExfiltration holds over %d states)"
                   % (egress_action, n_states))
        return ExfiltrationCheck(
            status=PROVEN, risk=risk, egress_action=egress_action,
            harness_denies=harness_denies, n_states=n_states,
            message=message + _two_engine_suffix(),
            tlc_status=tlc_status, tlc_n_states=tlc_n_states,
            crosscheck=crosscheck)

    if smt_status is VIOLATED:
        # Build the attack path as the witness (the NoExfiltration bypass).
        attack_path = None
        try:
            path = model.path_to(witness, max_states=max_states)
            if path:
                attack_path = [
                    (dict(step[0]),
                     step[1].name if hasattr(step[1], "name") else step[1],
                     dict(step[2]))
                    for step in path
                ]
        except Exception:
            attack_path = None
        message = ("EXFIL: violated (harness admits %r while private data is "
                   "held; exfiltration is reachable -- %d states)"
                   % (egress_action, n_states))
        return ExfiltrationCheck(
            status=VIOLATED, risk=risk, egress_action=egress_action,
            harness_denies=harness_denies, witness=dict(witness),
            attack_path=attack_path, n_states=n_states,
            message=message + _two_engine_suffix(),
            tlc_status=tlc_status, tlc_n_states=tlc_n_states,
            crosscheck=crosscheck)

    # Inconclusive (budget exceeded) -- report unknown, never a false proven.
    message = ("EXFIL: unknown (model check inconclusive over the bounded "
               "state space for %r)" % egress_action)
    return ExfiltrationCheck(
        status=UNKNOWN, risk=risk, egress_action=egress_action,
        harness_denies=harness_denies, n_states=n_states,
        message=message + _two_engine_suffix(),
        tlc_status=tlc_status, tlc_n_states=tlc_n_states,
        crosscheck=crosscheck)