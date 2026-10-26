# -*- coding: utf-8 -*-
"""trifecta_risk.py -- the D6 "Lethal Trifecta" design-time risk flag.

This is a *static, design-time* check that is deliberately distinct from
:mod:`rot.trifecta` (the three-facet *audit* -- safety / liveness /
conformance -- which is a sound model-checking result over the AgentStep
model).  Here we do NOT run an engine and we make NO soundness claim.  We
inspect only the policy's **action set** (``allowed ∪ denied``) and ask a
purely structural question about the *capabilities* the agent's action space
spans.

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
* **No engine, no state space.**  The check is a pure function of the
  policy's action names; it never touches :mod:`rot.modelfind` /
  :mod:`rot.symbolic`.  It is a *design-time heuristic flag*, not a proof.
* **Deterministic.**  The same policy always yields the same flag, the same
  facet witnesses, and the same message.  Facets and their witness actions
  are reported in a stable (sorted / canonical) order.
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