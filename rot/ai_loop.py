# -*- coding: utf-8 -*-
"""rot.ai_loop -- the AI-authored-policy demo loop (Phase 4).

The loop, end to end:

    intent (natural language)
      -> AI-authored policy (Rego, as the AI authoring would emit it)
      -> ROTN verdict (lower to the neutral ProtocolIR, decide the pinned
         property, cross-check against the Dogwood twin)

This is the "AgentCore writes your Dogwood policy. ROTN proves it can't
be bypassed." position made runnable: the default example is the
**APW-2 approval-replay** shape (the exact policy an AI authoring is
likely to produce -- the approval encoded as a bare, sticky fact), and
the loop shows:

* the intent (``samples/ai_authoring/intent.md``);
* the AI's draft (``samples/ai_authoring/apw2-buggy.rego``);
* the lowering (the ``.rego`` stub front-end -> the *same* ``ProtocolIR``
  the Dogwood twin ``samples/apw2-buggy.dw`` lowers to);
* the verdict (``VIOLATED``, witness ``{"approved": true, "orders": 2}``
  -- one approval admits two orders), and that the corrected draft is
  what the proof is about (``PROVEN``).

The cross-language check is part of the loop: when a Dogwood twin exists
(same stem, ``.dw`` in ``samples/``), both policies are lowered and the
loop asserts they are *structurally identical* (``ProtocolIR.__eq__``
ignores metadata) and decide to the *same verdict* -- the
"neutral checker across languages" claim, demonstrated, not asserted.

Pure stdlib; Python 3.6 compatible.  The engines are imported lazily
(``rot.modelfind``) so the module stays importable in a bare environment.
"""

import json
import os

__all__ = ["run", "default_paths"]

#: Default loop inputs (relative to the repo root).
DEFAULT_INTENT = os.path.join("samples", "ai_authoring", "intent.md")
DEFAULT_POLICY = os.path.join("samples", "ai_authoring", "apw2-buggy.rego")


def _repo_root():
    """Absolute path of the repository root (parent of the rot package)."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _abs(rel):
    """Resolve a path (absolute or repo-root-relative) to an absolute one."""
    if os.path.isabs(rel):
        return rel
    return os.path.join(_repo_root(), rel)


def default_paths():
    """The default ``(intent_path, policy_path)`` of the demo loop."""
    return _abs(DEFAULT_INTENT), _abs(DEFAULT_POLICY)


def _decide(ir):
    """Decide ``ir.pinned_property`` over the reachable states.

    Returns ``(status, witness)`` where status is one of ``"proven"`` /
    ``"violated"`` / ``"unknown"`` and witness is the violating state
    dict (or None).  Mirrors the safety dispatch in
    ``rot.__main__._verify`` (all Phase-4 shapes pin safety properties).
    """
    from rot.modelfind import ModelFinder

    mf = ModelFinder.from_ir(ir)
    pred = lambda s: ir.pinned_property.eval(s)
    result, witness = mf.forall_reachable(pred)
    if result is True:
        return "proven", None
    if result is False:
        return "violated", witness
    return "unknown", None


def _dw_twin(policy_path):
    """The Dogwood twin of a ``.rego`` sample, if one exists.

    ``samples/ai_authoring/apw2-buggy.rego`` -> ``samples/apw2-buggy.dw``
    (same stem, ``.dw`` extension, either next to the file or in
    ``samples/``).  Returns None when there is no twin.
    """
    root, ext = os.path.splitext(policy_path)
    if ext.lower() != ".rego":
        return None
    near = root + ".dw"
    if os.path.isfile(near):
        return near
    in_samples = os.path.join(_repo_root(), "samples",
                              os.path.basename(root) + ".dw")
    if os.path.isfile(in_samples):
        return in_samples
    return None


def run(intent_path=None, policy_path=None, out_dir=None, quiet=False):
    """Run the AI-authored demo loop end to end.

    Parameters
    ----------
    intent_path : str or None
        The natural-language intent file
        [default: ``samples/ai_authoring/intent.md``].
    policy_path : str or None
        The AI-authored policy to verify (``.rego`` / ``.dw`` / ``.ap2``)
        [default: ``samples/ai_authoring/apw2-buggy.rego`` -- the
        canonical APW-2 example].
    out_dir : str or None
        When given, the result is written to
        ``<out_dir>/ai-loop-report.json`` (a JSON-safe copy of the result).
    quiet : bool
        Accepted for CLI compatibility; the loop itself is silent either
        way (``rot ai`` prints the narrative).

    Returns
    -------
    dict
        The loop result: ``intent`` / ``policy_text`` (the two ends of
        the loop), ``frontend`` / ``shape`` / ``property`` (the
        lowering), ``verdict`` / ``witness`` (the decision),
        ``cross_language`` (the Dogwood-twin check, when a twin exists),
        and ``exit_code`` (``0`` proven / ``1`` violated / ``2`` unknown).

    Raises
    ------
    RuntimeError
        If an input file is missing.
    """
    intent_path = _abs(intent_path or DEFAULT_INTENT)
    policy_path = _abs(policy_path or DEFAULT_POLICY)
    if not os.path.isfile(intent_path):
        raise RuntimeError("intent file not found: %s" % intent_path)
    if not os.path.isfile(policy_path):
        raise RuntimeError("policy file not found: %s" % policy_path)

    with open(intent_path, "r") as f:
        intent = f.read()
    with open(policy_path, "r") as f:
        policy_text = f.read()

    # Step 1: lower the AI-authored policy (narrow-waist front-end).
    import rot.frontends.policy as fe

    ir = fe.build_ir(policy_path)
    status, witness = _decide(ir)

    # Step 2: the cross-language check (the neutral-checker claim).
    cross = None
    twin = _dw_twin(policy_path)
    if twin is not None:
        twin_ir = fe.build_ir(twin)
        twin_status, _twin_witness = _decide(twin_ir)
        cross = {
            "dogwood_policy": twin,
            "same_ir": bool(twin_ir == ir),
            "dogwood_verdict": twin_status,
            "same_verdict": twin_status == status,
        }

    result = {
        "intent_path": intent_path,
        "intent": intent,
        "policy_path": policy_path,
        "policy_text": policy_text,
        "frontend": ir.metadata.get("frontend"),
        "shape": ir.metadata.get("shape") or ir.metadata.get("ap2_apw"),
        "family": ir.metadata.get("family"),
        "property": ir.metadata.get("property_name"),
        "property_kind": ir.metadata.get("property_kind"),
        "verdict": status,
        "witness": witness,
        "cross_language": cross,
        "exit_code": {"proven": 0, "violated": 1, "unknown": 2}[status],
    }

    if out_dir:
        if not os.path.isdir(out_dir):
            os.makedirs(out_dir)
        report_path = os.path.join(out_dir, "ai-loop-report.json")
        with open(report_path, "w") as f:
            json.dump(result, f, indent=2, sort_keys=True)
        result["report_path"] = report_path
    return result