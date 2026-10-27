# -*- coding: utf-8 -*-
"""trace.py -- RTF v1: the deterministic, hashable Reasoning Trace Format.

A *trace* is a self-contained, deterministic, hashable record of one
verification run against an MCP Manifest v1. It is a strict **superset** of
the Cedar-AR findings report (:mod:`rot.mcp_adapter`): it carries the
provenance (schema, ``manifest_id``, source hash, policy, budget tier,
horizon), the gate verdict, the engines that ran, the reasoning (graph,
counterexample, decision tree, timeline), the blog-ready narration, and the
findings (each with its SOC 2 / AIUC controls).

Why a trace?
------------

The findings report answers *"what is wrong?"*. The trace answers *"how do
we know -- and is this the exact same run?"*: it is a single JSON document
that (a) is a **pure function** of the manifest + budget + horizon (no
timestamps, no random IDs, stable ordering), so the same input always
produces the same bytes; and (b) is **hashable** -- it carries a top-level
``hash`` (SHA-256 of its own canonical body) that pins the exact reasoning,
so a trace can be referenced, compared, and re-verified byte-for-byte.

The trace adds **no verification logic**: it reuses the structural checks and
findings from :func:`rot.mcp_adapter.audit_manifest` and the SOC 2 / AIUC
control mapping from :mod:`rot.compliance`. It only *re-assembles* them into
a deterministic, hashable, self-contained artifact.

Pure stdlib, Python 3.6 compatible.
"""

import hashlib
import json

import rot
import rot.license as lic

__all__ = [
    "SCHEMA",
    "TraceResult",
    "build_trace",
    "manifest_id",
    "trace_hash",
    "canonical_json",
]

#: The RTF v1 schema tag (stable; bump on breaking changes to the trace shape).
SCHEMA = "caravel.rtf/v1"

#: The two structural checks the manifest audit runs (stable order).
_MANIFEST_CHECKS = ("field_write_permission", "tenant_read_isolation")


def _json_default(obj):
    """JSON fallback for non-serialisable values (stable, deterministic).

    Prefer a stable ``to_dict()`` when present, then a sorted list for sets,
    then ``repr`` -- so serialisation never raises and stays deterministic.
    """
    to_dict = getattr(obj, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    return repr(obj)


def canonical_json(obj, indent=None):
    """Deterministic JSON (sorted keys, stable separators).

    ``indent=None`` -> compact (for hashing). Otherwise pretty-printed (for
    the artifact). Both are byte-stable for the same input.
    """
    if indent is None:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          default=_json_default)
    return json.dumps(obj, sort_keys=True, indent=indent,
                      default=_json_default)


def trace_hash(body):
    """SHA-256 hex digest of the trace body's canonical JSON.

    This is the *hashable* part of the trace: it pins the exact reasoning
    (every field in the body) to a single stable identifier.
    """
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def manifest_id(manifest_hash):
    """A deterministic, human-stable ID derived from the manifest hash.

    ``"mf-" + the first 16 hex chars of the manifest's SHA-256`` -- short
    enough to read, long enough to be collision-resistant in practice, and
    stable across runs (a pure function of the manifest content).
    """
    if not manifest_hash:
        return "mf-unknown"
    return "mf-" + manifest_hash[:16]


class TraceResult(object):
    """A deterministic, hashable RTF v1 reasoning trace.

    Attributes
    ----------
    body : dict
        The trace body (every field except the top-level ``hash``).
    hash : str
        The SHA-256 hex digest of the body's canonical JSON -- the trace's
        stable identity (the "hashable" part of the format).
    """

    def __init__(self, body):
        self.body = body
        self.hash = trace_hash(body)

    # -- queries -----------------------------------------------------------
    def verdict(self):
        """``"proven"`` / ``"violated"`` / ``"unknown"`` (the gate outcome)."""
        return self.body["verdict"]

    def manifest_id(self):
        """The deterministic manifest ID (``mf-<16hex>``)."""
        return self.body["manifest_id"]

    # -- serialisation -----------------------------------------------------
    def to_dict(self):
        """The full trace dict (body + the top-level ``hash``)."""
        d = dict(self.body)
        d["hash"] = self.hash
        return d

    def to_json(self, indent=2):
        """Deterministic JSON (sorted keys) -- the RTF v1 artifact."""
        return canonical_json(self.to_dict(), indent=indent)

    def __repr__(self):
        return "TraceResult(verdict=%s, manifest_id=%s, hash=%s...)" % (
            self.body["verdict"], self.body["manifest_id"], self.hash[:12])


# ---------------------------------------------------------------------------
# body assembly (pure, deterministic helpers -- no verification logic)
# ---------------------------------------------------------------------------

def _engines(report, trifecta=None):
    """The stable, de-duplicated list of engines that produced the verdict.

    For a temporal (Trifecta) audit, the engine names come from the facet
    evidence (``ModelFinder`` / ``SymbolicEngine.reach_within``). For a
    structural (manifest) audit -- where the facets are ``skipped`` stubs --
    the engine is the pure set-check auditor (``structural``).
    """
    engines = []
    if trifecta is not None:
        for facet_name in ("safety", "liveness", "conformance"):
            fv = getattr(trifecta, facet_name, None)
            if fv is None:
                continue
            engine = (fv.evidence or {}).get("engine")
            if engine and engine not in engines:
                engines.append(engine)
    if not engines:
        # Structural (manifest) audit: no temporal engine ran.
        engines = ["structural"]
    return engines


def _budget_dict(budget, tier):
    """The deterministic ``budget`` block (tier + source + limits).

    ``None`` budget -> the free-tier fail-closed floor (``lic.DepthBudget
    .free()``), so a trace is always grounded in a concrete, known budget.
    """
    if budget is None:
        budget = lic.DepthBudget.free()
    tier_val = tier or _infer_tier(budget)
    return {
        "tier": tier_val,
        "source": budget.source,
        "limits": {
            "max_states": int(budget.max_states),
            "max_horizon": int(budget.max_horizon),
            "max_tools": int(budget.max_tools),
            "max_tenant_scopes": int(budget.max_tenant_scopes),
        },
    }


def _infer_tier(budget):
    """Infer the tier (``free`` / ``paid``) from a budget (best effort).

    The free tier is the fail-closed floor: any budget whose ``max_states``
    is at or below the free maximum is ``free``; otherwise ``paid``.
    """
    if int(budget.max_states) <= int(lic.FREE_LIMITS["max_states"]):
        return "free"
    return "paid"


def _n_states_manifest(manifest):
    """The number of structural field-access checks performed.

    A manifest audit is a pure set-membership check (no state-space
    exploration), so the honest ``n_states`` is the number of (tool, field)
    accesses validated -- the graph edges (reads + writes across all tools).
    Deterministic and stable.
    """
    n = 0
    for tool in manifest.tools:
        n += len(tool.read_fields) + len(tool.write_fields)
    return n


def _provenance(engines, budget_dict, horizon, n_states, horizon_complete,
                policy_hash, policy_source):
    """The deterministic provenance block (the architecture contract's
    ``provenance`` field: engines, budget, ``n_states``, horizon completion,
    and the policy's provenance).

    ``n_states`` is the number of states explored (the manifest audit's
    structural checks, or the temporal engine's reachable-state count).
    ``horizon_complete`` is True when the bounded search finished within its
    budget (a structural audit always does).
    """
    return {
        "engines": list(engines),
        "budget": budget_dict,
        "horizon": int(horizon),
        "n_states": int(n_states),
        "horizon_complete": bool(horizon_complete),
        "policy_hash": policy_hash,
        "policy_source": policy_source,
    }


def _graph(manifest):
    """The structural manifest graph: tools (nodes) + field refs (edges).

    Deterministic: nodes in manifest order (stable), fields sorted, edges in
    a stable (node, kind, field) order.
    """
    nodes = []
    edges = []
    for tool in manifest.tools:
        nodes.append({
            "id": tool.name,
            "kind": "tool",
            "read_fields": sorted(tool.read_fields),
            "write_fields": sorted(tool.write_fields),
        })
        for field in sorted(tool.read_fields):
            edges.append({"from": tool.name, "to": field, "kind": "read"})
        for field in sorted(tool.write_fields):
            edges.append({"from": tool.name, "to": field, "kind": "write"})
    return {
        "kind": "manifest",
        "tenant_scope": manifest.tenant_scope,
        "allowed_write_fields": sorted(manifest.allowed_write_fields),
        "nodes": nodes,
        "edges": edges,
    }


def _counterexample_steps(report):
    """The ordered counterexample step path (the 'attack path').

    For a manifest audit the path is the sequence of the tool's violating
    field accesses, in report order (stable). Each step is
    ``{"step", "action", "state"}`` -- the shape the architecture contract
    requires for the counterexample path (G1: the playhead travels it).
    """
    steps = []
    i = 0
    for finding in report.findings:
        if finding.severity != "error" or finding.witness is None:
            continue
        witness = finding.witness
        tool = witness.get("tool")
        # Cross-tenant reads (tenant isolation violation).
        for field in (witness.get("cross_tenant_fields") or []):
            steps.append({
                "step": i,
                "action": "read %s" % field,
                "state": {"tool": tool, "field": field, "kind": "read"},
            })
            i += 1
        # Over-permission writes (field write permission violation).
        for field in (witness.get("over_permission") or []):
            steps.append({
                "step": i,
                "action": "write %s" % field,
                "state": {"tool": tool, "field": field, "kind": "write"},
            })
            i += 1
    return steps


def _counterexample(report, trifecta=None):
    """The concrete counterexample (witness) + the ordered step path.

    Prefer the first error-severity finding's witness (the structural
    violation). When none, fall back to a temporal facet's witness. ``None``
    for a proven / unknown verdict (no counterexample to show).

    The returned dict carries the witness fields plus a ``steps`` array --
    the ordered ``{step, action, state}`` path (the 'attack path') that the
    replay animation travels (G1).
    """
    witness = None
    if report is not None:
        for finding in report.findings:
            if finding.severity == "error" and finding.witness is not None:
                witness = finding.witness
                break
    if witness is None and trifecta is not None:
        for facet_name in ("safety", "liveness", "conformance"):
            fv = getattr(trifecta, facet_name, None)
            if fv is not None and fv.is_violated() and fv.witness is not None:
                witness = fv.witness
                break
    if witness is None:
        return None
    # Attach the ordered step path (the 'attack path') to the witness.
    out = dict(witness)
    if report is not None:
        steps = _counterexample_steps(report)
        if steps:
            out["steps"] = steps
    return out


def _decision_tree(report):
    """The decision tree: each structural check and its outcome.

    Deterministic: checks in a stable order, findings in report order.
    """
    checks = []
    for check in _MANIFEST_CHECKS:
        findings = [f for f in report.findings
                    if f.property_name == check]
        checks.append({
            "check": check,
            "result": "fail" if findings else "pass",
            "findings": [
                {
                    "property": f.property_name,
                    "severity": f.severity,
                    "message": f.message,
                    "witness": f.witness,
                }
                for f in findings
            ],
        })
    return {
        "root": "manifest_audit",
        "verdict": report.result(),
        "checks": checks,
    }


def _step_narration(step, status, findings, manifest, policy):
    """Engine-generated plain-English narration for one audit step.

    Deterministic: a pure function of the step name, its status, the
    findings it produced, and the manifest/policy context. This is the
    per-step narration the architecture contract requires (G1: the
    narration panel shows one plain-English line per step).
    """
    if step == "parse_manifest":
        n_tools = len(getattr(manifest, "tools", []) or [])
        return ("Parsed the manifest: %d tool(s), tenant scope %s, "
                "allowed writes %s."
                % (n_tools, policy.get("tenant_scope"),
                   policy.get("allowed_write_fields", [])))
    if step == "field_write_permission":
        if findings:
            return "Checked field-write permission: %s" % findings[0].message
        return ("Checked field-write permission: clean -- every write target "
                "is within the tenant's allowed write set.")
    if step == "tenant_read_isolation":
        if findings:
            return "Checked tenant read isolation: %s" % findings[0].message
        return ("Checked tenant read isolation: clean -- every read stays "
                "within the tenant scope.")
    if step == "verdict":
        if status == "proven":
            return ("Verdict: PROVEN -- the policy holds within the "
                    "verified bounds.")
        if status == "violated":
            return ("Verdict: VIOLATED -- a counterexample exists; the "
                    "violating path is highlighted.")
        return ("Verdict: UNKNOWN -- the bounded search exhausted its "
                "budget before deciding (fail-closed).")
    return "Checked %s: %s." % (step, status)


def _timeline(report, manifest):
    """The ordered audit steps, each with an engine-generated narration.

    Deterministic: parse first, then the checks in a stable order, then the
    verdict. Each step carries a plain-English ``narration`` line (G1).
    """
    policy = report.policy or {}
    steps = [{
        "step": "parse_manifest",
        "status": "ok",
        "narration": _step_narration("parse_manifest", "ok", [], manifest,
                                     policy),
    }]
    for check in _MANIFEST_CHECKS:
        findings = [f for f in report.findings
                    if f.property_name == check]
        status = "fail" if findings else "pass"
        steps.append({
            "step": check,
            "status": status,
            "findings": len(findings),
            "narration": _step_narration(check, status, findings, manifest,
                                         policy),
        })
    verdict = report.result()
    steps.append({
        "step": "verdict",
        "status": verdict,
        "narration": _step_narration("verdict", verdict, [], manifest, policy),
    })
    return steps


def build_trace(manifest, report, budget=None, horizon=12, tier=None,
                source_path=None, trifecta=None):
    """Build an RTF v1 reasoning trace from a manifest + findings report.

    This is the single entry point for the ``rot trace`` command. It reuses
    the structural findings from :func:`rot.mcp_adapter.audit_manifest`
    (passed in as ``report``) and re-assembles them -- plus the manifest's
    structural graph, decision tree, and timeline -- into a deterministic,
    hashable, self-contained trace. It adds no verification logic.

    Parameters
    ----------
    manifest : rot.mcp_manifest.McpManifest
        A validated manifest (see :mod:`rot.mcp_manifest`).
    report : rot.mcp_adapter.McpFindingsReport
        The findings report (from ``audit_manifest``).
    budget : rot.license.DepthBudget, optional
        The resolved tier budget. When ``None``, the free-tier defaults are
        used (fail-closed floor).
    horizon : int
        The bounded-liveness horizon (recorded for provenance; default 12).
    tier : str, optional
        ``"free"`` / ``"paid"``. When ``None``, inferred from the budget.
    source_path : str, optional
        The manifest file path (recorded for provenance).
    trifecta : rot.trifecta.TrifectaResult, optional
        A temporal (three-facet) result. When present, its engines are folded
        into ``engines`` and its counterexample enriches the trace.

    Returns
    -------
    TraceResult
    """
    import rot.mcp_adapter as mcp
    import rot.compliance as compliance

    manifest_hash = (report.policy or {}).get("hash")
    if not manifest_hash:
        manifest_hash = mcp._manifest_hash(manifest)

    budget_dict = _budget_dict(budget, tier)
    engines = _engines(report, trifecta)
    body = {
        "schema": SCHEMA,
        "manifest_id": manifest_id(manifest_hash),
        "rot_version": rot.__version__,
        "verdict": report.result(),
        "engines": engines,
        "horizon": int(horizon),
        "budget": budget_dict,
        "source": {
            "hash": manifest_hash,
            "path": source_path,
            "schema": manifest.manifest,
        },
        "policy": dict(report.policy or {}),
        "graph": _graph(manifest),
        "counterexample": _counterexample(report, trifecta),
        "decision_tree": _decision_tree(report),
        "timeline": _timeline(report, manifest),
        "narration": mcp.render_narrative(report),
        "findings": [f.to_dict() for f in report.findings],
        "compliance": compliance.compliance_section(report.findings,
                                                    report.result()),
        "provenance": _provenance(
            engines, budget_dict, horizon,
            _n_states_manifest(manifest), True,
            manifest_hash, source_path,
        ),
    }
    return TraceResult(body)


# ---------------------------------------------------------------------------
# spend-cap policy trace (rot.spendcap / .dw front-end) -- Phase G
# ---------------------------------------------------------------------------

class _SpendcapFinding(object):
    """A synthetic Cedar-AR finding for the spend-cap audit (autonomy)."""
    finding = "Overly Permissive"
    property_name = "spendcap_within_cap"


def _ir_policy_hash(ir):
    """A deterministic SHA-256 identity for a policy IR (stable + hashable)."""
    import hashlib
    meta = {}
    for k in sorted((ir.metadata or {}).keys()):
        v = ir.metadata[k]
        if isinstance(v, (int, float, str, bool)):
            meta[k] = v
    payload = {
        "name": ir.name,
        "variables": [v.name for v in ir.variables],
        "actions": [a.name for a in ir.actions],
        "metadata": meta,
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _reachable_states(ir, max_states=200000):
    """The reachable concrete states (list of dicts), deterministic order."""
    from rot.modelfind import ModelFinder, ProductTooLarge
    mf = ModelFinder.from_ir(ir, max_states=max_states)
    try:
        return mf.reachable_states()
    except ProductTooLarge:
        return []


def _spendcap_graph(steps, reachable_states, amount):
    """The state-space graph (nodes = states, edges = transitions).

    For a violated verdict the graph is the counterexample path (the attack
    path the replay animation travels, G1). For a proven verdict it is the
    reachable state space (showing every state stays within the cap).
    """
    def _state_id(s):
        return "s%d_%d" % (s.get("completed", 0), s.get("inflight", 0))

    def _node(s, witness):
        settled = s.get("completed", 0)
        inflight = s.get("inflight", 0)
        return {
            "id": _state_id(s),
            "kind": "state",
            "completed": settled,
            "inflight": inflight,
            "cumulative": settled + inflight * amount,
            "witness": witness,
        }

    if steps:
        nodes = []
        seen = set()
        for step in steps:
            s = step.get("state") or {}
            sid = _state_id(s)
            if sid not in seen:
                seen.add(sid)
                nodes.append(_node(s, True))
        edges = []
        for i in range(1, len(steps)):
            edges.append({
                "from": _state_id(steps[i - 1].get("state") or {}),
                "to": _state_id(steps[i].get("state") or {}),
                "action": steps[i].get("action"),
                "witness": True,
            })
        return {
            "kind": "state",
            "nodes": nodes,
            "edges": edges,
            "witness_path": [_state_id(step.get("state") or {})
                             for step in steps],
        }
    nodes = []
    seen = set()
    for s in (reachable_states or [])[:200]:
        sid = _state_id(s)
        if sid in seen:
            continue
        seen.add(sid)
        nodes.append(_node(s, False))
    return {"kind": "state", "nodes": nodes, "edges": [], "witness_path": []}


def _spendcap_counterexample(witness, steps):
    """The counterexample (witness + ordered step path) for a violation."""
    if witness is None:
        return None
    out = dict(witness)
    if steps:
        out["steps"] = list(steps)
    return out


def _spendcap_decision_tree(steps, status, buggy):
    """The decision tree: the ``spend_ok`` guard evaluation at each step.

    The guard is the seeded difference between the two variants:
      * buggy   -- ``completed + AMOUNT <= CAP`` (settled-only accounting);
      * correct -- ``completed + inflight * AMOUNT + AMOUNT <= CAP``.
    """
    guard = ("completed + AMOUNT <= CAP" if buggy
             else "completed + inflight * AMOUNT + AMOUNT <= CAP")
    checks = []
    for i, step in enumerate(steps or []):
        checks.append({
            "step": i,
            "action": step.get("action"),
            "state": step.get("state") or {},
            "guard": guard,
            "result": "admit" if step.get("action") == "spend_ok" else "deny",
        })
    return {
        "root": "spendcap_within_cap",
        "verdict": status,
        "guard": guard,
        "checks": checks,
    }


def _spendcap_timeline(steps, status, amount, cap):
    """The ordered audit steps, each with an engine-generated narration (G1)."""
    out = [{
        "step": "parse_policy",
        "status": "ok",
        "narration": ("Parsed the spend-cap policy: AMOUNT=%d, CAP=%d, "
                      "property spendcap_within_cap (safety)."
                      % (amount, cap)),
    }]
    for i, step in enumerate(steps or []):
        s = step.get("state") or {}
        settled = s.get("completed", 0)
        inflight = s.get("inflight", 0)
        cumulative = settled + inflight * amount
        crosses = cumulative > cap
        if crosses:
            narration = ("Step %d: %s -> completed=%d, inflight=%d "
                         "(cumulative %d EXCEEDS the cap of %d) -- the cap "
                         "is crossed here."
                         % (i, step.get("action"), settled, inflight,
                            cumulative, cap))
            step_status = "fail"
        else:
            narration = ("Step %d: %s -> completed=%d, inflight=%d "
                         "(cumulative %d within the cap of %d)."
                         % (i, step.get("action"), settled, inflight,
                            cumulative, cap))
            step_status = "ok"
        out.append({
            "step": "step_%d" % i,
            "status": step_status,
            "action": step.get("action"),
            "state": s,
            "narration": narration,
        })
    if status == "proven":
        verdict = ("Verdict: PROVEN -- the settled + in-flight amount never "
                   "exceeds the cap in any reachable state.")
    elif status == "violated":
        verdict = ("Verdict: VIOLATED -- a burst of parallel fires grows the "
                   "in-flight amount past the cap; the crossing moment is "
                   "highlighted.")
    else:
        verdict = ("Verdict: UNKNOWN -- the bounded search exhausted its "
                   "budget before deciding (fail-closed).")
    out.append({"step": "verdict", "status": status, "narration": verdict})
    return out


def _spendcap_narration(status, amount, cap, witness, n_states):
    """The blog-ready narrative for the spend-cap audit."""
    if status == "violated":
        inflight = (witness or {}).get("inflight", 0)
        return ("The spend-cap policy is VIOLATED. A burst of parallel "
                "``spend_ok`` approvals (before any ``respond`` settles) each "
                "sees ``completed = 0`` and is admitted, so the in-flight "
                "amount grows to %d * %d = %d -- past the cap of %d. The "
                "counterexample is %s. (%d reachable states explored.)"
                % (inflight, amount, inflight * amount, cap, witness,
                   n_states))
    if status == "proven":
        return ("The spend-cap policy is PROVEN. The ``spend_ok`` guard "
                "charges in-flight requests against the cap, so the settled "
                "+ in-flight amount never exceeds %d in any of the %d "
                "reachable states." % (cap, n_states))
    return ("The spend-cap audit is UNKNOWN: the bounded search exhausted "
            "its budget before deciding (fail-closed).")


def _spendcap_findings(status, witness, amount, cap):
    """The findings for the spend-cap audit (the cap violation)."""
    if status != "violated":
        return []
    inflight = (witness or {}).get("inflight", 0)
    return [{
        "finding": "Overly Permissive",
        "property_name": "spendcap_within_cap",
        "severity": "error",
        "message": ("the spend_ok guard admits %d in-flight requests "
                    "(cumulative %d), exceeding the cap of %d"
                    % (inflight, inflight * amount, cap)),
        "witness": dict(witness or {}),
        "controls": ["AIUC-1", "CC6.1"],
        "remediation": ("charge in-flight requests against the cap: guard on "
                        "completed + inflight * AMOUNT + AMOUNT <= CAP"),
    }]


def _spendcap_compliance(status):
    """The compliance block for the spend-cap audit (SOC 2 + AIUC)."""
    import rot.compliance as compliance
    findings = [_SpendcapFinding()] if status == "violated" else []
    return compliance.compliance_section(findings, status)


def _spend_section(steps, amount, cap, max_inflight, reachable_states):
    """The spend-cap timeline data (G2: cumulative spend vs cap).

    ``steps`` is the counterexample path (violated) with per-step
    settled/in-flight/cumulative and the exact crossing moment;
    ``reachable_states`` is the bounded state space (for the chart's
    background), each annotated with whether it is within the cap.
    """
    spend_steps = []
    crossing_step = None
    for i, step in enumerate(steps or []):
        s = step.get("state") or {}
        settled = s.get("completed", 0)
        inflight = s.get("inflight", 0)
        cumulative = settled + inflight * amount
        crosses = cumulative > cap
        spend_steps.append({
            "step": i,
            "action": step.get("action"),
            "state": s,
            "settled": settled,
            "inflight": inflight,
            "cumulative": cumulative,
            "crosses": crosses,
        })
        if crosses and crossing_step is None:
            crossing_step = i
    reachable = []
    for s in (reachable_states or [])[:200]:
        settled = s.get("completed", 0)
        inflight = s.get("inflight", 0)
        cumulative = settled + inflight * amount
        reachable.append({
            "completed": settled,
            "inflight": inflight,
            "cumulative": cumulative,
            "within_cap": cumulative <= cap,
        })
    return {
        "amount": amount,
        "cap": cap,
        "max_inflight": max_inflight,
        "steps": spend_steps,
        "crossing_step": crossing_step,
        "reachable_states": reachable,
    }


def build_spendcap_trace(ir, status, witness=None, steps=None,
                         n_states=None, budget=None, horizon=12, tier=None,
                         source_path=None):
    """Build an RTF v1 reasoning trace for a spend-cap policy audit.

    This is the entry point for the ``rot trace --policy`` command (the
    spend-cap / AWS Dogwood vertical slice). It assembles the full
    architecture contract -- timeline with per-step narration, the
    counterexample step path, the spend-cap timeline, the decision tree, and
    provenance with ``n_states`` -- into a deterministic, hashable trace.

    Parameters
    ----------
    ir : rot.ir.ProtocolIR
        The spend-cap protocol IR (for the state space + policy + amounts).
    status : str
        ``"proven"`` / ``"violated"`` / ``"unknown"``.
    witness : dict, optional
        The violating state (e.g. ``{"completed": 0, "inflight": 3}``).
    steps : list, optional
        The ordered step path ``[{"step", "action", "state"}]`` (the attack
        path; empty for a proven verdict).
    n_states : int, optional
        The number of reachable states explored. When ``None``, it is computed
        from the IR's reachable state space.
    budget : rot.license.DepthBudget, optional
        The budget the audit ran under (defaults to the free-tier floor).
    horizon : int, optional
        The bounded-liveness horizon (recorded for provenance; default 12).
    tier : str, optional
        The budget tier (``"free"`` / ``"paid"``); inferred when omitted.
    source_path : str, optional
        The policy file path (recorded for provenance).

    Returns
    -------
    TraceResult
        The deterministic, hashable RTF v1 trace.
    """
    amount = int((ir.metadata or {}).get("amount", 100))
    cap = int((ir.metadata or {}).get("cap", 200))
    max_inflight = (ir.metadata or {}).get("max_inflight")
    buggy = bool((ir.metadata or {}).get("buggy", False))

    reachable_states = _reachable_states(ir)
    if n_states is None:
        n_states = len(reachable_states)

    policy_hash = _ir_policy_hash(ir)
    budget_dict = _budget_dict(budget, tier)
    engines = ["symbolic"]
    horizon_complete = (status != "unknown")

    body = {
        "schema": SCHEMA,
        "manifest_id": manifest_id(policy_hash),
        "rot_version": rot.__version__,
        "verdict": status,
        "engines": engines,
        "horizon": int(horizon),
        "budget": budget_dict,
        "source": {
            "hash": policy_hash,
            "path": source_path,
            "schema": "caravel.dogwood/v1",
        },
        "policy": {
            "property": "spendcap_within_cap",
            "kind": "safety",
            "amount": amount,
            "cap": cap,
            "max_inflight": max_inflight,
            "buggy": buggy,
        },
        "graph": _spendcap_graph(steps, reachable_states, amount),
        "counterexample": _spendcap_counterexample(witness, steps),
        "decision_tree": _spendcap_decision_tree(steps, status, buggy),
        "timeline": _spendcap_timeline(steps, status, amount, cap),
        "narration": _spendcap_narration(status, amount, cap, witness,
                                         n_states),
        "findings": _spendcap_findings(status, witness, amount, cap),
        "compliance": _spendcap_compliance(status),
        "provenance": _provenance(
            engines, budget_dict, horizon, n_states, horizon_complete,
            policy_hash, source_path,
        ),
        "spend": _spend_section(steps, amount, cap, max_inflight,
                                reachable_states),
    }
    return TraceResult(body)

