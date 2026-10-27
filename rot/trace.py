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


def _counterexample(report, trifecta=None):
    """The concrete counterexample (witness) for a violated verdict.

    Prefer the first error-severity finding's witness (the structural
    violation). When none, fall back to a temporal facet's witness. ``None``
    for a proven / unknown verdict (no counterexample to show).
    """
    if report is not None:
        for finding in report.findings:
            if finding.severity == "error" and finding.witness is not None:
                return finding.witness
    if trifecta is not None:
        for facet_name in ("safety", "liveness", "conformance"):
            fv = getattr(trifecta, facet_name, None)
            if fv is not None and fv.is_violated() and fv.witness is not None:
                return fv.witness
    return None


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


def _timeline(report):
    """The ordered audit steps (stable, deterministic)."""
    steps = [{"step": "parse_manifest", "status": "ok"}]
    for check in _MANIFEST_CHECKS:
        findings = [f for f in report.findings
                    if f.property_name == check]
        steps.append({
            "step": check,
            "status": "fail" if findings else "pass",
            "findings": len(findings),
        })
    steps.append({"step": "verdict", "status": report.result()})
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

    manifest_hash = (report.policy or {}).get("hash")
    if not manifest_hash:
        manifest_hash = mcp._manifest_hash(manifest)

    body = {
        "schema": SCHEMA,
        "manifest_id": manifest_id(manifest_hash),
        "rot_version": rot.__version__,
        "verdict": report.result(),
        "engines": _engines(report, trifecta),
        "horizon": int(horizon),
        "budget": _budget_dict(budget, tier),
        "source": {
            "hash": manifest_hash,
            "path": source_path,
            "schema": manifest.manifest,
        },
        "policy": dict(report.policy or {}),
        "graph": _graph(manifest),
        "counterexample": _counterexample(report, trifecta),
        "decision_tree": _decision_tree(report),
        "timeline": _timeline(report),
        "narration": mcp.render_narrative(report),
        "findings": [f.to_dict() for f in report.findings],
    }
    return TraceResult(body)

