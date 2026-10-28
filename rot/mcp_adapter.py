# -*- coding: utf-8 -*-
"""mcp_adapter.py -- Phase C adoption surface: Trifecta -> Cedar-AR findings.

``rot check`` audits an agent tool policy with the three-facet Trifecta engine
(Safety / Liveness / Conformance) over a bounded state-space exploration and
reports ``PROVEN`` / ``VIOLATED`` / ``UNKNOWN`` per facet.

This module is the **adoption surface**: it translates those *temporal*
verdicts into the Cedar-AR findings vocabulary that AgentCore already applies
to agent tool policies -- **contradictions**, **unreachable rules**,
**Overly Permissive** / **Overly Restrictive**, **Ineffective** (see
``README.md`` "Novelty"). The point of the mapping is *not* to re-implement
those checks, but to speak the same language as the point-in-time static
analyses while backing each finding with what ROTN can add: a concrete
reachable-state **witness**, the **bounded state-space** that was explored, and
an honest ``UNKNOWN`` (``OUT_OF_SCOPE``) when the space was not fully explored.

The mapping is a *pure function* of the :class:`rot.trifecta.TrifectaResult`
plus the raw policy/tool name sets. It adds **no new verification logic** --
the Trifecta engine (``rot.trifecta.audit``) does all the proving; this module
only re-labels the verdicts and assembles a machine- and blog-ready report.

Mapping (a VIOLATED facet becomes a finding; PROVEN/UNKNOWN do not):

    facet         status      -> Cedar-AR finding          severity
    ----------    ----------  --------------------------  --------
    safety        violated    Overly Permissive           error
    liveness      violated    Overly Restrictive          error
    conformance   violated    Ineffective                 warning

plus two structural findings that are pure set checks over the raw names (no
model needed), so the report covers the full Cedar-AR vocabulary:

    check                                    -> Cedar-AR finding      severity
    ---------------------------------------  ---------------------   --------
    allowed ∩ denied != ∅                    contradictions          error
    action/tool not referenced by the other  unreachable rules       warning

Every finding is also mapped to the controls it touches -- **SOC 2** (AICPA
TSC, CC6 = Logical & Physical Access) and **AIUC** (Caravel AI Usage Control,
*autonomy*) -- via :mod:`rot.compliance`. The mapping is attached to each
finding (``controls``) and summarised in the report (``compliance``), so the
``--json`` artifact is directly consumable by a SOC 2 / AIUC audit. The AIUC
control set is Caravel-defined and **swappable** (see ``docs/compliance.md``).

Pure stdlib, Python 3.6 compatible.
"""

import hashlib
import json

import rot.compliance as compliance
import rot.ir as ir
from rot.trifecta import audit, PROVEN, VIOLATED, UNKNOWN

__all__ = [
    # Cedar-AR findings vocabulary (canonical names).
    "FINDING_CONTRADICTIONS",
    "FINDING_UNREACHABLE_RULES",
    "FINDING_OVERLY_PERMISSIVE",
    "FINDING_OVERLY_RESTRICTIVE",
    "FINDING_INEFFECTIVE",
    "FINDING_DEADLOCK",
    "FINDING_LIVELOCK",
    "FINDING_OVER_PRIVILEGED",
    "ALL_FINDINGS",
    "BINDS",
    "bind_finding_for",
    # Severities.
    "SEVERITY_ERROR",
    "SEVERITY_WARNING",
    # Types.
    "Finding",
    "McpFindingsReport",
    # Functions.
    "findings_from_facets",
    "structural_findings",
    "audit_mcp",
    "render_narrative",
    "REPORT_SCHEMA",
]


# ---------------------------------------------------------------------------
# Cedar-AR findings vocabulary (the finding classes AgentCore applies to
# agent tool policies). Canonical names from README.md ("Novelty").
# ---------------------------------------------------------------------------
FINDING_CONTRADICTIONS = "contradictions"
FINDING_UNREACHABLE_RULES = "unreachable rules"
FINDING_OVERLY_PERMISSIVE = "Overly Permissive"
FINDING_OVERLY_RESTRICTIVE = "Overly Restrictive"
FINDING_INEFFECTIVE = "Ineffective"
# G6 binds (liveness + privilege), added to the Cedar-AR findings vocabulary.
FINDING_DEADLOCK = "deadlock"
FINDING_LIVELOCK = "livelock"
FINDING_OVER_PRIVILEGED = "over-privileged tool"

#: The full Cedar-AR findings vocabulary, in a stable (documented) order.
ALL_FINDINGS = (
    FINDING_CONTRADICTIONS,
    FINDING_UNREACHABLE_RULES,
    FINDING_OVERLY_PERMISSIVE,
    FINDING_OVERLY_RESTRICTIVE,
    FINDING_INEFFECTIVE,
    FINDING_DEADLOCK,
    FINDING_LIVELOCK,
    FINDING_OVER_PRIVILEGED,
)

# Severity levels (a finding is either a hard error or a warning).
SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"

#: Stable report schema tag (bump on breaking changes to the report shape).
REPORT_SCHEMA = "rotn.mcp-findings/v1"


# A VIOLATED facet maps to exactly one Cedar-AR finding + severity.
_FACET_TO_FINDING = {
    "safety": (FINDING_OVERLY_PERMISSIVE, SEVERITY_ERROR),
    "liveness": (FINDING_OVERLY_RESTRICTIVE, SEVERITY_ERROR),
    "conformance": (FINDING_INEFFECTIVE, SEVERITY_WARNING),
}

# A short, blog-ready one-liner per finding (used when a facet has no note).
_FINDING_EXPLANATION = {
    FINDING_OVERLY_PERMISSIVE: (
        "a denied action is reachable: the policy permits an action it "
        "should block"
    ),
    FINDING_OVERLY_RESTRICTIVE: (
        "no allowed action is reachable within the horizon: the policy is so "
        "restrictive that the agent is stuck"
    ),
    FINDING_INEFFECTIVE: (
        "no reachable state takes an allowed action: the policy permits "
        "nothing realisable (it is vacuous)"
    ),
    FINDING_CONTRADICTIONS: (
        "an action is both allowed and denied: the policy is "
        "self-contradictory"
    ),
    FINDING_UNREACHABLE_RULES: (
        "a policy action or a catalog tool is not referenced by the other: "
        "the rule can never fire"
    ),
    FINDING_DEADLOCK: (
        "the system reaches a stuck circular-wait state (no action enabled) "
        "and the task never terminates: a deadlock"
    ),
    FINDING_LIVELOCK: (
        "the task never completes or escalates even though the system keeps "
        "making progress: a livelock"
    ),
    FINDING_OVER_PRIVILEGED: (
        "the harness permits a tool the task does not require, so the agent "
        "can take an over-privileged action (an over-grant)"
    ),
}


# ---------------------------------------------------------------------------
# The "binds" table (Product 1: "finds attack paths, binds and bypasses")
# ---------------------------------------------------------------------------
#: The Cedar-AR "binds" ROTN detects, each mapped to the ROTN property that
#: detects it and the registry target that *demonstrates* the violation.  This
#: is the "finds ... binds" claim made real: every row is backed by a property
#: that the model checker verifies (PROVEN on the correct target, VIOLATED on
#: the buggy target) and, where applicable, a reusable stuck-state check
#: (:func:`rot.modelfind.find_deadlock_state`) that separates a *deadlock*
#: (stuck) from a *livelock* (progressing but never terminating).
BINDS = {
    "contradiction": {
        "finding": FINDING_CONTRADICTIONS,
        "property": "policy_conformance",
        "detect": "structural_findings: allowed ∩ denied ≠ ∅",
        "target": None,
    },
    "unreachable rule": {
        "finding": FINDING_UNREACHABLE_RULES,
        "property": "policy_conformance",
        "detect": "structural_findings: a tool not referenced by the policy",
        "target": None,
    },
    "deadlock": {
        "finding": FINDING_DEADLOCK,
        "property": "no_deadlock / task_ends_or_escalates",
        "detect": ("no_deadlock VIOLATED (circular wait reachable) OR a stuck "
                   "state via find_deadlock_state (no action enabled)"),
        "target": "deadlock-buggy",
    },
    "livelock": {
        "finding": FINDING_LIVELOCK,
        "property": "task_ends_or_escalates",
        "detect": ("task_ends_or_escalates VIOLATED (never ends) AND NOT stuck "
                   "(find_deadlock_state finds no stuck state)"),
        "target": "livelock-buggy",
    },
    "over-privileged tool": {
        "finding": FINDING_OVER_PRIVILEGED,
        "property": "no_over_privileged_tool",
        "detect": "no_over_privileged_tool VIOLATED (over-grant witness)",
        "target": "overpriv-buggy",
    },
}

#: Direct map: a ROTN property name -> the Cedar-AR finding it binds.
_PROPERTY_TO_FINDING = {
    "no_deadlock": FINDING_DEADLOCK,
    "task_ends_or_escalates": FINDING_LIVELOCK,
    "no_over_privileged_tool": FINDING_OVER_PRIVILEGED,
    "policy_conformance": FINDING_CONTRADICTIONS,
}


def bind_finding_for(property_name):
    """Map a ROTN property name to the Cedar-AR finding it binds.

    This is the "binds" half of the Product 1 claim: given a property the
    model checker verifies, return the Cedar-AR finding name it corresponds
    to (e.g. ``no_over_privileged_tool`` -> ``over-privileged tool``).

    Parameters
    ----------
    property_name : str
        A ROTN property name (e.g. ``"no_deadlock"``).

    Returns
    -------
    str or None
        The Cedar-AR finding name, or ``None`` if the property does not bind
        a finding.
    """
    return _PROPERTY_TO_FINDING.get(property_name)


def _json_default(obj):
    """JSON fallback for non-serialisable values (witnesses, enums, sets).

    Witnesses are normally plain state dicts (already JSON-serialisable). For
    anything else we prefer a stable ``to_dict()`` when present, then a sorted
    list for sets, then ``repr`` -- so serialisation never raises and stays
    deterministic.
    """
    to_dict = getattr(obj, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    return repr(obj)


def _policy_hash(allowed, denied):
    """SHA-256 of the policy's canonical JSON (stable, order-independent).

    Matches :func:`rot.trifecta.policy_hash` for a valid policy (it hashes
    ``{"allowed": sorted, "denied": sorted}``), so the hash is identical
    whether computed here or by the engine -- including for a contradictory
    policy that :class:`rot.ir.AdversarialPolicy` would refuse to build.
    """
    policy_dict = {
        "allowed": sorted(set(allowed)),
        "denied": sorted(set(denied)),
    }
    policy_json = json.dumps(policy_dict, sort_keys=True,
                            separators=(",", ":"))
    return hashlib.sha256(policy_json.encode("utf-8")).hexdigest()


def _tool_names(tools):
    """Normalise a tools spec to a sorted list of tool names.

    Accepts ``None`` (no catalog), a ``dict`` (``name -> Tool``/meta), a list
    of names, or a set. Returns ``[]`` for ``None``.
    """
    if tools is None:
        return []
    if isinstance(tools, dict):
        names = list(tools.keys())
    else:
        names = list(tools)
    return sorted(set(n for n in names if n))


# ---------------------------------------------------------------------------
# Finding / report types
# ---------------------------------------------------------------------------
class Finding(object):
    """A single Cedar-AR finding derived from the audit.

    Attributes
    ----------
    finding : str
        The Cedar-AR finding name (one of :data:`ALL_FINDINGS`).
    facet : str
        The ROTN facet or check that produced it: ``"safety"``,
        ``"liveness"``, ``"conformance"``, or ``"policy"`` (structural).
    severity : str
        :data:`SEVERITY_ERROR` or :data:`SEVERITY_WARNING`.
    property_name : str
        The ROTN property / check name (e.g. ``policy_conformance``).
    message : str
        A human-readable explanation (blog-ready).
    witness : object or None
        A concrete counterexample (a reachable state, a path, or the
        offending name(s)), when the finding is definite.
    evidence : dict
        Engine evidence (method, bounds, ``n_states``, ...).
    """

    def __init__(self, finding, facet, severity, property_name, message,
                 witness=None, evidence=None):
        if finding not in ALL_FINDINGS:
            raise ValueError("unknown Cedar-AR finding %r" % (finding,))
        if severity not in (SEVERITY_ERROR, SEVERITY_WARNING):
            raise ValueError("bad severity %r" % (severity,))
        self.finding = finding
        self.facet = facet
        self.severity = severity
        self.property_name = property_name
        self.message = message
        self.witness = witness
        self.evidence = evidence or {}

    def to_dict(self):
        return {
            "finding": self.finding,
            "facet": self.facet,
            "severity": self.severity,
            "property": self.property_name,
            "controls": compliance.controls_for(self.finding,
                                                self.property_name),
            "message": self.message,
            "witness": self.witness,
            "evidence": self.evidence,
        }

    def __repr__(self):
        return "Finding(%s, %s, %s)" % (self.finding, self.facet,
                                        self.severity)


class McpFindingsReport(object):
    """The aggregated MCP findings report for one policy audit.

    Attributes
    ----------
    policy : dict
        ``{"allowed": [...], "denied": [...], "hash": "<sha256>"}``.
    tools : list[str]
        The tool catalog names (empty when no catalog was supplied).
    facets : dict
        The three facet verdicts (``safety``/``liveness``/``conformance``),
        each a :meth:`rot.trifecta.FacetVerdict.to_dict` dict, or a
        ``{"status": "skipped", ...}`` stub when the audit could not run.
    findings : list[Finding]
        The Cedar-AR findings (structural + facet-derived), in a stable order.
    any_unknown : bool
        True if any facet was ``UNKNOWN`` (bounded search did not complete).
    """

    def __init__(self, policy, tools, facets, findings, any_unknown=False,
                 note=""):
        self.policy = policy
        self.tools = list(tools or [])
        self.facets = facets
        self.findings = list(findings)
        self.any_unknown = bool(any_unknown)
        self.note = note

    # -- queries -----------------------------------------------------------
    def has_findings(self):
        return len(self.findings) > 0

    def findings_of(self, finding):
        """All findings with the given Cedar-AR name (stable order)."""
        return [f for f in self.findings if f.finding == finding]

    def by_severity(self, severity):
        return [f for f in self.findings if f.severity == severity]

    def result(self):
        """``"proven"`` / ``"violated"`` / ``"unknown"`` (the gate outcome)."""
        if self.has_findings():
            return "violated"
        if self.any_unknown:
            return "unknown"
        return "proven"

    def exit_code(self):
        """Map the report to the CLI exit code (fail-closed, never silent).

        0 = no findings and all facets proven (PASS)
        1 = at least one finding (BLOCK)
        2 = no findings, but some facet is UNKNOWN (OUT_OF_SCOPE)
        """
        if self.has_findings():
            return 1
        if self.any_unknown:
            return 2
        return 0

    # -- serialisation -----------------------------------------------------
    def to_dict(self):
        by_finding = {}
        for f in self.findings:
            by_finding[f.finding] = by_finding.get(f.finding, 0) + 1
        return {
            "schema": REPORT_SCHEMA,
            "policy": self.policy,
            "tools": self.tools,
            "facets": self.facets,
            "findings": [f.to_dict() for f in self.findings],
            "compliance": compliance.compliance_section(self.findings,
                                                        self.result()),
            "summary": {
                "total_findings": len(self.findings),
                "by_finding": by_finding,
                "any_unknown": self.any_unknown,
                "result": self.result(),
                "note": self.note,
            },
        }

    def to_json(self, indent=2):
        """Deterministic JSON (sorted keys) -- the MCP/CI artifact."""
        return json.dumps(self.to_dict(), sort_keys=True, indent=indent,
                          default=_json_default)

    def __repr__(self):
        return "McpFindingsReport(findings=%d, result=%s)" % (
            len(self.findings), self.result())


# ---------------------------------------------------------------------------
# Mapping: structural checks + facet verdicts -> Cedar-AR findings
# ---------------------------------------------------------------------------
def structural_findings(allowed, denied, tools=None):
    """Cedar-AR structural findings: contradictions + unreachable rules.

    These are pure set checks over the raw policy/tool name sets (no model
    required), mirroring the point-in-time checks Cedar-AR performs, so the
    MCP report speaks the *full* Cedar-AR vocabulary.

    Parameters
    ----------
    allowed : list[str]
        The allowed action names.
    denied : list[str]
        The denied action names.
    tools : dict or list, optional
        The tool catalog. When ``None`` (no catalog supplied), the
        "unreachable rules" check is skipped (it is only meaningful against a
        catalog) -- but "contradictions" is always checked.

    Returns
    -------
    list[Finding]
    """
    findings = []
    allowed_set = set(allowed)
    denied_set = set(denied)
    tool_names = _tool_names(tools)

    # 1. Contradictions: an action both allowed and denied. (Always checked.)
    overlap = sorted(allowed_set & denied_set)
    if overlap:
        findings.append(Finding(
            finding=FINDING_CONTRADICTIONS,
            facet="policy",
            severity=SEVERITY_ERROR,
            property_name="allowed_denied_disjoint",
            message=("action(s) in both 'allowed' and 'denied': %s"
                     % ", ".join(overlap)),
            witness={"overlap": overlap},
            evidence={"check": "allowed ∩ denied != ∅"},
        ))

    # 2. Unreachable rules: a policy/catalog mismatch (only with a catalog).
    if tool_names:
        policy_actions = allowed_set | denied_set
        catalog = set(tool_names)
        # 2a. A catalog tool the policy never references (ungoverned tool).
        for t in sorted(catalog - policy_actions):
            findings.append(Finding(
                finding=FINDING_UNREACHABLE_RULES,
                facet="policy",
                severity=SEVERITY_WARNING,
                property_name="tool_governed",
                message=("tool %r is in the catalog but neither allowed nor "
                         "denied by the policy" % t),
                witness={"tool": t},
                evidence={"check": "tool ∉ (allowed ∪ denied)"},
            ))
        # 2b. A policy action with no catalog tool (rule can never fire).
        for a in sorted(policy_actions - catalog):
            findings.append(Finding(
                finding=FINDING_UNREACHABLE_RULES,
                facet="policy",
                severity=SEVERITY_WARNING,
                property_name="action_tool_exists",
                message=("policy action %r has no tool in the catalog" % a),
                witness={"action": a},
                evidence={"check": "action ∉ catalog"},
            ))
    return findings


def findings_from_facets(result):
    """Map a :class:`rot.trifecta.TrifectaResult` to Cedar-AR findings.

    A VIOLATED facet becomes a finding; PROVEN and UNKNOWN facets do not
    (an UNKNOWN is an honest ``OUT_OF_SCOPE``, never read as a finding).

    Returns
    -------
    list[Finding]
    """
    findings = []
    for facet_name in ("safety", "liveness", "conformance"):
        fv = getattr(result, facet_name)
        if not fv.is_violated():
            continue
        finding_name, severity = _FACET_TO_FINDING[facet_name]
        message = fv.note or _FINDING_EXPLANATION[finding_name]
        findings.append(Finding(
            finding=finding_name,
            facet=facet_name,
            severity=severity,
            property_name=fv.property_name,
            message=message,
            witness=fv.witness,
            evidence=dict(fv.evidence),
        ))
    return findings


def _skipped_facets(reason):
    """A placeholder facets map for when the audit cannot run."""
    stub = {"status": "skipped", "note": reason}
    return {
        "safety": dict(stub),
        "liveness": dict(stub),
        "conformance": dict(stub),
    }


def audit_mcp(allowed, denied, tools=None, horizon=12, max_states=200000,
              budget=None):
    """Run the Trifecta audit and map it to the Cedar-AR findings vocabulary.

    This is the single entry point for the ``rot check --mcp`` adoption
    surface. It adds no verification logic of its own: it performs the two
    pure structural checks (contradictions / unreachable rules), runs
    :func:`rot.trifecta.audit` for the three temporal facets, and maps the
    verdicts to Cedar-AR findings.

    Parameters
    ----------
    allowed : list[str]
        The allowed action names.
    denied : list[str]
        The denied action names.
    tools : dict or list, optional
        The tool catalog (``name -> Tool``/meta, or a list of names). When
        given, the structural "unreachable rules" check is enabled.
    horizon : int
        The bounded-liveness horizon (default 12).
    max_states : int
        The state budget for the model finder / symbolic engine (default
        200000).

    Returns
    -------
    McpFindingsReport
    """
    allowed = list(allowed)
    denied = list(denied)
    tool_names = _tool_names(tools)

    # Tier gating (Phase D): a license budget may cap the bounded-search depth
    # (``max_states`` / ``horizon``) and the tool-catalog scope (``max_tools``).
    # An out-of-scope catalog is reported as UNKNOWN (exit 2), never silent.
    note = ""
    if budget is not None:
        # The budget is a *cap*: it can only lower the search depth, never raise
        # it. An explicit --liveness-horizon / --depth can only go lower.
        max_states = min(max_states, budget.max_states)
        horizon = min(horizon, budget.max_horizon)
        if (budget.max_tools is not None
                and len(tool_names) > budget.max_tools):
            note = ("tool catalog has %d tools, exceeding the tier cap of %d; "
                    "audit is out of scope"
                    % (len(tool_names), budget.max_tools))

    policy_info = {
        "allowed": sorted(set(allowed)),
        "denied": sorted(set(denied)),
        "hash": _policy_hash(allowed, denied),
    }

    # 1. Structural findings (pure set checks; no model needed).
    findings = structural_findings(allowed, denied, tools)

    # 2. Contradictions make the policy invalid -- AdversarialPolicy would
    #    raise, so there is no sound audit to run. Report and stop.
    if findings and findings[0].finding == FINDING_CONTRADICTIONS:
        return McpFindingsReport(
            policy=policy_info,
            tools=tool_names,
            facets=_skipped_facets("the policy is contradictory"),
            findings=findings,
            any_unknown=False,
            note=note,
        )

    # 3. Build the policy and run the three-facet (temporal) audit.
    policy = ir.AdversarialPolicy(allowed=allowed, denied=denied)
    result = audit(policy, buggy=False, horizon=horizon, max_states=max_states)

    # 4. Map each VIOLATED facet to its Cedar-AR finding.
    findings.extend(findings_from_facets(result))

    facets = {
        "safety": result.safety.to_dict(),
        "liveness": result.liveness.to_dict(),
        "conformance": result.conformance.to_dict(),
    }
    any_unknown = (result.safety.is_unknown()
                   or result.liveness.is_unknown()
                   or result.conformance.is_unknown())
    if note:
        any_unknown = True

    return McpFindingsReport(
        policy=policy_info,
        tools=tool_names,
        facets=facets,
        findings=findings,
        any_unknown=any_unknown,
        note=note,
    )

# ---------------------------------------------------------------------------
# MCP Manifest v1 (Phase B, B2): field/tenant structural checks
# ---------------------------------------------------------------------------

def _field_tenant(field):
    """The tenant a field is namespaced under, or ``None`` if it is global.

    A field namespaced under a tenant uses the same ``tenant:<id>`` namespace
    as ``tenant_scope`` (e.g. ``tenant:acme.account.balance``). A field with
    no such prefix (e.g. ``account.balance``) is *global* (shared data) and
    belongs to no tenant, so it is never a cross-tenant read.
    """
    if isinstance(field, str) and field.startswith("tenant:"):
        rest = field[len("tenant:"):]
        dot = rest.find(".")
        return "tenant:" + (rest[:dot] if dot >= 0 else rest)
    return None


def _is_cross_tenant(field, scope):
    """True if reading ``field`` is *outside* the tool's ``scope``.

    A global field (no tenant namespace) is never cross-tenant. A
    tenant-namespaced field is cross-tenant unless its tenant is exactly the
    tool's effective ``scope`` (a ``None`` scope means the tool is not bound
    to any tenant, so a tenant-namespaced read is out of scope).
    """
    ft = _field_tenant(field)
    if ft is None:
        return False
    return ft != scope


def _manifest_hash(manifest):
    """A deterministic SHA-256 over the manifest's canonical dict."""
    import hashlib
    canonical = json.dumps(manifest.to_dict(), sort_keys=True,
                           default=_json_default)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def manifest_findings(manifest):
    """Cedar-AR structural findings for an MCP Manifest v1.

    Two checks, both **Overly Permissive**:

    * **field permission** -- a tool's ``write_fields`` must be a subset of
      the manifest's ``allowed_write_fields`` (the tenant's write set).
      ``write_fields ⊄ allowed_write_fields`` -> Overly Permissive. (An
      empty/absent write set permits no writes -- fail-closed.)
    * **tenant isolation** -- a tool's ``read_fields`` must stay within its
      (effective) ``tenant_scope``. A read field namespaced under a *different*
      tenant is a cross-tenant read -> Overly Permissive.

    Parameters
    ----------
    manifest : rot.mcp_manifest.McpManifest
        A validated manifest (see :mod:`rot.mcp_manifest`).

    Returns
    -------
    list[Finding]
        The findings in a stable order (tools in manifest order; field
        permission before tenant isolation per tool).
    """
    findings = []
    allowed_write = set(manifest.allowed_write_fields)

    for tool in manifest.tools:
        scope = manifest.effective_tenant_scope(tool)

        # 1. Field permission: write_fields must be a subset of the write set.
        over_write = sorted(set(tool.write_fields) - allowed_write)
        if over_write:
            findings.append(Finding(
                finding=FINDING_OVERLY_PERMISSIVE,
                facet="policy",
                severity=SEVERITY_ERROR,
                property_name="field_write_permission",
                message=("tool %r writes field(s) %s not in the tenant's "
                         "allowed write set %s"
                         % (tool.name, over_write, sorted(allowed_write))),
                witness={
                    "tool": tool.name,
                    "write_fields": list(tool.write_fields),
                    "allowed_write_fields": sorted(allowed_write),
                    "over_permission": over_write,
                },
                evidence={"check": "write_fields ⊆ allowed_write_fields"},
            ))

        # 2. Tenant isolation: read_fields must stay within tenant_scope.
        cross = sorted(f for f in tool.read_fields
                       if _is_cross_tenant(f, scope))
        if cross:
            findings.append(Finding(
                finding=FINDING_OVERLY_PERMISSIVE,
                facet="policy",
                severity=SEVERITY_ERROR,
                property_name="tenant_read_isolation",
                message=("tool %r reads cross-tenant field(s) %s outside its "
                         "tenant_scope %r"
                         % (tool.name, cross, scope)),
                witness={
                    "tool": tool.name,
                    "read_fields": list(tool.read_fields),
                    "tenant_scope": scope,
                    "cross_tenant_fields": cross,
                },
                evidence={"check": "read_fields within tenant_scope"},
            ))

    return findings


def audit_manifest(manifest, budget=None):
    """Run the MCP Manifest v1 structural audit (Phase B, B2).

    This is the single entry point for the ``rot check --manifest`` adoption
    surface. It performs the two pure structural checks (field permission and
    tenant isolation) over the manifest's tool catalog and maps them to the
    Cedar-AR ``Overly Permissive`` finding. It does not run the temporal
    (three-facet) audit -- that is the ``--mcp`` (allowed/denied) surface.

    Parameters
    ----------
    manifest : rot.mcp_manifest.McpManifest
        A validated manifest (see :mod:`rot.mcp_manifest`).
    budget : rot.license.DepthBudget, optional
        A tier budget (Phase D). When present, ``max_tenant_scopes`` caps the
        number of distinct tenant scopes the audit may reason about; exceeding
        it marks the audit out of scope (UNKNOWN / exit 2).

    Returns
    -------
    McpFindingsReport
        The findings report (``facets`` are ``skipped`` stubs -- the manifest
        audit is structural, not temporal).
    """
    findings = manifest_findings(manifest)

    # Tier gating (Phase D): cap the number of distinct tenant scopes.
    note = ""
    if budget is not None and budget.max_tenant_scopes is not None:
        tenants = set()
        if manifest.tenant_scope:
            tenants.add(manifest.tenant_scope)
        for tool in manifest.tools:
            for field in list(tool.read_fields) + list(tool.write_fields):
                t = _field_tenant(field)
                if t:
                    tenants.add(t)
        if len(tenants) > budget.max_tenant_scopes:
            note = ("manifest references %d tenant scopes, exceeding the tier "
                    "cap of %d; audit is out of scope"
                    % (len(tenants), budget.max_tenant_scopes))

    policy_info = {
        "server": manifest.server,
        "version": manifest.version,
        "tenant_scope": manifest.tenant_scope,
        "allowed_write_fields": sorted(manifest.allowed_write_fields),
        "hash": _manifest_hash(manifest),
    }
    return McpFindingsReport(
        policy=policy_info,
        tools=manifest.tool_names(),
        facets=_skipped_facets(
            "manifest audit is structural (no temporal model)"),
        findings=findings,
        any_unknown=bool(note),
        note=note,
    )


# ---------------------------------------------------------------------------
# Human-readable (blog-ready) rendering
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Human-readable (blog-ready) rendering
# ---------------------------------------------------------------------------
def render_narrative(report):
    """Render a human-readable (blog-ready) narrative of the report.

    The narrative leads with the gate outcome (PASS / BLOCK / OUT_OF_SCOPE),
    then lists each Cedar-AR finding with its facet, property, message, and
    witness -- the same content as the JSON artifact, in prose.
    """
    lines = []
    lines.append("ROTN MCP findings  (Cedar-AR vocabulary, temporal proof)")
    lines.append("=" * 52)
    policy = report.policy or {}
    is_manifest = ("allowed" not in policy and "denied" not in policy)
    if is_manifest:
        # A manifest report (Phase B, B2) carries manifest provenance.
        lines.append("manifest server=%s  version=%s"
                     % (policy.get("server"), policy.get("version")))
        lines.append("         tenant_scope=%s  allowed_write_fields=%s"
                     % (policy.get("tenant_scope"),
                        policy.get("allowed_write_fields", [])))
    else:
        lines.append("policy   allowed=%s" % (policy.get("allowed", []),))
        lines.append("         denied=%s" % (policy.get("denied", []),))
    if report.tools:
        lines.append("tools    %s" % ", ".join(report.tools))
    lines.append("")

    if not report.has_findings():
        if report.any_unknown:
            lines.append("RESULT: OUT_OF_SCOPE -- the bounded search did not "
                         "complete; no definite finding, but not a proof")
        elif is_manifest:
            lines.append("RESULT: PASS -- field and tenant structural checks "
                         "clean; no Cedar-AR findings")
        else:
            lines.append("RESULT: PASS -- all three facets proven; no "
                         "Cedar-AR findings")
        lines.append("")
        lines.append("Cedar-AR findings: none")
        return "\n".join(lines)

    lines.append("RESULT: BLOCK -- %d Cedar-AR finding(s)"
                 % len(report.findings))
    lines.append("")
    for f in report.findings:
        lines.append("[%s] %s" % (f.severity.upper(), f.finding))
        lines.append("    facet: %s   property: %s"
                     % (f.facet, f.property_name))
        lines.append("    controls: %s"
                     % ", ".join(compliance.controls_for(
                         f.finding, f.property_name)))
        lines.append("    %s" % f.message)
        if f.witness is not None:
            witness_json = json.dumps(f.witness, sort_keys=True,
                                      default=_json_default)
            if len(witness_json) > 160:
                witness_json = witness_json[:157] + "..."
            lines.append("    witness: %s" % witness_json)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"