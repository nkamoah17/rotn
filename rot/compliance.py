# -*- coding: utf-8 -*-
"""compliance.py -- Phase C: map Cedar-AR findings to SOC 2 / AIUC controls.

A *compliance profile* is a pure, deterministic mapping from the Cedar-AR
findings vocabulary (see :mod:`rot.mcp_adapter`) to the controls an auditor
cares about -- **SOC 2** (AICPA TSC, CC6 = Logical & Physical Access) and
**AIUC** (Caravel AI Usage Control, *autonomy*).

The profile is a **leaf module**: it has no runtime dependencies and imports
nothing from the rest of the package. :mod:`rot.mcp_adapter` imports it and
attaches the result to every finding (``controls``) and to the report
(``compliance``), so the ``--json`` artifact is directly consumable by a
SOC 2 / AIUC audit.

Control catalog
---------------

SOC 2 (AICPA TSC) -- CC6 = Logical & Physical Access:

    CC6.1   Logical access security (access controls)
    CC6.3   Network security (tenant isolation)
    CC6.6   Change management / provisioning

AIUC (Caravel AI Usage Control) -- *autonomy*, **swappable**:

    AIUC-1  The agent must not act beyond its policy.

Finding -> control mapping
--------------------------

    finding (Cedar-AR)         SOC 2   AIUC
    -------------------------  -----   -----
    Overly Permissive          CC6.1   AIUC-1
      * tenant_read_isolation  CC6.3   AIUC-1   (cross-tenant read)
    Overly Restrictive         CC6.6   AIUC-1
    Ineffective                CC6.6   AIUC-1
    contradictions             CC6.1   AIUC-1
    unreachable rules          CC6.6   AIUC-1

``AIUC-1`` applies to **every** finding: any condition in which the agent can
act beyond its policy is an autonomy concern. ``Overly Permissive`` is one
finding name with two distinct checks; the *tenant-isolation* check is a
cross-tenant read (data exfil), which is a network/tenant-isolation concern
(``CC6.3``), not logical access (``CC6.1``).

Pure stdlib, Python 3.6 compatible.  See ``docs/compliance.md``.
"""

__all__ = [
    "COMPLIANCE_PROFILE",
    "FRAMEWORKS",
    "SOC2_CC61",
    "SOC2_CC63",
    "SOC2_CC66",
    "AIUC_1",
    "CONTROL_LABELS",
    "AIUC_1_DEFINITION",
    "FINDING_CONTROLS",
    "PROPERTY_CONTROLS",
    "controls_for",
    "controls_touched",
    "compliance_section",
]

#: The compliance profile schema tag (bump on breaking changes to the mapping).
COMPLIANCE_PROFILE = "caravel.compliance/v1"

#: The frameworks this profile maps findings to.
FRAMEWORKS = ("SOC2", "AIUC")

# ---------------------------------------------------------------------------
# Control IDs
# ---------------------------------------------------------------------------
#: SOC 2 (AICPA TSC) CC6.1 -- Logical access security (access controls).
SOC2_CC61 = "CC6.1"
#: SOC 2 (AICPA TSC) CC6.3 -- Network security (tenant isolation).
SOC2_CC63 = "CC6.3"
#: SOC 2 (AICPA TSC) CC6.6 -- Change management / provisioning.
SOC2_CC66 = "CC6.6"
#: Caravel AI Usage Control AIUC-1 -- Autonomy (the agent must not act beyond
#: its policy).
AIUC_1 = "AIUC-1"

#: Human-readable label for each control (for the report + docs).
CONTROL_LABELS = {
    SOC2_CC61: "SOC 2 CC6.1 -- Logical access security",
    SOC2_CC63: "SOC 2 CC6.3 -- Network security (tenant isolation)",
    SOC2_CC66: "SOC 2 CC6.6 -- Change management / provisioning",
    AIUC_1: "Caravel AIUC-1 -- Autonomy (agent must not act beyond policy)",
}

#: The AIUC-1 control definition (Caravel AI Usage Control, *autonomy*).
#:
#: This is a **Caravel-defined, swappable** control set (not a published
#: standard). The ``attributes`` below are its *default* values; an
#: organization can swap in its own autonomy policy without changing the
#: finding -> control mapping. ``AIUC-1`` is triggered by any finding in
#: which the agent can act beyond its policy.
AIUC_1_DEFINITION = {
    "id": AIUC_1,
    "name": "Caravel AI Usage Control -- Autonomy",
    "swappable": True,
    "trigger": "any finding in which the agent can act beyond its policy",
    "attributes": {
        "autonomy_level": "supervised",  # advisory | supervised | autonomous
        "human_in_the_loop": True,
        "approval_required_for": ["destructive"],
        "max_autonomous_actions": 0,
    },
}

# ---------------------------------------------------------------------------
# Finding -> control mapping
# ---------------------------------------------------------------------------
#: Base mapping: Cedar-AR finding name -> (SOC 2 control, AIUC control).
#:
#: Keyed by the canonical finding names (see
#: :data:`rot.mcp_adapter.ALL_FINDINGS`). Every finding maps to ``AIUC-1``.
FINDING_CONTROLS = {
    "Overly Permissive": (SOC2_CC61, AIUC_1),
    "Overly Restrictive": (SOC2_CC66, AIUC_1),
    "Ineffective": (SOC2_CC66, AIUC_1),
    "contradictions": (SOC2_CC61, AIUC_1),
    "unreachable rules": (SOC2_CC66, AIUC_1),
}

#: Property-level refinement: a specific check refines the SOC 2 control for
#: a generic finding. ``Overly Permissive`` is one finding name with two
#: distinct checks; the *tenant-isolation* check is a cross-tenant read,
#: which is a network/tenant-isolation concern (``CC6.3``), not logical
#: access (``CC6.1``).
PROPERTY_CONTROLS = {
    "tenant_read_isolation": (SOC2_CC63, AIUC_1),
}


def controls_for(finding, property_name=None):
    """Return the ordered list of control IDs for one finding.

    The control is a function of both the Cedar-AR finding name and -- where
    the finding is the generic ``Overly Permissive`` -- the specific check
    (``property_name``) that produced it:

    * ``field_write_permission`` -> ``CC6.1`` (logical access)
    * ``tenant_read_isolation``  -> ``CC6.3`` (network / tenant isolation)

    ``AIUC-1`` (autonomy) applies to every finding: any condition in which the
    agent can act beyond its policy is an autonomy concern.

    Parameters
    ----------
    finding : str
        A Cedar-AR finding name (one of :data:`rot.mcp_adapter.ALL_FINDINGS`).
    property_name : str, optional
        The specific check that produced the finding (refines the SOC 2
        control for ``Overly Permissive``).

    Returns
    -------
    list[str]
        A stable, de-duplicated, ordered list of control IDs (e.g.
        ``["CC6.1", "AIUC-1"]``).

    Raises
    ------
    ValueError
        If ``finding`` is not a known Cedar-AR finding name (fail-closed: a
        finding that cannot be mapped to a control is a bug, not a silent
        gap).
    """
    base = FINDING_CONTROLS.get(finding)
    if base is None:
        raise ValueError("unknown Cedar-AR finding %r" % (finding,))
    soc2, aiuc = base
    if property_name in PROPERTY_CONTROLS:
        soc2, aiuc = PROPERTY_CONTROLS[property_name]
    controls = []
    for control in (soc2, aiuc):
        if control not in controls:
            controls.append(control)
    return controls


def controls_touched(findings):
    """The sorted union of control IDs across a list of findings.

    Parameters
    ----------
    findings : iterable
        Cedar-AR findings (each with ``.finding`` and ``.property_name``).

    Returns
    -------
    list[str]
        The sorted, de-duplicated set of control IDs touched.
    """
    touched = set()
    for finding in findings:
        touched.update(controls_for(
            finding.finding, getattr(finding, "property_name", None)))
    return sorted(touched)


def compliance_section(findings, result):
    """Build the top-level ``compliance`` block for a findings report.

    Parameters
    ----------
    findings : iterable
        Cedar-AR findings (each with ``.finding`` and ``.property_name``).
    result : str
        The gate outcome (``"proven"`` / ``"violated"`` / ``"unknown"``).

    Returns
    -------
    dict
        A deterministic, JSON-serialisable compliance section::

            {
              "profile": "caravel.compliance/v1",
              "frameworks": ["SOC2", "AIUC"],
              "result": "violated",
              "controls_touched": ["CC6.1", "AIUC-1"],
              "controls": {
                "CC6.1": "SOC 2 CC6.1 -- Logical access security",
                "AIUC-1": "Caravel AIUC-1 -- Autonomy (...)"
              },
              "evidence": {
                "findings_total": 1,
                "by_control": {"CC6.1": 1, "AIUC-1": 1}
              }
            }
    """
    findings = list(findings)
    by_control = {}
    for finding in findings:
        for control in controls_for(
                finding.finding, getattr(finding, "property_name", None)):
            by_control[control] = by_control.get(control, 0) + 1
    touched = controls_touched(findings)
    return {
        "profile": COMPLIANCE_PROFILE,
        "frameworks": list(FRAMEWORKS),
        "result": result,
        "controls_touched": touched,
        "controls": dict((c, CONTROL_LABELS[c]) for c in touched),
        "evidence": {
            "findings_total": len(findings),
            "by_control": dict(sorted(by_control.items())),
        },
    }