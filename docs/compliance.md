# Compliance Profile

> **Schema tag:** `caravel.compliance/v1` · **Module:** `rot/compliance.py`
> **Status:** shipped (Phase C)

A **compliance profile** maps the Cedar-AR findings vocabulary
(`rot.mcp_adapter`) to the controls an auditor cares about — **SOC 2**
(AICPA TSC, CC6 = Logical & Physical Access) and **AIUC** (Caravel AI Usage
Control, *autonomy*).

The profile is a **pure leaf module**: no runtime dependencies, imports nothing
from the rest of the package. `rot.mcp_adapter` imports it and attaches the
result to every finding (`controls`) and to the report (`compliance`), so the
`--json` artifact is directly consumable by a SOC 2 / AIUC audit.

The control set is **Caravel-defined and swappable**: swap the
`FINDING_CONTROLS` / `PROPERTY_CONTROLS` tables (or the `AIUC` framework) and
the same findings re-map to a different control set without touching the
finding logic.

---

## 1. Control catalog

### SOC 2 (AICPA TSC) — CC6 = Logical & Physical Access

| ID | Control |
|----|---------|
| `CC6.1` | Logical access security (access controls) |
| `CC6.3` | Network security (tenant isolation) |
| `CC6.6` | Change management / provisioning |

### AIUC (Caravel AI Usage Control) — *autonomy*

| ID | Control |
|----|---------|
| `AIUC-1` | The agent must not act beyond its policy. |

`AIUC-1` is a **Caravel-defined** control (not an external standard). It
captures the *autonomy* property: any condition in which the agent can act
beyond its policy is an autonomy concern, so it applies to **every** finding.

---

## 2. Finding → control mapping

| finding (Cedar-AR) | SOC 2 | AIUC |
|--------------------|-------|------|
| Overly Permissive | `CC6.1` | `AIUC-1` |
|   · `tenant_read_isolation` | `CC6.3` | `AIUC-1` |
| Overly Restrictive | `CC6.6` | `AIUC-1` |
| Ineffective | `CC6.6` | `AIUC-1` |
| contradictions | `CC6.1` | `AIUC-1` |
| unreachable rules | `CC6.6` | `AIUC-1` |

`Overly Permissive` is one finding name with two distinct checks. The
*tenant-isolation* check is a cross-tenant read (data exfil), a
network/tenant-isolation concern (`CC6.3`), not logical access (`CC6.1`).
The *field-permission* check (default) is logical access (`CC6.1`).

The mapping is **fail-closed**: a finding name that cannot be mapped to a
control raises `ValueError` (a bug, not a silent gap).

---

## 3. The `compliance` report section

Every findings report (`--mcp` and `--manifest`) carries a top-level
`compliance` block:

```jsonc
{
  "profile": "caravel.compliance/v1",
  "frameworks": ["SOC2", "AIUC"],
  "result": "violated",
  "controls_touched": ["CC6.1", "AIUC-1"],
  "controls": {
    "CC6.1": "SOC 2 CC6.1 -- Logical access security",
    "AIUC-1": "Caravel AIUC-1 -- Autonomy (agent must not act beyond policy)"
  },
  "evidence": {
    "findings_total": 1,
    "by_control": { "CC6.1": 1, "AIUC-1": 1 }
  }
}
```

| key | meaning |
|-----|---------|
| `profile` | The schema tag (bump on breaking changes to the mapping). |
| `frameworks` | The frameworks this profile maps to. |
| `result` | The gate outcome (`proven` / `violated` / `unknown`). |
| `controls_touched` | The sorted, de-duplicated set of control IDs touched by the findings. |
| `controls` | Human-readable label for each touched control. |
| `evidence.findings_total` | The number of findings. |
| `evidence.by_control` | How many findings touch each control. |

Each finding also carries its own `controls` list (e.g. `["CC6.1", "AIUC-1"]`).

---

## 4. How it feeds the report

`rot.mcp_adapter` imports `rot.compliance` (one-directional — the profile is a
leaf and imports nothing back) and:

1. attaches `controls` to every finding (`Finding.to_dict()`);
2. summarises `compliance` at the report level (`Report.to_dict()`);
3. renders the per-finding `controls:` line in the narrative.

Neither the finding logic nor the gate depends on the control set — the
profile is a *projection* of the findings onto an auditor's vocabulary.