# How to read a replay (the RTF trace)

> **Schema tag:** `caravel.rtf/v1` · **Emitted by:** `rot/trace.py` · **Rendered by:** `site/`
> **Status:** shipped (Phase F/H)

A **replay** is ROTN's answer to *"is this attack real, and how do we know?"* in
two complementary forms:

1. **`rot replay`** (CLI) — re-derives a recorded counterexample
   (`attack.jsonl`) against a policy and reports whether it still holds. This is
   the verification loop that closes the "is this attack real?" question.
2. **The hosted replay** (site) — renders a deterministic, hashed trace (RTF v1)
   as an **interactive proof**: the verdict, the state-space graph, the
   counterexample, the findings, and the controls.

This page is the reader's guide to the second one — how to read a replay on the
site, panel by panel — plus the trace format and the tier model behind it. For
the CLI (`.dw` policy path, `rot replay`, `rot coach`), see
[`spendcap-usage.md`](spendcap-usage.md). For the formal contract, see
[`architecture.md`](architecture.md) §3.

---

## 1. The verdict hero

Every replay opens with a **verdict hero**:

| element | meaning |
|---------|---------|
| **PROVEN / VIOLATED / UNKNOWN** | the gate outcome (below) |
| `RTF v1 · caravel.rtf/v1 · mf-…` | the schema tag + the `manifest_id` (integrity badge) |
| chips: **engines · tier · horizon · K** | which engines ran, the budget tier, the bounded-search horizon, and the concurrency pool `K` (spend-cap only) |
| server / tenant scope / manifest hash | the audited policy and its content hash |
| **Re-verify in your terminal** | the exact `rot trace …` command that reproduces this trace, with a copy button |

**The verdict vocabulary is fixed and fail-closed:**

| verdict | meaning | read it as |
|---------|---------|------------|
| **PROVEN** | every check passed — the policy holds within the verified bounds | safe *within the bound* (see §7 for the honest caveat) |
| **VIOLATED** | a counterexample exists — the policy is broken | a concrete attack path is highlighted in red |
| **UNKNOWN** | the bounded search exhausted its budget before deciding | *never* read as proven — an honest "we could not decide" |

---

## 2. The state-space graph

The Cytoscape graph is the core of the proof:

- **nodes** = reachable states (spend-cap: in-flight / settled; manifest: tools + fields)
- **edges** = the enabled actions (`spend_ok`, `respond`, reads, writes)
- **red path** = the counterexample (the witness path that breaks the property)

Read the graph as the model's state space, and the red path as the *one*
sequence of actions that breaks the policy. That red path **is** the attack.

---

## 3. The counterexample (the "attack script")

The `counterexample` block is the concrete, IR-feasible witness:

| field | meaning |
|-------|---------|
| `steps` | the ordered path `{step, action, state}` — the attack script |
| the final `state` | the violating state (e.g. `completed=0, inflight=3`) |

For the buggy spend-cap policy, the counterexample is a **burst of parallel
`spend_ok` approvals** (before any `respond` settles): each sees `completed=0`
and is admitted, so the in-flight amount grows past the cap. That is the whole
bug in one line.

---

## 4. The audit timeline + narration

The **timeline** is the step-by-step replay: each step carries a human
**narration** line explaining *why the action is enabled* and *what it changes*,
with the crossing moment flagged (`status: fail`). The **narration** panel is
the same reasoning as a single blog-ready paragraph.

Read the timeline the way you'd read a stack trace: the last `fail` step is
where the property breaks, and the steps before it are the setup.

---

## 5. Findings & controls

The **findings** panel lists the Cedar-AR findings — each with `severity`,
`message`, `witness`, `remediation`, and its `controls`. The **compliance**
panel is the same findings projected onto the auditor's vocabulary:

| control | framework | meaning |
|---------|-----------|---------|
| `CC6.1` | SOC 2 | logical access security |
| `CC6.3` | SOC 2 | network security (tenant isolation) |
| `AIUC-1` | AIUC | autonomy — the agent must not act beyond its policy |

See [`compliance.md`](compliance.md) for the full control catalog and the
fail-closed mapping.

---

## 6. The spend-cap timeline (G2)

Spend-cap traces add a **cumulative-spend vs cap** chart with the **crossing
moment highlighted** — the exact step where the cumulative amount exceeds the
cap. This is the visual signature of the bypass.

---

## 7. Provenance (how much did we explore?)

The **provenance** footer is the honest caveat that keeps a `PROVEN` honest:

| field | meaning |
|-------|---------|
| `n_states` | how many reachable states were explored |
| `horizon` / `horizon_complete` | the bounded-search horizon, and whether it was fully explored |
| `budget` / `tier` | the `DepthBudget` that applied (free / standard / enterprise) |
| `engines` | which independent engines ran (`symbolic`, `structural`, SMT, TLC, …) |
| `policy_hash` / `policy_source` | the exact policy that was verified |

**Soundness in the trace:** a `VIOLATED` is only ever accompanied by a
counterexample re-validated as IR-feasible; an `UNKNOWN` is only ever
accompanied by the budget that was exhausted and the honest `horizon_complete`
flag. A `PROVEN` means *holds within the verified bound* — raising the tier can
only turn an `UNKNOWN` into a `PROVEN`/`VIOLATED`, never the reverse. The trace
never hides a gap.

---

## 8. The tier / budget model

Verification depth is **gated by tier**. A tier resolves to a named
**`DepthBudget`** — a bundle of the exact knobs that bound the search:

| knob | meaning |
|------|---------|
| `max_states` | max reachable states the engines may explore before returning `UNKNOWN` |
| `max_horizon` | max steps for bounded liveness / the search horizon |
| `max_tenant_scopes` / `max_tools` | abstraction bounds (recorded assumptions) |

The tier only ever *shrinks or grows the budget* — it never changes the verdict
semantics. A `free`-tier `UNKNOWN` is the same honest "we could not decide" as
an `enterprise`-tier `UNKNOWN`; the difference is how much of the state space
was explored, and that is recorded in the RTF `provenance` so the replay is
always honest about its depth. See [`architecture.md`](architecture.md) §4.

---

## 9. The K-sweep (concurrency bound)

For spend-cap, `K` (`--max-inflight`) is the client-side concurrency pool bound
— a **structural** knob shared by the correct and buggy variants. The bug's
*visibility* depends on it:

| `K` | buggy verdict | why |
|-----|---------------|-----|
| 1 | **PROVEN (masked)** | one in-flight request (100) can never overshoot the 200 cap |
| 2 | VIOLATED | one settled + two in-flight = 300 > 200 |
| ≥3 | VIOLATED | the clean 3-parallel-fire signature |

The **compare** view (`#/compare/spendcap-buggy/spendcap-correct`) puts the
buggy and correct policies side by side and sweeps `K`, so you can watch the
verdict flip at the bound.

---

## 10. Coaching (the third leg)

Spend-cap traces carry the **CoachingArtifact** (`caravel.coach/v1`): the agent
is coached back in bounds *with a proof* —

**detect → explain → correct → re-check → close**

| stage | meaning |
|-------|---------|
| `detect` | the buggy verdict + witness |
| `explain` | the root cause + rationale |
| `correct` | the corrected policy (the guard delta) |
| `recheck` | the corrected policy re-proven safe (PROVEN) |
| `close` | the coaching is discharged |

See [`spendcap-usage.md`](spendcap-usage.md) for the `rot coach` command.

---

## 11. The hash (integrity)

The top-level `hash` is the SHA-256 of the trace's canonical body (sorted keys,
compact separators, no timestamps, no random ids). It pins the *exact*
reasoning, so a trace can be referenced, compared, and re-verified
byte-for-byte. The `manifest_id` (`mf-…`) is derived from it.

Two runs with the same `(policy, environment, tier)` produce **byte-identical**
traces — that is the whole point of the "deterministic, hashed" claim.

---

## 12. Worked example: `spendcap-buggy`

Open the live replay of `spendcap-buggy` and read it in order:

1. **Verdict hero** — `VIOLATED`, `K: 4`, tier `free`, engine `symbolic`,
   `manifest_id mf-4227160622359a2c`.
2. **State-space graph** — the red path is three `spend_ok` approvals in a row
   (in-flight 1 → 2 → 3), no `respond` in between.
3. **Counterexample** — `completed=0, inflight=3`: three parallel fires, each
   seeing `completed=0`.
4. **Spend-cap timeline** — cumulative 100 → 200 → **300**, the crossing at
   step 2.
5. **Findings & controls** — `Overly Permissive` → `CC6.1` + `AIUC-1`.
6. **Coaching** — the guard is corrected from `response` to `request` (charge
   in-flight against the cap) and re-proven `PROVEN`.
7. **Provenance** — `n_states=20`, `horizon=12`, `horizon_complete=true`,
   `policy_source=samples/spendcap-buggy.dw`.

That is a complete, self-contained proof — no server, no runtime, reproducible
byte-for-byte.

---

## Related

- The RTF contract and determinism rules: [`architecture.md`](architecture.md) §3
- The CLI (`.dw` policy path, `rot replay`, `rot coach`): [`spendcap-usage.md`](spendcap-usage.md)
- The demo walkthrough: [`spendcap-demo.md`](spendcap-demo.md)
- The compliance control catalog: [`compliance.md`](compliance.md)
- The manifest format: [`manifest-format.md`](manifest-format.md)

