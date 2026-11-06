# Reference gate — bidirectional conformance report (v2)

Every shipped verdict is replayed against **Dogwood's reference interpreter**
(the pinned `dogwood replay`, commit `4ec5e2c…`) and checked **in both
directions** (spec [`docs/reference-gate.md`](reference-gate.md), WS4):
violations must be real (G1) and proofs must hold (G2). Disagreements block
merges. This is the committed, human-readable copy of
`out/gate/report.md`.

## Gate (first run)

| APW | class | model | outcome |
|-----|-------|-------|---------|
| APW-1 | Settled-sum cap bypass | VIOLATED / PROVEN | **AGREE** |
| APW-2 | Approval replay (approval never consumed) | VIOLATED / PROVEN | **DISAGREE-PROVEN** |
| APW-4 | Distinct-count race | VIOLATED / PROVEN | **LABELED-DIVERGENCE** (waived) |
| APW-3 | Taint race | n/a (no lowering) | **UNKNOWN** |
| APW-5 | Session splitting | n/a (no lowering) | **UNKNOWN** |
| APW-6 | Window-boundary burst | n/a (no lowering) | **UNKNOWN** |

**Gate: exit 1.** APW-2 is an honest DISAGREE-PROVEN (merge-blocking, critical
until fixed or waived); APW-4 is a documented, waived divergence (a pass *with a
warning*, never a silent PASS); APW-3/5/6 are UNKNOWN (never a pass, G6).

## Per-class detail

### APW-1 — Settled-sum cap bypass — AGREE

- **model**: `VIOLATED` (buggy, property `spendcap_within_cap`, witness
  `{"completed":0,"inflight":3}`) / `PROVEN` (correct)
- **policy**: `samples/apw1-buggy.dw` / `samples/apw1-correct.dw`
- **reference (correct)**: @0 ALLOW, @1 ALLOW, @2 DENY, @3 DENY (2 admitted;
  the reflexive window admits the in-cap fires and denies from fire #3)
- **Rules**: G1 PASS, G2 PASS, G3 PASS, G4 PASS — the model's proof and
  violation both match the reference.

### APW-2 — Approval replay — DISAGREE-PROVEN (measured, not waived)

- **model**: `VIOLATED` (buggy, property `approval_single_use`, witness
  `{"approved":true,"orders":2}`) / `PROVEN` (correct)
- **reference (correct)**: witness leg admits 1 (0=DENY, 2=ALLOW, 4=DENY,
  6=DENY); the **concurrent** leg admits **3** (0=DENY, 2=ALLOW, 3=ALLOW,
  4=ALLOW), so the property `approval_single_use` is VIOLATED on the
  reference-admitted events
- **Rules**: G1 PASS, **G2 FAIL**, G3 PASS, G4 PASS
- **Why**: the reference decides each in-flight request against only the
  *settled* history, so one approval admits N concurrent orders; the model
  proves the approval is single-use. This is a real concurrent-replay
  divergence — **measured**, and merge-blocking until the model is fixed or
  the class is waived. It is deliberately *not* waived in
  [`gate/waivers.yaml`](../gate/waivers.yaml) so the gate stays honest.

### APW-4 — Distinct-count race — LABELED-DIVERGENCE (waived)

- **model**: `VIOLATED` (buggy, property `distinct_within_cap`, witness
  `{"distinct":4,"counted":0}`) / `PROVEN` (correct)
- **reference (correct)**: witness leg admits **all 4** (0=ALLOW, 2=ALLOW,
  4=ALLOW, 6=ALLOW); concurrent leg admits 4 — the reference does **not**
  deny the cross-recipient burst
- **Rules**: G1 PASS, **G2 FAIL**, G3 PASS, **G4 FAIL** (the reference never
  denies → vacuous for the global-distinct claim)
- **Why it is a *labeled divergence*, not a defect.** This is the headline,
  not a footnote. Under Dogwood's semantics the "correct" policy enforces a
  **per-recipient (partitioned) cap** — `count … recipient:
  context.input.recipient` shards the aggregate by the pinned key, so each
  recipient is charged ≤ 3. It does **not** enforce a *global* distinct-
  recipient cap. ROTN's model checks the **global distinct** class, which is a
  real bug class. So the reference admitting a cross-recipient burst is a
  **documented semantic difference** between the two engines, not a model bug.
- **Waiver**: `APW-4/G2/nkamoah17` in
  [`gate/waivers.yaml`](../gate/waivers.yaml) (owner `nkamoah17`, expiry
  90 days). An expired waiver fails the gate. The gate reports
  **LABELED-DIVERGENCE — a pass with a warning**, never a silent PASS.

### APW-3 / APW-5 / APW-6 — UNKNOWN (no lowering)

These classes do not yet lower to a reference-interpretable shape (APW-3's
egress is data-dependent; APW-5/6 are concept / forward-looking). Per G6,
**unknown is never a pass**: they are reported UNKNOWN and excluded from the
pass count, labeled as concepts until they lower.

## Honest caveats (empirically verified)

* **default-deny.** The reference is Cedar-default-deny: a `forbid`-only
  policy set can only DENY, so "admits the violation" is shown on the
  **permit** form (the gateway's authorize-action form). ROTN's shape
  detection reads the policy's *intent* (permit/forbid) to disambiguate the
  formerly-gated shape: a **permit** gated on a prior approval event is APW-2;
  a **forbid** on egress after a confidential read is APW-3.
* **reflexive window.** `dogwood replay` includes the current event in its own
  temporal aggregate (spec §6: evaluation at position i reads positions
  j <= i) — the APW-1 correct policy decides the 4 × $100 burst as
  2 ALLOW / 2 DENY (the 3rd request is already over the cap).
* **partition guarantee (the APW-4 reason).** Temporal aggregates are sharded
  by the request's pinned key; APW-4's `count … recipient` is a *per-
  recipient* count in the reference, so the correct policy does not deny the
  cross-recipient burst there. This is the *reason* the gate reports
  APW-4 as a labeled, waived divergence — not a footnote under an `AGREE` row.

---
_Generated by `rot replay --oracle dogwood --gate --bidirectional --profile
dogwood-ref@4ec5e2c` (`rot.gate`); dogwood binary:
`C:\tools\dogwood\target\debug\dogwood.exe` (commit `4ec5e2c…`). A
DISAGREE-PROVEN is a false proof and is merge-blocking (critical). An expired
waiver fails the gate. Regenerate whenever the binary, the fixtures, the
spec, or the waivers change._