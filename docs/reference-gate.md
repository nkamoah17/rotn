# Reference gate v2 — bidirectional conformance with Dogwood

**Status:** proposed. Replaces the one-sided gate described in
`docs/apw-catalog.md` ("Reference-interpreter agreement").

## 1. Purpose

A ROTN verdict is only as good as the model's fidelity to Dogwood's
semantics. This gate requires every shipped verdict to agree with Dogwood's
reference interpreter **in both directions** — violations must be real, and
proofs must hold — and blocks merges when they don't.

## 2. Terms

- **Policy under test:** any `.dw` policy; for APW classes, both the buggy
  and the correct policy.
- **Semantics profile:** a named, versioned set of assumptions, e.g.
  `dogwood-ref@<commit>`: reflexive windows (positions [0, i]),
  observe-before-decide, denied requests recorded in history, trace order =
  ingestion order. Every verdict records its profile.
- **Probe set P(policy):** the traces the gate replays:
  1. ROTN's witness for the buggy policy;
  2. the same witness replayed against the correct policy;
  3. discriminating probes — N sequential decision events up to
     N = cap / amount + 2, and one single over-cap event;
  4. bounded enumeration of request/response interleavings up to the model's
     pool bound K (a fixed-seed sample when the space is too large).
- **Reference verdict:** per-event ALLOW / DENY from `dogwood replay` at the
  pinned commit.
- **Property on a trace:** the pinned invariant (e.g. admitted amount ≤ cap)
  evaluated over the events the reference admitted.

## 3. Rules

- **G1 — Violation soundness.** If ROTN reports VIOLATED with witness w, the
  reference must admit the decisions w relies on, and the property must be
  false on the reference-admitted prefix. Otherwise: DISAGREE-VIOLATED.
- **G2 — Proof soundness.** If ROTN reports PROVEN under bound B, the
  property must hold over the reference-admitted events of every trace in
  P(policy) within B. Otherwise: DISAGREE-PROVEN (a false proof; critical).
- **G3 — Decision agreement.** For every trace in P, ROTN's runtime guard
  must return the same decision as the reference for every decision event.
  Otherwise: DISAGREE-DECISION.
- **G4 — Non-vacuity.** For every permit policy, P must contain at least one
  trace the reference denies and at least one it allows. If the reference
  never denies: VACUOUS (catches predicates that match nothing).
- **G5 — Labeling.** Every verdict artifact records the profile, the engine,
  the bounds, the reference commit and the probe-set hash.
- **G6 — Unknown is never a pass.** A shape that doesn't lower to a
  reference-interpretable form is UNKNOWN: reported, and excluded from the
  pass count.

## 4. Outcomes and CI behavior

| outcome | meaning | merge |
|---|---|---|
| AGREE | G1–G4 hold | pass |
| DISAGREE-PROVEN | ROTN PROVEN; the reference shows a violation | **block (critical)** |
| DISAGREE-VIOLATED | ROTN's witness is not admitted by the reference | block |
| DISAGREE-DECISION | per-event decisions differ | block unless waived |
| VACUOUS | the reference never denies | block |
| LABELED-DIVERGENCE | a documented semantic difference with an active waiver | pass with warning |
| UNKNOWN | shape not reference-interpretable | reported, not a pass |

**Waivers** live in `gate/waivers.yaml`. Each entry names the policy, the
rule, a justification, an owner and an expiry date. An expired waiver fails
the gate.

## 5. CLI (proposed)

~~~
rot replay --oracle dogwood --gate --bidirectional \
    --profile dogwood-ref@<commit> --out out/gate
~~~

Exit codes: `0` all AGREE or waived; `1` any DISAGREE or VACUOUS; `2` UNKNOWN
above the configured threshold; `3` error.

Outputs: `out/gate/report.json` and `out/gate/report.md`, one row per policy:
model verdict, reference verdicts per trace, outcome, profile and hashes.

## 6. Report schema (minimum fields)

`policy`, `policy_sha256`, `apw_class`, `profile`, `reference_commit`,
`engine`, `bounds`, `model_verdict`, `witness`, `probe_set_sha256`,
`traces[]` (`id`, `reference_decisions[]`, `admitted_total`,
`property_holds`), `rules{G1..G4}`, `outcome`, `waiver_id`.

## 7. Expected results when first enabled

| class | expected outcome | action |
|---|---|---|
| APW-1 buggy | DISAGREE-PROVEN at K=1 until the lowering fix; AGREE after | derive the guard from the policy text |
| APW-1 correct | AGREE (reference: 2 ALLOW / 2 DENY on 4 fires) | none |
| APW-2 | measure | — |
| APW-4 correct | DISAGREE-PROVEN (ROTN PROVEN; reference 4 ALLOW / 0 DENY) | fix the model, or relabel: Dogwood's per-key semantics doesn't enforce a global distinct cap |
| APW-3, APW-5, APW-6 | UNKNOWN | label as concept until they lower |

## 8. Optional production leg

The same probe set can run against a live gateway through the
`agentcore_repro/` harness, adding a third column. Production results never
block ROTN merges. They feed the engine-conformance matrix and, for
customers, the gateway conformance attestation. Any production/reference
mismatch follows the disclosure note in `docs/agentcore-repro.md`.

## 9. Pinning and drift

Pin the Dogwood commit and record it in every report. A separate,
non-blocking nightly job reruns the gate against Dogwood's main branch to
detect upstream semantic changes.
