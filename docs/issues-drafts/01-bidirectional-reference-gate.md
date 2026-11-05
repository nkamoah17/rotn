# Gate: make the reference-interpreter gate bidirectional (both legs, labeled divergences, waivers, CI)

## Problem

The current gate (`rot replay --oracle dogwood --gate`, `rot/oracle.py`)
is **one-sided**: it requires the buggy policy to be admitted in the
reference while ROTN reports `VIOLATED` — and that is the whole rule.
Concretely:

- the **correct-policy leg** is recorded but not gated. APW-4's correct
  policy decides 4 ALLOW / 0 DENY in the reference (the partition
  guarantee shards `count … recipient` into a *per-recipient* count), yet
  the gate row reads `AGREE` — the divergence is visible only in the
  "Honest caveats" footnote;
- there is no first-class outcome for a **labeled divergence**, no waiver
  mechanism, and no pin of *which reference* the claims are made against
  (the report footer records the binary path, not a spec version);
- the gate is not in CI: the binary is not on the runner, and building
  Dogwood there is untested.

## Proposal

A bidirectional gate (C4 in the v0.2.0 plan):

1. **Pin the spec.** Save the Dogwood spec / semantics the gate relies on
   verbatim (`docs/reference-gate.md`) and record a profile id in every
   report (`dogwood-ref@4ec5e2c01b44ff3882a231ae5d315b330b38fa25`).
2. **New `rot/gate.py`:**
   - `SemanticsProfile` (binary path + spec commit + the semantics notes:
     reflexive windows, observe-before-decide, partition guarantee);
   - probe set **P**: the witness trace, witness-vs-correct, N =
     cap/amount+2 sequential, the over-cap single, and bounded
     interleavings ≤ K with fixed-seed sampling;
   - rules **G1–G6** (per-class agreement on *both* legs + report
     well-formedness);
   - outcomes: `AGREE`, `DIVERGENCE` (fail), `LABELED-DIVERGENCE` (pass
     *with warning*, only under a valid waiver), `UNKNOWN`;
   - `gate/waivers.yaml` — strict-subset parser (`class`, `rule`,
     `owner`, `expiry`, `reason`); **expired ⇒ fail**;
   - reports: `out/gate/report.json` + `out/gate/report.md` (schema fixed
     in the spec);
   - exit codes: `0` pass · `1` fail · `2` unknown/inconclusive · `3`
     error.
3. **CLI:** `rot replay --oracle dogwood --gate --bidirectional
   --profile … --out out/gate` — v2 becomes the default; the one-sided
   mode is kept for back-compat.
4. **CI:** a merge-blocking `reference-gate` job (Rust build of
   `dogwood-policy/dogwood @ 4ec5e2c…`, set `DOGWOOD_BIN`, fail on exit
   1) + a nightly drift job per spec §9 (upstream `main`, re-run the
   gate, report-only). The stdlib job stays binary-free.
5. **Tests:** G1–G6 with fake decision streams, waiver parse/expiry, exit
   codes, report schema (binary legs skippable per the existing
   convention).
6. **Docs:** catalog gate section + "Reproducing the catalog" updated,
   `docs/reference-replay.md` regenerated, README "Go deeper" points at
   the spec.

## First-run expectation (honest baseline)

| class | expected outcome |
|---|---|
| APW-1 | AGREE |
| APW-2 | measured (AGREE expected) |
| APW-4 | LABELED-DIVERGENCE (waived — see ②, the APW-4 issue) |
| APW-3 / 5 / 6 | UNKNOWN (out of gate scope; 5/6 are concept / pre-ship) |

## Acceptance

- [ ] the gate passes on **both** legs for every non-waived class
- [ ] APW-4 reports `LABELED-DIVERGENCE` with the waiver id (never a bare
      `AGREE`/`PASS`)
- [ ] an expired waiver ⇒ exit 1
- [ ] the CI `reference-gate` job is green (or a documented fallback:
      prebuilt-binary artifact)
- [ ] `docs/reference-gate.md` + regenerated `docs/reference-replay.md`
      committed
