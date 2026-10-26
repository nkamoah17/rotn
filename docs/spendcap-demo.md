# ROTN — Spend-cap demo (AWS Dogwood `.dw` policies)

The spend-cap demo is the shortest end-to-end story in ROTN: **one policy
family, one pinned safety invariant, one seeded one-word bug.** Two `.dw`
policies differ by exactly one word — `request` vs. `response` — and ROTN
discriminates them: the correct policy is **PROVEN**, the buggy one is
**VIOLATED** with a concrete counterexample. A third phase runs the
three-facet audit and emits a deterministic, integrity-checkable manifest.
A fourth phase cross-checks the verdict with three engines (SMT/Z3 + TLC +
policy-direct) and curates a compact report with an Apalache ITF witness.

```
  spendcap-correct.dw ─► --policy ─► rot.frontends.policy (dw) ─► IR (safety)
  spendcap-buggy.dw   ─► --policy ─► rot.frontends.policy (dw) ─► IR (safety)
      │                                                                 │
      ▼                                                                 ▼
  PROVEN (exit 0)                                          VIOLATED (exit 1) + witness

  --trifecta --manifest ─► rot.trifecta + rot.manifest ─► out/trifecta_manifest.json
                           + rot.trifecta_risk           ─► out/trifecta_risk.json (D6 flag)
```

Everything is pure stdlib, Python 3.6-compatible, offline and deterministic.
No Java and no TLC jar are required.

## The five phases

| phase | command (short form) | expected | what it shows |
|-------|----------------------|----------|---------------|
| 1 | `--policy .../spendcap-correct.dw` | exit 0 — **PROVEN** | settled + in-flight amount never exceeds the cap |
| 2 | `--policy .../spendcap-buggy.dw`   | exit 1 — **VIOLATED** | a parallel-fire burst overshoots the cap (witness emitted) |
| 3 | `--trifecta --manifest --out out`  | exit 0 — **PROVEN** | three-facet audit (safety + liveness + conformance) + deterministic manifest + D6 risk flag (CLEAR) |
| 4 | `--policy .../spendcap-buggy.dw --engine crosscheck` | exit 1 — **VIOLATED** | SMT/Z3 **and** TLC agree on the counterexample (skipped if TLC absent) |
| 5 | `--policy .../spendcap-buggy.dw --max-inflight {1,2,3}` | 0, 1, 1 | **K-dependence**: K=1 masks the bug, K≥2 exposes it (witness shape tracks K) |

## Run it

PowerShell (Windows):

```powershell
.\demo.ps1                 # symbolic engine (offline); manifest in out/
.\demo.ps1 -Engine auto    # TLC if java + tla2tools.jar are present
.\demo.ps1 -Out out-demo   # custom output dir for the phase-3 manifest
```

bash (Linux/macOS):

```bash
bash demo.sh               # symbolic engine (offline); manifest in out/
ENGINE=tlc bash demo.sh    # cross-check phases 1-2 with the real TLC
OUT=out-demo bash demo.sh  # custom output dir for the phase-3 manifest
```

Both scripts are **exit-code aware**: each phase asserts the *expected*
pipeline exit code (0 for proven, 1 for violated), prints a `[PASS]` /
`[FAIL]` line, and the script exits 0 only if all three phases match.
Phase 3 additionally verifies the manifest's integrity (the SHA-256
`manifest_id` must match the recomputed body hash) and the D6 risk flag
(`out/trifecta_risk.json` must be present and `clear` for the demo policy).

Or run the three phases by hand (full reference in
[`spendcap-usage.md`](spendcap-usage.md)):

```bash
# Phase 1 -- PROVEN (exit 0)
python pipeline.py --policy tests/fixtures/aws_dogwood/spendcap/policies/spendcap-correct.dw

# Phase 2 -- VIOLATED (exit 1, witness emitted)
python pipeline.py --policy tests/fixtures/aws_dogwood/spendcap/policies/spendcap-buggy.dw

# Phase 3 -- three-facet audit + manifest (exit 0)
python pipeline.py --trifecta \
    --allowed read_log,update_balance \
    --denied exfiltrate_secret \
    --manifest --out out
```

## Why the bug is one word

The service approves spend requests (`Transfer::request`) and settles them
asynchronously. The safety invariant `spendcap_within_cap` requires

```
completed + inflight·AMOUNT <= CAP        (CAP = 200)
```

in **every** reachable state. The cap must count *in-flight* (approved but
not yet settled) transfers — otherwise a parallel burst slips past the cap.

| policy | sums over | effect |
|--------|-----------|--------|
| `spendcap-correct.dw` | `Transfer::request` rows | in-flight requests count against the cap — a 3rd 100-unit fire in a burst is **DENY** |
| `spendcap-buggy.dw`   | `Transfer::response` rows | in-flight requests are invisible — 3 parallel 100-unit fires all permit, committing 300 > 200 |

ROTN's counterexample for the buggy policy is exactly that race:
`completed=0, inflight=3` — the cap is exceeded while all three transfers
are still in flight.

## What Phase 3 adds

`--trifecta` audits an agent action policy (`--allowed` / `--denied`)
across three independent facets on the `AgentStep` model:

| facet | checker | question |
|-------|---------|----------|
| `safety` | `forall_reachable` | does the agent *never* take a denied action? |
| `liveness` | `reach_within` (horizon) | does the agent commit to an allowed action *within* the horizon? |
| `conformance` | `exists_reachable` | does the policy permit *at least one* concrete action? (non-vacuity) |

`--manifest` writes the result to `out/trifecta_manifest.json`: a
deterministic report (schema v1) carrying the policy hash, environment,
per-facet verdicts, the witness, the overall result, and a `manifest_id`
(SHA-256 over the canonical body) so a re-run must reproduce the exact same
id — the integrity check `demo.ps1` / `demo.sh` run in Phase 3.

Phase 3 also runs the **D6 "Lethal Trifecta" risk flag**
(`rot.trifecta_risk`): a static, design-time capability check over the
policy's full action set (`allowed ∪ denied`) — no engine, no model
checking, no soundness claim. It prints one line in the summary and (with
`--manifest`) is written to `out/trifecta_risk.json` (deterministic):

| facets present in the action set | flag |
|----------------------------------|------|
| all three: `private-data-access` + `untrusted-content-intake` + `egress` | `TRIFECTA: detected (facets: private-data-access, untrusted-content-intake, egress)` |
| any facet missing | `TRIFECTA: clear` |

The demo policy is **CLEAR** by design: `read_log` / `update_balance` give
private-data-access and `exfiltrate_secret` gives egress, but no action
ingests untrusted external content — two of three facets, so the flag must
not fire. That is the calibration check `demo.ps1` / `demo.sh` assert in
Phase 3. A policy that spans all three facets, e.g.

```bash
python pipeline.py --trifecta \
    --allowed read_private_ledger,fetch_external_quote,update_balance \
    --denied exfiltrate_secret \
    --manifest --out out
# -> risk      : TRIFECTA: detected (facets: private-data-access, untrusted-content-intake, egress)
```

is `detected`. The flag is **informational only**: it never changes the
audit result or the pipeline exit code.

## What Phase 4 adds

Phase 4 runs the **buggy** policy through **all three** engines in parallel
(SMT/Z3 + TLC + policy-direct), joins their verdicts, then curates a compact
`crosscheck_report.json` with the Apalache ITF witness attached
(evidence-only — it does **not** change the `agree`/`verdict` join):

```
$ python pipeline.py --policy tests/fixtures/aws_dogwood/spendcap/policies/spendcap-buggy.dw --engine crosscheck
...
  engine    : crosscheck (SMT/Z3 + TLC + policy-direct)
  verdict   : VIOLATED
  note      : cross-check: SMT (Z3), TLC, and policy-direct all found a counterexample
  counterex : {"completed": 0, "inflight": 3}
  smt       : VIOLATED  (smtz3)
  tlc       : VIOLATED  (tlc)
  policy    : VIOLATED  (policy_direct)
  joined    : VIOLATED  (policy=PROVEN/VIOLATED require ALL THREE engines to agree)

$ python -m rot.crosscheck out/policy-spendcap-buggy.dw_spendcap_within_cap.json \
    --witness apalache-itf=tests/fixtures/aws_dogwood/spendcap/apalache-buggy.itf.json
...
  engine         status      counterexample
  smtz3          violated    {"completed": 0, "inflight": 3}
  tlc            violated    {"completed": 0, "inflight": 3}
  policy_direct  violated    {"completed": 0, "inflight": 3}
  apalache-itf   violated    {"completed": 0, "inflight": 3}   (witness)
  agreement      smtz3=violated  tlc=violated  policy_direct=violated  joined=violated  -> AGREE
```

- **Agreement** is a pure function of the SMT + TLC + policy-direct statuses:
  `PROVEN`/`VIOLATED` require **all three** engines to agree; any disagreement or
  `unknown` yields `unknown` (never read as proven). The ITF witness is
  **evidence-only** — it is replayed through `rot.itf` (sound refuter) and
  attached to the report, but it does not participate in the join.
- **Graceful degradation:** if TLC (java + `tla2tools.jar`) is absent,
  `demo.sh`/`demo.ps1` skip Phase 4 with a `[SKIP]` note (no failure) — the
  offline phases 1–3 already cover the symbolic path. Apalache 0.62.3 needs
  Java 21, so the ITF witness is supplied as a fixture and replayed via
  `rot.itf` rather than by invoking the Apalache binary.
- Produces `out/crosscheck_report.json` (see the artifact above): engine
  statuses, both counterexamples, the attached witness, and the `agree`
  verdict.

## What Phase 5 adds

Phase 5 sweeps the **concurrency pool bound** `K` (`--max-inflight`) across
the buggy policy and asserts the verdict flips with it:

| `K` | expected | verdict | witness |
|-----|----------|---------|---------|
| 1 | exit 0 | **PROVEN (masked)** | — |
| 2 | exit 1 | VIOLATED | `completed=100, inflight=2` |
| 3 | exit 1 | VIOLATED | `completed=0, inflight=3` (clean parallel fire) |

`K` is **structural, not policy**: it bounds how many in-flight requests the
state space can express, and both the correct and the buggy variants share it.
At `K=1` a single in-flight request (100) can never overshoot the 200 cap, so
the buggy policy *looks* proven — a false negative that is only exposed once
the model can express ≥2 parallel in-flight fires. The witness shape tracks
`K`: the minimum number of parallel fires needed to break the cap.

This is the core lesson of the reproducible demo: a `PROVEN` result for a
concurrency-sensitive policy is only as strong as its `K`.

## Exit codes (identical to the rest of the pipeline)

| code | meaning | interpretation |
|------|---------|----------------|
| 0 | proven | the pinned property holds in every reachable state (within the bound) |
| 1 | violated | a concrete counterexample (witness) refutes it |
| 2 | unknown | the bounded search was inconclusive — never read as proven |
| 3 | error | usage / IO failure |

## Related

- Fixture README (IR model, counterexample trace, atom → action mapping):
  `tests/fixtures/aws_dogwood/spendcap/README.md`
- CLI usage reference: [`spendcap-usage.md`](spendcap-usage.md)
- Agent Mode (Cedar / Dogwood-JSON policies): [`agent-mode.md`](agent-mode.md)
