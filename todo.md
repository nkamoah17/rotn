# TODO — ROTN (work-in-progress)

> **Status — Phase 6 (Docs/CLI refresh) complete.** All work phases plus the
> documentation / CLI refresh, and **Agent Mode** (Cedar / Dogwood policy
> verification: safety, non-vacuity, bounded liveness) are **done**. The full
> suite is green (**493 tests**, pure stdlib, Python 3.6). Three independent engines (symbolic-SAT, TLC,
> Apalache-ITF) plus the `--env` / `--before` / `--after` / `--itf` /
> `--llm-baseline` CLI surface are all wired into `pipeline.py`. See `README.md`
> and `ROTN_Technical_Report.md` for the full picture.

## Build plan (all phases complete)

- [x] **Phase 1 — IR + TLA+ emission.** A small IR (`rot.ir`), a deterministic
  TLA+ emitter (`rot.emitter`) that produces the spec + config, and the CEGAR
  loop (`rot.cegar`) that maps engine results to sound verdicts.
- [x] **Phase 2 — Symbolic engine.** A pure-Python bounded SAT model checker
  (`rot.sat`, `rot.symbolic`) with DPLL + clause learning, so the whole pipeline
  runs offline with **no Java and no TLC jar** (the sound baseline).
- [x] **Phase 3 — 2PC.** A trusted IR model of 2PC (`rot.twopc`) with `correct`
  and `buggy` variants and the `agreement` invariant.
- [x] **Phase 4 — ZAB.** A trusted IR model of ZAB (`rot.zab`) with `correct`
  and `buggy` variants and the `leader` invariant.
- [x] **Phase 5 — Environment fragments & refinement.** Bounded message-delay
  fragments (`rot.env`, `--env`), and a propose/check/repair refinement loop
  (`rot.refine`, `--before` / `--after`).
- [x] **Phase 6 — Apalache ITF + LLM baseline.** A new engine that consumes
  Apalache ITF counterexamples and replays them through the IR/invariant core
  (`rot.itf`, `--itf`) — one-directional (refutes, never proves). Plus an
  **opt-in, non-sound** LLM baseline (`rot.llm_baseline`, `--llm-baseline`) that
  writes an audit artifact and never affects the verdict.
- [x] **Phase 7 — PBFT.** A trusted IR model of PBFT (`rot.pbft`) with `correct`
  and `buggy` variants and the `view-agreement` invariant.
- [x] **Phase 8 — Documentation & CLI refresh.** `README.md` refreshed (three
  engines, `--env` / `refine` / `--itf` / `--llm-baseline`, 493 tests);
  `pipeline.py` CLI verified (`--env`, `refine`, `--itf`, `--llm-baseline`
  subcommand all present); `ROTN_Technical_Report.md` updated.
- [x] **Phase 9 — Agent Mode (Cedar / Dogwood policy verification).** The `AgentStep` model (`rot.agent_step`) and the policy front-ends (`rot/frontends/policy`: `cedar.py`, `dogwood.py`, `agent_step_liveness.py`) verify the action choice of an autonomous agent against a **Cedar** (`.cedar`) or **Dogwood** (`.json`) policy: `policy_conformance` (safety), `policy_permits_request` (non-vacuity), `bounded_eventually` (bounded liveness within horizon B). New CLI: `--policy` / `--tools` / `--kind {safety,realizability,liveness}` / `--liveness-horizon`; registry targets `agent-step` (PROVEN) / `agent-step-buggy` (VIOLATED + witness). `docs/agent-mode.md`, `scripts/run_agent_mode.sh`, `samples/agent.cedar`, `samples/policy.json`, `samples/tools.json`.

## Dogwood spending-cap concurrency checker (in progress)

Goal: build a checker that verifies an agent's spending-cap actions against
AWS Dogwood policy specs, using upstream spec artifacts as test fixtures.

- [x] **Step 0 — Local tooling prerequisites.** TLC verified available
  (`tla2tools.jar` under `C:\Users\jeren\Downloads\...`); Dogwood upstream
  repo identified (`dogwood-policy/dogwood`) and pinned to commit
  `4ec5e2c01b44ff3882a231ae5d315b330b38fa25` (Apache-2.0).
- [x] **Step 1 — Spec artifact fetch.** All 7 artifact groups fetched into
  `tests/fixtures/aws_dogwood/spendcap/` — **59 files, 59/59 git-blob
  SHA-verified** (independently re-checked on disk via
  `tmp_dogwood_verify.py`):
  - `examples/alert_total_transfer_over_200/` — 6 files (policy, schema, expected/explain, trace, README)
  - `examples/refund_budget_settled_plus_current/` — 7 files
  - `examples/cap_open_agent_prs_windowed/` — 7 files
  - `guide/08-formal-specification.md` — 1 file (72 KB, formal spec)
  - `corpus/0299_sum_resolved_filter/` — 16 files
  - `corpus/0301_sum_resolved_range_filter/` — 6 files
  - `corpus/mcagg_0299_sum_resolved_filter/` — 16 files
  - Provenance: top-level `PROVENANCE.json` / `PROVENANCE.md` plus a
    per-directory `PROVENANCE.json` sidecar (source URL, blob SHA, size per
    file). Fetch helpers: `tmp_dogwood_fetch.py`, `tmp_dogwood_finish.py`
    (rate-limit workaround via `raw.githubusercontent.com`),
    `tmp_dogwood_verify.py` — safe to delete once Step 2 is green.
- [ ] **Step 2 — Checker implementation.** (next)

## Source front-end (Java/CPG, narrow waist)

- [x] Verified `rot.ir` signatures and the `_joern_test/cpg_bridge.py` reference.
- [x] Java source → IR (`rot/frontends/frontend_java.py`) with provenance on
  every action; `--source` / `--cpg` pipeline modes (`pipeline.py`).
- [x] Narrow-waist guardrail: the frontend imports only `rot.ir` (no
  `rot.emitter` / `rot.tlc` / `rot.cegar`).
- [x] `tests/test_java_model.py`, `tests/test_frontend.java.py`,
  `tests/test_source_pipeline.py` — all green.

## Completion status

- **All phases done.** 493 tests pass (pure stdlib, Python 3.6, deterministic,
  no Java / TLC required for the baseline).
- Three independent engines: symbolic-SAT (default `auto` → `tlc` when a jar is
  present, else `symbolic`), TLC, Apalache-ITF.
- **What we deliberately did NOT do** (to stay honest):
  - The LLM baseline is **non-sound** and **never affects the verdict or exit
    code** — the verdict always comes from a sound engine.
  - No cross-process parallelism — the pipeline is single-process and bounded.
  - The Apalache ITF engine **refutes but never proves** (one-directional).