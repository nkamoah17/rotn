# rot-verify — Architecture

> **Single source of truth.** This document is the authoritative description of
> the `caravel/rot-verify` architecture. Every other phase of the master plan
> references the planes, contracts, and invariants defined here. If code and
> this document disagree, this document — and the tests that pin it — win.
>
> Status legend used throughout:
> **shipped** = implemented and tested today · **planned** = defined by this
> architecture, to be built in a later phase.

---

## 0. The product in one line

> **Ingest** an AI agent's tool policy (Dogwood *or* a standard **MCP
> manifest**), **verify** it with three independent engines + bounded CEGAR,
> **map** findings to SOC 2 / AIUC controls, **gate** depth by tier (license
> or GitHub-Action input), **emit** a deterministic trace, and **replay** it
> as an interactive proof on GitHub Pages.

The whole system is built on four invariants that never change:

| invariant | meaning |
|-----------|---------|
| **zero runtime deps** | the `rot` package is pure stdlib (Python 3.6+); optional external engines (TLC, Apalache, Z3) *degrade* to a skip or an honest `UNKNOWN`, never a hard failure |
| **narrow waist** | every front-end imports **only** `rot.ir`; every engine consumes **only** a `ProtocolIR` (§2) |
| **deterministic** | the same `(policy, environment, tier)` always produces a byte-identical, hash-stable trace (§3, §6) |
| **fail-closed** | `UNKNOWN` is never read as `PROVEN`; a counterexample is only trusted once re-validated; exit codes are `0/1/2/3` (§5) |

---

## 1. The four planes

```
┌─ Ingest ─────────────┐   ┌─ Verify ────────────┐   ┌─ Evidence ─────────────┐   ┌─ Ship ──────────────┐
│ policy.json (Dogwood)│   │ symbolic (bounded-  │   │ RTF trace.json         │   │ static site (Cytoscape)│
│ MCP manifest  (NEW)  │──▶│ exhaustive BFS)     │──▶│ (deterministic, hashed)│──▶│ GitHub Pages (deploy-pages)│
│ tools.json           │   │ SMT (Z3 + ref)      │   │ verdict+graph+CE+      │   │ verdict card, replay,    │
└──────────────────────┘   │ policy-direct       │   │ timeline+narration+    │   │ findings+compliance      │
                           │ + bounded CEGAR     │   │ findings+compliance+   │   └─────────────────────────┘
                           │  DepthBudget (tier) │   │ coaching (Rule+Proof+  │
                           └─────────────────────┘   │ Coach)                 │
                                                      └─────────────────────────┘
```

The planes are strictly ordered and communicate **only** through stable,
serializable artifacts: the **IR** between Ingest and Verify, and the **RTF
trace** between Verify/Evidence and Ship. No plane reaches into another's
internals. This is what lets a front-end, an engine, and the hosted replay each
evolve independently.

### 1.1 Ingest plane — *turn a policy into a `ProtocolIR`*

A front-end's **only** job is to produce a validated `rot.ir.ProtocolIR` with a
pinned property. It never imports an engine.

| input | front-end (module) | pinned property | kind |
|-------|--------------------|-----------------|------|
| Dogwood `policy.json` (+ optional `tools.json`) | **shipped** `rot.frontends.policy.dogwood` | `policy_conformance` — the conforming agent never takes a denied action | safety |
| Dogwood `.dw` spend-cap source | **shipped** `rot.frontends.policy.dw` → `rot.dw` / `rot.spendcap` | `spendcap_within_cap` — settled + in-flight amount ≤ cap | safety |
| Cedar `.cedar` policy | **shipped** `rot.frontends.policy.cedar` | non-vacuity — some concrete request is permitted | realizability |
| bounded-liveness view of any policy | **shipped** `rot.frontends.policy.agent_step_liveness` | `decision != idle` reachable within horizon `H` | liveness |
| **standard MCP manifest** | **planned** `rot.frontends.policy.mcp` | `policy_conformance` over the MCP tool universe | safety |

The router is `rot.frontends.policy.build_ir(policy_path, tools_path=None,
n_steps=1, kind=None, ...)`, which dispatches on file extension (or an explicit
`kind`) and returns one `ProtocolIR` regardless of source. Every returned IR
carries `pinned_property`, `metadata["property_kind"]`,
`metadata["property_name"]`, and provenance (`policy_source` /
`tools_source`).

The **MCP manifest** front-end (planned) is a first-class citizen, not an
adapter: it normalizes a standard MCP `tools` list (name, description, input
schema) into the same `allowed`/`denied` action universe the Dogwood front-end
uses, so the *entire* Verify/Evidence/Ship stack is shared. The `tools.json`
catalog is descriptive provenance — cross-checked against the policy (an action
named by the policy but absent from the catalog is recorded in IR metadata so a
report can flag it) — but it never changes the model.

### 1.2 Verify plane — *three independent engines + bounded CEGAR*

The IR is first turned into a **deterministic linear model**
(`rot.linearization.linearize` → `LinearModel`) so that no two engines can
drift apart: they all see the same ordered actions, the same initial state, and
the same `enabled_in(state)` / `next_states(state)` operations.

The three independent engines (the "trifecta" of the product name):

| engine | module | technique | can prove? |
|--------|--------|-----------|-----------|
| **symbolic** | **shipped** `rot.symbolic` + `rot.sat` | bounded-exhaustive BFS over the finite linear model; Kleene 3-valued evaluation; `rot.sat` supplies a DPLL SAT solver + 3-valued `eval3` | yes (bounded) |
| **SMT** | **shipped** `rot.smtz3` | dual backend: Z3 (Int/Bool arithmetic, bounded by horizon `H`) **and** a pure-Python reference backend; the two must *agree* on status or the result is `UNKNOWN` | yes (bounded), when Z3 present |
| **policy-direct** | **shipped** `rot.modelfind` | bounded enumeration over the IR's finite typed domains; the canonical concrete-state engine — counterexamples and witnesses come from it | yes (bounded) |

**Bounded CEGAR** (`rot.cegar`) is the referee, not a fourth engine. It turns an
engine's `EngineResult` into an auditable `rot.verdicts.Verdict` and — the CEGAR
core — *validates that a counterexample is real* rather than an artefact of an
over-approximation:

- `proven` → `Verdict.proven`
- `violated` → re-evaluate the invariant in the witness state with the IR's own
  3-valued `eval`: definite `False` → a real bug → `Verdict.violated`; not
  definite → spurious → `Verdict.unsound`
- `unknown` / `timeout` → bounded refinement loop (re-run up to
  `Config.cegar_max_iter`); if it converges, report that; otherwise
  `Verdict.unknown` (a sound "we could not decide" — never silently proven)
- `error` → `Verdict.error` (a tool failed to run)

The **three-facet audit** (`rot.trifecta.audit`) is the product-level verify
entry point: it checks the same `ProtocolIR` across **safety**
(`forall_reachable`), **liveness** (`reach_within`, bounded by the horizon), and
**conformance** (`exists_reachable`, non-vacuity), and returns a
`TrifectaResult` with one facet verdict each. It is deterministic and carries a
stable policy hash (SHA-256 of the canonical policy JSON).

Optional external engines exist but are **never required**: `rot.tlc` (real
TLC), `rot.apalache` (real Apalache runner), `rot.itf` (Apalache ITF trace
engine — refutes, never proves). `rot.config.Config.select_engine()` resolves
`"auto"`: use an external engine when its toolchain is present and reachable,
otherwise fall back to the symbolic engine. This keeps the pipeline runnable in
a bare Python environment.

### 1.3 Evidence plane — *the deterministic, hashed RTF trace*

The Verify plane's verdicts are assembled into a single, self-contained,
**byte-stable** artifact: the **RTF trace** (`trace.json`). The shipped core is
`rot.manifest` (schema `rotn.manifest/v1`): policy (hash + content), environment
(model family + parameters), the trifecta verdicts, and the witness, carrying a
`manifest_id` (SHA-256 over the canonical body) so it can be integrity-checked
and compared across re-runs.

The **RTF** (ROTN Trace Format) is the productized superset of the manifest that
adds everything the interactive replay needs (§3). Two more evidence modules
support it:

- `rot.verdicts` — the final verdict layer (`PROVEN` / `VIOLATED` / `UNKNOWN` /
  `UNSOUND` / `ERROR`), each carrying `property_kind` and, on violations, a
  `violation_code` (`POLICY_DENIAL` / `LIVENESS_BOUND_EXCEEDED` / `DEADLOCK`).
- `rot.mcp_adapter` — the **adoption surface**: a pure function of the
  `TrifectaResult` that re-labels the temporal verdicts into the Cedar-AR
  findings vocabulary (`contradictions`, `unreachable rules`, `Overly
  Permissive`, `Overly Restrictive`, `Ineffective`) without adding any new
  verification logic.
- `rot.tracefmt` — the formal v1 *empirical* trace format (structure,
  normalization, `CONFORMANT` / `NON-CONFORMANT` / `INCONCLUSIVE` verdicts). It
  is deliberately **never-refining**: it reads traces and reports verdicts, and
  reaches the formal plane only through an explicit refinement-request artifact.

### 1.4 Ship plane — *replay the proof on GitHub Pages*

| artifact | status | notes |
|----------|--------|-------|
| `rot ci` — CI gate (verdict + JUnit XML + SARIF) | **shipped** | `rot ci --policy … --out ci`; exit-code aware; PR annotations |
| static site (Cytoscape graph, verdict card, replay, findings, compliance) | **planned** | a pure static bundle rendered from the RTF trace — no server, no runtime deps |
| GitHub Pages deploy (`deploy-pages`) | **planned** | the static bundle is committed/deployed to `caravel.github.io/rot-verify` |

The Ship plane is a **pure function of the RTF trace**: it renders the verdict
card, draws the counterexample graph (states = nodes, actions = edges) with
Cytoscape, plays back the step-by-step attack timeline with narration, and lists
the Cedar-AR findings + SOC 2 / AIUC control mapping. Because it only reads the
trace, the same `trace.json` replays identically anywhere — locally, in CI, or
on GitHub Pages.

---

## 1A. The two audit planes (different depth guarantees)

The pipeline above is one *mechanism*; the product has **two audit planes** —
two modalities with *different depth guarantees* that answer different
questions. Both reuse the same narrow waist (`rot.ir`) and the same
deterministic, hashed RTF trace, but they are not the same depth of claim.

| | **Plane A — structural / temporal (MCP)** | **Plane B — deep temporal / concurrency (Dogwood)** |
|---|---|---|
| **Question** | Does the agent conform to policy? (no denied action, tenant isolation, no contradictions) | Can the agent *bypass the cap* under concurrent, in-flight activity? |
| **Input** | MCP manifest / Cedar `.cedar` / Dogwood `policy.json` | Dogwood `.dw` spend-cap source (the temporal extension) |
| **Engine** | Trifecta (safety + liveness + conformance) over the bounded model | Cross-check: **SMT/Z3 + TLC + policy-direct** (zero shared code) + bounded-exhaustive |
| **Depth guarantee** | Bounded: holds within the declared horizon / state budget; `UNKNOWN` is never read as `PROVEN` | Bounded-exhaustive over the *concurrent* state space (the K-sweep); the three engines must *agree* and find the *same* witness |
| **Maps to** | SOC 2 **CC6** (CC6.1 / CC6.3 / CC6.6) + **AIUC-1** (autonomy) | Spend-cap bypass prevention; the **CoachingArtifact** (Rule + Proof + **Coach**) discharges **AIUC-1** |
| **Evidence** | RTF trace (verdict + graph + counterexample + findings + compliance) | RTF trace **plus** the CoachingArtifact: the corrected policy + the re-proof that the correction is safe |

The distinction is the point. **Plane A** is a *structural* audit: it checks
that the policy is well-formed and the agent conforms, within a bound. **Plane
B** is a *deep temporal/concurrency* proof: it shows the policy is (or is not)
safe under parallel, in-flight activity — the regime where a naive settled-only
guard silently lets a burst overshoot the cap. Plane B is where the
**CoachingArtifact** lives: when the policy is violated, ROTN does not just
report it — it coaches the agent back in bounds and *proves* the correction
safe (the third leg of the triad, Rule + Proof + Coach).

Both planes are **fail-closed** and **bounded**: a `PROVEN` is always
bound-relative, and an `UNKNOWN` (budget-truncated or a tool absent) is never
read as safe. The difference is *what* is bounded — the structural horizon in
Plane A, the concurrent state space in Plane B.

---

## 2. The narrow waist

`rot.ir` is the **sole** intermediate artifact of the whole system — the strict
architectural boundary between *what a policy/protocol is* and *how it is
verified*.

- **Front-ends** (`rot.frontends.*`) have exactly one job: produce a
  `ProtocolIR`. A front-end must **never** import or touch `rot.emitter`,
  `rot.tlc`, `rot.cegar`, `rot.modelfind`, or any engine.
- **Engines** consume *only* a `ProtocolIR`. None of them knows how the IR was
  built — from a Dogwood policy, an MCP manifest, a Cedar policy, or a hand-
  authored fixture.

The rule is **enforced by test**: `tests/test_narrow_waist.py` checks the
import graph so a front-end that reaches for an engine fails CI.

Design principles of the IR (from `rot.ir`):

- **Language-agnostic** — an IR can come from a policy file, a CPG analysis, or
  be authored by hand. Downstream stages only ever see the IR.
- **Sound by construction** — every state variable that can influence a pinned
  property is either `precise` (translated exactly) or `existential`
  (over-approximated: "any value in the domain"). We never *delete* a variable,
  because deleting behaviours is an *under*-approximation and is UNSOUND for
  safety.
- **Bounded** — all domains are finite, so the symbolic engine can exhaustively
  check the model and the SAT/SMT solvers can decide counterexample feasibility.
- **Stable contract** — small, explicit, fully serializable (`to_dict` /
  `from_dict`) so it crosses process and language boundaries without either side
  depending on the other.

The IR also carries the **assurance ladder** (severity rungs × gate
permissions): a violation may only reach the gate permission its invariant's
rung allows (`RUNG_CEILING`), so an environment-asynchrony finding can never
drive a `BLOCK`.

---

## 3. The RTF contract (`trace.json`)

The **ROTN Trace Format** is the single, deterministic, hash-stable artifact
that the Evidence plane emits and the Ship plane renders. It is the contract
between "we verified this" and "here is the interactive proof."

**Determinism rules** (inherited from `rot.manifest`, enforced by
`tests/test_manifest.py`):

- serialized with **sorted keys** and **compact separators**;
- **stable hashing** (SHA-256) over the canonical body → `manifest_id`;
- **no** timestamps, **no** absolute paths, **no** random ids, **no**
  environment-dependent values;
- two runs with the same `(policy, environment, tier)` produce **byte-identical**
  traces — re-running `verify` must reproduce the exact same `manifest_id`.

**The RTF body** (schema `rotn.rtf/v1`, a superset of `rotn.manifest/v1`):

| field | content | rendered as |
|-------|---------|-------------|
| `schema` | `rotn.rtf/v1` | — |
| `manifest_id` | SHA-256 over the canonical body | integrity badge |
| `verdict` | overall status + per-facet (`safety` / `liveness` / `conformance`) verdicts, `property_kind`, `violation_code` | **verdict card** |
| `graph` | nodes = reachable states, edges = enabled actions (from the `LinearModel`), the witness path highlighted | **Cytoscape** counterexample graph |
| `counterexample` | the concrete, IR-feasible witness state + the step path (`{step, action, state}`) | the "attack script" |
| `timeline` | ordered steps, each with a human **narration** line explaining why the action is enabled and what it changes | step-by-step **replay** |
| `findings` | the Cedar-AR findings (`rot.mcp_adapter`) with severity | findings list |
| `compliance` | the SOC 2 / AIUC control mapping for each finding | **compliance** table |
| `provenance` | policy hash + content, environment (model family + parameters), engine(s) used, the `DepthBudget` that applied, `n_states` explored, `horizon_complete` | the "how much did we explore" footer |

**Soundness in the trace:** a `VIOLATED` verdict is only ever accompanied by a
counterexample that CEGAR re-validated as IR-feasible; an `UNKNOWN` verdict is
only ever accompanied by the budget that was exhausted and the honest
`horizon_complete` flag. The trace never hides a gap.

---

## 4. The tier / budget model (`DepthBudget`)

Verification depth is **gated by tier**. A tier is selected by a **license** or
by a **GitHub-Action input** (e.g. `with: tier: standard`), and it resolves to a
named **`DepthBudget`** — a bundle of the exact knobs that already live in
`rot.config.Config`:

| knob | `Config` field | meaning |
|------|----------------|---------|
| state budget | `max_states` | max reachable states the engines may explore before returning `UNKNOWN` |
| CEGAR depth | `cegar_max_iter` | max refinement iterations on an `unknown` result |
| liveness horizon | `liveness_horizon` | max steps for `bounded_eventually` / `reach_within` |
| abstraction bounds | `participant_bound` / `env_bound` | property-directed bounds that become recorded assumptions |
| engine set | `engine` (`auto` / `symbolic` / `smt` / `tlc` / `apalache`) | which independent engines cross-check |

The tiers (planned; the underlying knobs are shipped):

| tier | engines | budget | use |
|------|---------|--------|-----|
| `basic` | symbolic | small `max_states`, 1 CEGAR iter, short horizon | quick CI smoke, free tier |
| `standard` | symbolic + SMT cross-check | medium `max_states`, bounded CEGAR, full horizon | default product tier |
| `enterprise` | all three engines (+ TLC/Apalache when present) | large `max_states`, full CEGAR, longest horizon, compliance mapping | licensed / audit tier |

**Contract:** the tier only ever *shrinks or grows the budget* — it never
changes the verdict semantics. A `basic`-tier `UNKNOWN` is the same honest
"we could not decide" as an `enterprise`-tier `UNKNOWN`; the difference is how
much of the state space was explored, and that is recorded in the RTF
`provenance` so the replay is always honest about its depth. Raising the tier
can only turn an `UNKNOWN` into a `PROVEN`/`VIOLATED`, never the reverse.

---

## 5. The soundness contract (fail-closed)

The verdict vocabulary is fixed (`rot.verdicts`):

| status | meaning | exit code |
|--------|---------|:---------:|
| `PROVEN` | invariant holds in every reachable state (bounded model) | `0` |
| `VIOLATED` | a concrete, IR-feasible counterexample exists (a real bug) | `1` |
| `UNKNOWN` | budget exhausted / could not decide — **never** read as proven | `2` |
| `UNSOUND` | a counterexample CEGAR could not confirm concrete-feasible — do not trust | `2` |
| `ERROR` | a tool (TLC/Java/Z3) failed to run | `3` |

The rules that make it fail-closed:

1. **`UNKNOWN` is never `PROVEN`.** A budget-truncated search is surfaced, not
   silently passed. (Enforced in `rot.symbolic`, `rot.modelfind`, `rot.cegar`.)
2. **A violation needs a definite witness.** A counterexample is trusted only
   after CEGAR re-evaluates the invariant in the witness state and sees a
   *definite* `False` (never `UNDEF`).
3. **Liveness is always bounded.** A `NOT_REACHED` liveness verdict is sound only
   because the whole horizon was explored (`horizon_complete`).
4. **Cross-checks must agree.** The SMT engine's two backends must agree on
   status; any disagreement (or an unavailable backend) yields `UNKNOWN` that
   records both answers — never a false `PROVEN` or `VIOLATED`.
5. **External tools degrade, never break.** Missing Java/TLC/Apalache/Z3 drops
   that engine out and records the fallback; the pipeline still runs and still
   reports honestly.

---

## 6. Determinism contract

- **Stable JSON** — sorted keys, compact separators, no wall-clock values
  (`rot.manifest`, `rot.tracefmt`).
- **Stable hashing** — SHA-256 over the canonical body; the `manifest_id` /
  policy hash is the integrity anchor and is stable across runs and machines.
- **Deterministic engines** — the symbolic and policy-direct engines are
  exhaustive over a finite, ordered state space, so the same input always yields
  the same verdict, the same witness, and the same step path.
- **Replayable** — `rot replay <attack.jsonl>` re-derives a recorded counterexample
  against the policy, proving the trace is real and not a one-off artefact.

---

## 7. Module map (what lives where)

| plane | module | role |
|-------|--------|------|
| Ingest | `rot.frontends.policy` | router → `ProtocolIR` (Cedar / Dogwood `.dw` / Dogwood `.json` / liveness) |
| Ingest | `rot.frontends.policy.mcp` *(planned)* | standard MCP manifest → `ProtocolIR` |
| Ingest | `rot.agent_step` | the adversarial agent-step model (the IR for a single decision step) |
| Waist | `rot.ir` | the typed IR — domains, expressions, `ProtocolIR`, assurance ladder |
| Verify | `rot.linearization` | `ProtocolIR` → deterministic `LinearModel` |
| Verify | `rot.symbolic` + `rot.sat` | symbolic (bounded-exhaustive) engine + DPLL SAT / 3-valued eval |
| Verify | `rot.smtz3` | SMT engine (Z3 + pure-Python dual backend, cross-checked) |
| Verify | `rot.modelfind` | policy-direct bounded enumerator (canonical concrete engine) |
| Verify | `rot.cegar` | counterexample validation + bounded refinement |
| Verify | `rot.trifecta` | the three-facet audit (safety / liveness / conformance) |
| Verify | `rot.config` | engine selection + budgets (the `DepthBudget` knobs) |
| Verify | `rot.tlc` / `rot.apalache` / `rot.itf` | optional external engines (degrade, never required) |
| Evidence | `rot.manifest` | deterministic, hashed verification manifest (RTF core) |
| Evidence | `rot.verdicts` | the final verdict layer + violation codes |
| Evidence | `rot.mcp_adapter` | Cedar-AR findings adoption surface |
| Evidence | `rot.tracefmt` | formal v1 empirical trace format (never-refining) |
| Ship | `rot.__main__` (`rot ci`) | CI gate: verdict + JUnit XML + SARIF |
| Ship | static site + GitHub Pages *(planned)* | Cytoscape replay, verdict card, findings, compliance |

---

## 8. Constraints and invariants (non-negotiable)

1. **Zero runtime dependencies.** `install_requires=[]`. The `rot` package
   imports stdlib only. Optional engines degrade gracefully.
2. **Narrow waist.** Front-ends import only `rot.ir`; engines consume only a
   `ProtocolIR`. Enforced by `tests/test_narrow_waist.py`.
3. **Deterministic.** Same `(policy, environment, tier)` → byte-identical,
   hash-stable trace. Enforced by `tests/test_manifest.py`.
4. **Fail-closed.** `UNKNOWN` ≠ `PROVEN`; violations need a definite,
   CEGAR-validated witness; exit codes `0/1/2/3`.
5. **Python 3.6 compatible.** No f-strings, no dataclasses in the shipped core.

---

*This document is the single source of truth for `caravel/rot-verify`. Update
it in the same change that changes the architecture it describes.*