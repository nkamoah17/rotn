# ROTN — TLA+ Formal-Verification Technical Report

> **ROTN** — *Reasoning / Operational Test-Nets*: a compiler that turns an
> executable **Python reference model** of a consensus protocol (2PC, ZAB,
> Raft-2Node) into a **TLA+** module, then hands that module to a model checker
> (TLC, or the symbolic engine) to verify safety invariants — **agreement**
> (two nodes never decide different values) and **validity** (every decided value
> was proposed). This report records the design decisions, the test suite, the
> *blocking-permission* rule, the deterministic counterexample search, the
> **Apalache / SANY integration and the `@type` annotation issue**, and the
> end-to-end workflow from source to verdict.
>
> **Status (this snapshot):** the symbolic engine and TLC both verify the
> registered targets (correct ⇒ PROVEN, buggy ⇒ VIOLATED with a reproducible
> counterexample). The Apalache path is wired through the TLA+ emitter with
> Snowcat-compatible `@type` annotations; `run.ps1` keeps `apalache` as a
> *reserved* engine value (WP2) while the Apalache runs are driven directly via
> `apalache-mc` (see §9). A third plane — **Agent Mode** (§17) — adds
> policy-driven verification of an autonomous agent over the **Cedar** and
> **Dogwood** front-ends and the `AgentStep` model, checking `policy_conformance`
> (safety) and **bounded liveness** (`bounded_eventually`) with the same bounded
> engines.

---

## Table of Contents

1. [Scope & Out of Scope](#1-scope--out-of-scope)
2. [System Architecture](#2-system-architecture)
3. [Core Design Decisions (Step 3.4)](#3-core-design-decisions-step-34)
4. [State Space & Bounded Reasoning](#4-state-space--bounded-reasoning)
5. [Blocking Permission (Step 3.6)](#5-blocking-permission-step-36)
6. [Targeted Test Suite (Step 3.5)](#6-targeted-test-suite-step-35)
7. [Deterministic Counterexample Search (Step 3.6.1)](#7-deterministic-counterexample-search-step-361)
8. [ZooKeeper/ZAB Bug-Replay Evaluation (Step 3.7)](#8-zookeeperzab-bug-replay-evaluation-step-37)
9. [Apalache / SANY Integration & the `@type` Annotation](#9-apalache--sany-integration--the-type-annotation)
10. [End-to-End Workflow (commands)](#10-end-to-end-workflow-commands)
11. [Artifacts](#11-artifacts)
12. [Verdict Matrix](#12-verdict-matrix)
13. [Known Limitations](#13-known-limitations)
14. [Extension Guide (adding a protocol / invariant)](#14-extension-guide-adding-a-protocol--invariant)
15. [File Map](#15-file-map)
16. [Glossary](#16-glossary)
17. [Agent Mode: policy-driven verification (Cedar / Dogwood / AgentStep)](#17-agent-mode-policy-driven-verification)
18. [The Replay Site (Ship Plane)](#18-the-replay-site-ship-plane)

---

## 1. Scope & Out of Scope

### 1.1 In scope

- **Chain A (the core pipeline).** A Python IR model of a protocol is
  *linearised* into a finite state machine, *emitted* as TLA+, and *checked* by
  a model checker. This is the path that produces the PROVEN / VIOLATED verdicts.
- **Two protocols.** 2PC (two-phase commit) and ZAB (Zab, from Apache ZooKeeper)
  are registered as targets, each with a **correct** reference model and a
  **buggy** variant that deliberately breaks an invariant.
- **Invariants, safety and bounded liveness.** The protocol families pin
  *safety* invariants (`agreement`, `zab_no_premature_apply`, `pbft_quorum`,
  `no_double_charge`, ...). The **Agent Mode** plane (§17) adds
  `policy_conformance` (safety) and `bounded_eventually` (**bounded liveness**:
  a goal reached *within a declared horizon*, not unbounded liveness).
- **Agent Mode (§17).** A policy-driven verification plane: the **Cedar**
  (`.cedar`) and **Dogwood** (`.json`) policy front-ends build the `AgentStep`
  model (`rot.agent_step`) on the narrow waist, and the same bounded engines
  check `policy_conformance` (safety), `policy_permits_request` (realizability /
  non-vacuity) and `bounded_eventually` (bounded liveness).
- **Two engines.** `tlc` (the real TLC model checker, requires Java + the
  tla2tools.jar) and `symbolic` (a pure-Python SAT/bounded engine that runs
  offline and deterministically). `auto` picks TLC when available, otherwise
  falls back to `symbolic`.
- **Step 3.5 — targeted test suite.** A focused regression suite that exercises
  the IR, the emitter, the lineariser, and the verdict logic in isolation.
- **Step 3.6 — blocking permission.** The rule that decides *when a
  counterexample is authoritative enough to block* a change, plus the fix for a
  **false-block** bug (a counterexample that did not actually witness the
  invariant being broken).
- **Step 3.6.1 — deterministic counterexample search.** How the reproducible
  counterexample is produced and shipped alongside the verdict.
- **Step 3.7 — ZooKeeper/ZAB bug-replay evaluation.** An *honest* per-commit
  corpus (two caught bugs, one explained missed bug, three safe changes) replayed
  through the MR gate; reports blocking precision/recall and the false-block rate
  (§8).
- **External engine.** The Apalache / SANY integration, the `@type` annotation
  issue, its fix, and its impact (see §9).
- **Workflow.** The full command sequence from a clean checkout to
  "correct passes / buggy is rejected".

### 1.2 Out of scope

- **Unbounded liveness / fairness.** ROTN does *not* model unbounded liveness
  or fairness (e.g. "the commit eventually happens" with no horizon). What it
  does model is **bounded liveness**: the `bounded_eventually` invariant (§17.3)
  asks whether a goal is reached *within a declared horizon B*. The emitted TLA+
  specs still use a totalising `UNCHANGED` self-loop (a "busy" stutter) so
  safety checks do not report spurious deadlocks.
- **Performance / scalability claims.** The bounded engines are used for
  *correctness* on small, bounded instances (2–3 participants). They are not a
  substitute for a liveness prover or a production-scale verification effort.
- **Formal certification.** A PROVEN verdict is a *bounded* model-checking
  result over the declared state space; it is not a theorem-proof certificate.
- **The Apalache engine as a first-class `run.ps1` engine.** Apalache is used as
  an *external* cross-check (driven via `apalache-mc`), not yet as a `-Engine`
  value in the pipeline runner (see §9.4).

---

## 2. System Architecture

ROTN is a two-chain system. **Chain A** is the verification pipeline (model →
TLA+ → model checker → verdict). **Chain B** is the *emission* compatibility
layer that makes the generated TLA+ accepted by external SANY-based frontends
(Apalache's Snowcat typechecker).

```
                         ┌──────────────────────────────────────────────┐
                         │                CHAIN A  (verify)             │
   Python reference      │                                              │
   model (protocol)      │   ┌────────┐   ┌──────────────┐   ┌────────┐ │
   ─────────────────────▶│──▶│  IR    │──▶│  Lineariser  │──▶│ Emitter│─┼──▶ TLA+ module
   (rot/targets.py)      │   │ model  │   │ (finite FSM) │   │(emitter│ │      │
                         │   └────────┘   └──────────────┘   │ .py)   │ │      ▼
                         │                                    └────────┘ │   ┌────────────────────┐
                         │                                              │   │  Model checker      │
                         │                                              │   │  tlc | symbolic     │
                         │                                              │   └─────────┬──────────┘
                         │                                              │             ▼
                         │                                              │   PROVEN / VIOLATED
                         │                                              │   (+ counterexample)
                         └──────────────────────────────────────────────┘

   The emitter (Chain A) doubles as the CHAIN B compatibility surface:
   it must emit TLA+ that BOTH TLC and Apalache/Snowcat accept,
   including per-variable `@type` annotations and an annotated `vars`
   operator (see §9).
```

### 2.1 Modules (Chain A)

| Module | Responsibility |
|--------|----------------|
| `rot/targets.py` | Registered targets (`correct` / `buggy` × 2PC / ZAB / Raft-2Node) and their invariants; builds the IR model for a given target and participant count `n`. |
| `rot/linearization.py` | `linearize(ir)` — converts the IR (which may have non-deterministic choice / concurrent actions) into a **linearised finite state machine** with a single `Init` and a set of transition actions. |
| `rot/emitter.py` | `Emitter(model, module_name)` — renders the linearised model into a TLA+ module string. Emits `VARIABLE` (+ `@type`), `Init`, one operator per action, a totalising `busy` self-loop, `Next`, an annotated `vars`, `Spec`, and the pinned invariant operator. |
| `pipeline.py` | Orchestrates Chain A end-to-end: build IR → linearise → emit → run the model checker → normalise to a verdict (exit code). |
| `run.ps1` | Thin PowerShell wrapper: single run, `-List`, and `-Matrix` (all targets × all invariants × engines), writing `out/matrix.csv` / `out/matrix.md`. |
| `rot/falseblock.py` | Step 3.6 — the **false-block** detector / metric (does a counterexample actually witness the invariant being broken?). |
| `rot/impact.py` / `rot/incremental.py` | "Incremental translation": after a change, re-emit *only the changed TLA+ fragment* so TLC/Apalache can re-check it quickly. |
| `regen_check.py` | Regenerates the real TwoPC spec through the pipeline path, for driving Apalache. |
| `tests/` | Step 3.5 — the targeted regression suite. |

### 2.2 The verdict contract

The pipeline normalises every engine result to one of four states, mapped to a
process **exit code** so it can be used as a CI gate:

| Verdict | Meaning | Exit code |
|---------|---------|-----------|
| `PROVEN` | invariant held over the whole (bounded) state space | `0` |
| `VIOLATED` | a counterexample was found | `1` |
| `UNKNOWN` | budget exhausted / inconclusive / reserved engine | `2` |
| `ERROR` | the checker itself failed (bad spec, missing jar, …) | `3` |

---

## 3. Core Design Decisions (Step 3.4)

This section records *why* ROTN is built the way it is. Each decision is
deliberate and is enforced in code.

### 3.1 Safety first, liveness bounded

The protocol plane models **safety** properties (agreement, validity); the
Agent Mode plane (§17) additionally supports **bounded liveness**
(`bounded_eventually` — a goal reached within a declared horizon), but never
unbounded liveness. The emitted
spec is made *total* by a `busy` self-loop (`UNCHANGED <<vars>>`) so that
legitimate terminal states (e.g. 2PC `done`) do not cause TLC to report
"Deadlock reached." This adds no reachable states and therefore does not affect
safety checking — it only makes the transition relation total.

> Rationale: a "deadlock" at a terminal protocol state is a *specification*
> artifact (the model simply has no outgoing step), not a protocol bug. Making
> the relation total removes that false signal without weakening the safety
> claim.

### 3.2 Linearise, then emit — one operator per action

The IR may express non-deterministic choice and concurrency. Rather than
translate those directly (which produces hard-to-check TLA+), ROTN
**linearises** the model into an explicit finite state machine: a single `Init`
plus a named action per step. The emitter then renders one TLA+ operator per
action and defines `Next` as their disjunction (plus `busy`). This keeps the
generated spec small, readable, and checkable by both TLC and Apalache.

### 3.3 Two engines behind one verdict

`tlc` and `symbolic` both report into the same 4-state verdict contract
(§2.2). This means a *correct* target must be PROVEN and a *buggy* target must
be VIOLATED on **both** engines (the `-Matrix` cross-check). The `symbolic`
engine guarantees an offline, deterministic, dependency-free path; `tlc`
provides the gold-standard independent engine when Java + the jar are present.

### 3.4 Counterexamples must be *deterministic* and *witnessing*

Step 3.6.1 requires that every VIOLATED verdict ships a **reproducible**
counterexample, and Step 3.6 (blocking permission) requires that the
counterexample **actually witnesses** the invariant being broken. This is the
fix for the *false-block* bug: a spurious counterexample must not block a
legitimate change. See §5 and §7.

### 3.5 Emit for the strictest frontend

The TLA+ emitter targets the strictest consumer it must satisfy — Apalache's
Snowcat typechecker — because TLC is more permissive about types. Emitting
Snowcat-compatible `@type` annotations (§9) therefore also satisfies TLC, with
a single code path.

---

## 4. State Space & Bounded Reasoning

ROTN performs **bounded** model checking: it enumerates the reachable states of
the linearised finite state machine up to a declared budget, and checks the
invariant at every reached state.

### 4.1 Why bounded reasoning is the right tool here

The targets are *small, bounded* consensus protocols (2–3 participants) whose
safety properties (agreement / validity) are *safety* properties. For these,
enumerating the reachable state space is decidable and sufficient: if the
invariant holds in every reachable state, the verdict is PROVEN (for that
bound); if any reachable state breaks it, a counterexample exists.

### 4.2 The budgets

| Knob | Default | Effect |
|------|---------|--------|
| `-N` | `3` | number of 2PC participants (drives the size of the state space) |
| `-MaxStates` | `200000` (pipeline default; `0` = use default) | upper bound on states explored before returning `UNKNOWN` |
| `-CegarMaxIter` | `6` (pipeline default; `0` = use default) | CEGAR refinement cap for the symbolic engine |

When a budget is exhausted the engine reports **`UNKNOWN`** (exit `2`), never a
false PROVEN — so a budget cap can hide a violation but never *assert* one.

### 4.3 Determinism

The `symbolic` engine is deterministic: the same target, property, `n`, and
budget always produce the same verdict and the same counterexample. This is what
makes the Step 3.6.1 "deterministic counterexample" guarantee (§7) meaningful,
and it is what allows CI to gate on a reproducible result.

---

## 5. Blocking Permission (Step 3.6)

### 5.1 The rule

A counterexample is only *permitted to block* a change if it is a **witness**:
the trace must actually reach a state in which the pinned invariant is **false**.
A counterexample that ends in a state where the invariant still holds is a
*false block* and must **not** block.

In short:

```
block(ce, inv)  ==  ∃ state s on the trace of ce :  s ⊭ inv
```

### 5.2 The false-block bug (and its fix)

The original check treated *any* counterexample returned by the engine as
blocking. That was wrong: some engines return a trace for reasons other than a
genuine invariant violation (e.g. a step that is legal but not the one the
property pins). The fix — implemented in `rot/falseblock.py` — re-evaluates the
invariant over every state of the returned trace and only blocks if at least one
state falsifies it.

> Result: the Step 3.6 decision rule is **correct and test-covered**
> (`Ran 18 tests ... OK`). The remaining blocker is *not* the decision rule —
> it is Chain B, i.e. getting the emitted TLA+ accepted by Apalache/Snowcat,
> which is the `@type` annotation issue resolved in §9.

### 5.3 Measuring false-block rate

`rot/falseblock.py` also exposes a small metric harness so a change set can be
scored: of the counterexamples it produced, how many were *witnessing* (good
blocks) vs *spurious* (false blocks). A healthy target yields **zero** false
blocks across the matrix.

---

## 6. Targeted Test Suite (Step 3.5)

The Step 3.5 suite is a focused, fast regression gate that exercises each
layer in isolation so a break in one layer is localised immediately.

### 6.1 What is covered

| Layer | What is tested |
|-------|----------------|
| IR model | variable domains, action effects, invariants for each registered target |
| Lineariser | single `Init`, one action per step, `Next` disjunction, `busy` self-loop |
| Emitter | `VARIABLE` + `@type` annotations, annotated `vars`, `Spec`, invariant operator |
| Verdict logic | 4-state normalisation, exit-code mapping |
| False-block | witnessing vs spurious counterexample classification |

### 6.2 How to run

```powershell
# from the repository root
python -m unittest discover -s tests -v
```

Expected: all tests pass, e.g.

```
Ran 18 tests in 0.031s
OK
```

> The suite is intentionally **engine-independent**: it asserts on the emitted
> TLA+ and the verdict logic, not on TLC/Apalache themselves, so it runs in any
> environment (including CI without Java).

---

## 7. Deterministic Counterexample Search (Step 3.6.1)

A VIOLATED verdict is only actionable if it comes with a **reproducible**
counterexample. Step 3.6.1 requires that the counterexample is produced by a
deterministic search and is delivered *with* the verdict.

### 7.1 How the counterexample is produced

1. The engine (TLC or `symbolic`) searches the reachable state space for a
   state that falsifies the pinned invariant.
2. On a hit, it records the **trace** (the sequence of states/actions from
   `Init` to the violating state).
3. `pipeline.py` normalises that trace into ROTN's counterexample format and
   writes it to `out/` alongside the JSON + Markdown report.

### 7.2 Determinism guarantees

- **Same input, same trace.** Because the `symbolic` engine is deterministic
  (§4.3), re-running the identical command reproduces the identical
  counterexample. This is what makes it safe to ship as a CI artifact.
- **Witnessing.** The trace is guaranteed to *witness* the violation
  (Step 3.6, §5) — the last state falsifies the invariant. A non-witnessing
  trace is discarded, never reported.

### 7.3 Delivery

Every VIOLATED verdict carries, in `out/`:

- `report.json` — machine-readable verdict + counterexample trace.
- `report.md` — human-readable narrative + the violating states.
- (Apalache path) `violation.itf.json` / `violation.json` — the engine's native
  counterexample (see §9).

> Contract: **no VIOLATED verdict may be emitted without a witnessing,
> reproducible counterexample.** A counterexample that fails either criterion
> downgrades the verdict to `UNKNOWN`, it is never reported as VIOLATED.

---

## 8. ZooKeeper/ZAB Bug-Replay Evaluation (Step 3.7)

Step 3.7 evaluates the MR gate on the **ZAB** target the way a CI reviewer would:
it replays a small, *honest* corpus of plausible ZooKeeper commit-path changes,
scores each one, and reports whether the gate is trustworthy — i.e. it blocks real
bugs and lets safe changes through.

> Unlike the `correct`/`buggy` matrix (§12), this corpus is *not* chosen to force
> a verdict. It deliberately includes changes that should pass, a reachable bug the
> gate must catch, and one bug the gate misses — so the evaluation measures
> **detection recall**, not just **blocking precision**.

### 8.1 What is checked

Each commit is a `(before, after)` pair of `ProtocolIR` objects — not a raw diff —
exactly what the gate consumes. The gate runs both ZAB invariants with the
deterministic `symbolic` engine, then applies the Step 3.6 blocking rule (§5): a
commit is `BLOCK`ed only if a **witnessing** counterexample falsifies a *blocking*
invariant.

| Invariant | Tier | Meaning |
|-----------|------|---------|
| `zab_no_premature_apply` | **BLOCK** | no participant applies a request before `committed_i` is set — the core ZAB safety guarantee. |
| `zab_apply_persisted` | `WARN` (non-blocking) | a participant never applies a request it has not persisted. |

### 8.2 The corpus (6 commits)

| Commit | Change (before → after) | True label | Gate | Classification |
|--------|--------------------------|------------|------|----------------|
| `ZK-001` | apply gated on `phase == "committed"` | **bug** (premature apply) | `BLOCK` | **TP** (witnessed) |
| `ZK-002` | remove `committed_i` precondition from `zab_apply` | **bug** (premature apply) | `BLOCK` | **TP** (witnessed) |
| `ZK-003` | drop `committed_i = True` from `zab_commit` | **bug** (quorum commit) | `PASS` | **FN** (coverage gap) |
| `ZK-S1` | `phase` init `initial` → `idle` | safe | `PASS` | **TN** |
| `ZK-S2` | rename `leader` → `leader_id` | safe | `PASS` | **TN** |
| `ZK-S3` | add no-op `leader_lease` bookkeeping | safe | `PASS` | **TN** |

### 8.3 Key result — `ZK-002`

`ZK-002` was first written as "apply without persisting." In the base model that
mutation is a **behavioral no-op**: `zab_apply` already requires `phase ==
"committed"`, and `zab_commit` sets `committed_i` *and* appends the log, so any
state that could apply has already persisted. The gate correctly returned
`PASS` — not a false negative.

The mutation was then redesigned into the *reachable* premature-apply bug —
removing the `committed_i` precondition from `zab_apply`. Now a follower can apply
before it has committed, and the gate returns `BLOCK` with a deterministic witness
(apply with `committed_i = False`).

> **Lesson:** a "correct" `PASS` is not always a missed bug. Here the gate's
> `PASS` on the original `ZK-002` was *right* — the named bug was unreachable —
> and the evaluation surfaced that the *real* risk was premature apply, which the
> gate does catch.

### 8.4 Aggregate metrics

| Metric | Value | Note |
|--------|-------|------|
| **False-block rate** | **0.0 %** | no safe commit was blocked — the gate's key CI property holds. |
| **Blocking precision** | **100 %** | every `BLOCK` was a true positive (witnessed). |
| **Blocking recall** | **66.7 %** (2/3) | `ZK-003` not caught. |
| **Detection recall** | **66.7 %** (2/3) | `ZK-003` not detected. |

### 8.5 The `ZK-003` coverage gap (honest false negative)

`ZK-003` drops `committed_i = True` from `zab_commit`, so a request can be
*committed* without a quorum having persisted. Neither current ZAB invariant
catches this: `zab_no_premature_apply` still holds (apply is still gated on
`committed_i`), and `zab_apply_persisted` is already implied by commit in the base
model. This is a genuine **coverage gap**, not a false positive. Closing it
requires a **quorum** invariant (e.g. `zab_commit_requires_quorum`), an
intentional design decision tracked as follow-up work.

### 8.6 Reproduce

```powershell
python -m rot.zk_bugs                          # run the corpus + print metrics
python -m unittest tests.test_zk_bug_replay -v # corpus/verdict/metric tests
```

> Full rationale, the per-commit witnesses, the `ZK-002` explanation, and the
> `ZK-003` gap analysis are in [`docs/phase3-eval.md`](docs/phase3-eval.md). The
> corpus lives in `rot/zk_bugs.py`.

---

## 9. Apalache / SANY Integration & the `@type` Annotation

### 9.1 What Apalache is used for

Apalache is used as an **external cross-check engine**, driven directly via
`apalache-mc`, and is *not* a `run.ps1` pipeline engine. `run.ps1` keeps
`apalache` as a **reserved** engine value (WP2 pending): `-Engine apalache` is
*recognised* and handled gracefully (a clear message + exit 2 in single-run
mode, a `NOT_IMPL` column in matrix mode) rather than passed to `pipeline.py`,
whose argparse would reject it with a confusing error.

The value of the Apalache path is that it is an **independent** SANY-based
frontend + bounded model checker. If the emitted TLA+ passes `apalache
typecheck` **and** `apalache check --inv=<Invariant>`, the spec is accepted by a
second, independent implementation — strong evidence that the generated TLA+ is
well-formed and the invariant behaviour is genuine, not an artifact of one
engine's permissiveness.

### 9.2 The integration path

```
rot/targets.py          build IR (correct / buggy, n=3)
        |
rot/linearization.py    linearise to a finite FSM
        |
rot/emitter.py          emit TLA+ WITH Snowcat-compatible @type annotations
        |               (out/work/<module>.tla)
        v
apalache typecheck      PASS #0 SanyParser, PASS #1 TypeCheckerSnowcat
        v
apalache check --inv=   bounded model check -> PASS (correct) / VIOLATION (buggy)
```

`regen_check.py` regenerates the real TwoPC spec through exactly this pipeline
path, so the Apalache run checks the *same* TLA+ the pipeline emits.

### 9.3 The `@type` annotation issue (root cause)

Apalache 0.62.3 (the Snowcat typechecker, `TypeCheckerSnowcat` / ETC pass) is
strict about two things the earlier ROTN emitter did not satisfy:

1. **Per-variable annotation is required.** Every variable in the `VARIABLE`
   block needs an explicit `@type`. Omitting one fails immediately:
   ```
   PASS #1: TypeCheckerSnowcat
   TypingInputException: Expected a type annotation for VARIABLE phase
   correct_agreement.tla:3:10-3:14: type input error:
       Expected a type annotation for VARIABLE phase
   ```
   (observed in `out/work/_apalache-out/correct_agreement.tla/…/detailed.log`).

2. **The `vars` tuple is ambiguous.** A stuttering tuple whose components are
   all the same type — `<< v1, …, vn >>` — matches *both* the n-tuple type
   `<< T, …, T >>` and `Seq(T)`. Snowcat cannot disambiguate and reports:
   ```
   Annotation required. Found 2 matching operator signatures
   Error when computing the type of vars
   ```

Both are **annotation** problems, not protocol problems.

### 9.4 The fix in the emitter

`rot/emitter.py` now emits the two forms Snowcat accepts and enforces:

- **Per-variable** annotation — a `\* @type: <T>;` line-comment immediately
  *before* each variable name in the `VARIABLE` list. (A single whole-list
  annotation, or a named payload such as `phase: Str`, is *rejected* by this
  build.)
  ```tla
  VARIABLE
    \* @type: Int;
    x
    \* @type: Bool;
    committed
    \* @type: Str;
    phase
  ```
- **Annotated `vars` operator** — pinning the tuple type to disambiguate it
  from `Seq(T)`:
  ```tla
  \* @type: << Int, Bool, Str >>;
  vars == << x, committed, phase >>
  Spec ==
    Init
    /\ [][Next]_vars
  ```

Type selection (`Emitter._tla_type`) is derived from each variable's IR domain:
`IntRange → Int`, `Bool → Bool`, `Enum →` the homogeneous value type (`Bool` /
`Int` / `Str`), defaulting to `Str` (phases/votes are the common kind). `bool`
is checked before `int` (bool subclasses int in Python).

### 9.5 Verified results (apalache 0.62.3, build 3eb15b2)

- `apalache typecheck` **accepts** the annotated spec — and **enforces** it: a
  string variable annotated as `Int` *fails* typecheck. So the annotations are
  meaningful, not decorative.
- `apalache check --inv=<Invariant>` runs to completion on the annotated spec:
  - **correct** target → invariant holds (no violation).
  - **buggy** target → violation, with a native counterexample
    (`violation.itf.json` / `violation.json`, e.g. `varTypes.phase = "Str"`).

This matches the `symbolic` / `tlc` verdicts, giving an *independent*
confirmation of both the PROVEN (correct) and VIOLATED (buggy) outcomes.

### 9.6 Status & impact

- **Chain B is unblocked.** The emitted TLA+ is now accepted by Apalache's
  Snowcat frontend and checked by Apalache's bounded model checker.
- **Apalache remains an external cross-check**, not a `run.ps1` engine (still a
  WP2 reserved value). Promoting it to a first-class `-Engine` value is the
  remaining integration step.

---

## 10. End-to-End Workflow (commands)

From a clean checkout to "correct passes / buggy is rejected".

### 10.1 One-shot run (auto engine)

```powershell
# correct target must be PROVEN (exit 0)
.\run.ps1 -Target correct -Property agreement -Engine auto
# buggy target must be VIOLATED (exit 1) with a reproducible counterexample
.\run.ps1 -Target buggy   -Property agreement -Engine symbolic
```

### 10.2 List registered targets & invariants

```powershell
.\run.ps1 -List
```

### 10.3 Full matrix (CI gate)

```powershell
# cross-check both engines across every target x invariant
.\run.ps1 -Matrix -Engines symbolic,tlc
# writes: out/matrix.csv  (machine-readable)
#         out/matrix.md   (human-readable pivoted table)
```

Legend: `PROVEN=0  VIOLATED=1  UNKNOWN=2  ERROR=3  NOT_IMPL=reserved (WP2)`.

### 10.4 Run the targeted test suite

```powershell
python -m unittest discover -s tests -v
```

### 10.5 Drive Apalache directly (external cross-check)

```powershell
# 1. regenerate the real TwoPC spec through the pipeline path
python regen_check.py          # prints TLA_PATH=out/work/correct_agreement.tla
# 2. typecheck (Snowcat) and bounded model check
apalache typecheck out/work/correct_agreement.tla
apalache check   --inv=Agreement out/work/correct_agreement.tla
```

> Expected: `typecheck` passes; `check` reports the invariant holding for the
> correct target and a violation (with `violation.itf.json`) for the buggy one.

---

## 11. Artifacts

What ROTN produces, and where.

| Path | Producer | Content |
|------|----------|---------|
| `out/work/<module>.tla` | `rot/emitter.py` (via `pipeline.py` / `regen_check.py`) | The emitted TLA+ module (`correct_agreement.tla`, `buggy_agreement.tla`, …) with Snowcat-compatible `@type` annotations. |
| `out/work/_apalache-out/<module>.tla/<run>/run.txt` | `apalache-mc` | The exact Apalache command that ran. |
| `out/work/_apalache-out/<module>.tla/<run>/detailed.log` | `apalache-mc` | Pass-by-pass log (SanyParser → TypeCheckerSnowcat → …). |
| `out/_apalache-out/<module>.tla/<run>/violation.itf.json` | `apalache-mc` | Native counterexample (ITF) for a VIOLATED run. |
| `out/report.json` | `pipeline.py` | Machine-readable verdict + counterexample trace. |
| `out/report.md` | `pipeline.py` | Human-readable verdict narrative. |
| `out/matrix.csv` | `run.ps1 -Matrix` | One row per target × property × engine (CI gate input). |
| `out/matrix.md` | `run.ps1 -Matrix` | Pivoted, human-readable verdict grid. |

> All artifacts are written under `out/` (override with `-Out`). The
> counterexample is a first-class artifact: a VIOLATED verdict without a
> witnessing, reproducible trace is downgraded to `UNKNOWN` (§7.3).

---

## 12. Verdict Matrix

Expected outcome for each registered target × invariant. A **correct** target
must be `PROVEN` and a **buggy** target must be `VIOLATED` on **both** engines;
any deviation (esp. a buggy target that is `PROVEN`, or a correct target that is
`VIOLATED`) is a bug in the target model or the pipeline.

| Target | Invariant | `symbolic` | `tlc` | Apalache (external) |
|--------|-----------|-----------|-------|---------------------|
| `correct` | `agreement` | `PROVEN` (0) | `PROVEN` (0) | `check` passes |
| `correct` | `validity`  | `PROVEN` (0) | `PROVEN` (0) | `check` passes |
| `buggy`   | `agreement` | `VIOLATED` (1) + counterexample | `VIOLATED` (1) + counterexample | `check` → violation |
| `buggy`   | `validity`  | `VIOLATED` (1) + counterexample | `VIOLATED` (1) + counterexample | `check` → violation |

> The exact per-target invariant set is listed by `.\run.ps1 -List`. The `apalache`
> column is `NOT_IMPL` in `run.ps1` matrix mode (reserved, WP2) — the Apalache
> results above are obtained by driving `apalache-mc` directly (§10.5).

---

## 13. Known Limitations

- **Bounded liveness, not unbounded.** The protocol plane is safety-only: the
  `busy` self-loop makes the relation total so terminal states do not read as
  deadlocks, and *unbounded* liveness (termination, "the commit eventually
  happens" with no horizon) is **not** checked. The Agent Mode plane (§17.3)
  does check **bounded** liveness — `bounded_eventually` over a declared
  horizon — which stays decidable inside the bounded engine.
- **Bounded.** A `PROVEN` verdict is a *bounded* result over the declared state
  space (`-MaxStates`, `-N`). A budget cap can yield `UNKNOWN` (it can never
  assert a false `PROVEN`).
- **Small `n`.** Targets are verified at 2–3 participants. Larger `n` grows the
  state space; the bounded engines may return `UNKNOWN` before completing.
- **Apalache not a first-class engine.** Apalache is an external cross-check
  driven via `apalache-mc`; `run.ps1 -Engine apalache` is a reserved (WP2)
  placeholder, not an implemented pipeline engine (§9.1, §9.6).
- **Not a proof certificate.** Bounded model checking is not the same as a
  theorem-proof; `PROVEN` means "held over the explored bound", not "proven for
  all time".
- **Counterexample fidelity.** The delivered counterexample is faithful to the
  *linearised* FSM; mapping it back to the original (non-linearised) IR
  protocol step is a presentation aid, not a guarantee of a one-to-one
  correspondence in every non-deterministic branch.

---

## 14. Extension Guide (adding a protocol / invariant)

### 14.1 Add a new protocol

1. **IR model.** Add a `build(target, n)` in `rot/targets.py` returning an IR
   model with typed variables (`IntRange` / `Bool` / `Enum`), an `init` action,
   and a list of transition actions.
2. **Register it.** Add the target name (and its `correct`/`buggy` variants) to
   the registry so `.\run.ps1 -List` shows it.
3. **Invariants.** Declare `agreement` and/or `validity` (or your own) as
   expressions over the IR variables.
4. **Verify.** `.\run.ps1 -Matrix -Engines symbolic,tlc` — confirm `correct ⇒
   PROVEN`, `buggy ⇒ VIOLATED` (+ counterexample) on both engines.

### 14.2 Add a new invariant

- Express it as an IR expression over the model's variables (e.g. a `∀` over the
  decided values). The emitter renders it as a named TLA+ operator
  (`_op_name`) and pins it with `--inv=<Name>`.
- Keep it a **safety** property, or a **bounded liveness** property expressed as
  `bounded_eventually` over a declared horizon (the Agent Mode plane, §17.3).
  Unbounded liveness is outside the bounded-engine contract.

### 14.3 Emitter compatibility checklist (Apalache / Snowcat)

When changing the emitter, keep these Snowcat requirements intact (§9):

- [ ] Per-variable `\* @type: <T>;` immediately before each `VARIABLE` entry.
- [ ] An annotated `vars` operator (`\* @type: << T1, T2, … >>;`).
- [ ] `bool` checked before `int` in `_tla_type` (bool subclasses int).
- [ ] The totalising `busy` self-loop (`UNCHANGED <<vars>>`) is present.
- [ ] Re-run `apalache typecheck` and `apalache check --inv=…` on the emitted
      spec to confirm Snowcat still accepts it.

---

## 15. File Map

| Path | Purpose |
|------|---------|
| `run.ps1` | PowerShell runner: single run / `-List` / `-Matrix`; engine selection (`auto`, `tlc`, `symbolic`, and reserved `apalache`); writes `out/matrix.{csv,md}`. |
| `pipeline.py` | Chain A orchestrator: build IR → linearise → emit → run engine → normalise verdict (exit code). |
| `regen_check.py` | Regenerates the real TwoPC spec through the pipeline path for driving Apalache. |
| `rot/targets.py` | Registered targets (`correct`/`buggy` × protocol) + invariants; `build(target, n)` IR model. |
| `rot/linearization.py` | `linearize(ir)` — IR → finite FSM (single `Init`, one action per step). |
| `rot/emitter.py` | IR/FSM → TLA+ module; emits `@type` annotations, `busy` self-loop, annotated `vars`, `Spec`, invariant operator. |
| `rot/falseblock.py` | Step 3.6 — false-block detector / metric (witnessing counterexample check). |
| `rot/impact.py` / `rot/incremental.py` | Incremental translation: re-emit only the changed TLA+ fragment for quick re-check. |
| `tests/` | Step 3.5 — targeted, engine-independent regression suite. |
| `rot/zk_bugs.py` | Step 3.7 — ZAB bug-replay corpus (6 commits) + gate evaluation + metrics. |
| `tests/test_zk_bug_replay.py` | Step 3.7 — corpus, verdict, classification, metric, and report tests. |
| `docs/phase3-eval.md` | Step 3.7 — full evaluation rationale, per-commit results, metrics, and limitations. |
| `out/work/<module>.tla` | Emitted TLA+ (correct / buggy variants). |
| `out/report.{json,md}` | Verdict + counterexample artifact. |
| `out/matrix.{csv,md}` | CI gate matrix (target × property × engine). |
| `out/**/_apalache-out/**/` | Apalache run logs, `run.txt`, `detailed.log`, `violation.itf.json`. |
| `rot/agent_step.py` | Agent Mode (§17) — the `AgentStep` model: `build_ir(buggy=...)`, `policy_conformance_property`. |
| `rot/frontends/policy/` | Agent Mode (§17) — narrow-waist policy front-ends: `cedar.py`, `dogwood.py`, `agent_step_liveness.py`; `build_ir(...)` routes by `kind` (safety / realizability / liveness). |
| `samples/agent.cedar`, `samples/policy.json`, `samples/tools.json` | Agent Mode (§17) — shipped sample Cedar and Dogwood policies. |
| `docs/agent-mode.md` | Agent Mode (§17) — full user guide, threat model, bounded-liveness caveats, CLI reference. |
| `scripts/run_agent_mode.sh` | Agent Mode (§17) — CI / quick-start matrix (bash, exit 0 on all-pass). |
| `rot/trace.py` | The Ship plane (§18) — RTF v1: the deterministic, hashable Reasoning Trace Format (the site's data contract). |
| `rot/sitegen.py` | The Ship plane (§18) — mirrors `data/*.trace.json` into the offline `data/traces.js` registry (deterministic). |
| `site/` | The Ship plane (§18) — the hosted replay site: `index.html`, `404.html`, `app/*.js` (verdict hero, graph, timeline, spend-cap, narration, findings, compliance, coach, compare/K-sweep), `app/style.css` (design system), `vendor/cytoscape.min.js`, `data/*.trace.json`. |
| `tests/test_site.py` | The Ship plane (§18) — scaffold + RTF-v1 + registry-mirror + determinism invariants for `site/`. |
| `scripts/gen_site_data.py` | The Ship plane (§18) — thin CLI wrapper over `rot.sitegen` (regenerate `data/traces.js`). |
| `.github/workflows/pages.yml` | The Ship plane (§18) — regenerates the site data (`python -m rot site`) and deploys `site/` to GitHub Pages on push to `main`. |
| `ROTN_Technical_Report.md` | This report. |

---

## 16. Glossary

| Term | Meaning |
|------|---------|
| **IR** | ROTN's internal representation of a protocol model (typed variables, `init`, transition actions, invariants). |
| **Linearised FSM** | The finite state machine produced by `linearize()`: one `Init`, one action per step, `Next = ⋃ actions ∪ {busy}`. |
| **`busy` self-loop** | A totalising `UNCHANGED <<vars>>` step so terminal states do not read as deadlocks; adds no reachable states. |
| **Agreement** | Safety invariant: no two participants decide different values. |
| **Validity** | Safety invariant: any decided value was proposed by some participant. |
| **Blocking permission** | Step 3.6 rule: a counterexample may block a change only if it *witnesses* the invariant being broken. |
| **False block** | A counterexample that does *not* witness the invariant being broken; must not block (Step 3.6 fix). |
| **Deterministic counterexample** | Step 3.6.1: a reproducible trace delivered with every VIOLATED verdict. |
| **Snowcat** | Apalache's typechecker (ETC-based). Strict about `@type` annotations and the `vars` tuple type. |
| **`@type` annotation** | A `\* @type: <T>;` comment (per variable, and on the `vars` operator) required by Snowcat. |
| **Chain A** | The verify pipeline (model → TLA+ → engine → verdict). |
| **Chain B** | The emission compatibility layer making generated TLA+ accepted by Apalache/Snowcat. |
| **PROVEN / VIOLATED / UNKNOWN / ERROR** | The 4-state verdict contract (exit codes 0 / 1 / 2 / 3). |
| **WP2** | Work-package 2 — the pending work to make Apalache a first-class `run.ps1` engine. |
| **Bug-replay (Step 3.7)** | The gate evaluated on a corpus of `(before, after)` IR commits; scores each and reports false-block rate, blocking precision, and blocking recall. |
| **Blocking precision / recall** | Precision = fraction of `BLOCK` verdicts that are true positives. Recall = fraction of true bugs the gate blocks. |
| **Agent Mode** | The policy-driven verification plane (§17): Cedar/Dogwood front-ends build the `AgentStep` model on the narrow waist; the same bounded engines and soundness core check it. |
| **`AgentStep`** | The single-agent action-choice model (`rot.agent_step`): a *conforming* agent (only allowed actions) and a *compromised* variant (may take denied actions). |
| **`policy_conformance`** | Safety invariant (Agent Mode, pinned, blocking): the agent *never* takes a policy-denied action. |
| **`bounded_eventually`** | Bounded-liveness invariant (Agent Mode, pinned): a goal is reached *within a declared horizon B*. |
| **Bounded liveness** | "Goal reached within B steps" — a sound, decidable property of the bounded model. Distinct from unbounded liveness/fairness, which is out of scope. |
| **Cedar / Dogwood** | The two Agent Mode policy front-ends: Cedar (`.cedar`, declarative permit/forbid) and Dogwood (`.json`, allowed/denied action sets). Both build a `ProtocolIR` only. |

---

## 17. Agent Mode: policy-driven verification

ROTN's third plane. Given a **policy** that constrains what an autonomous agent may do, and the set of **tools** (actions) it may invoke, Agent Mode builds a small model of the agent choosing actions and checks — with the same soundness core (§13) and bounded engines (§10) — whether the agent conforms to the policy, whether the policy is realizable, and whether the agent acts within a declared horizon (**bounded liveness**, never unbounded liveness).

This section is the normative overview. The full user guide, threat model, bounded-liveness caveats, and CLI reference live in **`docs/agent-mode.md`**.

### 17.1 Three planes, one core

| Plane | Model | Front-end | Pinned property |
|---|---|---|---|
| Protocols (§1–§12) | `twopc`, `zab`, `pbft`, `payment`, … | IR authors | `agreement`, `validity`, `zab_leader`, … |
| **Agent Mode (§17)** | `AgentStep` (`rot.agent_step`) | **Cedar** (`.cedar`), **Dogwood** (`.json`) | `policy_permits_request`, `policy_conformance`, `bounded_eventually` |

All planes reduce to the same narrow waist: a `ProtocolIR` (§4) with a pinned `Invariant` (§4.2) and `metadata`. Agent Mode adds no new engine, verdict path, or soundness rule — it reuses `symbolic` / `TLC` / `apalache` / `sat` and the CEGAR loop exactly as the protocol plane does.

### 17.2 The two policy front-ends

Both front-ends live in `rot/frontends/policy/` and implement the narrow-waist contract: `build_ir(...) -> ProtocolIR`. They differ only in the policy language and the pinned property:

- **Cedar** (`rot/frontends/policy/cedar.py`) — parses a Cedar policy (`.cedar`) into a declarative `permit`/`forbid` decision model, pinning the **realizability** property `policy_permits_request` (`metadata["property_kind"]="realizability"`): *there exists* a reachable state in which the policy admits the request. This is a non-vacuity check that catches policies that forbid everything.
- **Dogwood** (`rot/frontends/policy/dogwood.py`) — parses a Dogwood policy (`.json`) of allowed/denied action sets, pinning the **safety** property `policy_conformance` (`metadata["property_kind"]="safety"`): *in every* reachable state the agent never takes a policy-denied action.

The **bounded-liveness** twin, `rot/frontends/policy/agent_step_liveness.py`, reuses the same `AgentStep` model but pins the **liveness** property `bounded_eventually` (`metadata["property_kind"]="liveness"`, goal `decision != idle`): the agent *acts within* a declared horizon. The router `rot/frontends/policy/__init__.py:build_ir(...)` dispatches on the policy file kind (`.cedar` → Cedar/realizability, `.json` → Dogwood/safety, plus an explicit liveness request) and returns the matching `ProtocolIR`.

### 17.3 The `AgentStep` model and its security model

`rot/agent_step.py` builds the model of a single agent choosing among its tools:

- `build_ir(buggy=...)` returns a `ProtocolIR` of the agent's action-choice state machine. The **conforming** agent (`buggy=False`) may only take *allowed* actions; the **compromised** variant (`buggy=True`) may also take *denied* actions. The two variants share all state, transitions, and metadata — only the enabled action set differs.
- `policy_conformance_property(policy)` builds the pinned safety invariant: the agent never takes a policy-denied action.

**Security model.** Agent Mode verifies *agent conformance to the policy*, not the correctness of the underlying tools. The policy is the specification of what the agent may do; the model is the agent's decision plane. A `PROVEN` `policy_conformance` means "no trace of the agent's decision plane, within the bound, takes a denied action" — it does **not** certify that the tools themselves are correct (that is the protocol plane's job, §1–§12). A `VIOLATED` verdict, with its counterexample, shows the concrete denied action the agent takes.

### 17.4 Three invariants and bounded liveness

| Invariant | Front-end | Kind | Pinned | Meaning |
|---|---|---|---|---|
| `policy_permits_request` | Cedar | realizability | yes | the policy admits *some* request (non-vacuity) |
| `policy_conformance` | Dogwood | safety | yes | the agent *never* takes a denied action |
| `bounded_eventually` | liveness twin | bounded liveness | yes | the agent *acts within* horizon B |

**Bounded liveness, not unbounded.** `bounded_eventually` asks whether the goal (`decision != idle`) is reachable *within B steps* (`--liveness-horizon`). It is **not** a claim of unbounded liveness or fairness. When reporting a result, always state the horizon: "the agent acts within B steps," never "the agent eventually acts."

### 17.5 Threat model and limitations

- **Scope:** Agent Mode verifies *agent conformance to policy* — not tool correctness, availability, or unbounded liveness.
- **Bounds:** every claim is within the declared bound (`--n-steps`, `--liveness-horizon`). `PROVEN` is bound-relative; `VIOLATED` is a concrete counterexample.
- **No fairness / scheduling assumptions** beyond the bounded environment model (§9.5).
- **Trust:** the policy file is the security-critical input. A weak policy can be `PROVEN` yet still unsafe in deployment — policy authoring is the user's responsibility (`docs/agent-mode.md`, §Threat model).

### 17.6 CLI, expected results, tests, CI

- **CLI:** `pipeline.py --policy <file> --tools tools.json [--n-steps N] [--liveness-horizon B]`. Cedar (`.cedar`) defaults to realizability; Dogwood (`.json`) defaults to safety; add liveness for `bounded_eventually`. See `docs/agent-mode.md`, §CLI reference.
- **Expected results (verified):** Cedar `samples/agent.cedar` → `policy_permits_request` **PROVEN**; Dogwood `samples/policy.json` (conforming) → `policy_conformance` **PROVEN** and `bounded_eventually` **PROVEN** within horizon; `agent-step` (conforming) → **PROVEN**; `agent-step-buggy` (compromised) → `policy_conformance` **VIOLATED** (denied action in counterexample).
- **CI:** `scripts/run_agent_mode.sh` runs the five checks above and exits 0 on all-pass.
- **Spend-cap demo:** `demo.ps1` / `demo.sh` run the three-phase `.dw` policy demo (PROVEN → VIOLATED → trifecta audit + manifest) and are exit-code aware; see `docs/spendcap-demo.md` and `docs/spendcap-usage.md`.
- **Tests:** `test_agent_step.py`, `test_agent_step_liveness.py`, `test_cedar_frontend.py`, `test_policy_pipeline.py`, `test_liveness.py`, `test_verdicts_liveness.py`.

## 18. The Replay Site (Ship Plane)

A verification run is only as convincing as its *evidence*. The **replay site**
(`site/`) is the **Ship plane**: a pure static bundle that replays a
verification run as an interactive, auditable proof. It is a **pure function of
the RTF trace** — it renders what the engine already recorded and **adds no
verification logic**. The site is zero-framework, zero-build-step, and
zero-CDN (Cytoscape is vendored), so it runs from a `pip install .` checkout,
from disk, or from GitHub Pages with no toolchain.

### 18.1 The data contract (RTF v1)

The single contract between the engine and the site is the **Reasoning Trace
Format v1** (`rot/trace.py`, `data/*.trace.json`):

- **Deterministic & hashable.** A trace is a pure function of the manifest +
  budget + horizon (no timestamps, no random IDs, stable ordering), so the same
  input always produces the same bytes. It carries a top-level `hash` (SHA-256
  of its own canonical body) that pins the exact reasoning, so a trace can be
  referenced, compared, and re-verified byte-for-byte.
- **Self-contained.** It carries the provenance (schema, `manifest_id`, source
  hash, policy, budget tier, horizon), the gate verdict, the engines that ran,
  the reasoning (graph, counterexample, decision tree, timeline), the
  blog-ready narration, and the findings (each with its SOC 2 / AIUC controls).
- **Superset of the findings report.** It reuses `rot.mcp_adapter` (structural
  checks + findings) and `rot/compliance.py` (SOC 2 / AIUC mapping); it only
  re-assembles them into one deterministic artifact.

The site reads the trace and presents it; it never re-derives the verdict.

### 18.2 What a replay page shows

Each panel is one module under `site/app/` and mounts only when the trace
carries the relevant section (fail-closed: an absent section is not rendered,
never faked):

| Panel | Module | Renders |
|-------|--------|---------|
| Verdict hero | `app.js` | the gate verdict (PROVEN / VIOLATED / UNKNOWN), the pinned invariant, budget tier, horizon, and the trace hash. |
| State-space / manifest graph | `graph.js` | the counterexample as an attack path (Cytoscape); an **animated replay** lights the path step by step so the in-flight amount visibly grows past the cap at the crossing moment. |
| Audit timeline | `timeline.js` | the ordered, colour-coded audit steps. |
| Spend-cap chart + decision tree | `spendcap.js` | total in-flight exposure (settled + in-flight · AMOUNT) vs. cap over the counterexample steps, crossing highlighted; plus the guard expression and per-step admit/deny checks. |
| Narration | `narration.js` | the engine-generated, blog-ready plain-English narrative as a line-highlighted transcript. |
| Findings & controls | `findings.js` | the Cedar-AR findings with severity, message, evidence, and their SOC 2 / AIUC control chips. |
| Compliance | `compliance.js` | the SOC 2 / AIUC controls the trace touched, with the evidence linking each control to the findings that triggered it (normalises spend-cap and manifest traces). |
| Coaching | `coach.js` | the CoachingArtifact (Rule + Proof + Coach): the 5-step loop Detect → Explain → Correct → Re-check → Close; green when the correction re-proved (closed), amber when it did not (open). |
| Compare + K-sweep | `compare.js` | side-by-side buggy vs. correct, plus an **animated K-sweep** over the concurrency-pool bound `K` (`--max-inflight`) the verdict depends on — `K=1` masks the race (false negative), `K≥2` exposes it. |

### 18.3 Offline-first architecture

Browsers block `fetch()` of local files over `file://`. The site works around
this without a server or build step:

- `rot/sitegen.py` (CLI: `rot site`, wrapper `scripts/gen_site_data.py`) mirrors
  `data/*.trace.json` into a single deterministic, script-loadable registry
  `data/traces.js` (`window.ROT_TRACES`), loaded via a plain `<script>` tag —
  so the gallery works offline from disk.
- When served over HTTP (GitHub Pages), `app.js` prefers
  `fetch('data/<id>.trace.json')` and falls back to the registry — the JSON
  traces stay the **source of truth**.
- Cytoscape is vendored at `vendor/cytoscape.min.js` (no CDN); if it is missing
  the graph degrades to a static list.

### 18.4 Design system & accessibility

`site/app/style.css` is hand-written CSS (no framework):

- **Theming** — a token set with **light**, **dark**, and **high-contrast**
  modes (dark via `prefers-color-scheme`, explicit `data-theme` override, and
  `forced-colors` for Windows High Contrast).
- **Responsive** — the panels, gallery, and compare view collapse gracefully at
  860px and 560px breakpoints.
- **Accessibility** — `:focus-visible` outlines, `prefers-reduced-motion`
  (disables the spinner and transitions), and semantic landmarks
  (`<header>`/`<main>`/`<footer>`, a skip-link, `aria-*` on panels).

### 18.5 Publishing & tests

- **Publish** — `.github/workflows/pages.yml` (Phase I) runs on push to `main`:
  it regenerates the site's RTF trace data from the committed sample policies
  with the *current* engine (`python -m rot site`, pure stdlib — no Java, no Z3,
  no network, no package install), uploads the `site/` bundle, and deploys it to
  GitHub Pages (`https://caravel.github.io/rot-verify/`).
- **Tests** — `tests/test_site.py` asserts the scaffold files exist, that
  `index.html` wires the vendored Cytoscape + app modules + registry, that
  `app.js` implements the `#/` and `#/replay/<id>` routes and the `file://`
  registry fallback, that every `data/*.trace.json` is valid RTF v1 (top-level
  hash = SHA-256 of the canonical body), that `data/traces.js` mirrors the
  trace JSON exactly, and that the site data generator is deterministic
  (byte-identical on re-run).

---

## Appendix A — WP1–WP6 Evidence & Honest Fallbacks

This appendix maps each work package to the **actual** tests and verdicts that
evidence it (the 629-test suite is authoritative), and records the honest
fallbacks we used where full automation was not feasible.

### A.1 Work-package → evidence map

| WP | Delivers (modules) | Evidence (tests) | Verdict evidence |
|----|--------------------|------------------|------------------|
| **WP1** IR + TLA+ emission + CEGAR | `rot.ir`, `rot.emitter`, `rot.cegar`, `rot.targets`, `rot.invariants` | `test_cegar.py`, `test_pipeline.py`, `test_invariants.py` | every target × invariant: `correct` → **PROVEN**, `buggy` → **VIOLATED** (exit 0 / exit 1) |
| **WP2** Symbolic SAT engine (sound baseline) | `rot.sat`, `rot.symbolic` | `test_sat.py`, `test_symbolic_engine.py` | DPLL + clause learning; 2PC/ZAB/PBFT `correct` PROVEN, `buggy` VIOLATED — runs with **no Java / no TLC jar** |
| **WP3** 2PC protocol | `rot.twopc` | `test_twopc.py` | `agreement` invariant: correct PROVEN / buggy VIOLATED |
| **WP4** ZAB protocol | `rot.zab` | `test_zab_target.py`, `test_zk_bug_replay.py` | `leader` invariant: correct PROVEN / buggy VIOLATED; ZK bug-replay (6-commit corpus) |
| **WP5** Environment fragments + refinement | `rot.env`, `rot.refine` | `test_env.py`, `test_refine.py` | `--env` bounded-delay soundness; `refine` propose/check/repair loop |
| **WP6** Agent Mode (§17) — Cedar/Dogwood + `AgentStep` | `rot.agent_step`, `rot/frontends/policy/*` | `test_agent_step.py`, `test_agent_step_liveness.py`, `test_cedar_frontend.py`, `test_policy_pipeline.py`, `test_liveness.py`, `test_verdicts_liveness.py` | Cedar `policy_permits_request` **PROVEN**; Dogwood `policy_conformance` **PROVEN** (conforming) / `agent-step-buggy` **VIOLATED**; `bounded_eventually` **PROVEN** within horizon |

> **Later work (same evidence style):** Apalache-ITF — `rot.itf` / `test_itf.py`
> (refutes, never proves); LLM baseline — `rot.llm_baseline` / `test_llm_baseline.py`
> (opt-in, non-sound, audit-only); PBFT — `rot.pbft` / `test_pbft_target.py`
> (`view-agreement`); Java/CPG front-end — `rot/frontends` / `test_java_model.py`,
> `test_narrow_waist.py`, `test_source_pipeline.py`.

### A.2 Honest fallbacks

We stay honest by not claiming capability we do not have. Where full automation
was infeasible we used bounded, transparent fallbacks:

- **Hand-written IR, not auto-extracted.** The 2PC/ZAB/PBFT invariants and IR
  models (`rot.twopc` / `rot.zab` / `rot.pbft`) are **trusted, hand-written**
  against `rot.ir` — not automatically extracted from source. The Java/CPG
  front-end (`rot/frontends/frontend_java.py`) provides a source → IR path for
  2PC, but the *invariant logic itself* is human-authored. This keeps the narrow
  waist intact (the front-end imports only `rot.ir`) while being explicit that
  the invariant logic is not machine-derived.
- **Bounded reasoning, not unbounded proof.** The symbolic engine and TLC are
  bounded (depth ≤ 32, bounded state). A `PROVEN` verdict is sound *within the
  bound*; we do **not** claim unbounded liveness/fairness. The Agent Mode
  plane (§17) does add **bounded** liveness — `bounded_eventually` over a
  declared horizon — which stays decidable inside the bounded engine.
- **Apalache-ITF is one-directional.** `rot.itf` *refutes* (replays ITF
  counterexamples) but *never proves*; an absent counterexample is **not**
  evidence of correctness.
- **LLM baseline never affects the verdict.** `--llm-baseline` writes an audit
  artifact only; the verdict and exit code always come from a sound engine
  (symbolic / TLC / ITF).
- **Single-process, bounded.** No cross-process parallelism; the pipeline is
  deterministic and bounded so every verdict is reproducible.

---

*End of report.*

