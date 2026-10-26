# ROTN — Novelty: temporal proof, not point-in-time checking

> Phase B.3 deliverable. This document states, precisely and honestly, what
> ROTN does differently from Cedar and Dogwood, why that difference matters,
> and — just as importantly — what ROTN does **not** claim. Every claim below
> is grounded in code that runs on this machine; the evidence commands at the
> end are reproducible.

## 1. The gap, in one paragraph

Cedar and Dogwood are **authorization languages**: a policy decision is a
pure function of *(the current request, the trace so far)*. That is the
**point-in-time** model — and it is a good one. It is sound, deterministic,
and monitorable, which is exactly what the Dogwood formal specification's
meta-properties (guide §7) require of a *monitor*.

But a point-in-time monitor has a structural blind spot: **it cannot see
concurrent, in-flight activity that has not yet settled into the trace.** A
burst of parallel requests, each individually admissible against the *settled*
trace, can collectively overshoot a budget — and the monitor, by design,
cannot catch it, because the in-flight requests are not in the settled trace.

ROTN changes the **unit of verification**. Instead of asking *"does this one
request, against the trace so far, pass?"*, it asks *"is there **any**
interleaving of concurrent requests that reaches a state that violates the
policy?"* It does this by **lowering the policy into a bounded transition
system** (the `ProtocolIR`) whose states include in-flight requests, and then
running **reachability analysis** (model checking) over *all* reachable states
— including the states that only exist when several requests are in flight at
once. That is **temporal proof**: reasoning about the *sequence of states* a
system can reach, not just the *trace* a monitor reads.

## 2. The point-in-time model (Cedar and Dogwood)

Cedar decides a single request from its context — principal, action,
resource. Dogwood extends Cedar with temporal constructs (`formerly within`,
`sum`, `count`, `exists`) that read the **history** of past events. In both,
the decision is still made **at one point in time**, against **one request**,
from **the settled history up to now**.

The Dogwood formal specification makes this model explicit and gives it six
meta-properties (guide §7,
[`tests/fixtures/aws_dogwood/spendcap/guide/08-formal-specification.md`](../tests/fixtures/aws_dogwood/spendcap/guide/08-formal-specification.md)):

| # | Meta-property | Statement (paraphrased) |
|---|---------------|-------------------------|
| 1 | **Fail-closed** | No evaluation failure produces `Allow`; every error path yields `Deny`. |
| 2 | **Lowering totality** | Every non-extension surface form has exactly one translation. |
| 3 | **Validation soundness** | `validate` presupposes a `Lowered`; parse/lowering failures are a separate fatal channel. |
| 4 | **Determinism of identity** | A rule's PolicyID and hoisted names are a pure function of rule key + ordinal. |
| 5 | **Statefulness confined to the temporal engine** | The policy engine is invoked *per-request over an empty entity set*; all history flows through hoisted `context.<id>` state. |
| 6 | **Acceptance ⇒ monitorability** | An accepted temporal condition denotes a finite, computable relation over the history (safe-range). |

Read carefully, these are all **operational** guarantees: they make the
*machinery* trustworthy — fail-closed evaluation, total lowering, sound
validation, deterministic identity, monitorable conditions. None of them is a
**soundness-of-intent** guarantee. Clause 5 says it plainly: the policy
engine is invoked *per-request over an empty entity set*, and history reaches
it only as settled, hoisted context. An in-flight request that has not
settled is simply not in that world.

**The blind spot, concretely.** Consider a spend-cap policy that sums over
*settled* (`response`) events. Three identical `fire(amount=100)` requests
arrive in parallel, before any response has settled. At each decision point,
the monitor sees `completed = 0` and admits the request — correctly, per the
settled history. All three fire. All three settle. `completed = 300 > cap`.
The monitor never once misbehaved; the policy was nevertheless violated.
This is the class of bug the point-in-time model is structurally blind to.

## 3. What ROTN does differently

ROTN's core novelty is a **change of the verification unit**:

| | Point-in-time (Cedar/Dogwood) | Temporal (ROTN) |
|---|---|---|
| **Question** | "Does this request pass against the trace so far?" | "Does **any** reachable state violate the policy?" |
| **Unit** | one request at one time | the entire reachable state space |
| **Concurrent in-flight** | invisible (not in the settled trace) | first-class state (`inflight = k`) |
| **Method** | monitor: pure function of the trace | model checker: reachability over states |
| **Result** | `Allow` / `Deny` for one request | `PROVEN` / `VIOLATED` / `OUT_OF_SCOPE` for the policy |

Concretely, ROTN:

1. **Lowers the policy into a bounded transition system** (`ProtocolIR`)
   whose state variables include the in-flight count (`inflight`) alongside
   the settled sum (`completed`). The lowering is the spend-cap class
   (`rot/lower.py`); the parser (`rot/dw.py`) supports the full Dogwood
   temporal language.
2. **Pins the property.** For a `<=` cap: the pinned property is
   `completed <= cap` in every reachable state (a safety invariant). The
   negation — `completed >= cap + 1` — is the target state for the
   reachability search.
3. **Runs bounded reachability.** The engine (symbolic-SAT, Z3, TLC, or
   Apalache — all wired in `rot/__main__.py`) explores the state space up to
   a bounded budget. If the target state is reachable, it returns a
   **witness** (a concrete interleaving). If it is not reachable within the
   bound, it reports `PROVEN` *within that bound* — and if the state space
   exceeds the budget, it reports `OUT_OF_SCOPE` (honest out-of-scope, not a
   silent error).
4. **Cross-checks.** With `--engine crosscheck`, the verdicts from multiple
   independent engines must agree on the witness fingerprint before the
   result is trusted.

The K-sweep (`--max-inflight`) makes the bound explicit: at `K = 1` the
in-flight state is structurally absent, so the race is unexpressible and the
buggy policy proves clean; at `K = 2` or `K = 3` the parallel-fire state
exists and the violation is found.

## 4. The K-dependence (an honest limit, not a bug)

The K-dependence is the most important honesty point in this document:

| K (max-inflight) | Buggy policy verdict | Why |
|---|---|---|
| 1 | `PROVEN` | With `inflight ≤ 1`, the state `(completed=0, inflight=3)` does not exist. The race is structurally unexpressible at this bound. |
| 2 | `VIOLATED` (witness) | `(completed=0, inflight=2)` is reachable; two parallel fires settle past the cap. |
| 3 | `VIOLATED` (witness) | `(completed=0, inflight=3)` is reachable; three parallel fires settle to `completed = 300 > cap`. |

This is not a bug in ROTN — it is the **expected behavior of a bounded model
checker**. The bound is part of the claim: "PROVEN at K=1" is a true and
useful statement (the policy holds for any schedule with at most one
in-flight request). "VIOLATED at K=3" is a true and actionable statement
(here is a concrete interleaving that breaks it). ROTN reports both,
honestly.

## 5. Comparison table

| Dimension | **Cedar** (per-request) | **Dogwood** (temporal monitor) | **ROTN** (temporal proof) |
|---|---|---|---|
| **Unit of verification** | one request at one time | one request against the settled history | all reachable states (up to bound) |
| **Temporal data** | none (context only) | settled history (past events) | settled state **+ in-flight state** |
| **Concurrency / in-flight** | not modeled | not in the settled history | first-class state variable |
| **Catches a parallel-fire budget bug?** | No (no temporal data) | No (in-flight not in history) | **Yes** (witness at K ≥ 2) |
| **Soundness** | sound decision | fail-closed (§7) | sound (holds in *all* reachable states) |
| **Determinism** | deterministic | deterministic (§7) | deterministic (pure function of model + bound) |
| **Scope of guarantee** | per-request | operational guarantees over the settled history (§7) | over the reachable state space, **within the bounded budget** |
| **Soundness-of-intent** (does the policy *hold* under interleavings?) | No | No | **Yes — bounded** (PROVEN over all reachable states) |
| **When it can't decide** | n/a | n/a (always decides) | `OUT_OF_SCOPE` (explicit, honest) |
| **Artifact on failure** | n/a | n/a | **witness** (replayable interleaving) |

The last two rows are the differentiators: ROTN is the only one of the three
that can produce a **concrete counterexample** (a witness interleaving) and
the only one that can report **"I cannot decide"** instead of silently
passing.

## 6. How ROTN relates to the §7 meta-properties

ROTN is **not** a replacement for the Dogwood monitor. It is a different
tool for a different question:

- **It inherits the monitor's guarantees.** ROTN's lowering produces a model
  whose *settled* behavior matches the monitor's semantics (the `sum` over
  `response` events, the `<=` cap). The monitor's fail-closed evaluation,
  determinism, and monitorability (guide §7) are preserved in the model —
  ROTN does not re-derive them; it builds on them.
- **It adds a guarantee the monitor cannot make.** "The pinned property
  holds in *all* reachable states (up to the bound)" is a statement about
  the *state space*, not the *history*. The monitor cannot make this
  statement because its world is the settled history. ROTN can, because its
  world is the state space. This is the same *spirit* as §7's fail-closed /
  determinism guarantees, applied to the state space instead of the history.
- **It extends the domain of verification.** §7's guarantees are scoped to
  the *machinery over the settled history* — Acceptance ⇒ monitorability is
  about the history the monitor can read. ROTN's guarantee is scoped to
  *"within the reachable state space (up to the budget)"* — a strictly
  larger domain that includes concurrent interleavings the monitor's world
  does not. That is the gap §2 identified, and it is exactly the domain where
  ROTN adds value.

## 7. Honesty: what ROTN reports and what it does not

ROTN's report semantics are designed so that a `PROVEN` verdict is always
trustworthy and a `VIOLATED` verdict always comes with evidence:

- **`PROVEN`** means: within the bounded state space (up to the budget and
  up to `K`), the pinned property holds in every reachable state. This is a
  bounded claim, and ROTN states the bound.
- **`VIOLATED`** means: a concrete reachable state violates the pinned
  property, and a **witness** (a replayable interleaving) is produced. The
  witness is the evidence; it can be re-run to confirm.
- **`OUT_OF_SCOPE` is a first-class verdict.** When a policy's state space
  exceeds the bounded budget (e.g. `ProductTooLarge`, state space > 200k) or
  its shape cannot be lowered to a model, ROTN reports `OUT_OF_SCOPE` — it
  does **not** fall back to `ERROR` and it does **not** silently pass. A
  verdict of "I cannot decide" is surfaced, not hidden. This is the same
  refusal to overclaim that §7's fail-closed property embodies — a success
  verdict is only ever reported when the machinery can back it — applied to
  the prover itself.
- **The K-sweep is exposed, not buried.** The K-dependence (Section 4) is a
  real limit: at `K = 1` ROTN reports `PROVEN` on the buggy policy because
  the race is structurally unexpressible. ROTN does not hide this — it is
  documented, and a K-sweep is the recommended way to surface it. A bounded
  model checker that admits its bound is honest; one that pretends to be
  unbounded is not.

The through-line: **ROTN would rather say "I cannot decide" than say "it's
safe" when it cannot actually rule out a violation.**

## 8. What ROTN does not claim

To keep the novelty claim honest, ROTN explicitly does **not** claim:

- **Not a general-purpose model checker.** It lowers a *specific, recognized
  shape* of temporal policy (budget/cap over a bounded event set) into a
  bounded transition system. It is not a full LTL/CTL model checker and does
  not claim completeness over arbitrary temporal logics.
- **Not unbounded.** The reachability search is bounded by the state-space
  budget and by `K`. Beyond that bound, ROTN reports `OUT_OF_SCOPE`; it does
  not claim to have checked the infinite system.
- **Not a runtime monitor.** ROTN is an offline, design/CI-time proof tool.
  It does not replace the Dogwood monitor at request time; it complements it
  (Section 6).
- **Not a security guarantee of the host system.** A `PROVEN` verdict means
  the *lowered model* satisfies the *pinned property* within the bound. It is
  a guarantee about the model and the property, not a guarantee that the
  surrounding system is free of all bugs.
- **Not a claim that Cedar/Dogwood are wrong.** They are sound, deterministic
  monitors for the point-in-time question. ROTN answers a *different*
  question (Section 5) that their model cannot express.

## 9. Evidence (reproducible on this machine)

Every claim above can be reproduced with the commands below (run from the
repo root; `python -m rot` is the entry point, `rot` once installed):

- **The corpus coverage matrix (B.2).**
  ```
  rot corpus
  ```
  Discovers 11 policies under `tests/fixtures/aws_dogwood/spendcap` and
  writes [`out/corpus/corpus_matrix.json`](../out/corpus/corpus_matrix.json)
  and [`out/corpus/corpus_matrix.md`](../out/corpus/corpus_matrix.md).
  Current summary: **3 PROVEN, 7 VIOLATED, 1 OUT_OF_SCOPE**, exit `0`
  (the matrix is data; `VIOLATED` rows are honest findings, not tool
  failures). The full evaluation (per-policy verdicts, aggregate metrics,
  the honest 11-vs-59 note, and the gaps) is in
  [`corpus-eval.md`](corpus-eval.md).
- **The parallel-fire bug (Section 4).**
  ```
  rot check --policy tests/fixtures/aws_dogwood/spendcap/policies/spendcap-buggy.dw --max-inflight 3
  rot check --policy tests/fixtures/aws_dogwood/spendcap/policies/spendcap-correct.dw --max-inflight 3
  ```
  The buggy policy exits non-zero with a witness at `inflight = 3`;
  the correct policy exits `0` (PROVEN).
- **The K-sweep (Section 4, honest limit).**
  ```
  rot check --policy tests/fixtures/aws_dogwood/spendcap/policies/spendcap-buggy.dw --max-inflight 1
  ```
  At `K = 1` the same buggy policy reports PROVEN — the race is
  structurally unexpressible at that bound.
- **The Phase A walkthrough.**
  [`dogwood-repro.md`](dogwood-repro.md) documents the full
  policy → model → witness derivation end to end.

The generated matrix artifacts are committed outputs of the tool, not
hand-written tables: re-running `rot corpus` regenerates them
deterministically.

## 10. One sentence

**Cedar and Dogwood answer "is this request admissible against the history so
far?"; ROTN answers "can this policy, under concurrency, ever reach a state
that violates it?" — by lowering the policy into a bounded model and
checking *all* reachable states, and by honestly reporting `OUT_OF_SCOPE`
when it cannot.**