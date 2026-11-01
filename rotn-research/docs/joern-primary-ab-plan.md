# ROTN — Joern-Primary + Objective A/B + Two-Layer Agreement Plan

> **Status: Phases 0–7 DONE** (IR contract, FSM extraction, general state
> space, the objective A/B harness + winner table, the default-frontend flip
> + two-layer agreement, the lossiness discipline, the TLA+ essentials, and
> the Phase 7 evidence layers + docs).
> This plan **builds on** `docs/cpg-integration-plan.md` (CPG-1 dataflow
> **DONE**, CPG-2 generic CPG→Candidate producer **DONE** + *parity* A/B gate,
> CPG-3 static↔formal cross-check **DONE**, CPG-4 claim packet **PRESENT** in
> `rot/cpg4.py` + `tests/test_cpg4.py`). It does **not** re-do any of that; it
> adds the *quality* A/B, the **default-frontend flip**, the **two-layer
> agreement**, the **lossiness reduction**, and the **TLA+ essentials**
> closure. **Phase 1 is implemented:** `rot/fsmextract.py` (the FSM-extraction
> lift), the §2.4 control records in `rot/frontends/cpg_model.py`, the IR's
> `alphabet`/`final_states` (Σ/F), the gate `tests/test_fsm_extraction.py`
> (2PC / ZAB / PBFT 5-tuple + a valid, round-tripping IR), and the committed
> 2PC CPG artifact `tests/fixtures/cpg/twopc.cpg.json`.
>
> **Decision change (explicit override):** the prior plan locked *"CPG is
> parallel, not primary — never replacing the hand targets."* This plan
> **overrides that decision** per the product goal: the **objective A/B
> harness ranks the 4 source frontends and the winner becomes the *default*
> (primary) frontend**, with the others remaining available (optional). Joern/CPG
> is *expected* to win, but the default is **chosen by measurement, not
> assertion**. The offline/stdlib guarantee is preserved either way.
>
> **North Star (from `orig_thesis.txt`):** **Product 1** (agent policy &
> harness verifier — the open-source wedge) + **Product 2** (runtime coach),
> with **Product 3** (AIUC-1 / SOC 2 evidence) as the downstream sink. One
> code-derived IR, checked by a **two-layer agreement** (static↔formal ∘
> 3-engine), with **less lossy** lowering and the **TLA+ essentials** closed.
> *"Joern is the smell test; ROTN is the proof."*
>
> **Mathematical frame (this rework):** the pipeline is a
> **factor-graph → FSM → temporal-logic** compiler. This rework applies two
> papers' insights: **(a) FSMExtractor** (Chen et al., FEAST'19) — the CPG→IR
> step is a *principled FSM extraction* (trip-count filter, liveness,
> control∧data-dependence, SAT-based δ synthesis → the full 5-tuple
> (Q,Σ,δ,s₀,F)), not a name-match; **(b) GSSM** (Lü, 2022) — the `LinearModel`
> chain is the *Kalman-filter special case*; the *general* state space keeps
> the three things it drops: **multi-connected** (CPG edges as connections),
> **distributed** (product of local factor graphs + channel factors), and
> **constant-aware** (never-written vars → constant nodes). **Sequenced:
> extraction first (§2.5), then the general state space (§2.6).** The 5-tuple
> is completed **in the IR** (Σ = `channels`, F = reachable-at-exit);
> `rot/factor.py` names the 3-factor decomposition (prior / between /
> measurement). See §2.4 for the **full Joern CPG spec** (metadata,
> filesystem, namespace, methods, CDG) the extraction consumes.
>
> **Guardrail (unchanged):** pure stdlib, Python 3.6, offline, deterministic,
> narrow waist (`tests/test_narrow_waist.py`). Joern remains *optional* (like
> TLC) — the CPG path is testable offline against committed CPG JSON fixtures.

---

## 0. Relationship to existing work (what's done vs. new)

| piece | status | where |
|---|---|---|
| CPG dataflow (`REACHING_DEF`/`ARGUMENT`, `taint_path`) | **DONE** | `rot/frontends/cpg_model.py`, `tests/fixtures/cpg/` |
| CPG→Candidate producer (budget + label_flow from *structure*) | **DONE** | `rot/frontends/cpg/extractor.py` |
| **Parity A/B** (AST vs CPG IRs `to_dict()`-equal) | **DONE** | `tests/test_cpg_extraction.py` |
| **static↔formal agreement invariant** (fail-closed `UNKNOWN` + `unsound_abstraction`) | **DONE** | `rot/cpg_crosscheck.py` |
| Claim packet (one CPG → N verticals, coach, `manifest_id`) | **PRESENT** | `rot/cpg4.py`, `tests/test_cpg4.py` |
| **FSM extraction** (Phase 1, §2.4 + §2.5: control records + 5-tuple `(Q,Σ,δ,s₀,F)` + IR Σ/F) | **DONE** | `rot/fsmextract.py`, `rot/frontends/cpg_model.py` (control half), `rot/ir.py`, `tests/test_fsm_extraction.py` |
| **Quality A/B** (rank the 4 frontends; pick the default) | **NEW (this plan)** | `rot/ab.py`, `tests/test_ab_frontends.py`, `bench/` |
| **Joern/CPG as the *default* frontend** | **NEW (this plan)** | `pipeline.py` routing |
| **Two-layer agreement** (static↔formal ∘ 3-engine, AND-combined) | **NEW (this plan)** | `pipeline.py`, `rot/crosscheck.py` |
| **Less-lossy lowering** (over-approx + manifest + CEGAR-on-disagreement) | **NEW (this plan)** | `rot/frontends/cpg/`, `rot/lower.py` |
| **TLA+ essentials** (stuttering, state constraints, strong fairness, symmetry) | **NEW (this plan)** | `rot/liveness.py`, `rot/symbolic.py`, `rot/ir.py` |

## 1. Current state (the optionality)

Four source frontends can produce the IR; the *default* is still the
hand-authored registry:

| frontend | mechanism | shapes | dataflow | default today? |
|---|---|---|---|---|
| `rot/targets.py` | hand-authored registry (8 protocols) | all | n/a (it *is* the model) | **YES** (`pipeline.run()` default) |
| `rot/frontends/code/extractor.py` | Python AST + name heuristics | budget, label_flow | none | no |
| `rot/frontends/java/ir_builder.py` | Java 2PC sources (narrow waist) | agreement / validity / no_spurious_abort | none | no (`source_dir` path) |
| `rot/frontends/cpg/extractor.py` | Joern CPG → Candidate → IR | budget, label_flow | **derived** | no (`cpg_path` path) |

- **Engine optionality:** `pipeline.run(engine="auto")` → `cfg.select_engine()`
  (symbolic default / crosscheck / apalache / tlc); liveness always → symbolic.
- **Property optionality:** `property_name=None` → `spec.default_property`.
- **Two cross-checks exist, separately:** `rot/crosscheck.py` (3-engine:
  SMT + TLC + policy, "all agree or `UNKNOWN`") and `rot/cpg_crosscheck.py`
  (static↔formal: fail-closed `UNKNOWN` + `unsound_abstraction`). **They are
  not AND-combined into one default verdict today.**
- **Lossy lowering:** `rot/frontends/cpg/extractor.py` + `rot/lower.py` keep
  security-relevant structure, drop the rest (best-effort, per the existing
  counterexample-fidelity note).

---

## 2. Factual answers (the design rationale)

### 2.1 Which cross-check is stronger / better street-cred?

The **two-layer agreement** is strictly stronger because the two rules guard
*different* failure sets:

- **3-engine** (`crosscheck.py`) = *formal-internal* diversity → catches
  engine / single-abstraction bugs. **Blind spot:** all three verify the
  *same* IR; if the IR is unfaithful to the code, all three agree on the
  *wrong* spec.
- **static↔formal** (`cpg_crosscheck.py`) = *cross-paradigm* diversity →
  catches the **model-fidelity axis** (the dominant real-world failure).

**Final = `PROVEN` only if (3-engine agree) ∧ (no static refuting path);
`VIOLATED` if either refutes; else `UNKNOWN` + the named disagreement.**
Failure coverage = *union* → strictly larger than either alone. Street-cred:

- **Insurers (AIUC-1 / SOC 2):** "a code scanner **and** a formal model
  checker agree; if they disagree we say `UNKNOWN`" = two independent
  controls (auditable). 3-engine = "three copies of the same homework."
- **Developers:** the *disagreement* is actionable ("your model ≠ your code").
- **AI agents:** a crisp machine-checkable gate
  `PROVEN ⇔ formal=PROVEN ∧ ¬static_refutes` + two independent signals.

### 2.2 How to make CPG→IR *less lossy* (soundly)?

1. **Over-approximate, don't omit** — a dropped branch becomes a
   *nondeterministic choice* (keeps the possibility; sound).
2. **Property-directed retention with a hard rule** — keep `ir_relevant` +
   the transitive reaching-def closure; every dropped edge is either
   *(a) proven irrelevant* or *(b) "unknown relevance" → triggers the
   static↔formal `UNKNOWN` flag*. "Silently lossy" → "explicitly lossy + loud."
3. **CEGAR on the front-end (disagreement-driven)** — if `taintPath(G,P)`
   exists but the IR says "no," re-add the dropped edges *on that Joern path*
   and re-check. Lossiness driven by the disagreement, not by taste.
4. **Kept/dropped manifest** — emit into IR metadata → the claim packet
   (`rot/cpg4.py:build_claim_packet`).

### 2.3 TLA+ essentials missing (from PDD.txt)

| essential | status | consequence of the gap |
|---|---|---|
| Stuttering (no-action step) | **stated** (Phase 6.1) | safe for safety; liveness over-approximates unless stated → *now* stated on every liveness discharge + report |
| Procedures vs macros | **missing** (flat `Action`s) | inlined procedures can over/under-approximate |
| Strong / multi-action fairness | **expressed + recorded** (Phase 6.3) | `SF(a1)/...` and multi-`WF(a1)/WF(a2)/...` now first-class; always recorded on the verdict; discharge fails closed until a fairness-aware engine exists |
| Labels / atomicity | **covered** (each `Action` = one step) | — |
| State constraints (`assume`) | **first-class + pruned** (Phase 6.2) | `Assume` in the IR; concrete engine prunes non-satisfying states (sound); a verdict under it carries it as a named assumption |
| Symmetry sets | **quotient in symbolic** (Phase 6.4) | orbit canonical representative; exact for group-invariant properties; spend-cap `k_sweep` is the K-scale with a loud K-masking advisory |
| Ghost / auxiliary vars | **partial** (abstraction manifest) | no first-class proof-helper var |
| Refinement (spec ⊆ spec) | **missing** (CEGAR ≠ refinement) | thesis-level |
| Multi-module / `INSTANCE` | **missing** | out of wedge scope |
| Liveness in a separate model; no symmetry+liveness | **covered** (matches PDD.txt) | — |

### 2.4 CPG spec completeness (the Joern properties we must not miss)

> **Why this section exists:** the CPG→IR step is only as good as the CPG
> scrape it reads. This section enumerates the **full Joern CPG spec** present
> in this filespace (the `semanticcpg` passes under
> `_joern_test/workspace/src/overlays/semanticcpg/`), maps **every** property
> to what the extraction needs, and names exactly what the current
> `rot/frontends/cpg_model.py` **does not yet carry**. Nothing below is
> invented — it is the spec the `export_cpg.sc` `valueMap` dump already
> exposes; we just consume it.

**A. The CPG node types the spec provides (and what ROTN captures today):**

| CPG node | spec source | ROTN `cpg_model.py` today | needed for |
|---|---|---|---|
| `FILE` | `FileCreationPass` | **MISSING** (only `meta`) | **filesystem** provenance (each file = one *distributed* component, GSSM 3b) |
| `NAMESPACE_BLOCK` | `NamespaceCreator` | **MISSING** (implied by `fullName`) | **namespace** grouping (module = one factor-graph component) |
| `TYPE_DECL` | `TypeDeclStubCreator` | `CpgType` (name/fullName/owner/lines/inherits/constants) | the state-space *domain* (bounded discrete = FSM Q) |
| `METHOD` | `MethodStubCreator` | `CpgMethod` (name/fullName/owner/lines/calls/read+write fields/defs/args) | the **factors** (actions); `isExternal`/`isImplicit` **MISSING** |
| `MEMBER` (field) | spec | `CpgField` (name/fullName/type/owner) | the **variable nodes** (state vars); `constant` **MISSING** |
| `METHOD_PARAMETER_IN/OUT` | spec | **MISSING** (folded into `CpgMethod.args`) | the **input alphabet Σ** + transition *pre-conditions* |
| `LOCAL` | spec | **MISSING** (folded into `CpgMethod.defs`) | the **FSM state-variable candidate** (FSMExtractor Q2) |
| `BLOCK` / `CONTROL_STRUCTURE` | `CfgCreationPass` | **MISSING** | the **FSM loop** (trip-count filter) + **transitions** (δ) |
| `CALL` | `StaticCallLinker` | `CpgEdge(CALL)` | the **multi-connected** edges (GSSM 3a) |
| `LITERAL` / `constant` | spec | **MISSING** (extractor: "a CPG scrape carries no constant values") | the **GSSM constant nodes** (3c) — the budget cap/threshold! |

**B. The CPG edge types the spec provides (and what ROTN captures today):**

| CPG edge | spec source | ROTN today | needed for |
|---|---|---|---|
| `REACHING_DEF` | spec | `CpgEdge` | dataflow (CPG-1 taint path) — **have** |
| `ARGUMENT` | spec | `CpgEdge` | parameter flow — **have** |
| `CFG` | `CfgCreationPass` | `CpgEdge(FLOW)` | control flow — **have (aliased)** |
| **`CDG`** | `CdgPass` | **MISSING** | **control-dependence = FSMExtractor's transition detector** (Q4) |
| `DOMINATE` | `CfgDominatorPass` | **MISSING** | loop-trip-count / exit-condition analysis (FSMExtractor §3.1) |
| `CONTAINS` | `ContainsEdgePass` | **MISSING** | method→block containment (the loop's body) |

**C. The `valueMap` metadata keys (what `export_cpg.sc` already dumps) — the "metadata" you flagged:**

`name`, `fullName`, `code`, `type`, `typeFullName`, `order`, `index`,
`lineNumber`, `endLineNumber`, `columnNumber`, `endColumnNumber`, `filename`,
`namespaceName`, `signature`, `isExternal`, `isImplicit`, `dispatchType`,
`inheritsFrom`, `modifier`, `annotation`, `comment`, `argumentIndex`,
`constant`, `typeSignature`, `methodFullName`.

ROTN's `cpg_model.py` today carries a **subset**: `name`, `fullName`, `owner`,
`lineNumber`, `endLineNumber`, `type`, `inherits`, `constants`. **Missing and
needed:** `filename` (filesystem), `namespaceName` (namespace), `code` (the
source snippet for the coach), `isExternal`/`isImplicit` (which methods are
*stubs* vs. *real* — the FSMExtractor false-positive guard), `dispatchType`
(static vs. virtual calls), `constant` (the GSSM constant nodes),
`signature`/`typeSignature` (the method contract), `comment`/`annotation`
(the coach's explanatory context).

**D. The required CPG-model extension (this plan's concrete deliverable):**

1. **Add node records** to `cpg_model.py`: `CpgFile` (filesystem),
   `CpgNamespace` (namespace), `CpgParam` (METHOD_PARAMETER_IN/OUT),
   `CpgLocal` (LOCAL — the FSM state-variable candidate), `CpgBlock`
   (BLOCK/CONTROL_STRUCTURE — the loop), `CpgCall` (CALL, with
   `dispatchType`). Each carries the full `valueMap` subset it needs.
2. **Add edge kinds** to `cpg_model.py`: `EDGE_CDG` (control-dependence),
   `EDGE_DOMINATE`, `EDGE_CONTAINS` (the loop body), alongside the existing
   `EDGE_REACHING_DEF`/`EDGE_ARGUMENT`/`EDGE_FLOW`/`EDGE_CALL`.
3. **Capture `constant`** on `CpgField`/`CpgLocal`/`CpgType` — this **closes
   the extractor's "no literals" honesty note** (the budget cap/threshold are
   CPG constants, not lighthouse fallbacks) and feeds the **GSSM constant
   nodes** (3c).
4. **Keep `validate()`** (well-formedness) and the JSON round-trip green; the
   new records are *additive* (the existing fixtures stay valid; the new
   fields default to empty).

**E. Why each property is *required* (mapped to the two papers):**

- **FSMExtractor (Q1–Q5):** the `BLOCK`/`CONTROL_STRUCTURE` + `DOMINATE` edges
  give the **trip-count filter** (Q1); the `LOCAL`/`MEMBER` + `CDG` give the
  **state-variable detection** (Q2) and the **control∧data-dependence
  transition detector** (Q4); the `METHOD_PARAMETER_IN` gives the **input
  alphabet Σ** (Q3); the `METHOD`'s before/after values give **s₀ and F** (Q5).
  **Without A–C, FSM extraction is impossible** — the current model is the
  *dataflow* half (CPG-1), not the *control* half the FSM needs.
- **GSSM (3a/3b/3c):** the `CALL` edges (multi-connected, 3a), the `FILE`/
  `NAMESPACE` (distributed, 3b), and the `constant` (constant nodes, 3c) are
  **exactly** the three things the general state space keeps that the
  linearized chain drops.
- **The two-layer agreement:** the `isExternal`/`isImplicit` metadata is the
  **FSMExtractor false-positive guard** (their two FPs were an int holding a
  function pointer — `isExternal`/`dispatchType` let us *exclude* stubs from
  the FSM candidate set, *more* complete than the paper, which "only examines
  the function containing the FSM loop").

> **Bottom line:** the CPG spec in this filespace is **richer than what
> `cpg_model.py` consumes today**. The rework's CPG step is to **consume the
> full spec** (A–D) so the FSM extraction (2.5) and the general state space
> (2.6) have the control, filesystem, namespace, and constant properties they
> need. This is *additive* — no existing fixture or test changes shape.

### 2.5 FSM extraction (the FSMExtractor discipline applied to the CPG)

> **Frame:** FSMExtractor (Chen et al., FEAST'19) *studied 25 real FSMs, found
> they follow code patterns, then built static heuristics around those
> patterns*. We adopt the same discipline, but on the **CPG** (more complete
> than the paper's LLVM IR — it has interprocedural `CALL` edges the paper
> lacks). The output is the **full 5-tuple (Q, Σ, δ, s₀, F)**, completed
> **in the IR** (confirmation #2).

**The extraction pipeline (each step is a CPG query over §2.4's extended model):**

1. **FSM-loop detection (Q1, trip-count filter).** Find `BLOCK`/
   `CONTROL_STRUCTURE` loop nodes whose exit condition does **not** compare a
   *reduction* (per-iteration-constant-delta) variable to a *constant* —
   i.e. **input-driven** loops. Use the `DOMINATE` edges (CfgDominator) for
   the exit-condition. A constant-trip-count loop → a `MODE_BOUNDED` action,
   **not** an FSM.
2. **State-variable pinpointing (Q2, liveness).** The FSM state variable is
   the `LOCAL`/`MEMBER` node that is (a) **bounded discrete** (`Enum` or
   bounded int — the `TYPE_DECL` gives the domain), (b) **written** inside
   the loop, and (c) **live** outside the loop or in a future iteration
   (the `REACHING_DEF`/`CDG` edges). This is the `Q` (states) = the variable's
   value set.
3. **Transition synthesis (Q4, control∧data-dependence + SAT).** A transition
   is a write to the state variable that is **control-dependent** (a `CDG`
   edge) on a branch whose condition is **data-dependent** (a `REACHING_DEF`
   edge) on the *same* state variable. Synthesize `δ` by **SAT-solving the
   path constraints** (reusing `rot/sat.py` — the same engine, a second use):
   collect the path's guard, check *no conflict* + *pre-condition holds*
   (state = the assigned value at the start site), and read the **input
   alphabet Σ** from the `METHOD_PARAMETER_IN` / channel the branch guards on.
4. **s₀ and F (Q5).** `s₀` = the state variable's value **before** the loop
   (the `REACHING_DEF` into the loop header); `F` = the set of state values
   **after** the loop (the `REACHING_DEF` out of the loop footer). **Both are
   stored in the IR** (the 5-tuple completion).
5. **False-positive guard (the paper's two FPs).** Exclude a candidate state
   variable if `isExternal`/`isImplicit` marks the owning method a *stub*, or
   `dispatchType` shows the "state" is a **function pointer**, not a state.
   This is *more* complete than the paper (which only looks inside the loop's
   own function) because the CPG's `CALL` edges let us see the callee.

**The 5-tuple completion in the IR (confirmation #2):**

- `Q` (states) = the state variable's bounded value set (`TYPE_DECL` domain)
  → already the `StateVar` domain in `rot/ir.py`.
- `Σ` (input alphabet) = the `METHOD_PARAMETER_IN` names + the channel
  messages the branches guard on → **new** `ProtocolIR.alphabet`
  (a `frozenset` of message/param names).
- `δ` (transitions) = the synthesized `Action`s (guard + effects) → already
  the `Action`s in `rot/ir.py`.
- `s₀` (initial state) = the pre-loop state value → already `init_state`.
- `F` (final/accepting states) = the post-loop state values → **new**
  `ProtocolIR.final_states` (a `frozenset` of state names, or `None` =
  "all states are final" for a loop that can exit in any state).

**Where it lives:** **new** `rot/fsmextract.py` (the heuristic suite, over the
§2.4 extended `CpgModel`, reusing `rot/sat.py` for δ synthesis). It emits the
*same* `Candidate` contract (narrow waist preserved) — the A/B
(`tests/test_cpg_extraction.py`) still checks `to_dict()`-equality. The
hand-authored `rot/targets.py` remains the *oracle* (ground truth) the A/B
scores against.

### 2.6 General state space (the GSSM lift)

> **Frame:** GSSM (Lü, 2022): "Kalman filter is a **special case** of
> factor-graph optimization." The `LinearModel` chain (ordered actions) is
> that special case. The *general* state space keeps the **three things** the
> chain drops. This is the **second** lift (sequenced *after* extraction,
> confirmation #1), and the A/B can *measure* whether it wins.

**The 3-factor decomposition (GSSM §III) — the name for your IR (confirmation #3):**

- **Prior factor** `p(x₀)` = `init_action` (the initial state).
- **Between factor** `p(xₖ₊₁|xₖ)` = the `actions` (the transitions, `δ`).
- **Measurement factor** `p(yₖ₊₁|xₖ₊₁)` = `pinned_property` (the query).

→ **new** `rot/factor.py` (a *pure lens* over `rot/ir` — `PriorFactor` /
`BetweenFactor` / `MeasurementFactor` views; **zero behavior change**, the
narrow waist + all green tests stay). This makes the *structure* visible and
lets the A/B score **per-factor fidelity** (prior / between / measurement)
separately.

**The three things the general state space keeps (GSSM §IV):**

1. **Multi-connected graph (3a).** The `LinearModel` is a *chain*; a 2PC
   protocol is *two* components (coordinator ∥ participants) joined by
   `CALL`/message edges. → **new** `rot/factor_graph.py` (a *multi-connected*
   view over the `ProtocolIR`, using the CPG's `CALL` edges as connections).
   The `LinearModel` chain remains the *sound special case* (the fallback).
2. **Distributed, not unified (3b).** One *unified* state → a **product** of
   *local* factor graphs (one per process/file/namespace, per §2.4's
   `FILE`/`NAMESPACE`) + *connection* factors (the channels). → **edit**
   `rot/env.py` (it already models "each environment is a self-contained
   `ProtocolIR` fragment" — now *named* the distributed view) +
   `rot/factor_graph.py` (the product construction).
3. **Constant-aware (3c).** Never-written variables (`cap`, `threshold`,
   `participants`) are **constants**, not time-varying state — modeling them
   as *constant nodes* **reduces the reachable-state-space dimension**
   (GSSM Table I). → **edit** `rot/linearization.py`: detect never-written
   vars (reusing `_action_written_vars` in `rot/impact.py`) and mark them
   *constant nodes*, shrinking the state space.

**Marginalization delay (GSSM §II — "Kalman filter can't pass messages
backward because it marginalizes every step"):** your `rot/abstraction.py`
"hiding" **is** marginalization, and it happens *before* CEGAR. → **edit**
`rot/cegar.py`: run the **backward pass** (CEGAR refinement + the two-layer
static↔formal check) *before* the hiding, so the full factor graph is still
available for backward inference. The "hiding never under-approximates"
soundness (already in `rot/abstraction.py`) is now the **soundness of the
factor-graph quotient** — the same theorem, named.

**Sequencing (confirmation #1):** **extraction (§2.5) first** — it is the
CPG-critical path and the A/B's primary metric. **Then the general state
space (§2.6)** — the A/B *rewards* it (dimension reduction + backward
inference) on the multi-process fixtures (2PC).

## 3. The product-aware objective A/B (the "as objective as possible" test)

**Why product-aware:** Product 1 (verifier) and Product 2 (coach) consume the
**same IR** ("one extraction, two sinks" — `rot/cpg4.py`, `rot/to_proceed.py`).
So the A/B scores each frontend on **both** the P1 verdict *and* the P2 coach
output, not just the verdict.

**Oracle corpus (shared, same property, fair):**

- `bench/spendcap/` — the Dogwood spend-cap (budget shape, **buggy** vs
  **correct**), ground-truth verdict fixed by 3-engine + human.
- `bench/labelflow/` — a taint/NoExfiltration fixture (enforced vs
  bypassable), ground-truth fixed.
- `bench/twopc/` — the 2PC (agreement) fixture.
- Each fixture has a **known ground-truth verdict** (the A/B's objective
  substrate).

**Metrics per (frontend, fixture):**

1. **false_proven** — PROVEN on a known-bug fixture. **Hard disqualifier**
   (any = automatic loss).
2. **violation_recall** — catches the real bugs.
3. **dataflow_edge_recall** — of the known `private→sink` / `request→cap`
   edges, how many the IR retains (directly measures lossiness).
4. **source_pinning_rate** — % of counterexample steps pinning to a real line
   + replay-agreement (P3 evidence).
5. **coach_quality** (P2) — `to_proceed` correctness: does the coach expose
   only allowed tools + a machine-readable unblock path, *derived from the IR*?
6. **unknown_rate** — precision (gated by #1 so it can't win by being unsound).
7. **cost** — CEGAR iterations, time, state count (secondary).

**Ranking = lexicographic total order (no weights to argue about):**

```
(frontend, fixture) ->
  ( false_proven == 0 ,          # hard gate
    violation_recall ,           # higher is better
    dataflow_edge_recall ,       # higher is better (less lossy)
    source_pinning_rate ,        # higher is better
    coach_quality ,              # P2: higher is better
    - unknown_rate ,             # lower is better
    - cegar_iters , - time )     # lower is better
```

- **Unavailable ≠ loss.** A frontend that can't run on a fixture (e.g., `java`
  on the spend-cap, or CPG with no artifact) is recorded **`UNAVAILABLE`**, not
  a loss — an honest, objective distinction.
- **The winner becomes the default** (Phase 2). The full metric table is
  emitted as JSON + a deterministic report, so the decision is *reproducible
  and citable* — the "as objective as possible" requirement.

**Parity vs quality A/B (both kept):** the existing CPG-2 *parity* A/B (AST vs
CPG IRs equal) proves CPG is *correct*; this *quality* A/B proves CPG is
*best*. Different questions, both required.

---

## 4. The plan (Phases 0–7, each gates the next)

> **Sequencing (confirmation #1):** **extraction (Phase 1) → general state
> space (Phase 2) → A/B (Phase 3) measures both.** The extraction is the
> CPG-critical path; the general state space is the measured lift; the A/B
> rewards whichever wins.

### Phase 0 — Unify the IR contract (prerequisite for a fair A/B)
- `rot/frontends/cpg/extractor.py` already emits the `Candidate` contract →
  `lower_candidate` → `ProtocolIR`. **Verify** the CPG path and the
  `code`/`targets` paths land in the **same `ProtocolIR` type** with **derived
  labels** + **source-pinned provenance** + a **lossiness manifest** in
  `metadata`.
- **Gate:** `linearize → emit → check → CEGAR → replay` runs byte-for-byte on
  all 4 frontends' IRs (narrow waist green).
- **Status (2026-10-30): DONE.** Verified: all 4 frontends (`code` / `cpg` /
  `targets` / `java`) land in the same `ProtocolIR` type, and every producer
  now stamps the contract metadata — the derived `protocol` label
  (`SPENDCAP` / `LABEL_FLOW` / `2PC`), source-pinned `provenance` (now also
  on the `targets` oracles and the `java` frontend), and a `lossiness`
  manifest built from `rot.ir.lossiness_entry` rows (stamped by the shared
  lowering `rot.lower` for the P1 shapes, so the `code` and `cpg` producers
  of the same control agree on it by construction). **Gate green:**
  `tests/test_phase0_ir_contract.py` asserts the type + metadata contract and
  that `linearize → emit → check → CEGAR → replay` is byte-for-byte identical
  across the frontends for each shared control (spendcap: `code`/`cpg`/
  `targets`; 2PC: `targets`/`java`); full suite 1331 tests OK.

### Phase 1 — Consume the full CPG spec + FSM extraction (the first lift, §2.4 + §2.5) · **DONE**
- **Extend `cpg_model.py`** with the §2.4 records (`CpgFile`/`CpgNamespace`/
  `CpgParam`/`CpgLocal`/`CpgBlock`/`CpgCall` + `EDGE_CDG`/`EDGE_DOMINATE`/
  `EDGE_CONTAINS` + `constant`); the new records are *additive* (existing
  fixtures stay valid). — **done** (control half in `rot/frontends/cpg_model.py`).
- **New `rot/fsmextract.py`** — the FSMExtractor heuristic suite over the
  extended `CpgModel` (trip-count filter Q1, state-variable detection Q2,
  control∧data-dependence Q4, false-positive guard). δ is derived from the
  CDG (control-dependence) + `REACHING_DEF` (data-dependence) edges — a sound,
  offline special case of the plan's SAT-based δ synthesis; a candidate that
  fails a soundness guard is `REJECTED`, an out-of-scope method `OUT_OF_SCOPE`
  (fail-closed, never a silent UNKNOWN). — **done**.
- **Complete the 5-tuple in the IR** — `rot/ir.py` gains
  `ProtocolIR.alphabet` (Σ) + `ProtocolIR.final_states` (F). — **done**.
- **Gate:** the 2PC CPG fixture yields a `ProtocolIR` with a *complete*
  5-tuple (Q, Σ, δ, s₀, F) + a valid, round-tripping IR; 2PC / ZAB / PBFT are
  all recognised (not fixture-memorized). — **done**: `tests/test_fsm_extraction.py`
  (21 tests) over the committed `tests/fixtures/cpg/twopc.cpg.json`; the
  existing `to_dict()` parity gate (`tests/test_cpg_extraction.py`) and the
  hand-authored `rot/targets.py` oracle stay green.

### Phase 2 — General state space (the second lift, §2.6)
- **New `rot/factor.py`** — the 3-factor decomposition lens (prior / between /
  measurement over `rot/ir`, zero behavior change).
- **New `rot/factor_graph.py`** — the multi-connected + distributed view over
  `ProtocolIR` (the 2PC coordinator ∥ participants as two components joined by
  channel factors); the `LinearModel` chain remains the sound special-case
  fallback.
- **Edit `rot/linearization.py`** — constant-node reduction (never-written
  vars via `_action_written_vars` in `rot/impact.py`).
- **Edit `rot/cegar.py`** — backward pass *before* marginalization (the
  factor-graph quotient soundness, named).
- **Edit `rot/env.py`** — the distributed view, now named.
- **Gate:** the 2PC fixture's state space is *smaller* than the linearized
  chain (constant-node reduction); the multi-process view is *visible*
  (coordinator ∥ participants); all green tests stay green (zero behavior
  change from `rot/factor.py`).

### Phase 3 — The objective quality A/B harness (measures both lifts)
- **New:** `rot/ab.py` (a `rot ab` subcommand), `bench/` oracle corpus
  (spendcap + labelflow + twopc, each with a ground-truth label),
  `tests/test_ab_frontends.py`.
- **Emit:** a JSON table of the §3 metrics per (frontend, fixture) + the
  lexicographic winner; **per-factor fidelity** (prior / between / measurement)
  via `rot/factor.py`.
- **Gate:** the harness runs offline; the winner is deterministic; the
  false-PROVEN hard gate is enforced; an `UNAVAILABLE` outcome is recorded
  distinctly.

### Phase 4 — Make **Joern/CPG the default** + adopt the **two-layer agreement**
- **Flip the default** in `pipeline.run()`: when a CPG artifact is present (or
  the A/B winner is CPG), route through the **CPG frontend** first; keep
  `targets`/`code`/`java` behind explicit flags (still available — the
  offline/stdlib guarantee is preserved).
- **Default cross-check = two-layer agreement:** `PROVEN` iff (3-engine
  `crosscheck` agree) ∧ (no `cpg_crosscheck` taint path); `VIOLATED` if either
  refutes; else `UNKNOWN` + the named disagreement. Wire into `pipeline.run()`
  + the report.
- **Gate:** on the oracle corpus, the default path's verdicts match the A/B
  winner's verdicts; the two-layer rule never emits PROVEN when a layer refutes.

### Phase 5 — Reduce lossiness (the 4 moves in §2.2)
- Over-approximate-don't-omit in the CPG→IR lowering; property-directed
  retention with the proven-irrelevant-or-UNKNOWN rule; CEGAR-on-disagreement
  (re-add Joern-path edges + re-check); emit the kept/dropped manifest into the
  claim packet.
- **Gate:** a deliberately-dropped dataflow edge now either (a) is proven
  irrelevant or (b) forces `UNKNOWN` + `unsound_abstraction`; the manifest
  names it.

### Phase 6 — Close the TLA+ essentials (priority order from §2.3) · **DONE**
1. **State the stuttering assumption** in the report + `liveness` discharge
   (safety-safe; liveness-honest).
2. **State constraints (`assume`)** in the IR + `symbolic` engine (sound
   pruning).
3. **Strong / multi-action fairness** (beyond single-action weak).
4. **Symmetry sets** in `symbolic` (K-scale for the spend-cap sweep).
- *(Procedures, ghost vars, refinement, multi-module = thesis-level; note in
  docs, likely out of wedge scope.)*

### Phase 7 — Evidence + docs (Product 1 + Product 2 + Product 3) · **DONE**
- Wire the **two-layer agreement**, the **A/B winner table**, and the
  **lossiness manifest** into the `VerdictReport` + claim packet
  (`rot/cpg4.py`).
- **Product 1 (verifier):** the A/B winner frontend + two-layer verdict +
  source-pinned counterexample = the open-source wedge's proof.
- **Product 2 (coach):** the same IR drives `to_proceed` / `allowed_now` /
  `contact_deny` (P2) — one extraction, two sinks.
- **Product 3 (AIUC-1 / SOC 2 evidence):** `rot/compliance.py` maps the
  two-layer agreement + claim packet to the underwriter-readable evidence.
- Add the **"static↔formal agreement invariant"** as a named, thesis-quotable
  property in `README`/`docs/`; update the honest-boundary section with the
  stuttering + lossiness assumptions.
- **Status (2026-10-30): DONE.** Implemented: `rot/ab.py` `winner_table()`
  (compact, memoized, deterministic — the citable A/B decision);
  `rot/cpg4.py` `two_layer_section()` (the per-shape static↔formal join,
  fail-closed, rule cited) + the claim-packet `wedge` (A/B winner frontend +
  two-layer verdicts + source-pinned counterexample) + the `ab` / `retention`
  sections in the hashed body; `rot/cpg4.py` `coach_vertical()` `allowed_now`
  (the complement of `blocked`) + the named `deny_branch` (`spend_deny` /
  `contact_deny` with its guard); `rot/verdicts.py` `VerdictReport` optional
  `two_layer` / `ab` / `retention` sections (JSON + Markdown, positional
  signature unchanged); `rot/compliance.py` `claim_packet_compliance()`
  (Product 3: `proven` only when every shape is two-layer PROVEN, any
  VIOLATED → `violated` (AIUC-1), UNKNOWN never read as proven, `None` →
  `None`); `pipeline._run_cpg_frontend` writes the sections into the report.
  Named property in `README.md` (the "Auditable report" block); honest
  boundaries updated below (§6). **Gate:** `tests/test_phase7_evidence.py`
  (28 tests: the winner table shape/determinism/agreement with the full A/B;
  the two-layer fail-closed rule incl. the static-threat-blocks-PROVEN and
  VIOLATED-never-upgraded cases; the coach's `allowed_now` = not-`blocked`
  + the named deny branch; the packet's evidence sections + wedge +
  manifest stability + JSON-serialisability; the report's optional sections;
  the compliance reading incl. the fail-closed cases) — all green.

---

## 5. Street-cred (why this is "best on the market" for the three audiences)

- **Insurers (AIUC-1 / SOC 2 / Lloyd's):** structural evidence ("this class of
  failure is impossible under these assumptions") that *complements* AIUC's
  5,000-scenario sampling — two independent controls (static + formal) that
  *disagree loudly* when uncertain. The A/B winner table is *citable* evidence
  of which analysis path was used and why.
- **Developers:** cheap per-path "smell test" (Joern taint path) + rigorous
  concurrency proof (model checker), and a loud "your model ≠ your code" when
  they diverge.
- **AI agents:** a crisp, machine-checkable gate + two independent signals to
  weight; `to_proceed` is computed from the spec (the coach), not hardcoded.

## 6. Honest boundaries & tradeoffs (locked)

- **The A/B winner is a measurement, not an assertion.** Predicted: CPG wins
  dataflow-edge recall + pinning; `targets` may win cost; on a fixture with no
  CPG artifact, CPG is `UNAVAILABLE`.
- **Less lossy = more honest = possibly more `UNKNOWN`.** Over-approximation +
  "unknown relevance → UNKNOWN" trades precision for soundness — the right trade
  for an insurer-facing product, but some previously-PROVEN fixtures will now
  say UNKNOWN, *correctly*. The **lossiness manifest** (claim-packet
  `retention`) names every kept / dropped / unknown fact, so the trade is
  auditable, never silent.
- **The stuttering assumption is stated, never silent** (Phase 6.1): the IR's
  transition system has no stuttering (no-op) steps, so every liveness verdict
  carries `rot.ir.STUTTERING_ASSUMPTION` — the claim is **safety-safe** (a
  safety invariant holding in all non-stuttering reachable states holds under
  stuttering extensions) but **liveness-honest** (an unbounded `<>Goal` is
  sound only *under* the assumption, or a fairness assumption that rules out
  infinite stuttering).
- **The CPG is static, single-iteration, per-path** — it grounds safety +
  deadlock evidence, not liveness/concurrency-bypass (those need the model
  checker). "Joern feeds the checker; it doesn't replace it."
- **The evidence layers are fail-closed** (Phase 7): the two-layer rule can
  only *disagree loudly* — a static threat to a PROVEN blocks the proof
  (`UNKNOWN` + the named disagreement), a VIOLATED is never upgraded, and the
  underwriter reading (`claim_packet_compliance`) never reads UNKNOWN as
  proven. The A/B winner table is *citable* (which frontend, why) but remains
  a **measurement** — re-run `rot ab` if the corpus changes.
- **Symmetry sets / strong fairness** are scale/liveness wins, not the core
  wedge — deferrable without harming the two-layer property.
- **No verdict-contract change** (PROVEN / VIOLATED / UNKNOWN / UNSOUND /
  OUT_OF_SCOPE keep their meaning) and **no downstream change** (linearize /
  emit / engines / CEGAR / replay untouched).

## 7. Act-mode file checklist (approved; implemented as listed)

- **New (the two lifts, sequenced):**
  - **Extraction (§2.5, first):** `rot/fsmextract.py` (the FSMExtractor
    heuristic suite over the extended `CpgModel`, reusing `rot/sat.py` for δ
    synthesis); `rot/frontends/cpg_model.py` **extended** with the §2.4
    records (`CpgFile`/`CpgNamespace`/`CpgParam`/`CpgLocal`/`CpgBlock`/
    `CpgCall` + `EDGE_CDG`/`EDGE_DOMINATE`/`EDGE_CONTAINS` + `constant`);
    `rot/ir.py` **extended** with `ProtocolIR.alphabet` (Σ) +
    `ProtocolIR.final_states` (F) — the 5-tuple completion.
  - **General state space (§2.6, second):** `rot/factor.py` (the 3-factor
    decomposition lens — prior/between/measurement over `rot/ir`, zero
    behavior change); `rot/factor_graph.py` (the multi-connected + distributed
    view over `ProtocolIR`); `rot/linearization.py` **edited** (constant-node
    reduction via `_action_written_vars`); `rot/cegar.py` **edited** (backward
    pass *before* marginalization); `rot/env.py` **edited** (the distributed
    view, now named).
- **New (the A/B + fixtures):** `rot/ab.py`, `bench/{spendcap,labelflow,twopc}/`
  (fixtures + ground-truth labels), `tests/test_ab_frontends.py`.
- **New (Phase 7 evidence + docs):** `tests/test_phase7_evidence.py` (the
  Phase 7 gate); `rot/ab.py` **extended** (`winner_table` + reset hook);
  `rot/cpg4.py` **extended** (`two_layer_section`, the claim-packet `wedge` +
  `ab`/`retention` sections, `coach_vertical` `allowed_now` + `deny_branch`);
  `rot/verdicts.py` **extended** (`VerdictReport` optional `two_layer` /
  `ab` / `retention` sections, positional signature unchanged);
  `rot/compliance.py` **extended** (`claim_packet_compliance`, Product 3);
  `pipeline.py` **edited** (the CPG path writes the sections into the
  report); `README.md` (the named "static↔formal agreement invariant" in the
  "Auditable report" block).
- **Edit (unchanged items):** `pipeline.py` (default routing + two-layer
  cross-check), `rot/crosscheck.py` (Layer A ∘ Layer B composition),
  `rot/frontends/cpg/extractor.py` + `rot/lower.py` (less-lossy lowering +
  manifest), `rot/liveness.py` + `rot/symbolic.py` (stuttering note + state
  constraints), `rot/__main__.py` (`rot ab` subcommand), `README.md` / `docs/`
  (the named property + A/B table + honest boundary + the FSMExtractor/GSSM
  frame).
- **Keep green:** `tests/test_narrow_waist.py`, `tests/test_cpg_extraction.py`
  (parity A/B), `tests/test_cpg4.py` (claim packet),
  `tests/test_cpg_crosscheck.py` (static↔formal), `tests/test_phase7_evidence.py`
  (the Phase 7 evidence gate).

## 8. Definition of done

- `rot ab` emits a **deterministic** winner over the oracle corpus with the
  **false-PROVEN hard gate** enforced and **UNAVAILABLE** recorded distinctly.
- The **default frontend** is the A/B winner (expected: CPG), and the
  **two-layer agreement** is the default cross-check.
- A **deliberately dropped edge** either proves irrelevant or forces `UNKNOWN`
  + a named `unsound_abstraction` flag + a manifest entry.
- The **stuttering assumption** is stated in every liveness report.
- **5-tuple complete in the IR:** every extracted `ProtocolIR` carries
  `alphabet` (Σ) and `final_states` (F) alongside the existing `init_state`
  (s₀), `actions` (δ), and `StateVar` domains (Q); the A/B scores per-factor
  fidelity (prior / between / measurement) via `rot/factor.py`.
- **CPG spec consumed, not just dataflow:** the extended `cpg_model.py`
  carries the `FILE`/`NAMESPACE` (filesystem + namespace), `LOCAL`/`PARAM`
  (the FSM state-variable + alphabet candidates), `BLOCK`/`CONTROL_STRUCTURE`
  (the loop), and the `CDG`/`DOMINATE`/`CONTAINS` edges (the
  control-dependence the FSMExtractor needs); the `constant` valueMap key is
  captured (closing the extractor's "no literals" honesty note).
- **Extraction is principled, not name-matched:** `rot/fsmextract.py` applies
  the trip-count filter (Q1), liveness (Q2), control∧data-dependence + SAT
  (Q4), and the false-positive guard (the paper's two FPs excluded via
  `isExternal`/`dispatchType`); the hand-authored `rot/targets.py` remains
  the oracle the A/B scores against.
- **General state space is the measured lift:** `rot/factor_graph.py` gives
  the multi-connected + distributed view (the 2PC coordinator ∥ participants
  as two components joined by channel factors); `rot/linearization.py`
  reduces the state space by marking never-written vars as constant nodes;
  `rot/cegar.py` runs the backward pass *before* marginalization; the
  `LinearModel` chain remains the sound special-case fallback.
- **Product 1** (verifier) and **Product 2** (coach) both consume the **same**
  A/B-winning IR; the **claim packet** carries the two-layer verdict + A/B
  table + lossiness manifest.
- **Phase 7 evidence (the three layers, fail-closed):** the claim packet
  carries the `two_layer` (per-shape static↔formal agreement, rule cited),
  `ab` (the compact winner table), and `retention` (the lossiness manifest)
  sections **in the hashed body**, plus the **wedge** (the A/B winner
  frontend + the two-layer verdicts + the source-pinned counterexample);
  the `VerdictReport` carries the same sections (JSON + Markdown) when a run
  has them — and is unchanged when it does not.
- **Product 2 reads both branches:** `allowed_now` is the complement of
  `blocked` (the two readings of the SAME guard never disagree) and the deny
  branch is named (`spend_deny` / `contact_deny`) with its guard.
- **Product 3 reads the packet as evidence:** `claim_packet_compliance` maps
  the two-layer agreement to the SOC 2 / AIUC-1 reading — `proven` only when
  every shape is two-layer PROVEN, any VIOLATED → `violated` (AIUC-1),
  UNKNOWN never read as proven, `None` → `None`.
- **The named property is in the docs:** the "static↔formal agreement
  invariant" is thesis-quotable in `README.md` (the "Auditable report"
  block) + this plan (§6 honest boundaries carries the stuttering + lossiness
  assumptions); `tests/test_phase7_evidence.py` is green (the Phase 7 gate).
