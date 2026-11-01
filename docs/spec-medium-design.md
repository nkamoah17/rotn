# KAMUNU (rot-verify) — Spec-Medium Design

> **Phase 0 — design & invariants lock.** This document extends
> [`docs/architecture.md`](architecture.md), the single source of truth for
> planes, contracts, and invariants. If the two disagree, architecture.md
> wins. What this document adds — and only adds — is the *semantics* the
> architecture presupposes but does not yet lock: the property taxonomy
> (invariants / liveness / deadlock / livelock), the **dual-soundness rule**,
> the fairness policy, the refinement (robustness) stages, the code-to-TLA+
> extraction scoping, and the assumption-ledger schema.
>
> Product identity: **KAMUNU** — named for Nyame's first creation, the first
> human. Engine: `rot-verify` (package `rot`), four planes, zero runtime deps.
>
> Companion: `orig_thesis.txt` ("the lighthouse") — the product north star.
> §10 maps the lighthouse onto this architecture line by line.
>
> Decisions D1–D6 (§9) are **LOCKED** with the recommended values.

---

## 1. Thesis (from the lighthouse)

> **Agents are replacing the software that used to enforce our rules. We make
> the rules explicit, prove agents can't break them — even when compromised —
> and coach agents back in bounds when they try.**

We are a **compiler for agents**: errors at design time (binds,
contradictions, unreachable rules), checks at runtime (guards, refusals with
computed `to_proceed`), and error messages that make the agent better rather
than just stopping it.

**Honest boundary (locked).** The engine proves *structural properties of the
harness*: who can do what, in what order, with which data, under which
approvals — against an agent that may be **fully compromised**. It does
**not** prove the model judged correctly (e.g. that it computed the right
tax amount). The sanctioned design pattern for that boundary is: **the LLM
proposes, a deterministic core decides**; the spec then proves every
consequential number came from that core and nothing consequential shipped
without a signature. That boundary is a first-class entry in the assumption
ledger (§8, kind `deterministic_core`) and a permanent line in every claim
packet's **non-claims**.

## 2. Threat model (locked)

Three roles, one rule:

| role | what it is | where it lives |
|------|-----------|----------------|
| **agent** (environment) | a nondeterministic actor that may, at any step, attempt **any** tool with **any** arguments, possibly in parallel; *fully compromised* is the default adversarial setting | `rot.agent_step` (`buggy=True`); the lighthouse `AgentStep` sketch (App. A) |
| **harness** (system under test) | the gateway policy: approvals, budgets, data labels, delegations, sequencing — the *only* thing that can stop the agent | front-ends → `rot.ir`; `spendcap`, `dogwood`, `cedar`, `mcp` |
| **rules** (properties) | the invariants and liveness obligations the harness must maintain | `rot.invariants` registry; pinned per-IR |

Locked consequences:

- **T1 — the agent is untrusted.** No property may assume the agent obeys,
  cooperates, or even acts. Fairness is never asserted on agent actions (§5).
- **T2 — the harness is trusted-but-unverified.** We assume the harness code
  *executes its spec*; we do **not** assume it is untampered. A compromised
  harness (integrity/tampering) is a named **non-claim**, not a silent gap.
- **T3 — the rules are the product.** A verdict is always "rule R holds /
  fails against harness H under environment E and assumptions A" — never
  "the agent is safe."

## 3. Property taxonomy

Five property kinds on one spectrum. Kinds 1–4 are state/reachability
properties; kind 5 is temporal.

### 3.1 TypeInvariant (state constraint)

A predicate every *well-formed* state satisfies: variable domains, budget
bounds, label membership, history shape. It is emitted as a **state
constraint**, not a checked invariant: an ill-formed state is *dropped from
the state space*, not reported as a violation (TLC semantics: a constraint
removes states; an invariant fails the model). In the IR this is
`ProtocolIR.validate()`; in the spec it is the `TypeInvariant` operator.
Purpose: (a) keep the state space sane for the bounded engines, (b) make
well-formedness an explicit, auditable claim, (c) catch front-end bugs
(mis-typed domains) at design time.

### 3.2 Safety invariant

"True in every reachable state." Checked by *refuting* reachability of a bad
state. Sound under over-approximation (concrete ⊆ over-approx); a violation
witness found in an abstraction must be **re-validated as IR-feasible**
(bounded re-check) before it is trusted — the codebase already does this
(`rot.cegar`;
architecture.md §3: "a `VIOLATED` verdict is only ever accompanied by a
counterexample that the bounded re-check re-validated as IR-feasible").

### 3.3 Deadlock-freedom (safety-shaped)

A deadlock is a reachable state in which **no action other than the busy
self-loop is enabled while the task is still pending** — "none of the
processes can take any action." Because it is expressible as *no bad state
is reachable*, it is checked as a safety invariant: over-approx sound with
IR-feasibility re-validation. The **busy self-loop** (the `UNCHANGED`
totalizing step the emitter already adds) is what separates *legitimately
terminal* (only the busy step enabled **and** the task complete) from
*stuck* (only the busy step enabled **and** the task pending). Without it,
TLC reports "Error: Deadlock reached." even on legitimate terminal states.
Existing machinery: `no_deadlock` (G4), `verdicts.DEADLOCK`, the
`rot.emitter` self-loop.

### 3.4 Livelock-freedom (liveness-shaped)

The system *progresses* (actions keep firing) but the task **never** reaches
`done ∨ escalated`. Checked as **bounded liveness**: is `done ∨ escalated`
reachable within the horizon? A `NOT_REACHED` verdict is sound only because
the whole horizon was explored (`horizon_complete`) — the existing `trifecta`
contract. The horizon H is the "auxiliary bound" of the working notes: it is
a recorded assumption, not a hidden one (ledger A2, §8). Existing machinery:
`task_ends_or_escalates` (G6), `bounded_eventually`, `cegar_liveness`,
`LIVENESS_BOUND_EXCEEDED`.

### 3.5 Unbounded liveness (temporal; opt-in)

`[]<>(done ∨ escalated)` under **explicitly stated fairness** on **harness**
actions only. This is the full "eventually" sentence the lighthouse wants —
`TaskEndsOrEscalates == \A task : <>(Done(task) \/ Escalated(task))`,
"liveness — Dogwood can't yet." It is **opt-in** (D1), always labeled with
its fairness assumption in the ledger (§8), and always paired with a vacuity
witness (R3, §4).

### 3.6 The lighthouse's four rules, placed

| lighthouse rule | kind | codebase home | checker | soundness |
|---|---|---|---|---|
| `NoExfiltration` (labeled data ⇒ approved recipients) | safety | exfiltration property (G7), `coach_exfiltration` | symbolic + TLC/Apalache cross-check | R1 (over-approx proof; re-check-validated witness) |
| `SpendCap` (in-window sum ≤ cap, *including in-flight*) | safety | `spendcap_within_cap`, Plane B K-sweep | SMT/Z3 + TLC + policy-direct (zero shared code) | R1 |
| `NoUnapprovedIrreversible` (irreversible ⇒ approved) | safety | `policy_conformance` + the over-privileged-tool bind | Trifecta / re-check | R1 |
| `TaskEndsOrEscalates` (every task ends or escalates) | **liveness** | `task_ends_or_escalates` (G6), `bounded_eventually` | symbolic `reach_within` (concrete, `horizon_complete`) | **R2** |

Plus the binds vocabulary the lighthouse lists, already shipped in
`rot.compliance`: `contradictions`, `unreachable rules` (≈ "vacuous
permission"), `deadlock`, `livelock`, `over-privileged tool`.

## 4. The dual-soundness rule (locked)

The single most important architectural invariant in this document. It is
already enforced by `rot.pipeline` dispatch ("only the symbolic engine
exposes `reach_within`, so liveness is dispatched to it — it is the
independent oracle, and the other engines can only refute safety"); this
section makes it explicit and adds the two missing teeth (R3, R4).

**R1 — safety is over-approx-sound.** If P is a safety property (§3.2, §3.3),
then P holds on a sound over-approximation ⇒ P holds on the concrete model
(concrete ⊆ over-approx). A *violation* witness from an over-approximation is
a **candidate** and must be re-validated as IR-feasible (bounded re-check)
before it is
trusted.

**R2 — liveness is concrete-only (or fairness-labeled).** If P is a liveness
property (§3.4, §3.5), a *proof* (goal reachable) is **unsound** on a bare
over-approximation (the abstraction may contain paths the concrete model
lacks). Liveness is therefore discharged only by (a) a **concrete** bounded
reachability search with `horizon_complete`, or (b) an engine check under
**explicitly stated fairness** on harness actions only.

The symmetry, made explicit — this is the "no hole" table a reviewer audits:

| verdict direction | sound on over-approx? | why | required |
|---|---|---|---|
| safety PROVEN | **yes** | concrete ⊆ over-approx | — |
| safety VIOLATED | witness may be spurious | abstraction adds paths/states | IR-feasibility re-validation (bounded re-check) |
| liveness PROVEN (goal reached) | witness may be spurious | same | concrete re-validation (or run concrete: R2a) |
| liveness VIOLATED (goal not reached in H) | **yes** | no path in the superset ⇒ none in the subset | `horizon_complete` |
| unbounded liveness | **never** on a bare over-approx | fairness unasserted ⇒ stuttering is allowed | fairness + vacuity (R3) |

**R3 — vacuity is refuted, not assumed.** Every liveness claim ships with:
(a) a **vacuity witness** — a model in which the goal is *not* trivially
reachable (e.g. not reachable in the init state, the agent is not inert) in
which the claim still holds; and (b) a **negative control** — a buggy model
(the lighthouse's `--buggy` shape) in which the claim *fails*. A liveness
claim that holds vacuously, or that holds on the buggy model too, is a
**modeling bug**, reported as such.

**R4 — "eventually decided", never "eventually permitted".** Liveness claims
are about *decided outcomes* (`done ∨ escalated ∨ committed`), not about
*permission*. "Eventually permitted" is satisfied by a harness that permits
everything and does nothing; it is not a liveness claim and is never emitted
as one.

**Enforcement points.** `rot.pipeline` dispatch (kind → engine); the table
above; and three tests: (i) no liveness property is routed to a bare
over-approximating engine without a fairness label; (ii) every liveness claim
in the registry carries a vacuity witness + negative control; (iii) every
emitted liveness `PROPERTY` is about a decided outcome.

## 5. Fairness policy (locked with D1/D2)

- **Weak fairness** (used): if a harness action is continuously enabled, it
  eventually fires. **Strong fairness** (reserved): if enabled infinitely
  often, it fires infinitely often. We use weak fairness on the harness's
  *decision* action (the step that decides the pending request / advances the
  task) — the minimal assumption that rules out infinite stuttering.
- **Scope (T1 restated):** fairness is asserted on **harness actions only**.
  Never on agent actions — the agent is fully compromised and may do
  nothing, anything, or both. A fairness assumption on the agent is an
  unsound assumption and is refused by the emitter.
- **Labeling:** every fairness-based verdict carries the exact fairness
  formula in the assumption ledger (kind `fairness`); the claim text cites
  its ledger ID.
- **Engine of record (D2):** Apalache primary (SMT-based; bounded `--length`
  already wired in `rot.apalache`), TLC cross-check (weak-fairness native;
  the gold standard). Both must **agree**; disagreement ⇒ `UNKNOWN`
  (fail-closed), never a majority vote.
- **Opt-in:** unbounded liveness is off by default; bounded liveness (§3.4)
  is the default claim. Enabling unbounded liveness raises cost (liveness
  checks are "very slow — often not needed") and is recorded in the ledger
  (kinds `fairness` + `engine`).

## 6. Refinement stages — the robustness ladder (locked)

"Refinement is just implication." We do not refine the harness (it is the
same system under test at every rung); we **weaken the environment** rung by
rung and show the claim survives each weakening. Each rung *implies* the one
above it: the same harness, a strictly larger environment, the same (stated)
fairness on the harness. This generalizes the tier contract already in
architecture.md — "raising the tier can only turn an `UNKNOWN` into a
`PROVEN`/`VIOLATED`, never the reverse."

| rung | environment | claim shape | existing machinery |
|------|-------------|-------------|--------------------|
| **R0 — ideal** | agent conforming (`buggy=False`): denied actions disabled | rules hold | `rot.agent_step` default; Trifecta |
| **R1 — adversarial** | agent fully compromised (`buggy=True`): denied actions enabled, any arguments, in parallel | rules **still** hold; counterexamples are attack paths | Plane B K-sweep; `no_over_privileged_tool`, `no_runaway_budget` |
| **R2 — fault-tolerant** | R1 **plus** harness faults: crash / retry / stutter of harness steps | no duplicate side effects after resume (exactly-once); approvals never lost; deadlock-freedom under retry; eventual completion under fairness | `no_deadlock` (G4); busy self-loop; `rot.refine` CLI |

Locked rules:

- **F1 — monotone safety.** A safety violation found at R0 is also a
  violation at R1/R2 (larger environment ⇒ more paths). A safety proof at R2
  implies the proofs at R0 and R1. We therefore report the **highest rung at
  which the claim was discharged**.
- **F2 — liveness per rung.** Liveness is re-discharged at each rung under
  that rung's fairness (R2's fairness covers the retry/stutter steps). Under
  the stated fairnesses, R2 liveness ⇒ R1 ⇒ R0.
- **F3 — the integrity rung is out of scope.** A compromised *harness*
  (tampered gateway, injected transitions) is **not** a rung. It is a named
  non-claim on every claim packet (T2).
- **F4 — refinement is evidence.** Each rung's verdict + the implication
  argument is part of the RTF trace (provenance), so the ladder is auditable
  end-to-end.

## 7. Code-to-TLA+ extraction — scoping (locked with D3)

A new Ingest front-end, `rot/frontends/code/`, whose **only** job (narrow
waist) is to produce `ProtocolIR` candidates from legacy code — one pinned
property per extracted control — so the Verify plane can PROVE each or hand
back the exact bypass witness.

**Pattern classes (D3):**

| class | patterns | lighthouse shape | status |
|-------|----------|------------------|--------|
| **P1** | budget controls (sum ≤ cap over a window; in-flight vs. settled) | `SpendCap` | **first** — end-to-end machinery exists (Plane B) |
| **P1** | label/flow controls (labeled data ⇒ allowed channels/recipients) | `NoExfiltration` | **first** — G7 machinery exists |
| **P2** | delegation/approval controls (irreversible ⇒ approved; delegation never amplifies privilege) | `NoUnapprovedIrreversible`, AP2 mandates | after P1 ships |

**Honesty rules (locked):**

- **E1 — candidate ≠ intent.** Extraction finds controls the code *enforces*;
  it does not infer what the code *meant*. Every extracted property is
  labeled `candidate` in the IR metadata.
- **E2 — pattern-class scope.** Anything outside the declared pattern class
  is reported `OUT_OF_SCOPE`, never silently `UNKNOWN` and never claimed.
- **E3 — verify or refute.** Static extraction has known false
  positives/negatives (the FSMExtractor lesson). A candidate is therefore
  never reported as a finding on its own: it is discharged by the Verify
  plane (PROVEN / VIOLATED + witness / UNKNOWN + budget) exactly like any
  other pinned property.
- **E4 — per-instance claims.** A PROVEN extraction claim is scoped to the
  extracted shape and the instantiation bounds; it is never a universal
  statement about the codebase.
- **E5 — the agent-replacement check is the product.** The lighthouse's
  migration story: legacy code → extracted controls → the *agent
  replacement* is checked against them (same pipeline, different harness).

## 8. Assumption ledger (locked)

A per-run, deterministic, hash-stable artifact listing **every** assumption a
verdict depends on. It generalizes what already exists (RTF `provenance`:
policy hash, environment, engines used, `DepthBudget`, `n_states`,
`horizon_complete`; `Config`'s "property-directed bounds that become recorded
assumptions") into stable, citable IDs.

**Kinds (closed set):** `agent_model` · `horizon` · `bound` · `fairness` ·
`deterministic_core` · `pattern_class` · `engine` · `model_version`.

**Schema `rotn.assumptions/v1`** (one run, every entry):

```json
{
  "schema": "rotn.assumptions/v1",
  "run": "<manifest_id>",
  "entries": [
    {"id": "A1", "kind": "agent_model",
     "statement": "The agent may attempt any tool with any arguments, including denied ones (fully compromised).",
     "value": "adversarial (buggy=true)", "source": "T1; rot.agent_step",
     "claim_impact": "Claims hold against a compromised agent; a conforming-agent claim would be strictly weaker."},
    {"id": "A2", "kind": "horizon",
     "statement": "Liveness discharged within H steps; the whole horizon was explored.",
     "value": "liveness_horizon=12, horizon_complete=true", "source": "rot.config; rot.trifecta",
     "claim_impact": "A longer horizon may (only) strengthen the claim."},
    {"id": "A3", "kind": "fairness",
     "statement": "Weak fairness on harness action Decide: if continuously enabled, it eventually fires. No fairness on agent actions.",
     "value": "WF(Decide)", "source": "fairness policy (5)",
     "claim_impact": "Unbounded-liveness claims depend on A3; bounded claims do not."},
    {"id": "A4", "kind": "deterministic_core",
     "statement": "Consequential figures are decided by the deterministic core, not the model; the harness enforces the signature check.",
     "value": "<core name/version>", "source": "honest boundary (1)",
     "claim_impact": "Claims do not cover the correctness of the model's judgments."},
    {"id": "A5", "kind": "bound",
     "statement": "State-space budget; the search is truncated beyond it.",
     "value": "max_states=200000; participant_bound=K", "source": "rot.config DepthBudget",
     "claim_impact": "UNKNOWN beyond the budget is never read as PROVEN."},
    {"id": "A6", "kind": "pattern_class",
     "statement": "Extraction claim scoped to pattern class P1 (budget + label/flow), per-instance.",
     "value": "P1", "source": "extraction scoping (7)",
     "claim_impact": "OUT_OF_SCOPE outside P1; candidate, not intent (E1)."},
    {"id": "A7", "kind": "engine",
     "statement": "Engines run and their status, including degraded/skipped.",
     "value": "symbolic=ran; tlc=ran; apalache=degraded(jar absent)", "source": "rot.config select_engine",
     "claim_impact": "Cross-check agreement required only among engines that ran."},
    {"id": "A8", "kind": "model_version",
     "statement": "Model (LLM) identity + version, for re-certification.",
     "value": "<family>/<version>", "source": "RTF provenance environment",
     "claim_impact": "Harness claims are model-independent by construction (T1); drift checks are out of proof scope."}
  ]
}
```

**Semantics (locked):**

- **L1 — citable.** Claim text (verdict narration, claim packets) cites
  ledger IDs ("holds under A1, A2, A4"). A claim without its assumption set
  is malformed and fails validation.
- **L2 — hashed.** The ledger is part of the RTF provenance and of the
  `manifest_id` hash; no timestamps, no absolute paths, no random IDs
  (determinism rules inherited from `rot.manifest`).
- **L3 — never elided.** A degraded/absent engine, a truncated budget, and a
  fairness assumption are each an entry. Honesty by construction: the trace
  never hides a gap (architecture.md §3).
- **L4 — fail-closed.** An `UNKNOWN` verdict carries the entry that explains
  *why* (budget, tool absent); `UNKNOWN` is never read as `PROVEN`.
- **L5 — re-certification.** A model change re-runs the ladder under a new
  `A8`; harness claims should reproduce (they do not depend on the model —
  T1), and the ledger diff *is* the re-certification report.

## 9. Decision register (LOCKED)

| # | decision | choice | rationale (lighthouse tie-in) |
|---|----------|--------|-------------------------------|
| **D1** | unbounded liveness | **both**: bounded liveness is the default claim; fairness-labeled unbounded liveness is opt-in | `TaskEndsOrEscalates` is the headline liveness claim ("liveness — Dogwood can't yet"); bounded is the defensible default, unbounded is the full "eventually" sentence |
| **D2** | fairness engine of record | **Apalache primary, TLC cross-check; agreement required, else UNKNOWN** | the Plane B cross-check principle (independent engines must agree); Apalache already integrated (`rot.apalache`, `--length` bound); TLC native weak fairness |
| **D3** | extraction pattern class | **P1 (budget + label/flow) first; P2 (delegation/approval) after** | both P1 shapes have end-to-end machinery (Plane B spend-cap; G7 exfiltration); product 1 (open-source wedge) is exactly "find bypasses like Dogwood's response-vs-request example" |
| **D4** | verticals first cut | **finance + health** | finance = spend-cap + mandate shapes (already proven); health = label/flow + irreversible shapes (already proven); claim packets are compositions of existing invariants, not new logic |
| **D5** | PlusCal authoring | **yes** — canonical spec authored in PlusCal (actors/labels read as agents/atomicity), translated to the pure TLA+ the emitter already produces; the IR remains the narrow waist | "PlusCal is the gateway drug": the reviewer-facing spec should read like a program of actors; the narrow waist and the engines are unchanged |
| **D6** | symmetry sets | **enabled for safety runs only; hard-disabled for liveness, with a test** | the working-notes warning: "DO NOT COMBINE TEMPORAL PROPERTIES AND SYMMETRY SETS"; symmetry is a state-space optimization with no role in a fairness argument |

## 10. Lighthouse fit map

Every load-bearing claim in `orig_thesis.txt`, and where it lands in this
architecture. "Shipped" = in `rot` today with tests; "Phase N" = the Phase
1–6 build this document governs; "reserved" = named, out of Phase 0–6 scope.

| lighthouse item | landing | status |
|---|---|---|
| 4 rules: `NoExfiltration`, `SpendCap`, `NoUnapprovedIrreversible`, `TaskEndsOrEscalates` | §3.6 table; `rot.invariants` registry | shipped (bounded liveness); unbounded = Phase 2 |
| "liveness — Dogwood can't yet" | `bounded_eventually` + `reach_within` + `cegar_liveness`; unbounded via §5 | shipped (bounded); Phase 2 (unbounded, D1/D2) |
| honest boundary: LLM proposes, deterministic core decides | §1; ledger kind `deterministic_core` (A4) | locked |
| §4.1 tool masking (show only enabled tools) | enabled-action computation already exists in the `LinearModel` graph; masking is a runtime consumer of it | reserved (forward hook) |
| §4.2 constructive refusal (`to_proceed` computed from the spec) | `rot.coach.py` (5-step loop, G7), `rot.to_proceed.py`, `rot/runtime/refusal.py` | **shipped** |
| §4.3 DBN/ProbGuard forecasting | complementary *statistical* layer; never in the proof path (proofs are structural; forecasts are probabilistic) | reserved |
| §4.4 near-miss learning (prompt/rule tuning) | safe *because* permissions live in the spec, not the prompt: a prompt edit cannot widen authority | reserved |
| §4.5 binds (contradiction, deadlock, livelock, vacuous permission, over-privileged) | `rot.compliance.py` findings vocabulary; `no_deadlock` (G4); `task_ends_or_escalates` (G6) | shipped |
| durable workflows: no duplicate side effects, approvals never lost, eventual completion | refinement rung R2 (fault-tolerant), §6 | Phase 3 |
| agent payments (AP2/ACP): total spend within intent, no double-use, mid-flight revocation | finance vertical (D4): spend-cap shape + exactly-once (R2) | Phase 5 |
| agent memory: "deleted data never reappears" | P1 label/flow shape + temporal rule | Phase 5 |
| multi-agent orchestration (deadlock, ping-pong, delegation escalation) | `no_deadlock`, `no_runaway_budget`, `no_over_privileged_tool`; R1/R2 ladders | shipped (single-agent slice); multi-agent = Phase 3 |
| re-certification on model change | T1 ⇒ harness claims are model-independent; ledger `A8` diff = the re-certification report (L5) | locked |
| AIUC-1: structural vs. sampled evidence | `rot.compliance.py` AIUC-1 mapping; claim packets carry structural evidence | shipped |
| 7 products | P1 verifier = shipped core; P2 runtime coach = §4.2 shipped + reserved hooks; P3 proof-grade evidence = claim packets + ledger; P4 MCP connectors = Plane A; P5 vertical packs = D4; P6 legacy extraction = §7; P7 re-cert = L5 | mixed |
| "compiler for agents" | design-time errors (binds) + runtime checks (guards) + constructive errors (coach) — the whole architecture | thesis |
| AWS window (Dogwood is point-in-time / per-request — spec Clause 5 — an absence of a soundness-of-intent guarantee over in-flight concurrency) | Plane B + §3.5 are exactly the gap; cross-cloud, framework-neutral | positioning |
| "overclaiming is fatal" | §8 ledger + fail-closed + non-claims | locked |

## 11. Forward hooks (named, out of Phase 0–6 scope)

Reserved so later work has a defined landing; none of these may leak into
the proof path:

1. **Tool masking** — a runtime consumer of the `LinearModel`'s
   enabled-action set (the agent cannot attempt what it cannot see).
2. **DBN/Markov forecasting** — statistical early warning (ProbGuard-style);
   PAC guarantees, not proofs; advisory only.
3. **Near-miss learning** — cross-run block/near-miss aggregation suggesting
   prompt or rule edits; safe because authority lives in the spec, and
   E1–E5 keep extraction honest.
4. **Re-certification service** — L5 as a product: re-run the ladder under a
   new `A8`, diff the ledger, publish the report.
5. **Multi-agent composition** — `rot.composition` (namespaced actions,
   provenance-preserving) is the existing landing for A2A/sub-agent models.

## 12. Phase 0 acceptance (the gate)

A reviewer auditing this document must be unable to find:

- [ ] a **vacuous-liveness hole** — every liveness claim (§3.4, §3.5) carries
      the R3 vacuity witness + negative control requirement, and R4 forbids
      "eventually permitted" claims;
- [ ] an **over-approx-liveness hole** — the R2 rule + the §4 soundness
      matrix name the only two sound discharge paths for liveness, and the
      enforcement points (pipeline dispatch + the three named tests) exist;
- [ ] an **unlabeled assumption** — every kind of assumption that can appear
      in a claim is a ledger kind (§8), and L1–L5 make it citable, hashed,
      non-elidable, fail-closed;
- [ ] a **silent scope** — out-of-scope items (compromised harness,
      model-judgment correctness, out-of-pattern extraction) are named
      non-claims (T2, §1, E2), not gaps.

And the register: D1–D6 are LOCKED with rationale (§9).

**This document changes no shipped contract** — the narrow waist, the RTF
format, the tier model, the fail-closed verdict vocabulary, and the zero
runtime-dependency rule are all inherited unchanged from architecture.md. It
only *adds* the semantics above, and every addition is anchored to an
existing module.

## Appendix A — the lighthouse's TLA+ sketch, annotated

The lighthouse's canonical sketch, with where each piece lives in `rot` and
which rule governs its check.

```tla
(* agent = environment: fully compromised (T1).  rot.agent_step, buggy=True *)
AgentStep == \E t \in Tools, args \in Args(t) : Request(t, args)

Request(t, args) ==
    /\ Policy(t, args, history)        (* harness guard: front-ends -> rot.ir *)
    /\ inflight' = inflight \cup {[tool |-> t, args |-> args]}   (* in-flight: Plane B *)
    /\ history' = Append(history, [ev |-> "request", tool |-> t, args |-> args])
```

```tla
(* RULE 1 — safety (R1). Exfiltration property (G7); coach_exfiltration. *)
NoExfiltration == \A m \in sent : "private" \in m.labels => m.to \in ApprovedRecipients

(* RULE 2 — safety (R1). spendcap_within_cap; Plane B K-sweep.
   The lighthouse's point: sum REQUESTS, not SETTLED responses, in the window. *)
SpendCap == SumOf(requested_transfers_in_window) <= Limit

(* RULE 3 — safety (R1). policy_conformance + the over-privileged-tool bind. *)
NoUnapprovedIrreversible == \A a \in executed : Irreversible(a) => Approved(a)

(* RULE 4 — liveness (R2). task_ends_or_escalates (G6); bounded_eventually.
   Bounded discharge: reach_within(goal, H), horizon_complete.
   Unbounded discharge (opt-in, D1): under WF(Decide) only (D2), with the
   R3 vacuity witness.  "liveness — Dogwood can't yet." *)
TaskEndsOrEscalates == \A task : <>(Done(task) \/ Escalated(task))
```

Emission notes: the emitter's totalizing **busy self-loop** (`UNCHANGED`)
makes the model stutter-tolerant so TLC does not report legitimate terminal
states as deadlocks (§3.3); a `TypeInvariant` (§3.1) is emitted as a state
constraint; the `TypeInvariant`, the four rules, and the fairness formula
(when opt-in) together form the reviewer-facing spec (D5: PlusCal-authored,
pure-TLA+ emitted).

## Appendix B — references

- Lamport, L. — TLA+ / PlusCal (the spec medium; "PlusCal is the gateway
  drug").
- `orig_thesis.txt` — the lighthouse: thesis, 4 rules, 5 feedback mechanisms,
  7 products, AIUC-1, positioning.
- `docs/architecture.md` — planes, narrow waist, RTF, tiers, fail-closed
  (this document's parent).
- Working notes (Lamport's TLA+ chapters): symmetry sets — never with
  temporal properties; invariants vs. temporal properties; TypeInvariant as
  a sanity state constraint; the MapReduce three-stage refinement; weak
  fairness as "if enabled, will eventually happen"; auxiliary variables for
  bounds.
- Reflexion (arXiv:2303.11366), Self-Refine (arXiv:2303.17651) — verbal
  coaching; `rot.coach`'s differentiator is the *proof-discharged*
  correction.
- CaMeL (DeepMind) — capability/information-flow defense; validates the
  information-flow rule shapes (P1 label/flow).
- Dogwood (AWS, Cedar temporal extension) — the gap this product fills: a
  point-in-time / per-request monitor (formal spec Clause 5: the engine is
  invoked per-request over an empty entity set), so an absence of a
  soundness-of-intent guarantee over concurrent in-flight activity — and its
  own response-vs-request concurrency example.
- ProbGuard / Pro2Guard (SMU, ASE 2026) — PAC-guaranteed runtime
  forecasting; the reserved §11.2 hook.
- AIUC-1 (Artificial Intelligence Underwriting Company) — the
  certification/insurance lane; structural (ours) vs. sampled (theirs)
  evidence.
