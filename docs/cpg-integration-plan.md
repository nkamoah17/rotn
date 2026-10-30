# ROTN — CPG + TLA+ Integration Plan

> **Status: CPG-1 + CPG-2 + CPG-3 DONE (CPG-2 gate passed 2026-10-30, offline;
> CPG-3 cross-check gate passed 2026-10-30, offline — 28/28); CPG-4 planned.**
> This is the durable record of the CPG + TLA+ integration. It **builds on** the committed Phase 1–4 work
> (constraint emission, liveness R1–R4, the R0→R1→R2 ladder, and the P1
> code extractor) and **converges with** the pending emblematic Phases 5–6
> (claim packet + artifacts). It is the "good mix" of `emblematic.txt`
> (the TLA+ phase plan) and `cpgtla.txt` (the Joern CPG front-end idea).
>
> **Guardrail (unchanged from `architecture.md` / `spec-medium-design.md`):**
> pure stdlib, Python 3.6, offline, deterministic. Joern is **optional**
> (like TLC) — the whole chain runs and is tested against committed CPG JSON
> artifacts with no Java / Joern present. The narrow waist
> (`tests/test_narrow_waist.py`) is untouched: a front-end imports only
> `rot.ir` + its own package + stdlib.
>
> **Products served:** Product 1 (agent policy & harness verifier, the
> open-source wedge) and Product 2 (runtime coach) from `orig_thesis.txt`
> ("the lighthouse").

---

## 1. One-sentence integration

**Make the CPG the *generic, code-grounded IR producer* — a fourth front-end
that emits the *same `Candidate`* as the Phase-4 AST extractor — by (a)
extending the scrape + CPG model to carry **dataflow** (the missing half),
(b) recognizing the **P1 shape vocabulary from CPG structure** instead of name
heuristics, and (c) adding a **static↔formal soundness cross-check** — so the
verifier (P1), the coach (P2), and the claim packet (P5) all consume one
code-derived IR, and the static half and the formal half *disagree loudly*.**

**Why this beats both source plans:**

- `emblematic.txt` (Phase 4) gives the *pipeline*
  (`Candidate → lower_candidate → verify_candidate → coach`) but a
  name-heuristic, Python-only producer, with no dataflow and no cross-check.
- `cpgtla.txt` gives the *CPG-as-IR-source* idea but a new IR producer that
  **bypasses** that pipeline, with no dataflow spec and the cross-check left
  as prose.
- **This plan** slots the CPG into the *exact existing contract* (a third
  `Candidate` producer), makes "derived label flow" *real* (the scrape now
  carries the dataflow edges), and promotes the cross-check to a
  **first-class, checkable, fail-closed property**. One extraction, two sinks —
  the "one IR, N consumers" shape the pipeline already has.

---

## 2. Current state (what's in the tree)

**The TLA+ pipeline is a pure function of the IR:**

```
IR  →  linearize  →  emit  →  check  →  CEGAR  →  verdict  →  replay / coach
rot.ir      rot.linearization  rot.emitter  rot.{tlc,symbolic,apalache}  rot.cegar  rot.verdicts  rot.trace / rot.coach
```

Every stage after the IR is engine-agnostic and contract-stable. The **IR
source** is the only hand-authored, non-scalable, non-code-grounded stage.
**Three IR producers exist today, and none is the generic one:**

| producer | mechanism | shape coverage | dataflow |
|---|---|---|---|
| `rot/targets.py` (synced) | hand-authored | 8 protocols | n/a (it *is* the model) |
| `rot/frontends/code/extractor.py` (P4, local) | Python AST + **name heuristics** | P1: budget, label_flow | none |
| `rot/frontends/java/ir_builder.py` (synced) | CPG, but **2PC-specific** | 2PC only | none |

**The decisive gap:** the CPG scrape (`rot/frontends/java/scrape.sc`) emits
*call edges + field read/write* but **no dataflow** — no `REACHING_DEF` /
`FLOW` / `ARGUMENT`, no taint. So the CPG cannot *derive* label-flow or budget
accounting; it is used only for provenance + enum recovery + apply-mode
detection. That is exactly the half `cpgtla.txt` needs and the tree is missing.

**Already present and reusable (no change):**

- `rot/frontends/joern.py` — Joern CLI driver (`find_toolchain`,
  `run_joern_script`, `scrape_model`); the brittle plumbing, isolated.
- `rot/frontends/cpg_model.py` — `CpgType` / `CpgField` / `CpgMethod` /
  `CpgModel` (types, fields, methods + `calls` / `read_fields` /
  `written_fields`); language-agnostic JSON.
- `rot/frontends/cpg_reader.py` — `load_cpg` / `load_cpg_or_none` (graceful
  degradation when the artifact is absent).
- `rot/frontends/cone.py` — `cone_of_influence` (property-directed subgraph).
- `rot/frontends/code/extractor.py` — the P1 `Candidate` contract
  (`pattern`, `enforced`, `params`, `provenance`, `pinned_property`,
  `candidate=True`, `out_of_scope`, `reason`) + the E1–E5 honesty rules.
- `rot/lower.py:lower_candidate` — `Candidate → ProtocolIR` (reuses
  `spendcap.build_ir` + the label-flow shape).
- `rot/cegar.py:verify_candidate` — `ProtocolIR → Verdict` (PROVEN /
  VIOLATED+witness / UNKNOWN / OUT_OF_SCOPE) via the existing safety pipeline.
- `rot/coach.py` + `rot/to_proceed.py:compute_to_proceed` — Product 2,
  **already generic over the IR** (the `to_proceed` list is computed from the
  action's guard — the spec — not hardcoded).
- `rot/compliance.py:coaching_compliance` — Product 3 (AIUC-1 / SOC 2 mapping).
- `rot/manifest.py` — deterministic, byte-stable, SHA-256 `manifest_id`.
- `rot/crosscheck.py` — the *engine-vs-engine* cross-check (SMT + TLC +
  policy-direct, `join_status`). The new check in §5 is the *static-vs-formal*
  analogue (a different pair of oracles), so it is a **separate module**
  (`rot/cpg_crosscheck.py`) to avoid conflation.
- `rot/verdicts.py` — statuses (PROVEN / VIOLATED / UNKNOWN / UNSOUND / ERROR
  / OUT_OF_SCOPE), `violation_code`, and the **advisory-code** mechanism
  (`MASKED_AT_LOW_K`) — the precedent for the `unsound_abstraction` flag.

**Buildability note (verified on this box):** Joern has been run here
(`_joern_test/workspace/` holds `cpg.bin` + semanticcpg passes), but the
toolchain is not on the standard discovery paths and **no CPG JSON is
committed**. Therefore the plan makes the CPG path **testable offline**
against a committed CPG JSON fixture; the live Joern scrape remains the
production path (optional, exactly like TLC).

---

## 3. The mathematical core (stated precisely)

Let `G` be the CPG, `A` the abstraction (CPG→IR), `M` the model checker, and
`P` a pinned taint property (e.g. NoExfiltration:
`¬∃ path : private_source →* unapproved_sink`; SpendCap: the in-flight-aware
cap predicate).

**(S) Abstraction soundness (counter-monotonicity).** `A` may *add*
existential freedom (an over-approximation of the state space — the IR's
existing "no deleted variable" rule, `StateVar` has no `deleted` mode) but
must **never delete a taint-critical dataflow edge**. Formally:

> `taintPath(G, P) ⟹ ¬ Proven(M(A(G)), P)`  ⟺  `Proven(M(A(G)), P) ⟹ ¬ taintPath(G, P)`

i.e. **if the ground-truth program has a taint path, the abstract model must
not prove `P`.** This lifts the IR's "never under-approximate a safety
behaviour" rule from the *variable* level to the *graph* level.

**The check (fail-closed):** run `A(G) → IR → M → verdict`, and query `G` for
`taintPath(G, P)` (a cheap per-path query over the def-use / flow edges).

- **Disagree:** `PROVEN ∧ taintPath(G,P)` ⟹ `A` dropped a dataflow edge ⟹
  **downgrade `PROVEN → UNKNOWN`**, attach the advisory flag
  `unsound_abstraction`, and **name the dropped edge**. (The
  `MASKED_AT_LOW_K` advisory is the precedent: a loud, non-silent marker that
  makes the bound that produced a verdict visible.)
- **One-directional soundness, bidirectional reporting:**
  `VIOLATED ∧ ¬ taintPath(G,P)` is *expected and sound* — it is a
  **concurrency-only witness** the static single-path analysis cannot see (the
  parallel-fire spend-cap bypass). Tag it `concurrency_only`. This *is* the
  thesis line: **"Joern is the smell test; ROTN is the proof."**

This is the **static↔formal agreement invariant** — the same shape as the
Phase-2 cross-engine rule (D2: symbolic + TLC agree, else UNKNOWN), now applied
to the pair *static (Joern) + formal (model checker)*. It is the new,
defensible, thesis-quotable property of this plan.

**Derived label flow (sound-by-construction).** A "private" label is a *taint
source*; an egress call is a *sink*. `taintPath(G, P)` = a REACHING_DEF/FLOW
path from a private source to an unapproved sink. The IR's `labels` term in
NoExfiltration is **derived from this closure** (reachable-def of the private
source = the data carrying the label; approved sinks = the allowed channels),
so the invariant's labels are *grounded in the dataflow*, not assumed. The
coach's capability set (allowed channels) is the *same* derivation — one
extraction, two sinks.

---

## 4. The contract (what the CPG front-end must emit)

The CPG front-end is a **third producer of the same `Candidate`** the Phase-4
AST extractor already emits, so the entire downstream chain is untouched:

```
rot/frontends/cpg/extractor.py            (NEW; narrow-waist)
    extract_cpg(model, shape=None) -> Candidate
        # model : rot.frontends.cpg_model.CpgModel
        # shape : "budget" | "label_flow" | None (auto-detect)
        # emits the SAME Candidate as rot.frontends.code.extractor.extract
        #   (pattern, enforced, params, provenance, pinned_property,
        #    candidate=True, out_of_scope, reason)
[then, UNCHANGED]
    rot.lower.lower_candidate(candidate)      -> ProtocolIR
    rot.cegar.verify_candidate(ir, cfg)       -> Verdict   (+ CPG-3 cross-check)
    rot.to_proceed.compute_to_proceed(ir,…)   -> to_proceed (P2)
    rot.coach / rot.compliance / rot.manifest -> artifact (P1 + P3)
```

**Smoothness invariants (kept):**

1. **Single boundary.** The CPG feeds the *Candidate/IR* contract;
   `lower / verify / coach / compliance / manifest` are byte-for-byte untouched.
2. **Optional, like TLC.** Joern *builds* the CPG as a separate process; the
   core only *reads* the CPG JSON (stdlib). No Joern → hand- or AST-IR → the
   pipeline runs exactly as today.
3. **A/B-able.** The *same* control can be produced two ways (AST vs. CPG) and
   run through the identical downstream chain; the A/B test (§5, CPG-2 gate)
   asserts the lowered IRs are `to_dict()`-equal.
4. **No verdict-contract change.** `PROVEN / VIOLATED / UNKNOWN / OUT_OF_SCOPE`
   mean exactly what they do now. The CPG changes *what the spec is about*
   (real code vs. hand-model), never *what a verdict means*.
5. **Narrow waist.** `rot/frontends/cpg/extractor.py` imports only `rot.ir` +
   `rot.frontends.cpg_model` + stdlib (enforced by `tests/test_narrow_waist.py`).

---

## 5. The plan (4 phases, strictly sequential; each gates the next)

### CPG-1 — The dataflow half (scrape + model + fixture)  · *Effort S–M · Risk Low*

**Objective:** give the CPG the half it is missing — dataflow — so label-flow
and budget can be *derived*, not assumed.

| work item | module |
|---|---|
| Scrape emits def-use (`REACHING_DEF`), argument (`ARGUMENT`), and a conservative taint source/sink set (a classifier, not full taint-tracking) | `rot/frontends/java/scrape.sc` |
| `CpgMethod` gains `defs` / `args`; `CpgModel` gains typed `edges` + `taint_sources` / `taint_sinks` + a `taint_path(src, sink)` query | `rot/frontends/cpg_model.py` |
| Commit a **CPG JSON fixture** (a small Java spend-cap + exfiltration connector, dataflow edges populated) so everything below is testable **offline** | `tests/fixtures/cpg/*.cpg.json` |
| Tests: model round-trips the new fields; `taint_path` finds the private→sink edge; `load_cpg_or_none` still degrades when absent | `tests/test_cpg_model.py` |

**Gate (stop/go):** the fixture round-trips; `taint_path` locates the
private→sink edge; offline (no Joern) the whole chain still imports and runs.

**Status: DONE (2026-07-10).** All work items landed and the gate passes —
`tests/test_cpg_model.py` 6/6, fully offline:
- `scrape.sc` emits per-method `defs` / `args`, typed `REACHING_DEF` /
  `ARGUMENT` / `CALL` edges, and the conservative source/sink classifier.
  Every dataflow section is best-effort (a query failure degrades to empty
  lists; the verified-good core — types/fields/methods — is never lost), and
  the success contract (`ROTN-SCRAPE-OK` + the JSON at `ROTN_CPG_OUT`) is
  unchanged, so `joern.py` needed no changes.
- `cpg_model.py` carries the new fields with backwards-compatible
  round-trip (`old JSON still loads`) + `validate()`; `taint_path` /
  `taint_paths` implement `taintPath(G, P)` over the dataflow edges
  (parameter-slot → owning-method projection included; `CALL` excluded by
  default, opt-in via `include_calls`).
- Fixture committed: `tests/fixtures/cpg/` — `connector.java` (provenance:
  spend-cap + exfiltration connector), `connector.cpg.json` (dataflow
  populated; the private→sink path `report#ssn → mask#ssn → report#payload →
  AuditLog.send#payload → AuditLog.send`), and a README.
- **Pending (not blocking, per the buildability note):** one live Joern run
  of the new `scrape.sc` against a real target to confirm the dataflow
  sections populate in the production toolchain. The offline path above is
  the committed test path (Joern optional, like TLC).

### CPG-2 — The generic CPG→Candidate producer (the unifying front-end)  · *Effort M · Risk Med*

**✅ Done — CPG-2 gate passed (2026-10-30, offline).** `rot/frontends/cpg/`
subpackage: `extract_cpg(model, shape=None, method=None)` emits the *same*
`Candidate` contract (imported from `rot.frontends.code` — one contract,
one class). Both P1 shapes are recognized from **CPG structure**, not names:
* **budget** — a *decision method* (boolean return, no writes, no calls)
  combining ≥ 2 inputs (REACHING_DEF/ARGUMENT) against exactly one
  non-flowing candidate (the cap); the enforced/bypassable split is read
  from *which fields the sum is over* (in-flight in the sum → enforced;
  settled-only → bypassable) — the `detect_apply_mode` idea generalized;
* **label_flow** — classified private source → `taint_path` → classified
  egress sink; enforced iff the egress caller reads a **boolean-typed field
  some other method writes** (a type-based mutable-gate test; the egress
  receiver is excluded structurally), else bypassable.

**A/B gate:** `tests/test_cpg_extraction.py` — for the *same* control, the
CPG producer and the code producer classify identically and lower to a
`to_dict()`-identical `ProtocolIR` (provenance excluded — necessarily
language-specific); both flow through the same gate: enforced → PROVEN,
bypassable → VIOLATED + exact witness, E2 → OUT_OF_SCOPE (never a silent
UNKNOWN). Ground truth: the committed Java/Joern scrape
`tests/fixtures/cpg/connector.cpg.json` (budget ENFORCED + label_flow
BYPASSABLE) plus in-memory models with *new* names covering the other two
quadrants — proof the recognition is structural, not fixture-memorized.
Honesty boundaries: no literals in a scrape → the lighthouse defaults
(100/200), exactly as the code side falls back; out-of-pattern → E2.

*Also fixed (found by the gate):* `rot/frontends/cone.py` seeded the cone
roots into `depth` but not `in_cone` — with two call-connected roots the BFS
re-queued them forever (infinite loop) and the cone silently excluded its
own roots. Roots now seed both; the liveness bug is regression-covered by
`test_label_flow_enforced_from_structure`.

**Objective:** a narrow-waist front-end that recognizes the **P1 shapes from
CPG structure** (dataflow + calls + field read/write) — not name heuristics —
and emits the *same `Candidate`* as the AST extractor.

| work item | module |
|---|---|
| `extract_cpg(model, shape=None) -> Candidate`; out-of-pattern → `out_of_scope=True` (E2), never a silent UNKNOWN | `rot/frontends/cpg/extractor.py` (new) |
| **budget** = a decision method comparing a *sum* to a cap; *enforced* vs. *bypassable* read from **which field the sum is over** (in-flight vs. settled) — the `java/ir_builder.detect_apply_mode` idea generalized | same |
| **label_flow** = a taint path private-source→sink; *enforced* = the egress is guarded on the path (a `holding_private` check), *bypassable* = unguarded | same |
| Property-directed abstraction via the existing cone-of-influence (only the taint/call-relevant subgraph) | `rot/frontends/cone.py` (reuse) |
| Provenance: CPG method `fullName` + line range + the taint path, on `Candidate.provenance` (source-pinning for CPG-4) | same |
| **A/B test:** `extract_cpg` on the fixture yields a `Candidate` whose lowered IR is `to_dict()`-equal to the AST extractor's for the same control | `tests/test_cpg_extraction.py` |

**Gate (stop/go):** the A/B test passes (one control, two code-grounded
producers, identical lowered IR); out-of-pattern → `OUT_OF_SCOPE`; the new
module is narrow-waist clean.

### CPG-3 — The static↔formal soundness cross-check (the integrity win) · *DONE*

**Objective:** make §3's condition **(S)** a first-class, checkable,
fail-closed property that runs on every CPG-derived verdict.

| work item | module |
|---|---|
| `check_abstraction_soundness(cpg, ir, verdict, shape)` implementing (S); pure function of the inputs (unit-testable with no engine) | `rot/cpg_crosscheck.py` (new — distinct from the engine-vs-engine `rot/crosscheck.py`) |
| `PROVEN ∧ taintPath` → downgrade to `UNKNOWN` + advisory `unsound_abstraction` + the named dropped edge | same |
| `VIOLATED ∧ ¬ taintPath` → tag `concurrency_only` (the model checker's value-add) | same |
| Agreement (the common case) → clean verdict, cross-check recorded in evidence | same |
| Wire into `verify_candidate` so every CPG-derived verdict carries the result in `evidence` | `rot/cegar.py` |
| Tests: all branches (agreement clean / PROVEN+path→UNKNOWN+flag / VIOLATED+no-path→concurrency_only / not-applicable) | `tests/test_cpg_crosscheck.py` |

**Gate (stop/go):** all branches green; the downgrade is fail-closed
(never a silent PROVEN); the flag names the dropped edge. **PASSED
2026-10-30 (offline, 28/28; full suite 1332/1332).**

**Implementation record (what actually shipped):**

- **The (S) cells are a 2×2, not three branches.** `check_abstraction_soundness`
  returns one of four `SoundnessResult.status` values, keyed by
  *(threat present? × verdict)*:

  | | **PROVEN** | **VIOLATED** |
  |---|---|---|
  | **taintPath(G, P)** | `UNSOUND` (downgrade) | `AGREEMENT` |
  | **¬ taintPath(G, P)** | `AGREEMENT` | `CONCURRENCY_ONLY` (tag) |

  Undecided verdicts (`UNKNOWN`) and a CPG with no P1 control both return
  `NOT_APPLICABLE` — recorded, never a verdict change.
- **The threat query is shape-specific and cheap** (a per-path query over the
  committed def-use / flow edges — no engine): for **budget** it asks whether
  a taint-critical summand (the in-flight / parallel-fire term the cap must
  bound) reaches the spend decision; for **label/flow** it asks whether the
  private source reaches the egress sink. The **dropped edge is named** on the
  `UNSOUND` result (and stamped on
  `evidence["abstraction_soundness"].dropped_edge`) so a downgrade is always
  *explainable*, never a bare flag.
- **Fail-closed application.** `apply_soundness` turns a `UNSOUND` on a `PROVEN`
  into a fresh `UNKNOWN` verdict (advisory `unsound_abstraction`, no
  counterexample, the dropped edge on the note + soundness notes); it tags a
  `CONCURRENCY_ONLY` on a `VIOLATED` (advisory `concurrency_only`, the witness
  preserved — the tag never hides the violation). `AGREEMENT` /
  `NOT_APPLICABLE` return the verdict untouched. It never mutates in place.
- **Wiring.** `verify_candidate(ir, cfg, engine, cpg=None)` runs the cross-check
  on every CPG-derived verdict (the caller passes the ground-truth scrape) and
  records the result on `evidence["abstraction_soundness"]`. Without `cpg`
  the behaviour is byte-identical to before (the cross-check is opt-in, so the
  engine-vs-engine `rot/crosscheck.py` path is untouched).
- **Distinct from `rot/crosscheck.py`.** That module is the *engine-vs-engine*
  oracle (SMT + TLC + policy-direct, `join_status`). This one is the
  *static-vs-formal* oracle (CPG ground truth vs. the model) — a different pair
  of oracles, the same fail-closed shape, a separate module to avoid conflation.

### CPG-4 — Product 1 + Product 2 + the CPG-aware claim packet  · *Effort M · Risk Med*

> This phase **converges the two plans**: it *is* the pending emblematic
> Phases 5–6 (claim packet + artifacts) with CPG provenance, and it is where
> Products 1 & 2 land.

| work item | module |
|---|---|
| **P1 verifier:** `rot check --from-cpg <cpg.json> [--shape …]`; the witness maps to **source lines** (citable); code-level evidence in the RTF trace | `rot/__main__.py`, `rot/trace.py` |
| **P2 coach:** `compute_to_proceed` (already generic over the IR) runs on the CPG-derived IR; the refusal `why` / `to_proceed` cite the **guard's source line**; the allowed-channel set is the **derived** label flow (CPG-2) | `rot/to_proceed.py`, `rot/coach.py` |
| **Claim packet:** the CPG→IR mapping becomes the **abstraction manifest** (`AbstractionEntry` list) filled with code-level kept/dropped detail; non-claims carry the honest boundary (§6); ledger + SHA-256 `manifest_id` | `rot/manifest.py`, `rot/compliance.py`, `rot/tracefmt.py` |
| Tests: one CPG → N verticals (no re-derivation); claim packet complete (non-claims + ledger + cross-check); deterministic manifest; coach refusal source-pinned | `tests/` |

**Gate (stop/go):** one CPG → N verticals; claim packet complete and
byte-stable; the coach's `to_proceed` cites a real source line; the manifest
reproduces.

---

## 6. Honest boundaries (locked; stated in every claim packet's non-claims)

- **The CPG is static, single-iteration, per-path.** It grounds the *safety*
  IR (NoExfiltration, SpendCap, TypeInvariant) + deadlock *evidence*. It does
  **not** discharge *liveness* (`task_ends_or_escalates`) or *concurrency
  bypass* — those still need the model checker. The CPG *feeds* the checker;
  it does not replace it.
- **The CPG→IR translation is lossy** (keeps security-relevant structure,
  drops the rest). The counterexample→source mapping is **best-effort**
  (consistent with the existing counterexample-fidelity note) — not a
  one-to-one guarantee.
- **Java-first** (Joern's strongest front-end), but the `CpgModel` JSON is
  **language-agnostic** — a C# / Go / Python CPG tool can emit the same JSON
  later; the front-end is written against the `CpgModel`, not the scrape.
- **The cross-check is one-directional for soundness** (PROVEN ⟹ no taint
  path) and **bidirectional for reporting** (concurrency-only witnesses are
  the model checker's value-add, tagged, not errors).
- **The enhancement is upstream of the emitter.** The CPG changes the *input*
  to `rot/emitter.py`, never the TLA+ it generates; the Snowcat / `@type`
  emission path stays exactly as is.

## 7. Effort & risk

**~2–3 person-weeks**, dominated by CPG-2 (generic shape recognition,
ground-truthed by the A/B test) and CPG-4 (claim packet + coach + CLI). Much
smaller than a rebuild because it reuses the existing CPG machinery, the
Phase-4 `Candidate` pipeline, and the coach.

| risk | where | mitigation (locked) |
|---|---|---|
| Joern toolchain not on standard discovery paths | CPG-1 | committed CPG JSON fixture = offline test path (Joern optional, like TLC) |
| dataflow-extraction fragility (Joern taint API) | CPG-1 | def-use / argument edges (stable) + a conservative source/sink classifier, not full taint-tracking |
| abstraction overclaim | CPG-3 | fail-closed `UNKNOWN` + named dropped edge (condition **(S)**) |
| verifier / coach divergence | CPG-4 | single `Candidate` contract — one extraction, two sinks |
| narrow-waist regression | all | `tests/test_narrow_waist.py` stays green; new front-end imports only `rot.ir` + `cpg_model` + stdlib |

## 8. Sequencing & gating

```
CPG-1 → CPG-2 [A/B gate] → CPG-3 [cross-check gate] → CPG-4
```

- **Strictly sequential** — each phase's output is the next phase's input
  (dataflow → producer → cross-check → products/claim packet).
- **CPG-4 completes emblematic Phases 5–6** (claim packet + artifacts) with
  the CPG provenance, so the two plans converge there rather than diverge.
- **No rework of Phases 1–4** — this is a front-end (upstream of the
  emitter); the committed safety/liveness/ladder/extraction work is consumed,
  not touched.

## 9. Locked decisions

1. **Parallel, not primary.** The CPG is a *drop-in third* `Candidate`
   producer alongside the hand targets + AST extractor, A/B-able — never
   replacing them. (Preserves the offline/stdlib guarantee; `cpgtla.txt`'s
   "single boundary" + "optional, like TLC".)
2. **Java-first, JSON-agnostic.** Ship the Java/Joern path now; the
   `CpgModel` schema is the language-agnostic contract for later front-ends.
3. **The cross-check is its own module** (`rot/cpg_crosscheck.py`), distinct
   from the engine-vs-engine `rot/crosscheck.py` — a different pair of oracles
   (static vs. formal), same fail-closed shape.
4. **Fail-closed everywhere.** Disagreement ⟹ `UNKNOWN`; `UNKNOWN` never reads
   as `PROVEN`; a `PROVEN` that the CPG refutes is downgraded, never elided.

## Appendix A — references

- `orig_thesis.txt` — the lighthouse: Products 1 & 2, the 5 feedback
  mechanisms, AIUC-1, the "Joern is the smell test, ROTN is the proof" line.
- `emblematic.txt` — the TLA+ phase plan (Phases 1–6) this builds on /
  converges with.
- `cpgtla.txt` — the Joern CPG front-end idea this generalizes.
- `docs/architecture.md` — planes, narrow waist, RTF, fail-closed (parent doc).
- `docs/spec-medium-design.md` — the locked semantics (D1–D6, dual-soundness,
  fairness, E1–E5, assumption ledger) inherited unchanged.
- `rot/ir.py` — the narrow waist (`ProtocolIR`, `StateVar`, `Expr`, `Action`,
  `AbstractionEntry`, `AdversarialPolicy`; the "no deleted variable" rule).
- `rot/frontends/cpg_model.py` / `cone.py` / `cpg_reader.py` / `joern.py` —
  the reusable CPG machinery.
- `rot/frontends/code/extractor.py` — the P1 `Candidate` contract + E1–E5.
- `rot/cegar.py:verify_candidate`, `rot/coach.py`, `rot/to_proceed.py`,
  `rot/compliance.py`, `rot/manifest.py` — the downstream consumers (untouched).
- `rot/verdicts.py` — the verdict vocabulary + the `MASKED_AT_LOW_K` advisory
  precedent for the `unsound_abstraction` flag.
- CaMeL (DeepMind) — capability/information-flow; validates the derived
  label-flow shape (P1 label_flow).