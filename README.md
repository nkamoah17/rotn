<p align="center">
  <img src="assets/caravel_logo.jpeg" alt="Caravel" width="160"/>
</p>

<h1 align="center">ROTN — Regression-detection Oracle via Trace Non-emptiness</h1>

> **CARAVEL** — *Agents are replacing the software that used to enforce our rules. We make the rules explicit, prove agents can't break them — even when compromised — and coach agents back in bounds when they try.*

**ROTN** (R**o**gression-detection **O**racle via **T**race **N**on-emptiness) is a small, fully offline, **Python 3.6-compatible**, pure-stdlib verification platform that checks distributed-transaction and replication protocols against named safety invariants - and, in **Agent Mode**, verifies an autonomous agent's action choices against **Cedar** / **Dogwood** policies (safety, non-vacuity, bounded liveness) - using **three independent engines** and a **bounded CEGAR** loop. Each protocol ships a *correct* variant (the invariant holds) and a *seeded-buggy* variant (the invariant is violated); the pipeline must discriminate them and, for the buggy one, hand back a **concrete, IR-feasible counterexample**.

It is organised in verification planes over one sound core:

1. **Formal core (Phase 1).** Property-directed, bounded verification over four protocol targets: **2PC**, **ZAB**, **PBFT**, and the **Payment** composition.
2. **Composition plane (Phase 2).** Independently modelled services are merged into one concurrent IR and checked against *cross-service* invariants.
3. **Merge-request gate.** Invariant verdicts map to `PASS`/`BLOCK` through an *assurance ladder* (label × rung × pinning).
4. **Agent Mode (policy plane).** The autonomous agent's `AgentStep` model is checked against a **Cedar** (`.cedar`) or **Dogwood** (`.json`) policy: `policy_conformance` (safety), `policy_permits_request` (non-vacuity), `bounded_eventually` (bounded liveness within horizon B).
5. **Two audit planes (different depth guarantees).** **Plane A** — structural + *behavioral* (MCP manifest / Cedar / Dogwood `.json`) — is the Trifecta audit mapped to **SOC 2 CC6** + **AIUC-1** (autonomy). The MCP-manifest audit is *behavioral* (gap G8): the manifest's safety property is **model-checked over the adversarial agent's tool-call sequences** — not just a declaration check — and the lethal-trifecta exfiltration risk is flagged (see `docs/manifest-format.md` §7). **Plane B** — deep temporal/concurrency (Dogwood `.dw` spend-cap) — is the cross-check proof (SMT/Z3 + TLC + policy-direct) that prevents spend-cap bypass, and carries the **CoachingArtifact** (Rule + Proof + **Coach**) that discharges **AIUC-1**. See `docs/architecture.md` §1A.

```
 CPG/IR  ->  property-directed abstraction  ->  linearization
        ->  ENGINE  (symbolic-bounded-exhaustive  |  SMT-Z3  |  policy-direct  |  TLC  |  Apalache)
        ->  bounded CEGAR (recheck on unknown)
        ->  Verdict  ->  auditable report (JSON + Markdown)
```

Everything is pure stdlib except the optional TLC engine (which shells out to
`java` + `tla2tools.jar`). The symbolic engine is fully offline and
deterministic, so the whole pipeline runs in a bare Python environment.

---

## Hosted replay

Every `rot check` run emits a **deterministic, hashed trace** (`trace.json`)
that replays as an **interactive proof** on GitHub Pages — a verdict card,
the counterexample graph (Cytoscape), the step-by-step attack timeline with
narration, the Cedar-AR findings, and the SOC 2 / AIUC control mapping:

> **Live replay: [caravel.github.io/rot-verify](https://caravel.github.io/rot-verify/)**
>
> Published to GitHub Pages on every push to `main` (the **Ship plane** — a pure
> function of the RTF trace; see `docs/architecture.md` §1.4 and
> `.github/workflows/pages.yml`).

---

## 60-second run

Zero dependencies, no Java, no network. From a source checkout:

```bash
pip install .

# 1) A spend-cap policy with a parallel-fire bypass -> VIOLATED (exit 1)
rot check --policy samples/spendcap-buggy.dw --out out
#    -> out/attack.jsonl: the auditable counterexample (attack script)

# 2) Re-derive that attack against the policy -> REPRODUCED (exit 1)
rot replay out/attack.jsonl --policy samples/spendcap-buggy.dw

# 3) The corrected policy -> PROVEN (exit 0)
rot check --policy samples/spendcap-correct.dw --out out

# 4) Coach the buggy policy back in bounds, *with a proof* (exit 0 = closed)
rot coach --policy samples/spendcap-buggy.dw --out out
#    -> out/coaching.json: the deterministic CoachingArtifact (Rule + Proof + Coach)
```

Exit codes: `0` PROVEN · `1` VIOLATED · `2` UNKNOWN · `3` ERROR.

CI gate (JUnit XML + SARIF for GitHub PR annotations):

```bash
rot ci --policy samples/spendcap-buggy.dw --out ci   # exit 1; writes ci/JUnit.xml + ci/results.sarif
```

Full 5-phase demo (PROVEN / VIOLATED / REPLAY / K-sweep):

```bash
rot demo
```

---

## Deep dive

<details>
<summary><strong>Research pipeline (pipeline.py)</strong></summary>


```bash
# List available targets and invariants
python pipeline.py --list

# Correct 2PC, agreement invariant, symbolic engine (offline, no Java needed)
python pipeline.py correct --property agreement --engine symbolic

# Buggy 2PC, agreement invariant -> must come back VIOLATED with a witness
python pipeline.py buggy   --property agreement --engine symbolic

# Use the real TLC model checker (needs java + tla2tools.jar)
python pipeline.py correct --property agreement --engine tlc
python pipeline.py buggy   --property agreement --engine tlc

# Pick the engine automatically: TLC if a jar+java are present, else symbolic
python pipeline.py correct --property agreement --engine auto
```

PowerShell wrapper (adds a matrix mode):

```powershell
.\run.ps1 -Target buggy   -Property agreement -Engine symbolic
.\run.ps1 -Target correct -Property validity  -Engine auto
.\run.ps1 -List
.\run.ps1 -Matrix -Engine auto        # verdict grid for every target x property
```

### Exit codes

| code | meaning  |
|:----:|----------|
| `0`  | `proven` — invariant holds for every reachable state |
| `1`  | `violated` — a concrete counterexample was found |
| `2`  | `unknown` / `unsound` — budget exhausted or a spurious witness |
| `3`  | `error` — engine/config/IO failure |

---

</details>

<details>
<summary><strong>The targets</strong></summary>


ROTN verifies four protocol families and the AWS Dogwood **spend-cap** policy
target, each shipped as a *correct* variant (the invariant holds) and a
*seeded-buggy* variant (the invariant is violated). The
two variants of a family share the same state, actions and invariants and differ
only in one decision rule, so any engine-result difference is attributable to the
bug, not to a modelling difference.

| target | module | holds on `*-correct` | breaks on `*-buggy` |
|--------|--------|----------------------|---------------------|
| `correct` / `buggy` | `rot.twopc` | `agreement` | `agreement` |
| `zab-correct` / `zab-buggy` | `rot.zab` | `zab_no_premature_apply` | `zab_no_premature_apply` |
| `pbft-correct` / `pbft-buggy` | `rot.pbft` | `pbft_quorum` | `pbft_quorum` |
| `payment-correct` / `payment-buggy` | `rot.payment` (composed) | `no_double_charge` | `no_double_charge` |
| `spendcap-correct` / `spendcap-buggy` | `rot.spendcap` (policy) | `spendcap_within_cap` | `spendcap_within_cap` |

### 2PC (`rot.twopc`)

Two variants share the same state, actions and invariants; they differ only in
how participants apply the coordinator's decision:

| target  | apply rule                                            | expected (agreement) |
|---------|-------------------------------------------------------|----------------------|
| `correct` | `applied_i = decision` (apply the coordinator's decision) | **PROVEN** |
| `buggy`   | `applied_i = (vote_i = yes) ? commit : abort` (self-decide from own vote) | **VIOLATED** + witness |

The **bug** is the classic 2PC mistake: a participant that voted `yes` commits
on its own while a participant that voted `no` aborts — so two participants
make *different* final decisions, breaking **agreement**. The counterexample
TLC / the symbolic engine returns is exactly such a mixed state.

### ZAB (`rot.zab`)

Broadcast/commit replication. `zab-correct`: followers apply only after the
leader commits. `zab-buggy`: followers apply as soon as they persist, before the
leader commits — breaking `zab_no_premature_apply`.

### PBFT (`rot.pbft`)

Prepare/commit consensus. `pbft-correct`: a node commits only on a quorum
certificate. `pbft-buggy`: a node commits after preparing itself, without a
quorum certificate — breaking `pbft_quorum`.

### Payment (`rot.payment`, composed by `rot.composition`)

The Phase 2 **composition plane**: a client and a payment service, each modelled
independently and merged into one concurrent IR. `payment-correct`: charge is
idempotent. `payment-buggy`: charge ignores the idempotency guard, so a
re-issued charge double-charges — breaking `no_double_charge`. See the
*Composition plane* section below.

### AWS Dogwood spend-cap (`rot.spendcap`)

A **policy** target (not a protocol family): a single service approves spend
requests (`Transfer::request`) and settles them asynchronously, so *in-flight*
(approved-but-unsettled) requests must count against the spend cap before they
respond. `spendcap-correct` charges in-flight requests up front (sums over
`Transfer::request`); `spendcap-buggy` charges only settled responses (sums over
`Transfer::response`), so a parallel-fire burst of in-flight requests overshoots
the cap. The pinned invariant `spendcap_within_cap`
(`completed + inflight·AMOUNT <= CAP`) is **PROVEN** on `spendcap-correct` and
**VIOLATED** on `spendcap-buggy` (counterexample `completed=0, inflight=3`). The
one-word diff (`request` vs. `response`) is the entire seeded bug.

> **Defensible claim.** ROTN does **not** claim to compile arbitrary policy
> text into an equivalent model. It **lowers the spend-cap policy class**
> (aggregate-over-events + cap) to a bounded transition system by a
> **mechanical derivation** from the parsed policy — parameterized on
> amount/cap/pool — and verifies it with **multiple independent engines**
> (Z3 SMT + TLC) **and a second, structurally different model family**
> (direct policy SMT). The three engines span two axes of independence:
> *engine* independence (SMT/Z3 and TLC are independent model checkers over
> the same IR state-machine) and *model* independence (the policy-direct
> engine checks a different model family — a direct Z3 encoding of the policy
> obligation over a bounded event sequence, not the transition system). The
> correspondence between the model and the policy is **checked**, not argued
> (`tests/test_correspondence.py`). The policy→model derivation and the
> assumptions it bakes in (uniform `AMOUNT=100`, `CAP=200`, bounded pool `K`)
> are shown explicitly by the demo's `POLICY → MODEL ABSTRACTION` block
> (`python -m rot.spendcap_display <policy.dw>`).
>
> **What we do NOT claim.** No arbitrary-policy compilation. The lowering
> (`rot/lower.py::lower_policy`) reads the parsed structure (the `Sum` node,
> the event reference's `.kind`, the `<= cap` comparison, the `input.amount`
> binding) and constructs the IR — it does not interpret arbitrary Dogwood
> text. Policies outside the spend-cap class are not supported.

Both Dogwood policies (`.dw`), the exact IR model ROTN checks, the
counterexample trace, and the Dogwood-atom → IR-action mapping table live in the
fixture README: `tests/fixtures/aws_dogwood/spendcap/README.md`.

Run the three-phase spend-cap demo end-to-end (PROVEN → VIOLATED →
three-facet audit + deterministic manifest); the scripts are exit-code aware:

```powershell
.\demo.ps1            # PowerShell (Windows)
```

```bash
bash demo.sh          # bash (Linux/macOS)
```

See `docs/spendcap-demo.md` (the demo walkthrough) and
`docs/spendcap-usage.md` (CLI usage reference for the `.dw` policy path).

### Phase 5: SAFE / UNSAFE classification (`--classify`)

The two endpoints above are *instances* of one structural question: **does the
spend-cap sum over `request` (issued) rows — SAFE — or over `response` (settled)
rows — UNSAFE?** Phase 5 turns that into a *classifier*: given any spend-cap
policy, report `SAFE` or `UNSAFE` (with a concrete counterexample witness for
UNSAFE), using the same sound core (`build_ir` + `ModelFinder.forall_reachable`)
— no per-policy tuning.

```bash
# Classify one policy (SAFE -> exit 0, UNSAFE -> exit 1)
python pipeline.py --classify --policy tests/fixtures/aws_dogwood/spendcap/policies/spendcap-buggy.dw

# Classify a batch (exit 0 iff all SAFE; exit 1 if any UNSAFE)
python pipeline.py --classify \
    --policies tests/fixtures/aws_dogwood/spendcap/policies/spendcap-correct.dw \
    --policies tests/fixtures/aws_dogwood/spendcap/policies/spendcap-buggy.dw \
    --out _cls
```

The report (`classify_report.json`) carries, per policy: `verdict`
(`SAFE`/`UNSAFE`/`UNKNOWN`), `witness` (the counterexample state for UNSAFE),
`event_kind` (the event the sum quantifies over), and `property`; plus a
`summary` (`safe`/`unsafe`/`unknown`/`error`). Exit codes: `0` all-SAFE,
`1` any-UNSAFE, `2` any-UNKNOWN, `3` error.

**Generalization.** The classifier is pinned on five first-class policies in
`tests/fixtures/aws_dogwood/spendcap/policies/` — the two endpoints *plus* three
promoted from the AWS Dogwood corpus (filters, thresholds, forbid/permit shapes)
that ROTN had never seen before:

| policy | shape | event kind | verdict |
|--------|-------|:----------:|:-------:|
| `spendcap-correct.dw` | request-sum (endpoint) | `request` | **SAFE** |
| `spendcap-buggy.dw` | response-sum (endpoint) | `response` | **UNSAFE** |
| `spendcap-resolved-filter.dw` | response-sum + `a > 0` filter (corpus 0299) | `response` | **UNSAFE** |
| `spendcap-resolved-range-filter.dw` | response-sum + range filter (corpus 0301) | `response` | **UNSAFE** |
| `spendcap-inflight-filter.dw` | request-sum + `a > 0` filter (mirror of 0299) | `request` | **SAFE** |

The verdict is driven solely by the event kind the sum quantifies over: every
`response`-sum policy is UNSAFE (witness `completed=0, inflight=3`) and every
`request`-sum policy is SAFE — regardless of filter, threshold, or forbid/permit
shape. That is the point: the same sound core classifies unseen corpus policies
with no per-policy tuning. Tests: `tests/test_classify.py`.

### Invariants (pinnable one at a time)

Every invariant carries an **assurance ladder** (`label` × `rung` × `pinned`) that the MR gate maps to a `PASS`/`BLOCK` verdict (see *Merge-request gate*). `pinned=True` invariants are the regression discriminators — the ones whose violation is a *new* bug introduced by a candidate change.

| invariant | family | label / rung | pinned | statement |
|-----------|--------|--------------|--------|-----------|
| `agreement` | 2PC | `core` / `atomicity` | **yes** | two decided participants apply the same decision |
| `validity` | 2PC | `auxiliary` / `correctness` | no | commit only if all voted `yes` |
| `no_spurious_abort` | 2PC | `auxiliary` / `correctness` | no | unanimous `yes` ⇒ coordinator does not abort |
| `zab_no_premature_apply` | ZAB | `core` / `atomicity` | **yes** | a follower applies only after the leader commits |
| `zab_apply_persisted` | ZAB | `auxiliary` / `correctness` | no | a follower applies only what it has persisted |
| `pbft_quorum` | PBFT | `core` / `consistency` | **yes** | commit only on a quorum certificate |
| `pbft_prepare_before_commit` | PBFT | `auxiliary` / `correctness` | no | a node commits a sequence only after preparing it |
| `no_double_charge` | Payment | `core` / `idempotency` | **yes** | charge applied at most once per order |
| `charge_requires_order` | Payment | `auxiliary` / `correctness` | no | the service never charges an order that was not placed |
| `settle_requires_charge` | Payment | `auxiliary` / `correctness` | no | the service never settles an order that was not charged |
| `policy_conformance` | AgentStep | `core` / `safety` | **yes** | the agent never takes a policy-denied action |
| `bounded_eventually` | AgentStep | `core` / `liveness` | **yes** | the agent reaches its goal within a bounded horizon B |
| `spendcap_within_cap` | SpendCap | `core` / `safety` | **yes** | settled + in-flight amount never exceeds the cap |

The `*-correct` targets prove the pinned invariant; the `*-buggy` target violates exactly the pinned one while the auxiliaries still hold — which is what lets the gate distinguish a *regression* from a vacuous invariant.

---

</details>

<details>
<summary><strong>Composition plane (Phase 2)</strong></summary>


`rot.composition` merges independently modelled service IRs into a single
concurrent `ProtocolIR`, so **cross-service** invariants can be checked
end-to-end:

    rot.composition.compose(service_irs, sync_actions) -> ProtocolIR
    rot.composition.validate(ir)              # raises CompositionError on a bad merge
    rot.composition.witness_path(ir, state)   # bounded, replayable path to the state

A service IR may reference another service's variables (e.g. `client.ordered`);
`validate` enforces that the *composed* IR is self-contained (every referenced
variable is defined) and that each sync action names a defined variable.

</details>

<details>
<summary><strong>Merge-request gate (Phase 3)</strong></summary>


`rot.mr_gate` maps invariant verdicts to a `PASS`/`BLOCK` merge decision, comparing a
**candidate** change against a **baseline**:

    rot.mr_gate.evaluate_mr(candidate_name, baseline_name,
                            invariants=None, max_states=6000) -> MRVerdict

Each invariant is checked against both IRs: violated only in the candidate is a
**regression**; held in both is *non-vacuous*. The gate BLOCKs if any invariant
regresses, else PASSes, and attaches the first regression's bounded witness path for
the reviewer. `evaluate_mr('payment-correct', 'payment-buggy')` returns **BLOCK**
with the `no_double_charge` witness.

---

</details>

<details>
<summary><strong>Agent Mode (policy-driven verification)</strong></summary>


ROTN can also verify the *action choice of an autonomous agent* against the
**policy** it must obey. Instead of a protocol target, pass a policy file - a
**Cedar** policy (`.cedar`) or a **Dogwood** policy (`.json`) - and the pipeline
builds the `AgentStep` model (`rot.agent_step`) on the narrow waist, then checks
the pinned property with the same bounded engines and the same soundness core:

| `property_kind` | pinned property            | checker                | question asked                                 |
|-----------------|----------------------------|------------------------|------------------------------------------------|
| `safety`        | `policy_conformance`       | `forall_reachable`     | does the agent *never* take a denied action?   |
| `realizability` | `policy_permits_request`   | `exists_reachable`     | does the policy permit *at least one* request? |
| `liveness`      | `bounded_eventually`       | `reach_within` (B)     | does the agent *act within* B steps?           |

`bounded_eventually` is **bounded liveness, not unbounded**: the goal
(`decision != idle`) must be reachable *within* the declared horizon
(`--liveness-horizon`, default 12) - always report the horizon, never
"the agent eventually acts".

```bash
# 1. Cedar policy -- non-vacuity (realizability): PROVEN
python pipeline.py --policy samples/agent.cedar --engine symbolic

# 2. Dogwood policy -- conformance (safety): PROVEN
python pipeline.py --policy samples/policy.json --tools samples/tools.json \
    --engine symbolic

# 3. Dogwood policy -- bounded liveness within horizon B=3: PROVEN
python pipeline.py --policy samples/policy.json --tools samples/tools.json \
    --kind liveness --engine symbolic --liveness-horizon 3

# 4/5. Registry targets: conforming agent PROVEN, compromised agent VIOLATED
python pipeline.py agent-step --property policy_conformance --engine symbolic
python pipeline.py agent-step-buggy --property policy_conformance --engine symbolic
```

Full reference, CLI flags, expected results and threat model:
[`docs/agent-mode.md`](docs/agent-mode.md); CI matrix (bash, exit 0 on
success): `bash scripts/run_agent_mode.sh`.

---

</details>

<details>
<summary><strong>Novelty: temporal proof, not point-in-time checks</strong></summary>


The spend-cap result above exposes a class of bug that point-in-time
authorization tooling cannot see. The framing is precise, not a claim about
AWS's tooling: it is an **absence of a soundness-of-intent guarantee**.

- **Cedar's Automated Reasoning** checks - the finding vocabulary AgentCore
  applies to agent tool policies (contradictions, unreachable rules, Overly
  Permissive / Overly Restrictive, Ineffective) - are *point-in-time* static
  analyses over one request.
- **Dogwood's** formal spec (guide §7) adds *operational* meta-properties:
  fail-closed evaluation, lowering totality, validation soundness,
  determinism of identity, statefulness confined to the temporal engine, and
  acceptance-implies-monitorability. Clause 5 is the boundary: the policy
  engine is invoked *per-request over an empty entity set* - an in-flight
  request that has not settled is not in the monitor's world.
- **ROTN** answers the question neither asks: *can this policy, under
  concurrency, ever reach a state that violates it?* - by lowering the policy
  into a bounded model and checking **all** reachable states, and by honestly
  reporting `OUT_OF_SCOPE` when it cannot.

| Dimension | **Cedar AR** (point-in-time checks) | **Dogwood** (operational guarantees) | **ROTN** (temporal proof) |
|---|---|---|---|
| Question answered | "Is this policy well-formed / effective?" | "Is this request admissible against the settled history?" | "Can this policy ever reach a violating state under concurrency?" |
| Concurrency / in-flight | not modeled | not in the settled history (per-request engine) | first-class state; interleavings explored |
| Parallel-fire budget bug | invisible | invisible (each request admissible in isolation) | **VIOLATED + witness** (`inflight = 3`), K >= 2 |
| Honesty | reports findings | fail-closed | PROVEN / VIOLATED / **OUT_OF_SCOPE** - never silent |

Full analysis (K-sweep, corpus coverage matrix, honest limits, and what ROTN
does not claim): [`docs/novelty.md`](docs/novelty.md). The corpus coverage
evaluation (per-policy verdicts, aggregate metrics, the honest 11-vs-59 note,
and the gaps): [`docs/corpus-eval.md`](docs/corpus-eval.md).

---

</details>

<details>
<summary><strong>Engines</strong></summary>


The invariant check is discharged by one of three **independent** engines, all
behind the same `EngineResult` interface (`rot.symbolic.EngineResult`):

### 1. `symbolic` — pure-Python SAT engine (`rot.symbolic` + `rot.sat`)

- Fully offline, deterministic, no JVM required.
- Encodes the linearized transition system + invariant and discharges it with
  a bounded SAT loop (`rot.sat` DPLL + clause learning).
- This is the engine the test suite uses, so tests never depend on Java.

### 2. `tlc` — the real TLC model checker (`rot/tlc.py`)

- The gold standard. Shells out to `java -cp tla2tools.jar tlc2.TLC` against
  the TLA+ artifacts emitted by `rot/emitter.py`.
- Runs in a private working directory, enforces a **wall-clock timeout**
  (`Config.tlc_timeout`), and classifies the run as
  `HOLDS` / `VIOLATED` / `TIMEOUT` / `ERROR`.
- On `VIOLATED` it locates and parses the TLC `.model` counterexample and maps
  it back to IR state names, so the CEGAR recheck can validate it against the
  IR semantics.

### 3. `apalache` — Apalache ITF counterexample evaluation (`rot/itf.py`)

- Not an external process: it takes an Apalache **ITF counterexample** (a
  `.itf.json` trace) via `--itf <trace.json>` and replays it through the same
  IR/invariant core, reporting a definite refutation as a `violated` verdict.
- It is **one-directional**: a single concrete path can refute a safety
  invariant but cannot prove it, so the engine never reports `proven`.
- This is the Apalache/ITF path — the *Quint-emitter* work item from the plan
  was superseded by this concrete-trace engine (no Quint emitter exists).

### Engine selection (`Config.select_engine()`)

- `auto`      → `tlc` if a usable `java` + `tla2tools.jar` pair is present,
                 else `symbolic`. This keeps the pipeline runnable in a bare
                 Python env.
- `tlc`       → force TLC (errors out if no jar).
- `symbolic`  → force the offline engine.
- `apalache`  → force the ITF-trace engine (requires `--itf <trace.json>`;
                 refutes, never proves).

### Configuring the TLC jar

Resolution order in `Config.tlc_jar_path()`:

1. explicit `--tlc-jar <path>` / `Config(tlc_jar=...)`
2. `$TLA2TOOLS_JAR`
3. `$TLC_JAR`
4. a well-known local Toolbox install
   (`~\Downloads\TLAToolbox-1.7.1-win32.win32.x86_64\toolbox\tla2tools.jar`)

```bash
# point at a specific jar
python pipeline.py correct --property agreement --engine tlc \
    --tlc-jar "C:\path\to\tla2tools.jar"

# or via environment
$env:TLA2TOOLS_JAR = "C:\path\to\tla2tools.jar"
```

---

</details>

<details>
<summary><strong>CEGAR (`rot/cegar.py`)</strong></summary>


Counterexample-guided handling of the engine outcome. It maps an
`EngineResult` to a `Verdict` and, when the result is **unknown**, makes a
**bounded** number of recheck/refinement attempts (capped by
`Config.cegar_max_iter`) before giving up soundly.

| engine result            | verdict      | notes                                            |
|--------------------------|--------------|--------------------------------------------------|
| `proven`                 | `proven`     | invariant holds                                   |
| `violated` + feasible witness | `violated` | concrete counterexample returned                  |
| `violated` + infeasible witness | `unsound` | spurious over-approximation artefact (sound: not a real bug) |
| `unknown` / `timeout`    | `unknown`    | after ≤ `cegar_max_iter` bounded rechecks         |
| `error`                  | `error`      | engine/config/IO failure                          |

The **recheck** hook (plumbing for future counterexample-guided abstraction
refinement) takes `(model, property, max_states)` and returns a new
`EngineResult`; `rot/cegar.py` loops on it only while the result stays
`unknown` and the iteration budget has not been exhausted. This guarantees the
loop **terminates** (`cegar_max_iter` is the hard cap).

---

</details>

<details>
<summary><strong>Auditable report</strong></summary>


`VerdictReport.write(out_dir, base_name)` writes two files per run:

- `<target>_<property>.json` — machine-readable: config, engine, verdict,
  counterexample, the abstraction manifest (what was kept/dropped and why),
  and the CEGAR iteration count.
- `<target>_<property>.md`   — human-readable summary.

The **abstraction manifest** is the audit trail for soundness: it records
exactly which state variables/actions were kept for the pinned property (the
property-directed closure) and which were dropped, so a reviewer can confirm
the abstraction is *property-relevant* (no spurious behaviour introduced).

---

</details>

<details>
<summary><strong>Environment fragments, refinement & LLM baseline</strong></summary>


Three optional extensions of the same core, all wired into the CLI:

### Environment fragments (`rot.env`, `--env <bound>`)

`rot.env` adds a bounded **message-delay / environment** fragment to the transition system — a bound `K` on the number of in-flight messages — so message-loss and delay scenarios can be checked. Pass `--env <K>` to fold an environment fragment into the run (default `K = 2`):

```bash
python pipeline.py correct --property agreement --engine symbolic --env 2
```

### Refinement loop (`rot.refine`, `--before` / `--after`)

`rot.refine` verifies a **rewritten** protocol against its original: it loads a before and an after model (target names or JSON IR files), runs a bounded propose/check/repair loop (up to `--rounds`), and reports whether the rewrite is behaviour-preserving. `pipeline.py` delegates directly to `rot.refine`'s standalone CLI:

```bash
python pipeline.py --before correct --after buggy --invariant agreement
python -m rot.refine correct buggy --invariant agreement   # standalone
```

### LLM baseline (`rot.llm_baseline`, `--llm-baseline`)

An **opt-in, explicitly non-sound** LLM baseline: it feeds the exact TLA+ the engine sees to an LLM for a human-readable second opinion and writes an audit artifact (`<out>/<target>_<prop>_llmbaseline.json`). It **never** affects the verdict or the exit code — it is informational only and degrades to `unavailable` when no endpoint is reachable.

```bash
python pipeline.py correct --property agreement --engine symbolic \
    --llm-baseline --llm-model gpt-4o-mini
```

---

</details>

<details>
<summary><strong>Project layout</strong></summary>


```
rot/
  ir.py             # protocol IR: StateVar / Action / Expr (And/Or/Not/If/eq/neq)
  twopc.py          # the 2PC target as a trusted IR (correct / buggy)
  zab.py            # the ZAB target as a trusted IR (correct / buggy)
  pbft.py           # the PBFT target as a trusted IR (correct / buggy)
  payment.py        # the payment service + client as service IRs (correct / buggy)
  invariants.py     # named invariants across 2PC / ZAB / PBFT / Payment / AgentStep
  agent_step.py     # AgentStep model: agent action choice vs policy (conformant / compromised)
  targets.py        # target registry -> ProtocolIR + pinnable properties
  abstraction.py    # property-directed abstraction (free-variable closure)
  linearization.py  # linearize the IR for the engines
  emitter.py        # deterministic TLA+ emitter (TLA+ spec + config)
  sat.py            # bounded SAT solver (DPLL + clause learning)
  symbolic.py       # pure-Python SAT-based model checker (offline)
  tlc.py            # TLC engine (java + tla2tools.jar), robust output parsing
  cegar.py          # bounded CEGAR: EngineResult -> Verdict (+ recheck hook)
  env.py            # bounded message-delay / environment fragments (--env)
  refine.py         # propose/check/repair refinement loop (--before / --after)
  itf.py            # Apalache ITF counterexample engine (--itf; refutes, never proves)
  llm_baseline.py   # opt-in NON-SOUND LLM baseline (audit artifact only)
  witness.py        # witness / counterexample utilities
  specdiff.py       # spec-diff (before/after behavioural comparison)
  tracecheck.py     # trace checking (concrete-trace refutation)
  impact.py         # bounded impact analysis over IR actions/vars
  incremental.py    # incremental / delta verification
  modelfind.py      # model-finding helpers
  zk_bugs.py        # ZK (zero-knowledge) bug scenarios
  falseblock.py     # false-positive BLOCK analysis for the MR gate
  order_service.py  # additional order-service target
  composition.py    # Phase 2: merge service IRs -> one concurrent ProtocolIR
  mr_gate.py        # Phase 3: PASS/BLOCK merge-request gate over invariants
  verdicts.py       # Verdict + VerdictReport (JSON + Markdown)
  config.py         # Config: engine selection, budgets, jar resolution
  frontends/        # source front-ends (narrow waist: build_ir(source_dir, ...) -> ProtocolIR)
    frontend.py       # narrow-waist frontend contract
    frontend_java.py  # Java source -> IR frontend
    frontend_spec.py  # spec-driven frontend
    java/           # Java source -> IR: enums + apply() mode, CPG-enriched provenance
    cpg_reader.py   # CPG artifact reader (invalid artifact -> warning, source-only)
    policy/         # Cedar / Dogwood policy frontends -> AgentStep IR (Agent Mode)
      cedar.py            # Cedar policy (.cedar) -> AgentStep IR (realizability)
      dogwood.py          # Dogwood policy (.json) -> AgentStep IR (safety)
      agent_step_liveness.py  # bounded-liveness twin (bounded_eventually)
pipeline.py         # CLI orchestration + exit codes (+ --source / --cpg modes)
run.ps1             # PowerShell wrapper (single / list / matrix)
samples/            # Cedar / Dogwood policy + tools samples (Agent Mode)
scripts/            # run_agent_mode.sh (CI matrix for Agent Mode)
docs/               # agent-mode.md, phase3-eval.md (Step 3.7),
                    # novelty.md (B.3), corpus-eval.md (B.2),
                    # compliance.md (Phase C, SOC 2 / AIUC control map)
tests/
  test_cegar.py             # CEGAR mapping + bounded refinement
  test_pipeline.py          # end-to-end (symbolic) + CLI exit codes
  test_twopc.py             # IR / invariant units
  test_zab.py               # ZAB IR / invariant units
  test_pbft.py              # PBFT IR / invariant units
  test_payment.py           # payment + client service IR units
  test_composition.py       # Phase 2 composition (cross-service merge + witness)
  test_mr_gate.py           # Phase 3 MR gate (PASS / BLOCK over invariants)
  test_java_model.py        # Java source -> IR == canonical 2PC IR (n x buggy matrix)
  test_source_pipeline.py   # --source end-to-end + CPG degradation contract
  test_env.py               # environment fragments (delay bound, determinism)
  test_itf.py               # Apalache ITF engine (refutes, never proves)
  test_refine.py            # refinement loop (propose/check/repair)
  test_llm_baseline.py      # LLM baseline (audit artifact, never affects verdict)
  test_witness.py           # witness utilities
  test_specdiff.py          # spec-diff
  test_tracecheck.py        # trace checking
  test_impact.py            # bounded impact analysis
  test_incremental.py       # incremental verification
  test_modelfind.py         # model-finding
  test_zk_bugs.py           # ZK bug scenarios
  test_falseblock.py        # false-positive BLOCK analysis
  test_frontend.java.py     # Java source frontend (narrow waist)
```

---

</details>

<details>
<summary><strong>Testing</strong></summary>


```bash
# full suite (pure stdlib, Python 3.6)
python -m unittest discover -s tests -v
```

The suite is deterministic and **does not require Java/TLC**: it exercises the
symbolic engine end-to-end for every protocol (`correct` proves its pinned
invariant, `buggy` violates it with a witness that genuinely refutes the
invariant), the CEGAR mapping for all four outcomes, the composition plane
(cross-service merge, bounded witness), the MR gate (`PASS` / `BLOCK`), the
environment fragments (`--env`), the refinement loop (`--before` / `--after`),
the Apalache ITF engine (concrete-trace refutation, never `proven`), the
LLM baseline (audit artifact only — never affects the verdict), the impact /
spec-diff / trace-check / model-finding / ZK-bug / false-block extensions, the
SAFE/UNSAFE spend-cap classifier (`tests/test_classify.py`), and the CLI
exit-code contract. **947 tests** currently pass. The TLC and
Apalache engines are exercised by the CLI / `run.ps1` matrix when the
respective tooling is available.

### Expected results (n = 3)

| target  | pinned invariant | correct | buggy |
|---------|------------------|---------|-------|
| 2PC     | `agreement`              | PROVEN | **VIOLATED** (witness) |
| ZAB     | `zab_no_premature_apply` | PROVEN | **VIOLATED** (witness) |
| PBFT    | `pbft_quorum`            | PROVEN | **VIOLATED** (witness) |
| Payment | `no_double_charge`       | PROVEN | **VIOLATED** (witness) |
| SpendCap | `spendcap_within_cap`    | PROVEN | **VIOLATED** (witness) |

The pinned invariant is the discriminator in each family; the auxiliary
invariants (e.g. `validity`, `charge_requires_order`, `settle_requires_charge`) hold for
both variants and exist to show the registry drives *different* property-directed
abstractions (different free-variable closures).
</details>
