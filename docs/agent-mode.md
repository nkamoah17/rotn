# ROTN — Agent Mode (policy-driven verification)

**Agent Mode** verifies the *action choice of an autonomous agent* against a
**policy** it must obey. Instead of checking a distributed protocol (2PC / ZAB /
PBFT / Payment), you hand ROTN a *policy file* — a **Cedar** policy (`.cedar`)
or a **Dogwood** policy (`.json`) — and it builds the `AgentStep` model
(`rot.agent_step`) on the narrow waist, then checks the pinned property with
the same bounded engines and the same soundness core.

Everything is pure stdlib, Python 3.6-compatible, offline and deterministic.
No Java and no TLC jar are required.

```
  policy file (.cedar / .json)
        |  rot.frontends.policy  (narrow waist: builds a ProtocolIR only)
        v
  AgentStep ProtocolIR  --  linearize  --  bounded engine (symbolic | modelfind)
        |
        v
  Verdict  (proven / violated / unknown)  +  auditable JSON report
```

The policy front-end's *only* job is to produce a `rot.ir.ProtocolIR` (the
narrow waist) with a pinned property and a `property_kind` in its metadata. It
never imports an engine. The pipeline then dispatches the property kind to the
right bounded checker:

| `property_kind` | pinned property            | checker                     | question asked                                |
|-----------------|----------------------------|-----------------------------|-----------------------------------------------|
| `safety`        | `policy_conformance`       | `forall_reachable`          | does the agent *never* take a denied action?  |
| `safety`        | `policy_denies_forbidden`  | `forall_reachable`          | is *every* forbidden Cedar request denied?    |
| `realizability` | `policy_permits_request`   | `exists_reachable`          | does the policy permit *at least one* request?|
| `liveness`      | `bounded_eventually`       | `reach_within` (horizon B)  | does the agent *act within* B steps?          |

---

## Quick start

All commands run from the repository root. The samples ship in `samples/`.

```bash
# 1. Cedar policy -- non-vacuity (realizability).
#    Asks: does the policy set permit at least one concrete request?
python pipeline.py --policy samples/agent.cedar --engine symbolic

# 2. Cedar policy -- safety (forbid-holds / no over-granting).
#    Asks: is every forbidden request denied (forbidden -> not decision)
#    across the whole bounded request space?
python pipeline.py --policy samples/agent.cedar --kind safety --engine symbolic

# 3. Dogwood policy -- conformance (safety).
#    Asks: does the conforming agent never take a denied action?
python pipeline.py --policy samples/policy.json --tools samples/tools.json \
    --engine symbolic

# 4. Dogwood policy -- bounded liveness.
#    Asks: does the agent commit to an action within the horizon (default 12)?
python pipeline.py --policy samples/policy.json --tools samples/tools.json \
    --kind liveness --engine symbolic --liveness-horizon 3

# 5. Registry target -- the *conforming* agent must be PROVEN.
python pipeline.py agent-step --property policy_conformance --engine symbolic

# 6. Registry target -- the *compromised* agent must be VIOLATED (+ witness).
python pipeline.py agent-step-buggy --property policy_conformance --engine symbolic
```

Run the whole matrix with the CI script (bash, exit code 0 on success):

```bash
bash scripts/run_agent_mode.sh
```

### CLI reference (`--policy` path)

| flag                 | default   | meaning                                                        |
|----------------------|-----------|----------------------------------------------------------------|
| `--policy FILE`      | —         | the policy file (`.cedar` -> Cedar, `.json` -> Dogwood)        |
| `--tools FILE`       | —         | Dogwood `tools.json` catalog (ignored for Cedar, provenance only) |
| `--kind {safety,realizability,liveness}` | auto | force the property kind (default: auto-route by extension; `safety` pins Cedar `policy_denies_forbidden`, `realizability` pins Cedar `policy_permits_request`) |
| `--n-steps N`        | `1`       | agent-step horizon bound (recorded in metadata)                |
| `--liveness-horizon B` | `12`    | bounded-liveness horizon B (only for `--kind liveness`)        |

### Exit codes (identical to the rest of the pipeline)

| code | meaning  | interpretation |
|:----:|----------|----------------|
| `0`  | `proven`   | the pinned property holds (within the bound) |
| `1`  | `violated` | a concrete counterexample / witness was found |
| `2`  | `unknown`  | the state / horizon budget was exhausted |
| `3`  | `error`    | engine / config / IO failure (e.g. bad policy file) |

---

## The three property kinds

### 1. Safety — `policy_conformance` (Dogwood, `--kind safety`)

The conforming agent chooses one action each step from the policy's universe
(`allowed` union `denied`). Because the agent is *conforming*, every **denied**
action is *policy-enforced*: the transition to it is guarded to be **never
enabled** (`ir.F()`). A denied action is therefore unreachable, and the property

```
policy_conformance   (decision not in policy.denied)
```

holds in every reachable state. The model finder answers it with
`forall_reachable`: `True` -> **proven** (exit 0); `False` -> **violated**
(exit 1).

### 2. Realizability — `policy_permits_request` (Cedar, `--kind realizability`)

A Cedar policy set that denies *every* request is useless. The sound,
engine-checkable question is whether the **permit set is realizable** over the
bounded request space. The front-end pins `decision == True` and the model
finder answers with `exists_reachable`: `SAT` -> **proven** (the witness is a
concrete permitted request, e.g. `read_log`); `UNSAT` -> **violated** (the
policy is vacuous).

### 3. Bounded liveness — `bounded_eventually` (`--kind liveness`)

The goal is `decision != idle` — *the agent commits to a concrete action*
(it is not stuck). It is checked with the existing bounded-liveness machinery
(`SymbolicEngine.reach_within` + `cegar_liveness`), **not** re-implemented in
the front-end. See the next section for exactly what this claims, and what it does not.

---

## Bounded liveness — what it means, and what it does not

> **ROTN does not prove unbounded (fair) liveness.** A `bounded_eventually`
> verdict is a *bounded* result: it says the goal is reachable **within the
> declared horizon B steps** (`--liveness-horizon`, default 12).

* **`proven` (exit 0)** means: *there exists a trace of length at most B in
  which the goal holds* — e.g. `goal reachable within horizon 3 at step 1`. It
  is a **reachability-within-a-bound** guarantee, not a statement about *all*
  schedules or about infinite execution.
* If the goal is **not** reached within B steps, the engine reports
  **`unknown`** (exit 2) once the budget is exhausted. A budget cap can hide a
  violation (or a slow goal) but can **never assert a false `proven`**.
* Raising B only enlarges the search; it does not change the *kind* of claim.
  ROTN has no `B = infinity` mode.

This is the same bounded-reasoning contract as the safety checks (see the
Technical Report, "State Space & Bounded Reasoning"): bounded, deterministic,
and honest about its horizon.

---

## Threat model

The `AgentStep` vertical slice models a **single decision step** of an agent
that must pick an action from the policy's universe. Two variants share the same
state, actions and invariants and differ only in how the policy is applied, so
any engine-result difference is attributable to the *agent's behaviour*, not to
a modelling difference (the same discriminator design as 2PC correct/buggy).

| variant  | agent posture                              | how the policy is applied                                   | `policy_conformance` |
|----------|--------------------------------------------|-------------------------------------------------------------|----------------------|
| `agent-step`      | **conforming** — obeys the policy   | each *denied* action's transition is never-enabled (`ir.F()`)  | **PROVEN** (exit 0)  |
| `agent-step-buggy`| **compromised / mis-configured**  | the *denied* action is left enabled (guard `decision == idle`)| **VIOLATED** (exit 1) + witness |

The buggy variant is the *adversary*: a compromised or mis-configured agent that
is free to attempt a denied action. The counterexample is exactly that choice —
for the shipped policy (`allowed = [read_log, update_balance]`,
`denied = [exfiltrate_secret]`) the witness is `{"decision": "exfiltrate_secret"}`.

**Scope note.** This is a *policy-enforcement* model: it asks whether the agent
can be driven into a state where it has chosen a denied action, and whether a
conforming agent provably cannot. It is **not** a model of the agent's internal
reasoning, its tool side-effects, or of multi-turn conversations. It reuses the
engine's existing existential-choice machinery, so no new engine is required.

---

## The two policy front-ends

Both front-ends live in `rot.frontends.policy` and obey the **narrow waist**:
they import only the stdlib, `rot.ir` and other `rot.frontends` modules — never
an engine (`rot.modelfind`, `rot.symbolic`, `rot.emitter`, `rot.tlc`).

| front-end | file       | module | property pinned | kind          |
|-----------|-----------|--------|-----------------|---------------|
| **Cedar**   | `*.cedar` | `rot.frontends.policy.cedar`   | `policy_permits_request` (default) / `policy_denies_forbidden` (`--kind safety`) | `realizability` / `safety` |
| **Dogwood** | `*.json`  | `rot.frontends.policy.dogwood` | `policy_conformance`     | `safety`        |
| **liveness twin** | `*.json` | `rot.frontends.policy.agent_step_liveness` | `bounded_eventually` | `liveness` |

The public entry point is `rot.frontends.policy.build_ir(policy_path,
tools_path=None, n_steps=1, kind=None)`:

* `kind=None` (default) — auto-routes by file extension (`.cedar` -> Cedar
  non-vacuity, `.json` -> Dogwood safety).
* `kind="liveness"` — orthogonal to the policy family: the *same* Dogwood
  policy can be checked for safety **or** for bounded liveness.
* `kind="safety"` — Dogwood conformance, **or** Cedar
  `policy_denies_forbidden` (every forbidden request is denied) for `.cedar`.
* `kind="realizability"` — Cedar `policy_permits_request` (at least one
  request is permitted).

Every returned IR carries `pinned_property`, `metadata["property_kind"]`,
`metadata["property_name"]`, and provenance (`policy_source` / `tools_source`).

### Cedar (`samples/agent.cedar`)

A declarative policy: `permit` / `forbid` rules over `(principal, action,
resource)`. Cedar is **default-deny**, and `forbid` overrides `permit`. The
sample permits `read_log` and `update_balance` and forbids `exfiltrate_secret`.
The front-end parses the policy into a `ProtocolIR` and pins one of two
*twin* properties (the pair that makes Cedar a real verifier):

* **non-vacuity** (default, `realizability`) — `policy_permits_request`: the
  policy must permit at least one concrete request (`exists` over the bounded
  request space).
* **safety** (`--kind safety`) — `policy_denies_forbidden`: every forbidden
  request is denied, i.e. `forbidden -> not decision` holds in *every*
  reachable state (`forall` over the whole bounded request space). This is the
  "forbid rules hold / permit rules don't over-grant" direction that a
  realizability-only query cannot express.

### Dogwood (`samples/policy.json` + `samples/tools.json`)

A JSON policy with disjoint `allowed` / `denied` action sets, optionally paired
with a `tools.json` catalog (descriptive provenance, cross-checked against the
policy — an action named by the policy but absent from the catalog is recorded
in the IR metadata for the report, but does not change the model). The
front-end builds the *conforming* `AgentStep` model and pins *policy
conformance*.

```json
{ "allowed": ["read_log", "update_balance"], "denied": ["exfiltrate_secret"] }
```

---

## Expected results (default budgets, symbolic engine)

| command (see Quick start) | property | verdict | exit |
|---------------------------|----------|---------|:----:|
| `--policy samples/agent.cedar` | `policy_permits_request` (realizability) | **PROVEN** — witness `read_log` | `0` |
| `--policy samples/agent.cedar --kind safety` | `policy_denies_forbidden` (safety) | **PROVEN** — no forbidden request permitted | `0` |
| `--policy samples/policy.json` | `policy_conformance` (safety) | **PROVEN** | `0` |
| `--policy samples/policy.json --kind liveness` | `bounded_eventually` | **PROVEN** — reached at step 1 | `0` |
| `agent-step --property policy_conformance` | `policy_conformance` | **PROVEN** (3 reachable states) | `0` |
| `agent-step-buggy --property policy_conformance` | `policy_conformance` | **VIOLATED** — witness `exfiltrate_secret` | `1` |
| `agent-step[-buggy] --property bounded_eventually` | `bounded_eventually` | **PROVEN** — within horizon | `0` |

The `agent-step` / `agent-step-buggy` pair is the *discriminator*: the correct
target proves `policy_conformance`, the buggy target violates it with a concrete
witness, while `bounded_eventually` holds for both. That is what lets a MR gate
distinguish a *regression* from a vacuous invariant.

---

## Files

| file | role |
|------|------|
| `rot/agent_step.py` | the `AgentStep` model (`build_ir(buggy=...)`, `policy_conformance_property`) |
| `rot/policy_verify.py` | the Cedar verification half: `policy_denies_forbidden` (safety) + `policy_permits_request` (non-vacuity) sweeps |
| `rot/frontends/policy/__init__.py` | `build_ir` entry point + `kind` routing (safety / realizability / liveness) |
| `rot/frontends/policy/cedar.py` | Cedar policy to IR, pins `policy_permits_request` (realizability) or `policy_denies_forbidden` (safety) |
| `rot/frontends/policy/dogwood.py` | Dogwood JSON to IR, pins `policy_conformance` |
| `rot/frontends/policy/agent_step_liveness.py` | bounded-liveness twin, pins `bounded_eventually` |
| `samples/agent.cedar`, `samples/policy.json`, `samples/tools.json` | shipped sample policies |
| `scripts/run_agent_mode.sh` | CI / quick-start matrix (bash) |
| `pipeline.py` (`_cmd_policy`) | `--policy` CLI surface, exit codes, JSON report |
