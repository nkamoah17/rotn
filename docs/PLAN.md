# ROTN Phase 1 — the safety side (G1 + G4)

> Status: **Phase 1 (safety side) — DONE.** Implemented and verified by the test
> suite (`python -m pytest tests/`). `task_ends_or_escalates` is registered as
> **liveness** with discharge deferred to Phase 2.

This is the only safety-side work. **TypeInvariant is a state constraint, not a
property** — it constrains the state space and drops ill-formed states; it is not
a `VIOLATED` counterexample and is not a `PROPERTY` in the `.cfg`.

## What was implemented (Phase 1)

| Item | Where |
|---|---|
| `Invariant.kind` (`safety` / `liveness` / `constraint`) + `Invariant.violation_code` | `rot/invariants.py` |
| `type_invariant(model)` — well-formedness **state constraint** (domains, budget bounds, label membership, history shape); drops ill-formed states; not blocking | `rot/invariants.py` |
| `no_deadlock` — safety, `violation_code=DEADLOCK` | `rot/invariants.py` |
| `task_ends_or_escalates` — **liveness** (reachability; discharge deferred to Phase 2) | `rot/invariants.py` |
| `DEADLOCK` verdict code + exit code (stamped on the refuted `no_deadlock` witness; VIOLATED → exit 1) | `rot/verdicts.py`, `rot/cegar.py` |
| Emitter: state constraint baked into `Init`/`Next` + `INVARIANT` in `.cfg` (never `PROPERTY`); temporal property as `PROPERTY`; busy self-loop preserved | `rot/emitter.py` (`emit_spec` / `cfg_spec` / `write_spec`) |

### Tests added
- `tests/test_invariants.py` — `TypeInvariant` is a constraint (not a blocking
  claim), drops out-of-domain states, and covers all four well-formedness
  categories (domains, budget bounds, label membership, history shape);
  `no_deadlock` is safety with the `DEADLOCK` code; `task_ends_or_escalates` is
  liveness; the buggy orchestration is refuted with a circular-wait witness and
  the re-check layer stamps `DEADLOCK`; the correct model holds.
- `tests/test_emitter_spec.py` — `TypeInvariant` emitted as a constraint (not
  `PROPERTY`), baked into `Init`/`Next` (drops ill-formed states); `no_deadlock`
  emitted as `PROPERTY`; the busy self-loop is preserved; IntRange models extend
  `Integers`; `.tla`/`.cfg` round-trip.

## Plan (for reference)

- **`rot/invariants.py`** — `Invariant.kind` (`safety` / `liveness` /
  `constraint`); `type_invariant(ir)` as a **state constraint** (not a pinned
  MR-gate invariant, not blocking) covering domains, budget bounds, label
  membership, history shape; `no_deadlock` as safety; `task_ends_or_escalates`
  as liveness (reachability — discharge deferred to Phase 2).
- **`rot/verdicts.py`** + **`rot/cegar.py`** — wire the `DEADLOCK` verdict +
  exit code (stamped on the refuted `no_deadlock` witness; VIOLATED → exit 1).
- **`rot/emitter.py`** (the keystone) — the constraint-vs-property emission
  path: a state constraint is baked into `Init`/`Next` (so ill-formed states are
  *dropped*, not VIOLATED) and listed as `INVARIANT` in the `.cfg` — **never** a
  `PROPERTY`; a temporal property is listed as `PROPERTY`. Keep the busy
  self-loop so terminal ≠ deadlock.
- **`docs/PLAN.md`** — mark Phase 1 (safety side) as done.

### Phase 2 (liveness side) — pending
- `rot/liveness.py` — `task_ends_or_escalates` as `LIVENESS`
  (`reach_within(horizon)`): `done OR escalated` reachable within the bounded
  horizon; `escalate` is the escape hatch that makes it hold even in the
  deadlock-prone orchestration.
- **`rot/cegar.py`** — bounded re-check for the liveness bound (the
  `recheck` hook; bounded re-checking, not CEGAR refinement).
- **`rot/emitter.py`** — emit the liveness property as a `PROPERTY` alongside
  the safety properties; keep the busy self-loop.
- **`tests/`** — `task_ends_or_escalates` reachable in the correct model and in
  the buggy model via `escalate`; unreachable in the pure 2-agent deadlock
  (no `escalate`) → liveness VIOLATED.