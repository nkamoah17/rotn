# ROTN verification report

- Target: `policy-spendcap-buggy.dw`
- Property: `spendcap_within_cap`
- Engine: `crosscheck`
- Resolved engine: `crosscheck`
- Invariant label: `bounded_depth` (pinned=True, blocking_permission=True)

## Abstraction (property-directed)

- Keep: completed, inflight
- Hide: 

# ROTN verdict: spendcap_within_cap

- Status: **VIOLATED**
- Engine: `crosscheck`
- States explored: 0
- CEGAR iterations: 0
- Note: cross-check: SMT (Z3), TLC, and policy-direct all found a counterexample
- Property kind: `safety`

## Counterexample

```
completed = 0
inflight = 3
```

## Counterexample trace

Step-by-step witness from the initial state, each step a `(state, action, guard, policy_clause, delta)` 5-tuple:

1. **spend_ok**
   - state: `completed=0, inflight=0`
   - guard: `completed + 100 <= 200 and inflight < 3`
   - policy_clause: ``
   - delta: `inflight=1`
2. **spend_ok**
   - state: `completed=0, inflight=1`
   - guard: `completed + 100 <= 200 and inflight < 3`
   - policy_clause: ``
   - delta: `inflight=2`
3. **spend_ok**
   - state: `completed=0, inflight=2`
   - guard: `completed + 100 <= 200 and inflight < 3`
   - policy_clause: ``
   - delta: `inflight=3`

## Recorded assumptions

- cross-check policy: PROVEN/VIOLATED require ALL THREE engines (SMT/Z3, TLC, policy-direct) to agree
- SMT (Z3) engine reported: violated
- TLC engine reported: violated
- policy-direct engine reported: violated

## Soundness notes

- no PROVEN/VIOLATED is issued on a single engine's answer alone
- disagreement or UNKNOWN/ERROR on any engine forces UNKNOWN
- model independence: policy_direct uses a different model family (direct policy vs IR state-machine)

## Engine evidence

```json
{
  "engine": "smtz3",
  "model": "concrete-state BFS (rot.modelfind)",
  "z3": "sat",
  "crosscheck": {
    "policy": "PROVEN/VIOLATED require ALL THREE engines to agree; disagreement or UNKNOWN -> UNKNOWN",
    "smt": {
      "engine": "smtz3",
      "model": "ir_state_machine",
      "status": "violated",
      "normalized": "violated",
      "note": "",
      "counterexample": {
        "completed": 0,
        "inflight": 3
      }
    },
    "tlc": {
      "engine": "tlc",
      "model": "ir_state_machine",
      "status": "violated",
      "normalized": "violated",
      "note": "TLC found a counterexample",
      "n_states": 5,
      "complete": true,
      "witness": {
        "completed": 0,
        "inflight": 3
      }
    },
    "policy_direct": {
      "engine": "policy_direct",
      "model": "direct_policy",
      "status": "violated",
      "normalized": "violated",
      "note": "policy_direct: counterexample found (steps=4)",
      "witness": {
        "completed": 0,
        "inflight": 3
      }
    },
    "apalache": null,
    "independence": {
      "engine": "SMT/Z3, TLC, Apalache are independent model checkers (different engines) over the IR state-machine model",
      "model": "policy_direct is a different model family (direct Z3 encoding of the policy obligation) checked by the same Z3 engine -- a soundness leak in one model family cannot hide a bug in the other"
    },
    "joined": "violated",
    "witness_match": true
  }
}
```
