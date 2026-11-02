# ROTN Attestation -- one-pager

> **Artifact hierarchy (stated once).** RTF v1 trace = source of truth (hash-pinned) -> one-pager = underwriter view (this artifact) -> site = demo view.

**Verdict:** VIOLATED (UNSAFE)

## Source of truth

- Trace schema: `caravel.rtf/v1`
- Manifest ID: `mf-4227160622359a2c`
- Trace hash (SHA-256): `75b3ba0790e33476ed18b934e5089f9b496875b83c7582bc86b2854258a1ee80`
- Version: `4227160622359a2c+0.1.0` (policy-hash + engine-version)

## Scope

- property: spendcap_within_cap
- kind: safety
- amount: 100
- cap: 200
- max_inflight: 4

## Coverage conditions (assumptions)

- AMOUNT = 100 (per-request spend)
- CAP = 200 (the spend cap)
- bounded pool: max_inflight = 4 (the reachable state space is bounded)
- K >= 2 (a burst of parallel fires exposes the bug; K = 1 masks it under settled-only accounting)
- reachable state space explored: n_states = 20

## Out of scope

- liveness (task completion) -- this is a SAFETY property; liveness is bounded only by the horizon
- other invariant kinds (approval ordering, information-flow) -- not in this trace
- state space beyond the reachable set explored (n_states = 20)

## Counterexample

```json
{
  "completed": 0,
  "inflight": 3,
  "steps": [
    {
      "action": "spend_ok",
      "state": {
        "completed": 0,
        "inflight": 1
      },
      "step": 0
    },
    {
      "action": "spend_ok",
      "state": {
        "completed": 0,
        "inflight": 2
      },
      "step": 1
    },
    {
      "action": "spend_ok",
      "state": {
        "completed": 0,
        "inflight": 3
      },
      "step": 2
    }
  ]
}
```

## Controls (SOC 2 / AIUC)

- SOC 2: `CC6.1` -- SOC 2 CC6.1 -- Logical access security
- AIUC: `AIUC-1` -- Caravel AIUC-1 -- Autonomy (agent must not act beyond policy)

## Bounded caveat

This is a BOUNDED proof: it holds over the reachable state space explored (n_states = 20). It is not an unbounded theorem -- a larger pool or a longer horizon would require a re-issue of this attestation.

## Re-verify (byte-for-byte)

```bash
rot trace --policy samples/spendcap-buggy.dw --out /tmp/rotn_reverify.json && rot report --verify-trace /tmp/rotn_reverify.json --expect 75b3ba0790e33476ed18b934e5089f9b496875b83c7582bc86b2854258a1ee80
```

Expected trace hash: `75b3ba0790e33476ed18b934e5089f9b496875b83c7582bc86b2854258a1ee80`

## Defensible claim / What we do NOT claim

**Defensible claim.** ROTN does NOT claim to compile arbitrary policy text into an equivalent model.  It lowers the spend-cap policy class (aggregate-over-events + cap) to a bounded transition system by a mechanical derivation from the parsed policy -- parameterized on amount / cap / pool -- and verifies it with independent engines.  The policy<->model correspondence is CHECKED, not argued (tests/test_correspondence.py).

**What we do NOT claim.** No arbitrary-policy compilation.  The lowering reads the parsed structure (the Sum node, the event reference's .kind, the '<= cap' comparison, the amount binding) and constructs the IR -- it does not interpret arbitrary policy text; policies outside the spend-cap class are not supported.  Every verdict is BOUNDED: it holds over the explored state space, not over all possible states.

---

**Attestation hash (SHA-256):** `61cb2938498e168242b5a8ff4b6aadf3f1b14cb98e438944454a72f8971a1a48`
**Stale:** no

