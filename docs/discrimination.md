# Discrimination: where a keyword scan gets the verdict wrong

The sharpest critique of a policy checker is: *"this is an elaborate grep."*
A keyword or pattern scan reads a policy one line at a time and applies a local
rule -- "the sum is over **responses** ⇒ in-flight is invisible ⇒ **UNSAFE**",
or "the action is **gated on an approval** ⇒ **SAFE**".  Each heuristic is
sometimes right.  The problem is that the true verdict depends on *context the
scan cannot see*: the concurrency bound the environment imposes, and whether a
capability is single-use.

These two fixtures pin the two directions of the scan's error.  In Case 2 the
scan and a model checker **disagree**, and the model checker is right.  In
Case 1 they **agree** -- but the scan stops at a bare flag, while the model
checker adds what the scan cannot: a **concrete witness**, a **sound proof**,
and the *K-dependence* of the failure.

---

## Case 1 — response-sum, bounded in-flight → **UNSAFE at every K**  *(scan says "buggy" — and is right)*

`tests/fixtures/discrimination/response-sum-bounded.dw` is a **response**-sum
spend-cap policy: the temporal sum quantifies over `Transfer::response` rows
(settled completions only).  A keyword scan fires on "response-sum" and calls
it **UNSAFE** -- and it is right: the decision event is a *request*, never a
*response*, so it is excluded from that sum by event kind, and the policy is
UNSAFE at **every** K.

ROTN agrees with the scan -- and adds what the scan cannot: a **concrete
witness** and a **sound proof**, with the witness *shape tracking K*, the
client-side request-pool bound the scan cannot read from the policy text:

| pool bound K | verdict | witness | why |
|:---:|:---:|:---|:---|
| **K = 1** | **UNSAFE** | `{ "completed": 200, "inflight": 1 }` | the **sequential off-by-one**: a fire admitted while `completed` already equals the cap settles past it. |
| **K = 3** | **UNSAFE** | `{ "completed": 0, "inflight": 3 }` | the **parallel-fire race**: three un-settled fires each pass the guard (`settled` still 0) and settle to `3 × 100 = 300 > 200`. |

The **witnesses** are the two faces of the same one-word bug:

```
{ "completed": 200, "inflight": 1 }   # K = 1: the sequential off-by-one
{ "completed": 0, "inflight": 3 }     # K = 3: 3 in-flight × 100 = 300 > 200 cap
```

The *same policy text* is UNSAFE at every bound the model can express -- and
the shape of the counterexample tells you *which* failure that bound
expresses.  A per-request scan cannot know K, and it stops at a flag.  ROTN
models K, witnesses the exact failure, and proves the rest of the state space.

---

## Case 2 — approval-gated, but replayable → **UNSAFE**  *(scan says "safe")*

The approval-replay shape (APW-2) gates an action on an approval: *"you may
place an order only after a cart check."*  A scan reads the gate and calls it
**SAFE** -- "the action is properly gated."

ROTN asks the question the scan cannot: *is the approval consumed on use?*

| approval | verdict | why |
|:---:|:---:|:---|
| **replayable** (not consumed) | **UNSAFE** | one cart-check re-arms forever; the same approval is replayed into an unbounded number of orders. |
| **single-use** (consumed) | **SAFE** | each approval authorizes exactly one order; the counter `orders <= 1` holds. |

The **witness** for the replayable variant is the replay itself:

```
{ "approved": true, "orders": 2 }     # approval still present, 2nd order placed
```

Both variants gate the order on the *same* approval predicate -- a scan cannot
tell them apart.  Only the **consumption** of the approval separates them, and
only a model checker checks it.

---

## Why this is not "an elaborate grep"

| | keyword scan | ROTN (model checker) |
|---|:---:|:---:|
| sees the **bound K** | ✗ | ✓ (models in-flight concurrency) |
| sees **consumption** | ✗ | ✓ (models the state transition) |
| Case 1 (response-sum, K=1) | **UNSAFE** (right — but a bare flag) | **UNSAFE** (right — with witness `{ "completed": 200, "inflight": 1 }` + proof) |
| Case 2 (approval, replayable) | **SAFE** (wrong) | **UNSAFE** (right) |

The scan is a *static* read of local structure.  ROTN lowers the policy to a
state machine, explores its reachable states, and returns a **witness** -- a
concrete counterexample trace -- for every UNSAFE it reports, and a
no-counterexample proof for every SAFE.  In Case 1 the scan is *right* but
blind: it cannot say *why* the policy fails, *which* failure K expresses, or
that nothing else does.  In Case 2 it is *wrong*.  The witnesses in both
cases are the proof that the model checker is not just a fancier pattern
match.

---

## Reproduce

```
python -m unittest tests.test_discrimination -v
```

Both cases run against the same sound core (`ModelFinder` over the lowered IR /
the hand-written oracle in `rot/shapes.py`), so the discrimination is not a
per-fixture tuning.
