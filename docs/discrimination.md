# Discrimination: where a keyword scan gets the verdict wrong

The sharpest critique of a policy checker is: *"this is an elaborate grep."*
A keyword or pattern scan reads a policy one line at a time and applies a local
rule -- "the sum is over **responses** ⇒ in-flight is invisible ⇒ **UNSAFE**",
or "the action is **gated on an approval** ⇒ **SAFE**".  Each heuristic is
sometimes right.  The problem is that the true verdict depends on *context the
scan cannot see*: the concurrency bound the environment imposes, and whether a
capability is single-use.

These two fixtures pin both directions of the error.  In each, a scan and a
model checker **disagree**, and the model checker is right.

---

## Case 1 — response-sum, bounded in-flight → **SAFE**  *(scan says "buggy")*

`tests/fixtures/discrimination/response-sum-bounded.dw` is a **response**-sum
spend-cap policy: the temporal sum quantifies over `Transfer::response` rows
(settled completions only).  A keyword scan fires on "response-sum" and calls
it **UNSAFE** -- and for an unbounded pool, it is.

ROTN's verdict turns on **K**, the client-side request-pool bound, which a
scan cannot read from the policy text:

| pool bound K | verdict | why |
|:---:|:---:|:---|
| **K = 1** | **SAFE** | a fire is admitted only while `inflight < 1`, i.e. when `settled + amount <= cap`; the single in-flight fire settles to `<= cap`. the parallel-fire race is structurally impossible. |
| **K = 3** | **UNSAFE** | three un-settled fires each pass the guard (`settled` still 0) and settle to `3 × 100 = 300 > 200`. |

The **witness** at K = 3 is the parallel-fire race itself:

```
{ "completed": 0, "inflight": 3 }     # 3 in-flight × 100 = 300 > 200 cap
```

The *same policy text* is SAFE or UNSAFE purely by the bound the environment
imposes on in-flight concurrency.  A per-request monitor cannot know K; it sees
"response-sum" and flags it.  ROTN models K and proves the bound makes it
safe.

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
| Case 1 (response-sum, K=1) | **UNSAFE** (wrong) | **SAFE** (right) |
| Case 2 (approval, replayable) | **SAFE** (wrong) | **UNSAFE** (right) |

The scan is a *static* read of local structure.  ROTN lowers the policy to a
state machine, explores its reachable states, and returns a **witness** -- a
concrete counterexample trace -- for every UNSAFE it reports, and a
no-counterexample proof for every SAFE.  The two cases above are the two
directions in which the static read is wrong, and the two witnesses are the
proof that the model checker is not just a fancier pattern match.

---

## Reproduce

```
python -m unittest tests.test_discrimination -v
```

Both cases run against the same sound core (`ModelFinder` over the lowered IR /
the hand-written oracle in `rot/shapes.py`), so the discrimination is not a
per-fixture tuning.
