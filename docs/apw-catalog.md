# APW catalog — six ways agent policies fail under concurrency

An **Agent Policy Weakness (APW)** is a named bug class: a policy that reads
correctly on paper, that a **per-request monitor** (a guard checked on each
individual call) admits, and that is **wrong under concurrency** — a burst, a
replay, a race, or a boundary crossing that only a whole-protocol model
check catches.

ROTN is a regression-detection oracle. For each APW class it ships:

- a **buggy / correct `.dw` pair** (`samples/apwN-buggy.dw`, `samples/apwN-correct.dw`);
- a **lowering to `ProtocolIR`** (a shape in `rot/lower.py` + a hand-written
  oracle in `rot/shapes.py`);
- **oracle-based tests** (`tests/test_apwN.py`): the buggy oracle is
  `VIOLATED` with a named witness, the correct oracle is `PROVEN`;
- a **row in this catalog**.

The one-sentence claim each entry supports: *if your intent is "at most K",
this policy doesn't actually enforce "at most K" under concurrency.*

## The six classes

| APW | Weakness | Dogwood shape | Why a per-request monitor misses it | Buggy / correct | Witness |
|-----|----------|---------------|--------------------------------------|-----------------|---------|
| **APW-1** | Settled-sum cap bypass | `sum_within(…::response…) > cap` | Each in-flight fire sees settled = 0; a burst of in-flight requests commits past the cap. | [buggy](../samples/apw1-buggy.dw) · [correct](../samples/apw1-correct.dw) | `{"completed":0,"inflight":3}` |
| **APW-2** | Approval replay (approval never consumed) | `formerly within 1m get_cart::response{…}` gating `place_order` | A bare `formerly` fact is **sticky** — once one cart check occurs it stays true, so one approval admits N orders. | [buggy](../samples/apw2-buggy.dw) · [correct](../samples/apw2-correct.dw) | `{"approved":true,"orders":2}` |
| **APW-3** | Taint race ("no egress after a confidential read") | `formerly within 24h Read::response{private}` forbidding `Send` | The egress is admitted **while the taint is held** — the parallel read/send interleaving a per-request check never sees. | [buggy](../samples/apw3-buggy.dw) · [correct](../samples/apw3-correct.dw) | `{"holding_private":true,"exfiltrated":true}` |
| **APW-4** | Distinct-count race | `count_distinct_within(… recipients) > cap` | In-flight sends to *new* recipients aren't settled yet, so the distinct set grows past the cap before any settle. | [buggy](../samples/apw4-buggy.dw) · [correct](../samples/apw4-correct.dw) | `{"distinct":4,"counted":0}` |
| **APW-5** | Session splitting (cap scoped to a session) | per-session cap (*concept*) | The per-session counter resets on every event, so the guard is always satisfied and N sessions each admit K events — N× the per-session budget. | [buggy](../samples/apw5-buggy.dw) · [correct](../samples/apw5-correct.dw) | `{"session_count":4,"scope_count":1}` |
| **APW-6** | Window-boundary burst | absolute "daily" window (*roadmap*) | The counter hard-resets at the window edge, so K events just before + K just after the reset is a 2× burst. | [buggy](../samples/apw6-buggy.dw) · [correct](../samples/apw6-correct.dw) | `{"count":1,"total":4}` |

Every row is **oracle-verified**: `python -m unittest discover -s tests -p
'test_apw*.py'` runs the buggy→VIOLATED (with the named witness) and
correct→PROVEN legs for all six.

## Reference-interpreter agreement (the credibility backbone)

Oracle-verified is the *internal* leg. The *external* leg is the one that
matters for trust: **replaying every gate-class counterexample against
Dogwood's own reference interpreter** (`dogwood replay`) and recording the
reference verdict next to ROTN's, on the *same* trace -- the "Dogwood admits
it, ROTN catches it" side-by-side.

For each of the three **gate classes** (APW-1, APW-2, APW-4), the replay must
show **ROTN = VIOLATED** and the **reference = admitted** (the buggy policy
admits the violating requests). On this machine the gate passes:

| APW | class | ROTN | reference (buggy) | reference (correct) | gate |
|-----|-------|------|-------------------|---------------------|------|
| **APW-1** | Settled-sum cap bypass | VIOLATED | 4 ALLOW / 0 DENY | 2 ALLOW / 2 DENY | **AGREE** |
| **APW-2** | Approval replay | VIOLATED | 3 ALLOW / 1 DENY | 1 ALLOW / 3 DENY | **AGREE** |
| **APW-4** | Distinct-count race | VIOLATED | 4 ALLOW / 0 DENY | 4 ALLOW / 0 DENY | **AGREE** |

**Gate: PASS -- 3 of 3 gate classes agree.**

Two caveats are empirically verified in the report, and they keep the claim
honest. First, the reference is Cedar-default-deny, so the "admits the
violation" leg is shown on the **permit** form (the gateway's authorize-action
form); ROTN's shape detection reads the policy's *intent* (permit/forbid) to
disambiguate the formerly-gated shape — a **permit** gated on a prior
approval event is APW-2 (approval replay), a **forbid** on egress after a
confidential read is APW-3 (taint race). Second, the
reference window is *open and non-reflexive* (an event is decided before it is
appended to the trace), and APW-4's `count` is a **per-recipient** count in the
reference (a partition guarantee), so the reference does not deny the
cross-recipient burst there -- ROTN still catches the global distinct-recipient
class. APW-3 (taint race) and APW-5/6 (concept / forward-looking) are not gate
classes: APW-3's egress is data-dependent, and APW-5/6 do not yet lower to a
reference-interpretable shape.

Reproduce: `rot replay --oracle dogwood --gate` (writes
`out/reference-replay.md`).


---


## APW-1 — Settled-sum cap bypass

The canonical shape. The policy admits a spend when the **settled** total
(within the window) is under the cap. The one-word bug is the aggregate's event
kind: summing the **responses** (settled charges) instead of the **requests**
(in-flight + settled). A burst of three `$100` fires each passes the per-request
check (each sees settled = 0) but commits **`$300`** against the `$200` cap.

- **Why a monitor misses it:** the guard is evaluated per request, and each
  request sees the *settled* total (0) — the in-flight term is invisible.
- **The fix:** charge the in-flight term against the cap (sum the requests).
- **K-sweep:** the pool size is the whole story — `K=1` masks the bug
  (PROVEN), `K≥2` exposes it (VIOLATED). See the K-sweep table in
  [spendcap-demo.md](spendcap-demo.md).
- **Buggy / correct:** [apw1-buggy.dw](../samples/apw1-buggy.dw) ·
  [apw1-correct.dw](../samples/apw1-correct.dw)
- **Witness:** `{"completed": 0, "inflight": 3}`

## APW-2 — Approval replay (the commercially important one)

The policy gates `place_order` on a **bare temporal fact** — "a cart check
happened within the window" (`formerly within 1m get_cart`). A bare `formerly`
predicate is **sticky**: once one cart check occurs, the fact stays true for the
rest of the window, so the *same* approval admits N orders.

- **Why a monitor misses it:** each `place_order` sees "an approval is present"
  (true) — the approval was never *consumed*.
- **The fix:** a `since` clause that consumes the approval — an order is
  admitted only since the cart check **and** no order has already responded
  since that check. This is the exact Classmethod policy, pinned in
  [apw2-buggy.dw](../samples/apw2-buggy.dw) /
  [apw2-correct.dw](../samples/apw2-correct.dw).
- **Framing:** *"If your intent is one approval → one action, this policy
  doesn't enforce it."*
- **Witness:** `{"approved": true, "orders": 2}`

## APW-3 — Taint race

"Never contact an outsider after touching confidential data." The agent touches
confidential data (the taint), then sends to an outsider (the egress). The
rule is **data-dependent + temporal**. The one-word bug is the event *kind* of
the taint trigger: `response` (buggy) vs. `request` (correct).

- **Why a monitor misses it:** the egress is admitted *while the taint is
  held* — the parallel read/send interleaving. A per-request check on the send
  alone sees no rule violation (the read is a different request).
- **The fix:** taint on the read's *request*, so the egress is admitted only
  when the agent is **not** holding private data.
- **Witness:** `{"holding_private": true, "exfiltrated": true}`



## APW-4 — Distinct-count race

The policy caps the number of **distinct** recipients an agent may message
within a window (anti-fan-out / anti-spam). The bug is which event feeds the
counter: counting only *settled* (responded) events lets a burst of in-flight
sends to many distinct recipients through before any settle.

- **Why a monitor misses it:** each in-flight send to a *new* recipient passes
  the per-request check (the distinct set of *settled* sends is still under the
  cap).
- **The fix:** count *all* (request + response) events, so in-flight distinct
  recipients are charged against the cap.
- **Witness:** `{"distinct": 4, "counted": 0}`

## APW-5 — Session splitting (forward-looking)

The policy says "at most K events **per session**". The bug is that the counter
the guard reads is *scoped* to the session and is reset on every event, so the
guard is always satisfied and **N sessions each admit K events** — the total is
N× the per-session budget. The Classmethod tutorial itself notes temporal
limits are *per-session*; this shape makes the split explicit.

- **Why a monitor misses it:** each event sees the (reset) per-session counter
  under the cap.
- **The fix:** a lock-step counter that tracks the session's true event count.
- **Status:** *concept* — the oracle (`rot.shapes.build_scoped_cap_ir`) is
  hand-written; Dogwood has no per-session scoping operator yet, so the sample
  does not lower to a ROTN shape.
- **Witness:** `{"session_count": 4, "scope_count": 1}`

## APW-6 — Window-boundary burst (forward-looking)

The policy says "at most K events **per day**". The bug is that the counter
**hard-resets** at the window boundary (an absolute window), so an attacker does
K events just before the boundary and K more just after — a **2× burst** past
the cap.

- **Why a monitor misses it:** each event sees the current-window counter under
  the cap (the reset just happened).
- **The fix:** a sliding window (no hard reset), so the total across windows
  stays bounded.
- **Status:** *forward-looking* — Dogwood's roadmap lists absolute-time windows
  ("here's the bug class before AWS ships absolute windows"). The oracle
  (`rot.shapes.build_window_boundary_ir`) is hand-written; the shape does not
  yet lower from a `.dw` file.
- **Witness:** `{"count": 1, "total": 4}`

---

## Additional verified shapes

Beyond the six named classes, ROTN's lowering also covers two more shapes with
oracle-based tests (in [`tests/test_dw.py`](../tests/test_dw.py)):

- **Event-ordering** — a temporal *order* obligation (B must follow A); the
  buggy (A→B→A) vs. correct (A→B) orderings.
- **Count-window** — a cap on the number of events in a window (the
  "at most K per window" shape that APW-5/6 generalize with a scope or a
  boundary).

## Reproducing the catalog

```bash
# All six APW legs (buggy -> VIOLATED + witness, correct -> PROVEN):
python -m unittest discover -s tests -p 'test_apw*.py' -v

# The flagship APW-1 through the CLI (exit 1 / 0):
rot check --policy samples/apw1-buggy.dw   # VIOLATED, witness {"completed":0,"inflight":3}
rot check --policy samples/apw1-correct.dw # PROVEN

# The reference-interpreter agreement (the credibility backbone): replay each
# gate-class counterexample against Dogwood's reference interpreter and gate on
# "ROTN = VIOLATED, reference = admitted" (writes out/reference-replay.md):
rot replay --oracle dogwood --gate
```

## What this is (and isn't)

- **Is:** a *named, public* set of bug classes with a reproducible buggy/correct
  pair and an oracle-verified verdict for each.
- **Isn't:** an exhaustive taxonomy. Six classes is a beachhead — the engine
  (parser + lowering + oracle) is what generalizes, and each new class is a new
  shape + oracle + pair, not a new engine.

