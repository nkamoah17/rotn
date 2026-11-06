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
| **APW-6** | Window-boundary burst | absolute "daily" window (*if absolute windows ship*) | The counter hard-resets at the window edge, so K events just before + K just after the reset is a 2× burst. | [buggy](../samples/apw6-buggy.dw) · [correct](../samples/apw6-correct.dw) | `{"count":1,"total":4}` |

Every row rests on a **hand-written oracle, cross-checked against the
reference interpreter**: `python -m unittest discover -s tests -p
'test_apw*.py'` runs the buggy→VIOLATED (with the named witness) and
correct→PROVEN legs for all six.

## Reference-interpreter agreement (the credibility backbone)

The hand-written oracle is the *internal* leg. The *external* leg is the one
that matters for trust: the **bidirectional reference gate** (spec
[`docs/reference-gate.md`](reference-gate.md), WS4) — every shipped verdict is
replayed against Dogwood's own reference interpreter (`dogwood replay`) at the
pinned commit, and **both directions** must agree: violations must be real
(G1) and proofs must hold (G2). Disagreements block merges.

The gate runs the **gateable** classes (APW-1, APW-2, APW-4) and reports the
**non-lowering** classes (APW-3, APW-5, APW-6) as UNKNOWN. First-run
outcomes (spec §7):

| APW | class | model | outcome | note |
|-----|-------|-------|---------|------|
| **APW-1** | Settled-sum cap bypass | VIOLATED / PROVEN | **AGREE** | reference: 2 ALLOW / 2 DENY on the 4-fire burst |
| **APW-2** | Approval replay | VIOLATED / PROVEN | **DISAGREE-PROVEN** | concurrent replay: reference admits 3 where the model proves 1 — *measured*, not waived |
| **APW-4** | Distinct-count race | VIOLATED / PROVEN | **LABELED-DIVERGENCE** | waived (`gate/waivers.yaml`, `APW-4/G2/nkamoah17`) — a pass *with a warning*, never a silent PASS |
| **APW-3** | Taint race | n/a (no lowering) | **UNKNOWN** | egress is data-dependent; concept until it lowers |
| **APW-5** | Session splitting | n/a (no lowering) | **UNKNOWN** | per-session cap is a concept until it lowers |
| **APW-6** | Window-boundary burst | n/a (no lowering) | **UNKNOWN** | absolute windows don't ship yet |

**Gate: exit 1** — APW-2 is an honest DISAGREE-PROVEN (a concurrent-replay
divergence the team must fix or waive) and APW-4 is a documented, waived
divergence; APW-3/5/6 are UNKNOWN (never a pass). See
[`docs/reference-gate.md` §7](reference-gate.md) for the first-run
expectations, and the full per-probe detail in
[`docs/reference-replay.md`](reference-replay.md).

Two caveats are empirically verified and keep the claim honest. First, the
reference is Cedar-default-deny, so the "admits the violation" leg is shown on
the **permit** form (the gateway's authorize-action form); ROTN's shape
detection reads the policy's *intent* (permit/forbid) to disambiguate the
formerly-gated shape — a **permit** gated on a prior approval event is APW-2
(approval replay), a **forbid** on egress after a confidential read is APW-3
(taint race). Second, the reference window is **reflexive** (the current
event is included in its own temporal aggregate — spec §6: evaluation at
position i reads positions j <= i; the APW-1 correct policy decides the
4 × $100 burst as 2 ALLOW / 2 DENY).

**APW-4 is a relabeled class.** Under Dogwood's semantics the "correct"
policy enforces a **per-recipient** (partitioned) cap — each recipient is
charged ≤ 3 — not a *global* distinct-recipient cap. ROTN's model checks the
**global distinct** class, which is a real bug class. The reference therefore
admits a cross-recipient burst (4 ALLOW / 0 DENY) that the model's proof
forbids; that is a **documented semantic difference, not a model defect**, and
is waived in [`gate/waivers.yaml`](../gate/waivers.yaml) (owner + expiry; an
expired waiver fails the gate). The gate reports it as **LABELED-DIVERGENCE —
a pass with a warning**, never a silent PASS.

Reproduce (v2 bidirectional gate, the default for `--gate`):

    rot replay --oracle dogwood --gate --bidirectional \
        --profile dogwood-ref@4ec5e2c --out out/gate

This writes `out/gate/report.json` + `out/gate/report.md` (spec §6 schema).
The legacy one-sided gate is still available as `rot replay --oracle dogwood
--gate --onesided` (writes `out/reference-replay/reference-replay.md`) for
back-compat.



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
- **K-sweep:** the buggy policy is VIOLATED at every `K`, and the witness
  shape tracks the bound — `K=1` the sequential off-by-one
  (`{"completed": 200, "inflight": 1}`), `K≥2` the parallel-fire signature
  (`{"completed": 100, "inflight": 2}` at K=2;
  `{"completed": 0, "inflight": 3}` at K≥3). See the K-sweep table in
  [spendcap-demo.md](spendcap-demo.md).
- **Buggy / correct:** [apw1-buggy.dw](../samples/apw1-buggy.dw) ·
  [apw1-correct.dw](../samples/apw1-correct.dw)
- **Witness:** `{"completed": 0, "inflight": 3}` (the K≥3 parallel-fire
  signature — the default `K=4` run)

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

## APW-6 — Window-boundary burst (if absolute windows ship)

The policy says "at most K events **per day**". The bug is that the counter
**hard-resets** at the window boundary (an absolute window), so an attacker does
K events just before the boundary and K more just after — a **2× burst** past
the cap.

- **Why a monitor misses it:** each event sees the current-window counter under
  the cap (the reset just happened).
- **The fix:** a sliding window (no hard reset), so the total across windows
  stays bounded.
- **Status:** *if absolute windows ship* — Dogwood's roadmap lists
  absolute-time windows; this is the bug class before they do. The oracle
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

# The bidirectional reference gate (the credibility backbone, WS4): every
# verdict is replayed against Dogwood's reference interpreter, both directions
# (violations real, proofs hold). Writes out/gate/report.{json,md}:
rot replay --oracle dogwood --gate --bidirectional \
    --profile dogwood-ref@4ec5e2c --out out/gate
```

## What this is (and isn't)

- **Is:** a *named, public* set of bug classes with a reproducible buggy/correct
  pair — each backed by a hand-written oracle and cross-checked against the
  reference interpreter.
- **Isn't:** an exhaustive taxonomy. Six classes is a beachhead — the engine
  (parser + lowering + oracle) is what generalizes, and each new class is a new
  shape + oracle + pair, not a new engine.

