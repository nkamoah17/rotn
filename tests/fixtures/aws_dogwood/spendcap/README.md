# spendcap — a spend-cap policy under a parallel-fire race

A single service approves spend requests (`Transfer::request`) and *later*
settles them (`Transfer::response`). The response is asynchronous, so several
approved-but-unsettled (**in-flight**) requests can coexist. The policy must
charge **in-flight** requests against the cap: the settled amount plus the
in-flight amount may never exceed it. This fixture ships a *correct* policy and
a *seeded-buggy* policy that differ by **one word** — `request` vs. `response`
in the temporal `sum` — and lets ROTN discriminate them with the same sound
core (the symbolic engine) behind the same narrow waist.

> **Why `spendcap`, not `dogwood*`.** "Dogwood" is also the name of this repo's
> JSON policy *frontend* (`rot/frontends/policy/dogwood.py`, the Agent Mode
> `.json` policies). To avoid that name collision, the new target, invariant,
> module and fixtures are all named **`spendcap`**; "Dogwood" in this file
> always means the AWS **Dogwood policy language** (`.dw`), which is the source
> of the two policies below.

---

## The bug (parallel-fire race)

The two policies share the same schema and the same `permit`; the only
difference is the event kind the `sum` quantifies over.

- **Buggy** sums over `Transfer::response` rows — *settled* completions only.
  In-flight (issued, not-yet-responded) transfers are **invisible** to the
  sum. A burst of parallel fires each sees the settled total as `0` and is
  admitted, so the in-flight amount grows past the cap.
- **Correct** sums over `Transfer::request` rows — *all issued* transfers,
  including in-flight ones. The temporal window is **closed and reflexive**, so
  the current request being decided is already in the sum; no
  `+ context.input.amount` term is needed (it would double-count).

This is the guide §5.4 "budget incl. this request" idiom, with the sum over the
*request* kind: admitted-but-unsettled requests count against the cap
*before* their responses settle.

### Counterexample trace (buggy, parallel-fire race)

Three identical `fire(amount=100)` requests arrive in parallel, before any
response has settled. With the buggy (response-sum) accounting the settled total
is `0` at every decision point, so all three are admitted and the committed
amount reaches `300 > 200`:

| #  | This request | Settled (response sum) | Buggy verdict | In-flight after |
|----|--------------|------------------------|---------------|-----------------|
| 1  | 100          | 0                      | **permit**    | 1               |
| 2  | 100          | 0                      | **permit**    | 2               |
| 3  | 100          | 0                      | **permit**    | 3 → **300 > 200** |

With the correct (request-sum) accounting the same burst is `100`, then `200`,
then `300` — so the third fire is **DENY**ed and the committed amount never
exceeds the cap.

The concrete counterexample the symbolic engine returns for `spendcap-buggy`
(the state where the pinned property first fails) is:

```
completed = 0
inflight  = 3          # 3 in-flight × 100 = 300 > CAP = 200
```

---

## The policies (Dogwood, `.dw`)

Both are self-contained, valid Dogwood policies over the `Drupe` namespace
(`alert_total_transfer_over_200` schema; `TransferInput` carries `amount: Long`,
`TransferOutput` is empty).

### `policies/spendcap-buggy.dw` — sums over `response` (the bug)

```dogwood
permit (
    principal,
    action == Drupe::Action::"Transfer",
    resource
)
when temporal {
    (sum a for (a: Long), (t: Timepoint). where (
        formerly within 24h (Drupe::Action::"Transfer"::response{ input.amount: a } && tp(t))
    )) <= 200
};
```

### `policies/spendcap-correct.dw` — sums over `request` (the fix)

```dogwood
permit (
    principal,
    action == Drupe::Action::"Transfer",
    resource
)
when temporal {
    (sum a for (a: Long), (t: Timepoint). where (
        formerly within 24h (Drupe::Action::"Transfer"::request{ input.amount: a } && tp(t))
    )) <= 200
};
```

> **Note on `formerly`.** The Dogwood `formerly` operator quantifies over *past*
> timepoints only, so a `response`-sum misses the in-flight set and a naive
> `+ context.input.amount` is the usual workaround. Here we instead switch the
> sum to the *request* kind (reflexive → already includes the current request),
> which is cleaner and avoids double-counting. See
> `examples/refund_budget_settled_plus_current/policy.dw` for the
> `response`-sum-plus-current idiom, and `examples/alert_total_transfer_over_200`
> for the `request`-sum idiom.

### Promoted corpus policies (Phase 5 generalization)

Three more policies in `policies/` are promoted from the AWS Dogwood corpus
(`tests/fixtures/aws_dogwood/corpus/`), where they were only *reference*
fixtures. They carry the same structural question as the two endpoints above —
does the sum quantify over `request` (SAFE) or `response` (UNSAFE)? — but with
filters, thresholds, and forbid/permit shapes ROTN had never seen before. The
`--classify` subcommand (see the top-level README, "Phase 5") classifies all
five with no per-policy tuning:

| policy | corpus source | shape | event kind | verdict |
|--------|---------------|-------|:----------:|:-------:|
| `spendcap-resolved-filter.dw` | `0299` | `forbid` + `a > 0` filter, response-sum | `response` | **UNSAFE** |
| `spendcap-resolved-range-filter.dw` | `0301` | `forbid` + range filter, response-sum | `response` | **UNSAFE** |
| `spendcap-inflight-filter.dw` | mirror of `0299` | `permit` + `a > 0` filter, request-sum | `request` | **SAFE** |

The three UNSAFE policies all return the same witness
(`completed=0, inflight=3`); the two SAFE policies carry none. The verdict is
driven solely by the event kind, not by the filter or threshold. Tests:
`tests/test_classify.py`.

---

## The IR model ROTN actually checks (`rot.spendcap` + `rot.lower`)

ROTN verifies a *property-directed IR* **derived from the parsed policy** —
not the `.dw` text directly, and not a hand-selected model. The production
lowering path is `rot/lower.py::lower_policy`, which reads the parsed
structure (the `Sum` node, the event reference's `.kind`, the `<= cap`
comparison, the `input.amount` binding) and *constructs* the
`ProtocolIR`: the `StateVar`s, the `spend_ok` / `respond` actions (the guard
is built from the event kind — which term to charge), and the pinned property.

The event kind drives the decision rule:

- `response` → settled-only accounting (the "buggy" side):
  `completed + amount <= cap`;
- `request` → in-flight accounting (the "correct" side):
  `completed + inflight * amount + amount <= cap`.

`rot.spendcap.build_ir(buggy=...)` is retained as a **test oracle** — the
expected output the lowering must reproduce — not the production path. The two
are asserted equal in `tests/test_dw.py`
(`test_to_ir_matches_spendcap_build_ir`), which turns "the model is derived
from the policy" from an argument into a checked fact.

The model is parameterized on `amount`, `cap`, and `max_inflight` (all
overridable via CLI flags); the canonical defaults are `AMOUNT=100`,
`CAP=200`, `MAX_INFLIGHT=4`. The `max_inflight` bound (`K`) is a shared
client-side request-pool limit (a resource limit, not the policy), present in
**both** variants. The two variants share state, actions, and the pinned
property; they differ only in the `spend_ok` decision rule.

State (all owned by `"service"`):

| variable    | meaning                                       |
|-------------|-----------------------------------------------|
| `completed` | settled amount (sum of responded requests)    |
| `inflight`  | approved-but-unsettled (in-flight) request count |

Actions:

| action       | guard (buggy → correct differ)                                | effect                                            |
|--------------|---------------------------------------------------------------|---------------------------------------------------|
| `init`       | `true` (initial)                                              | `completed := 0`, `inflight := 0`                 |
| `spend_ok`   | **buggy:** `completed + AMOUNT ≤ CAP ∧ inflight < K`<br>**correct:** `completed + inflight·AMOUNT + AMOUNT ≤ CAP ∧ inflight < K` | `inflight := inflight + 1` |
| `spend_deny` | `¬(decision)` — the other branch of the same decision         | *(no-op)* — no assignment; no transition generated |
| `respond`    | `inflight ≥ 1`                                                | `inflight := inflight − 1`, `completed := completed + AMOUNT` |

Pinned safety property (registered in `rot.invariants` as
`spendcap_within_cap`):

```
completed + inflight * AMOUNT <= CAP          (in every reachable state)
```

---

## Proof results (symbolic engine, offline)

| target            | invariant          | result      | states explored |
|-------------------|--------------------|-------------|-----------------|
| `spendcap-correct`| `spendcap_within_cap` | **PROVEN**  | 6 (holds in all) |
| `spendcap-buggy`  | `spendcap_within_cap` | **VIOLATED** (`POLICY_DENIAL`) | 20 (counterexample `completed=0, inflight=3`) |

The pinned invariant is the discriminator: it holds for every reachable state of
the correct model and is refuted (with a concrete, IR-feasible witness) by the
buggy model. TLC / Apalache are not required — the offline symbolic engine
carries the soundness here.

Reproduce (from the repo root):

```bash
python pipeline.py spendcap-correct --property spendcap_within_cap --engine symbolic
python pipeline.py spendcap-buggy   --property spendcap_within_cap --engine symbolic

# test suite for this target (11 tests)
python -m unittest tests.test_spendcap -v
```

Reports land in `out/` (e.g.
`out/spendcap-buggy_spendcap_within_cap.{md,json}` and
`out/spendcap-correct_spendcap_within_cap.{md,json}`).

---

## Dogwood-atom → IR mapping

How the Dogwood policy atoms translate to the IR `rot/spendcap` model:

| Dogwood atom / construct                    | IR counterpart                | meaning / effect                                              |
|--------------------------------------------|-------------------------------|---------------------------------------------------------------|
| `Drupe::Action::"Transfer"::request`       | `spend_ok` (admit)            | an issued transfer: `inflight := inflight + 1`                |
| `Drupe::Action::"Transfer"::response`      | `respond` (settle)            | a settled transfer: `inflight − 1`, `completed += AMOUNT`     |
| the `permit` decision (allow / deny)        | `spend_ok` / `spend_deny`     | the decision plane (guard vs. its negation; the seeded diff)  |
| `sum … ::request` (issued, incl. in-flight) | `completed + inflight·AMOUNT` | the correct accounting (in-flight charged before settling)    |
| `sum … ::response` (settled only)           | `completed`                   | the buggy accounting (in-flight invisible)                    |
| `formerly within 24h (… && tp(t))`          | (temporal window)             | the bounded history the sum ranges over                       |
| `<= 200`                                    | `… <= CAP`                    | the cap predicate                                             |

---

## Files

- `apalache-buggy.itf.json` — a 4-state Apalache ITF counterexample trace
  (the parallel-fire burst) that refutes `spendcap_within_cap`; replayed
  by `rot.itf` as a third-party **witness** of the crosscheck report
  (see [`docs/spendcap-usage.md`](../../docs/spendcap-usage.md)).
- `policies/spendcap-buggy.dw` — the response-sum (buggy) policy.
- `policies/spendcap-correct.dw` — the request-sum (correct) policy.
- `policies/spendcap-resolved-filter.dw` — UNSAFE; response-sum + `a > 0` filter
  (promoted from corpus `0299`).
- `policies/spendcap-resolved-range-filter.dw` — UNSAFE; response-sum + range
  filter (promoted from corpus `0301`).
- `policies/spendcap-inflight-filter.dw` — SAFE; request-sum + `a > 0` filter
  (the SAFE mirror of `0299`).
- `examples/` — upstream Dogwood examples the two idioms are drawn from
  (`alert_total_transfer_over_200`, `refund_budget_settled_plus_current`,
  `cap_open_agent_prs_windowed`).
- `corpus/` — upstream `sum … resolved filter/range filter` test corpus.
- `guide/08-formal-specification.md` — the temporal-window semantics (§5.4).
- `PROVENANCE.md` / `PROVENANCE.json` — pinned commit + per-file blob SHAs.

Upstream provenance and the pinned commit are recorded in
[PROVENANCE.md](PROVENANCE.md).


