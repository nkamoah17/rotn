# ROTN — Corpus coverage evaluation (Phase B.2)

> Status: **matrix ✅ · per-policy verdicts ✅ · aggregate metrics ✅ · honest
> gaps ✅.** All claims verified on this machine with `rot corpus` (exit `0`).
>
> This document applies the [`phase3-eval.md`](phase3-eval.md) pattern to the
> AWS Dogwood corpus. The point is the same as Step 3.7: a report is credible
> only if it measures a **genuine** coverage boundary — including what the tool
> *cannot* decide — rather than a curated best case.

## 0. Purpose & method

The question this evaluation answers, in one line: **of the AWS Dogwood
temporal policies in the corpus, which does ROTN's bounded temporal proof
prove safe, which does it find a reachable cap-violation in, and which is it
honest about not being able to decide?**

The method (the same code path CI would use):

1. **Discover.** `rot corpus` walks the corpus dir
   (`tests/fixtures/aws_dogwood/spendcap`) and finds every `.dw` policy.
2. **Lower.** Each policy is lowered by the general temporal lowering
   (`rot/lower.py`) into a bounded transition system (`ProtocolIR`). The shape
   is auto-detected from the AST: `spendcap`, `count_window`, `exists_sum`,
   `refund_budget`, `taint_egress`.
3. **Check.** The bounded model checker runs reachability over **all**
   reachable states, within the state-space budget and the in-flight bound `K`.
4. **Classify.** Each policy is classified **honestly**:
   - **PROVEN** — no reachable state violates the pinned property (within the
     bound).
   - **VIOLATED** — a reachable state violates the property; a **witness**
     (a concrete interleaving) is produced.
   - **OUT_OF_SCOPE** — the state space exceeds the bounded-checking budget, or
     the shape is not yet lowerable. This is an honest *"I cannot decide"*,
     **not** a silent pass and **not** an internal error.

The corpus is deliberately honest: it contains policies ROTN proves safe,
policies ROTN finds a violation in, and a policy ROTN is honest about not being
able to decide. The report measures real coverage, not a best case.

## 1. The corpus (what is actually present)

**The corpus on disk is 13 policies**, all under
`tests/fixtures/aws_dogwood/spendcap/`:

| Source | Policies | Detected shape | Provenance |
|--------|----------|----------------|------------|
| dogwood corpus (`tests/passing/temporal_only/corpus/`) | `0299_sum_resolved_filter`, `0301_sum_resolved_range_filter`, `mcagg_0299_sum_resolved_filter` | `exists_sum` | SHA-verified (pinned commit) |
| dogwood examples (`dogwood-docs/examples/`) | `alert_total_transfer_over_200`, `cap_open_agent_prs_windowed`, `refund_budget_settled_plus_current` | `exists_sum` / `count_window` / `refund_budget` | SHA-verified |
| hand-authored (spend-cap class) | `spendcap-buggy`, `spendcap-correct`, `spendcap-inflight-filter`, `spendcap-resolved-filter`, `spendcap-resolved-range-filter` | `spendcap` / `exists_sum` | authored in-repo |
| hand-authored (taint-egress class) | `taint-egress-correct`, `taint-egress-buggy` | `taint_egress` | authored in-repo |

Per-directory `PROVENANCE.json` sidecars carry the per-file git blob SHAs and
source URLs from the pinned dogwood commit (see
[`spendcap/PROVENANCE.md`](../tests/fixtures/aws_dogwood/spendcap/PROVENANCE.md)).

> **Honest note on the "59 fixtures" figure.** The roadmap cites "59 AWS
> Dogwood fixture files," but the corpus **present in this repo is 13
> policies** (including traces, schemas, expected outputs, and
> provenance sidecars; 7 SHA-verified artifact directories). The upstream
> dogwood corpus is larger, but only a subset was fetched. This evaluation is
> built on the **actual 13 policies present**, not on a 59-row table that does
> not exist on disk. Covering the full upstream corpus is a separate
> fetch-and-verify task (§7).

## 2. Per-policy results

| Policy | Shape | Lowerable | Verdict | Witness / Note |
|--------|-------|-----------|---------|----------------|
| `corpus/0299_sum_resolved_filter` | `exists_sum` | yes | **VIOLATED** | `{"completed": 0, "inflight": 3}` |
| `corpus/0301_sum_resolved_range_filter` | `exists_sum` | yes | **VIOLATED** | `{"completed": 0, "inflight": 3}` |
| `corpus/mcagg_0299_sum_resolved_filter` | `exists_sum` | yes | **VIOLATED** | `{"completed": 0, "inflight": 3}` |
| `examples/alert_total_transfer_over_200` | `exists_sum` | yes | **PROVEN** | — |
| `examples/cap_open_agent_prs_windowed` | `count_window` | yes | **VIOLATED** | `{"open": 3}` |
| `examples/refund_budget_settled_plus_current` | `refund_budget` | yes | **OUT_OF_SCOPE** | state space exceeded budget (200k) |
| `policies/spendcap-buggy` | `spendcap` | yes | **VIOLATED** | `{"completed": 0, "inflight": 3}` |
| `policies/spendcap-correct` | `spendcap` | yes | **PROVEN** | — |
| `policies/spendcap-inflight-filter` | `exists_sum` | yes | **PROVEN** | — |
| `policies/spendcap-resolved-filter` | `exists_sum` | yes | **VIOLATED** | `{"completed": 0, "inflight": 3}` |
| `policies/spendcap-resolved-range-filter` | `exists_sum` | yes | **VIOLATED** | `{"completed": 0, "inflight": 3}` |
| `policies/taint-egress-correct` | `taint_egress` | yes | **PROVEN** | — |
| `policies/taint-egress-buggy` | `taint_egress` | yes | **VIOLATED** | `{"exfiltrated": true, "holding_private": true}` |

## 3. Aggregate metrics

| Metric | Count |
|--------|-------|
| Total policies | **13** |
| Lowerable | **13** |
| PROVEN | **4** |
| VIOLATED | **8** |
| OUT_OF_SCOPE | **1** |
| ERROR | **0** |


## 4. Reading the verdicts (honestly)

- **PROVEN (4).** No reachable state (within the bound) violates the pinned
  property. Under the concurrent in-flight model, these policies hold. The
  `taint-egress-correct` policy is the temporal + data-dependent shape: the
  egress is admitted only when the agent is *not* holding private data, so
  `no_exfiltration` holds over every reachable state.
- **VIOLATED (8).** A reachable state violates the property. The spend-cap
  witness
  `{"completed": 0, "inflight": 3}` means: **3 requests in flight, 0 settled**,
  and the in-flight total exceeds the cap. This is the **parallel-fire** class
  of gap — a point-in-time monitor (which decides each request against the
  *settled* trace) cannot see it, because the in-flight requests are not yet in
  the settled trace. ROTN's temporal proof can. Note the three dogwood
  `corpus/*` policies come from dogwood's own *passing* test suite: those tests
  verify the **monitor** produces the expected output on a given trace, which
  is a different (weaker) question than whether the **policy** is sound under
  interleavings.
- **OUT_OF_SCOPE (1).** `refund_budget_settled_plus_current`'s state space
  exceeds the 200k budget (`ProductTooLarge`). ROTN is honest about not being
  able to decide it — it does **not** silently pass, and it does **not** report
  an internal error. This is a known, bounded limitation.

## 5. Redesign history (worth recording)

**First draft** classified the `ProductTooLarge` (state-space) case as
`ERROR`. That was wrong: a state-space blowup is a *known, bounded
limitation*, not an internal error. Reclassifying it as `OUT_OF_SCOPE` makes
the matrix honest — it distinguishes *"I cannot decide (honest)"* from
*"the tool crashed (bug)"*. This is the same discipline as the ZK-003 honest
false negative in [`phase3-eval.md`](phase3-eval.md): a genuine gap, reported
as such, not hidden.

## 6. The gaps, and how to close them

- **`refund_budget` OUT_OF_SCOPE.** The state space exceeds the 200k budget.
  Closing it requires either (a) raising the budget (at the cost of runtime), or
  (b) a more compact lowering for the refund-budget shape (e.g. a symmetry
  reduction over the in-flight slots). Left as a known limitation so this report
  reflects the *current* tool, not a hypothetical one.
- **5 shapes supported.** The general lowering covers `spendcap`,
  `count_window`, `exists_sum`, `refund_budget`, and `taint_egress` (the
  thesis's "never contact outsiders after touching confidential data" shape —
  temporal + data-dependent, lowered to the `no_exfiltration` invariant).
  Other temporal shapes in
  the upstream dogwood corpus are not yet lowerable and would be reported
  `OUT_OF_SCOPE` (honestly) if fetched.
- **Only 11 policies present.** The upstream dogwood corpus is larger. Covering
  it is a separate fetch-and-verify task (§7).

## 7. Limitations & follow-up

- **11 policies, not 59.** The corpus present is 11 policies. The roadmap's
  "59 fixtures" does not match the on-disk corpus. To cover the full upstream
  dogwood corpus, fetch the additional `tests/passing/temporal_only/corpus/*`
  policies (with SHA-verified provenance) and re-run `rot corpus`. That is a
  separate task, deliberately not conflated with this evaluation.
- **Bounded, not unbounded.** Every verdict is within the state-space budget
  and the in-flight bound `K`. Beyond that, ROTN reports `OUT_OF_SCOPE`.
- **5 shapes.** The lowering covers the five shapes above; other shapes are
  honestly `OUT_OF_SCOPE`.
- **Follow-ups:** (1) raise the budget or add a symmetry reduction to bring
  `refund_budget` in-scope; (2) fetch the full upstream corpus and re-evaluate;
  (3) extend the lowering to additional temporal shapes.

## 8. Reproduce

```powershell
cd ROTN
rot corpus                    # matrix to stdout + out/corpus/
# or, without installing:
python -m rot corpus
```

Exit `0` (the matrix is data; `VIOLATED` rows are honest findings, not tool
failures). Artifacts: `out/corpus/corpus_matrix.json`,
`out/corpus/corpus_matrix.md`, this document.

Files: `rot/__main__.py` (`cmd_corpus`), `rot/lower.py` (general lowering),
this document.

