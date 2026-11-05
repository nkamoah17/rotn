## [Unreleased]

### Fixed — soundness fix
The spend-cap model reported a false `PROVEN` for the buggy (response-sum)
policy at `K=1`, calling it a "masked" bug. Under Dogwood's documented
semantics the window is **closed/reflexive** and whether the current request
is charged is decided by the aggregate's **event kind** — a `::response` sum
does not include the current request. The model had wrongly added a
`+ context.input.amount` term the policy does not contain, justified by a
false "formerly is past-only" premise.

- `spend_ok_guard_buggy` is now derived as `completed <= CAP` under an
  explicitly named semantics (`SEMANTICS`), instead of the hand-written
  `completed + AMOUNT <= CAP`.
- The K-sweep is corrected: the buggy policy is **VIOLATED at every K**
  (off-by-one sequentially at K=1, unbounded under concurrency at K≥2); the
  witness shape tracks K: `{completed:200, inflight:1}` →
  `{completed:100, inflight:2}` → `{completed:0, inflight:3}`.
- Corrected: `rot/spendcap.py`, `rot/lower.py`, `rot/attestation.py`,
  `rot/coach.py`, `rot/frontends/policy/dw.py`, `rot/policy_smt.py`,
  `rot/smtz3.py`, `rot/trace.py`, `README.md`,
  `ROTN_Technical_Report.md`, `docs/{apw-catalog,discrimination,
  spendcap-demo,spendcap-usage,dogwood-repro,novelty,replay}.md`, the site
  (`compare.js`, `app.js`, `smoke_h.js`, regenerated `site/data`), and
  `demo.{ps1,sh}`.
