## [Unreleased]

### Added — governance docs + follow-up tracking
- `SECURITY.md` — private disclosure policy, in/out scope, and the
  vendor-divergence rule (suspected live-gateway defects or semantic
  divergences go privately to the vendor first — no public claim before
  that).
- `CONTRIBUTING.md` — setup, the test suite, the reference gate
  (`DOGWOOD_BIN` resolution order, exit codes, the pinned
  `dogwood-ref@4ec5e2c…` build), the waiver / `LABELED-DIVERGENCE`
  rules, and the repo conventions.
- `docs/issues-drafts/` — paste-ready drafts of the five follow-up
  issues: ① the bidirectional reference gate, ② the APW-4 labeled
  divergence + waiver, ③ the PyPI name claim + trusted publisher,
  ④ the AgentCore E1–E4 follow-up, and ⑤ the APW-7 "denied attempts
  drain the budget" proposal.
- README: "Contributing and security" pointers to the two new docs.

### Changed — wording (honesty pass)
- README + site: "proves each one" → "demonstrates each one";
  "oracle-verified" → "hand-written oracle, cross-checked against the
  reference interpreter"; APW-5/6 carry `concept` / `if absolute windows
  ship` badges in the README table, the site grid, and the catalog.
- README / `setup.py` long_description / `rot/__init__.py`: the engine
  story is now stated as the built-in pure-stdlib default engine, with
  optional Z3/TLC/Apalache cross-checks and engine-labeled verdicts.
- `agentcore_repro/64_replay_reference.py`: the missing-binary error
  now points at `CONTRIBUTING.md` (the old `docs/03-build-dogwood.md`
  reference was dangling).

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

### Removed — scratch
- 15 tracked scratch paths + the `agentcore_repro` probe scripts
  (`_peprobe.py`, `_probe_boto3.py`, `_probe_ops.py`, `_sanity.py`);
  untracked `_tmp_*` / `test_out.txt` / `tmp_test_out.txt` deleted;
  `.gitignore` tightened (`/out_apw*/`, `/tmp_*/`, `test_out.txt`).
- `todo.md` removed — superseded by `docs/issues-drafts/` and the release
  plan (the open work is now tracked as issues ①–⑤).
