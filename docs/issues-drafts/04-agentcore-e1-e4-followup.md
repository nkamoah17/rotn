# AgentCore live repro: complete the E1–E4 controls (spend-cap investigation)

> **Status: investigation in progress — no cause established, no
> vendor-defect claim.** This issue is an internal task tracker. Per
> `SECURITY.md` §3, the *findings* stay private until the disclosure
> decision.

## State (runbook `docs/agentcore-repro.md` §6)

| run | policy | firing | result |
|---|---|---|---|
| 1 | buggy (`::response`) | 3 × $100 parallel, one session | 3 admitted, $300 — matches the spec prediction (not, by itself, evidence of a race) |
| 2 | corrected (`::request`) | 3 × $100 parallel, fresh session | 3 admitted, $300 — the spec predicts $200 |
| 3 | corrected | 3 × $100 sequential, fresh session | 3 admitted, $300 — the spec predicts $200 |
| 4 | corrected + `+ context.input.amount` | — | rejected by the validator (arithmetic in comparison operands is an off-by-default experimental feature) |

Runs 1–3 were deployed with `--validation-mode IGNORE_ALL_FINDINGS`.
Three explanations remain open: **A** the temporal predicate does not
match the gateway's events; **B** the production engine evaluates without
the current request (non-reflexive); **C** another deployment issue
(session handling, or policy propagation).

## Pending controls (runbook §5)

| control | reflexive (spec) | non-reflexive engine | predicate never matches |
|---|---|---|---|
| E1. findings from step 3 | clean | clean | likely a finding |
| E2. corrected, 5 × $100 sequential, one session | #3–5 denied ($200) | #4–5 denied ($300) | none denied ($500) |
| E3. corrected, one $300 call, fresh session | denied | allowed | allowed |
| E4. reference replay of E2's events | denies #3 | shows the live/reference gap | shows whether the predicate matches |

## Plan

1. Redeploy the corrected policy **with validation on** — record the
   findings (E1) to `out/validation-findings.json`; do not suppress them.
2. **E2:** 5 × $100 sequential, one session (`31_fire_sequential.py`);
   record `events.jsonl` + CloudWatch + the Lambda `SETTLE` lines.
3. **E3:** one $300 call, fresh session (`63_test_single300.py`).
4. **E4:** `64_replay_reference.py` (local, no AWS) — replay E2's events
   through `dogwood replay` (`DOGWOOD_BIN` set).
5. Update runbook §6–§8 with the results and the interpretation (A / B /
   C).
6. **Disclosure decision (`SECURITY.md` §3):** if the controls indicate
   a divergence from Dogwood's documented semantics → report privately
   to AWS (its vulnerability-reporting process) *before* publishing
   further detail. Otherwise, close with a documented deployment /
   predicate explanation.

## Guardrails

- One policy family, one gateway configuration, one region, a mock
  backend — do not widen scope before the controls complete.
- Run only in an account you own; `70_cleanup.py` tears everything down;
  `out/` must never contain credentials (verify on every run).
- Only after E2 shows a deny: fire the corrected policy 5× in parallel —
  more than $200 admitted would indicate the engine does not serialize
  observe-then-decide (that *is* divergence evidence — handle it via
  step 6, not via a public issue).
