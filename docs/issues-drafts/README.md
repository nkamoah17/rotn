# Issue drafts (paste-ready)

Paste-ready drafts of the five follow-up issues for `nkamoah17/rotn`, in
the planned order ①–⑤. File them in this order so the cross-references
hold, then replace the ①–⑤ placeholders with the real `#N` numbers.

| file | issue |
|---|---|
| `01-bidirectional-reference-gate.md` | ① the bidirectional reference gate (C4) — spec pin, probe set, G1–G6, waivers, CI |
| `02-apw4-labeled-divergence.md` | ② APW-4 relabel + waiver (per-recipient partitioned cap) |
| `03-pypi-claim-and-trusted-publisher.md` | ③ claim `rotn` on PyPI + trusted publisher + the `v0.2.0` tag |
| `04-agentcore-e1-e4-followup.md` | ④ the AgentCore E1–E4 controls (the live spend-cap investigation) |
| `05-apw7-denied-attempts-drain-budget.md` | ⑤ the APW-7 proposal: "denied attempts drain the budget" |

## Filing

Via `gh` (after `gh auth login`):

```bash
gh issue create --repo nkamoah17/rotn \
  --title "Gate: make the reference-interpreter gate bidirectional (both legs, labeled divergences, waivers, CI)" \
  --body-file docs/issues-drafts/01-bidirectional-reference-gate.md
# … and so on for 02 → 05 (the titles are the first line of each file)
```

Or in the GitHub UI: **New issue** → paste the title (the first line of
each file, without the leading `#`) → paste the body.

## Notes

- **04 is the sensitive one.** It tracks the live vendor investigation.
  Per `SECURITY.md` §3, the *findings* stay private until the disclosure
  decision — the body intentionally mirrors only what
  `docs/agentcore-repro.md` already states publicly (runs 1–4,
  hypotheses A/B/C, the controls table). Do not paste new evidence into
  it publicly.
- ② depends on ① (the waiver mechanism lives in the gate). ⑤ is
  independent catalog work, but its open question #1 is answered by ④.
- After filing, update any `①`–`⑤` cross-references in the repo docs with
  the real issue numbers.
