# GAP-4 live repro — real AWS AgentCore Gateway

Run the live spend-cap investigation **on real AWS AgentCore** from this
machine. No console, no browser: AWS CLI v2 + the official AgentCore CLI,
local AWS credentials profile, everything scripted and resumable.

The full runbook (IAM, pricing, video shot list) lives in
[`../docs/agentcore-repro.md`](../docs/agentcore-repro.md).

## One-time setup

```powershell
# 1. AWS CLI v2 (if not installed)
tools\install_awscli.ps1            # or: winget install AWS.AWSCLI

# 2. Node 18+ + official AgentCore CLI
npm install -g @aws/agentcore

# 3. Credentials (any method you like; the CLI/SDK picks up the profile)
aws configure                       # access key / secret / region
#    or: set-Content $env:AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN
#    or: a pre-authenticated SSO profile

# 4. Check readiness
python agentcore_repro\00_preflight.py
```

## Run the demo

```powershell
python agentcore_repro\run_all.py        # pauses at the two decision points
# or step by step:
python agentcore_repro\10_setup.py            # roles, Lambda, engine, gateway
python agentcore_repro\20_deploy_policy.py    # BUGGY policy -> ACTIVE (E1: findings recorded)
python agentcore_repro\31_fire_sequential.py  # buggy baseline: 5 x $100 SEQUENTIAL, one session
python agentcore_repro\30_fire_parallel.py    # 3 x $100 parallel, ONE session
python agentcore_repro\40_capture_evidence.py # CloudWatch + Lambda SETTLE lines
python agentcore_repro\50_rot_catch_fix_prove.py  # ROTN local verdicts: VIOLATED / PROVEN
python agentcore_repro\60_redeploy_correct.py     # FIXED policy (E1: findings) + re-fire
python agentcore_repro\31_fire_sequential.py  # E2: 5 x $100 SEQUENTIAL under FIXED
python agentcore_repro\63_test_single300.py   # E3: one $300 fire, fresh session
python agentcore_repro\64_replay_reference.py # E4: reference replay of E2 (local, no AWS)
python agentcore_repro\70_cleanup.py          # tear everything down
```

## What you'll see

| step | buggy policy | fixed policy |
|---|---|---|
| 3 parallel $100, one session | **3 admitted, $300** — the spec prediction for the settled-sum template (not, by itself, evidence of a race) | **3 admitted, $300 — not yet explained** (the spec predicts $200; hypotheses A/B/C open, runbook §7) |
| ROTN local verdict | **VIOLATED** (exit 1, witness: completed=0, in-flight=3) | **PROVEN** (exit 0) |

## Files

| file | what it does |
|---|---|
| `00_preflight.py` | toolchain + credentials + IAM permission probes |
| `10_setup.py` | roles, mock-transfer Lambda, policy engine, gateway, MCP target |
| `20_deploy_policy.py` | deploy the BUGGY temporal policy (AgentCore namespace), wait ACTIVE; E1: findings → `out/validation-findings.json` |
| `31_fire_sequential.py` | E2 control + buggy baseline: N × $100 SEQUENTIAL, one session, three-way verdict; records `events.jsonl` for E4 |
| `30_fire_parallel.py` | 3 parallel `transfer` invokes, one session id |
| `40_capture_evidence.py` | CloudWatch metrics + Lambda SETTLE lines + responses |
| `50_rot_catch_fix_prove.py` | run repo `pipeline.py` on canonical policies; cross-check live |
| `60_redeploy_correct.py` | swap in FIXED policy (one word), E1 findings recorded, re-fire |
| `63_test_single300.py` | E3 control: one $300 fire, one fresh session |
| `64_replay_reference.py` | E4 control: replay E2's events against the local Dogwood reference (no AWS) |
| `70_cleanup.py` | delete policies, gateway, engine, Lambda, roles |
| `61_test_pluscurrent.py` | (historical) the `+ current` policy attempt — rejected by the validator (runbook §6, run 4) |
| `62_test_sequential.py` | (historical, deprecated) superseded by `31`; its `sequential-results.json` is runbook §6 run 3 |
| `policies/*.dw` | the 4 policy candidates (buggy/fixed × 2 syntax forms) |
| `lambda/transfer_handler.py` | the mock bank-transfer backend |
| `out/` | state.json + all evidence (fire-*.json, events.jsonl, sequential5-results.json, single300.json, e4-report.json, validation-findings.json, evidence.md, rot-verdict.md) |

## Expectations & caveats

* The **AgentCore** policy syntax is a live surface: two candidate forms are
  shipped (`*-agentcore.dw` primary, `*-agentcore-alt.dw` fallback) and the
  deployer records which one the real validator accepts. If both are
  rejected, the run is **inconclusive** (exit 2) and the validator's
  findings are saved to `out/validation-findings.json` (E1) — that is the
  evidence to start from.
* Temporal counts are **per session** (new session = fresh count), so all
  three fires share one session id. Policy updates invalidate in-flight
  sessions (409), which is why the fixed-policy re-fire uses a fresh session.
* Cost is tiny (a few minutes of Lambda + gateway); `70_cleanup.py` removes
  everything. The demo is a *demonstration of an unexplained $300
  admission* — the corrected policy admitted $300 live against the $200
  spec prediction, and the cause is not yet established (runbook §7) — not
  a production control plane; the mock "bank" is a 30-line Lambda.