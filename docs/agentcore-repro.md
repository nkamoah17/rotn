# AgentCore live reproduction — spend-cap policies on a real AgentCore Gateway

> **Status: investigation in progress.** The live runs below did not reproduce
> the expected behavior of the corrected policy, and the cause is not yet
> established. Nothing in this document claims an AWS defect. If the controls
> in §5 indicate a divergence from Dogwood's documented semantics, we will
> report it privately to AWS before publishing further detail.

## 1. What this is

A scripted, fully local procedure (`agentcore_repro/`) that deploys Dogwood
spend-cap policies to a real Amazon Bedrock AgentCore Gateway, fires $100
transfers at a mock tool, and records AWS-side evidence: gateway responses,
CloudWatch decision metrics, and the mock Lambda's `SETTLE` log lines.

Its purpose is to compare three things on the same policy and the same
events: ROTN's model, Dogwood's reference interpreter, and the live gateway.

## 2. Semantics this document assumes

From the Dogwood guide (Temporal expressions → Evaluation semantics) and the
formal specification §6:

- `formerly within W body` holds if `body` holds at some position j in
  [0, i] — the current event included.
- Every event is observed before it is decided. A recorded request stays in
  history even if evaluation then denies it.

Predictions for the two policies used here (cap $200, $100 per call):

| policy | sums | sequential (spec) | parallel (spec, serialized engine) |
|---|---|---|---|
| `spendcap-buggy` (`::response`) | settled transfers only | **$300** — admits the 3rd call (settled $200 ≤ $200) | up to $200 + K × $100 |
| `spendcap-correct` (`::request`) | all requests, incl. the current one and denied attempts | **$200** — denies the 3rd call | **$200** |

Because the buggy policy reaches $300 even sequentially, a $300 result on its
own is **not** evidence of a race.

## 3. Prerequisites

### 0.1 Tools (installed on this machine, no console needed)

| tool | why | install |
|---|---|---|
| AWS CLI **v2** | control plane (IAM, Lambda, AgentCore control) | `tools\install_awscli.ps1` or `winget install AWS.AWSCLI` |
| Node.js 18+ | the AgentCore CLI is a Node package | `winget install OpenJS.NodeJS` |
| **AgentCore CLI** (`@aws/agentcore`) | data plane: `agentcore gateway invoke` (SigV4 with local creds) | `npm install -g @aws/agentcore` |
| Python 3.9+ | the step scripts (stdlib only) | already in this repo's toolchain |

Verify: `python agentcore_repro\00_preflight.py` → must print **READY**.

### 0.2 AWS credentials

Any of these work (the scripts use the default profile / env, in that order):

```powershell
# option A: interactive
aws configure                          # access key id / secret / region
# option B: env vars (session token optional)
$env:AWS_ACCESS_KEY_ID     = "AKIA..."
$env:AWS_SECRET_ACCESS_KEY = "..."
$env:AWS_SESSION_TOKEN     = "..."     # if from STS
# option C: a pre-authenticated SSO profile
aws sso login --profile myteam
```

> **Security note for the record:** use a *dedicated* access key (or an SSO
> role) scoped to the permissions in §0.3. Nothing in this repro reads or
> prints secret material; the CLI signs requests locally with SigV4.

### 0.3 Minimum IAM permissions (for the key/role running the scripts)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["sts:GetCallerIdentity"], "Resource": "*" },
    { "Effect": "Allow",
      "Action": ["iam:CreateRole","iam:GetRole","iam:PutRolePolicy","iam:AttachRolePolicy",
                 "iam:DetachRolePolicy","iam:DeleteRole","iam:DeleteRolePolicy",
                 "iam:ListRolePolicies","iam:ListAttachedRolePolicies"],
      "Resource": "arn:aws:iam::*:role/rot-*" },
    { "Effect": "Allow",
      "Action": ["lambda:CreateFunction","lambda:GetFunction","lambda:UpdateFunctionCode",
                 "lambda:AddPermission","lambda:RemovePermission","lambda:DeleteFunction"],
      "Resource": "arn:aws:lambda:*:*:function/rot-*" },
    { "Effect": "Allow",
      "Action": ["bedrock-agentcore-control:CreateGateway","bedrock-agentcore-control:GetGateway",
                 "bedrock-agentcore-control:ListGatewaySummaries","bedrock-agentcore-control:DeleteGateway",
                 "bedrock-agentcore-control:CreateGatewayTarget","bedrock-agentcore-control:GetGatewayTarget",
                 "bedrock-agentcore-control:ListGatewayTargets","bedrock-agentcore-control:DeleteGatewayTarget",
                 "bedrock-agentcore-control:CreatePolicyEngine","bedrock-agentcore-control:GetPolicyEngine",
                 "bedrock-agentcore-control:GetPolicyEngineSummary","bedrock-agentcore-control:ListPolicyEngineSummaries",
                 "bedrock-agentcore-control:DeletePolicyEngine",
                 "bedrock-agentcore-control:CreatePolicy","bedrock-agentcore-control:GetPolicy",
                 "bedrock-agentcore-control:ListPolicies","bedrock-agentcore-control:UpdatePolicy",
                 "bedrock-agentcore-control:DeletePolicy"],
      "Resource": "*" },
    { "Effect": "Allow",
      "Action": ["logs:DescribeLogGroups","logs:DescribeLogStreams","logs:GetLogEvents"],
      "Resource": "arn:aws:logs:*:*:log-group:/aws/lambda/rot-*:*" },
    { "Effect": "Allow",
      "Action": ["cloudwatch:ListMetrics","cloudwatch:GetMetricStatistics"],
      "Resource": "*" }
  ]
}
```

> AgentCore control-plane actions are ARN-scoped in the console; the wildcard
> above is the simplest form for a demo key. Tighten it for real use.

### 0.4 Region

AgentCore Gateway + policy engines are available in the standard commercial
regions (e.g. `us-east-1`, `eu-west-1`). Pick one and keep it:

```powershell
$env:AC_REPRO_REGION = "us-east-1"
```

### 0.5 Cost (order of magnitude)

| resource | usage for this demo | approx cost |
|---|---|---|
| Lambda (128 MB, ~10 invokes) | a few GB-s | **$0.00** (free tier) |
| AgentCore Gateway | pay-per-invocation / duration, minutes | **~$0.01–0.05** |
| Policy engine | evaluated per decision, minutes | **~$0.00–0.02** |
| CloudWatch Logs | a few KB | **$0.00** (free tier) |
| **total** | | **well under $0.10** |

`70_cleanup.py` deletes everything, so nothing keeps billing.

## 4. Steps

All commands run from the repo root. State lives in
`agentcore_repro/out/state.json`; every step is resumable.

1. **Preflight** — `python agentcore_repro\00_preflight.py` → `READY`.
2. **Setup** — `python agentcore_repro\10_setup.py` (roles, policy engine,
   mock Lambda, gateway, target).
3. **Deploy the buggy policy with findings recorded.** `20_deploy_policy.py`
   must not use `--validation-mode IGNORE_ALL_FINDINGS`. Use the mode that
   surfaces findings and save them to `out/validation-findings.json`. A run
   with any unresolved finding is reported as **inconclusive**.
4. **Buggy, sequential baseline** — 5 × $100, one session, session ID logged
   on every call: `31_fire_sequential.py 100 5`. Spec
   prediction: $300.
5. **Buggy, parallel** — `python agentcore_repro\30_fire_parallel.py 100 5`.
   The difference from step 4 is the concurrency effect.
6. **Evidence** — `40_capture_evidence.py` (CloudWatch, Lambda `SETTLE`
   lines, responses) → `out/evidence.{json,md}`.
7. **ROTN local verdicts** — `50_rot_catch_fix_prove.py`. After the
   spend-cap soundness fix, the buggy policy is VIOLATED at every K,
   including K=1.
8. **Corrected policy controls** — `60_redeploy_correct.py`, then the
   controls in §5.
9. **Reference replay** — replay the recorded event sequence through
   Dogwood's reference interpreter with the same policy text:
   `rot replay --oracle dogwood --events out/events.jsonl`.
10. **Cleanup** — `python agentcore_repro\70_cleanup.py`.

## 5. Controls

| control | reflexive (spec) | non-reflexive engine | predicate never matches |
|---|---|---|---|
| E1. findings from step 3 | clean | clean | likely a finding |
| E2. corrected, 5 × $100 sequential, one session | #3–5 denied ($200) | #4–5 denied ($300) | none denied ($500) |
| E3. corrected, one $300 call, fresh session | denied | allowed | allowed |
| E4. reference replay of E2's events | denies #3 | shows the live/reference gap | shows whether the predicate matches |

Only after E2 shows a deny: fire the corrected policy 5× in parallel. More
than $200 admitted indicates the engine does not serialize
observe-then-decide.

## 6. Results to date

| run | policy | firing | result | evidence |
|---|---|---|---|---|
| 1 | buggy (`::response`) | 3 × $100 parallel, one session | 3 admitted, $300 | 3 Lambda `SETTLE` lines; CloudWatch 3 allow / 0 deny |
| 2 | corrected (`::request`) | 3 × $100 parallel, fresh session | 3 admitted, $300 | `out/fixed-results.json` |
| 3 | corrected | 3 × $100 sequential, fresh session | 3 admitted, $300 | `out/sequential-results.json` |
| 4 | corrected + `+ context.input.amount` | — | rejected by the validator (`unexpected token '+'`) | `out/_61_err.log` |

Runs 1–3 were deployed with `--validation-mode IGNORE_ALL_FINDINGS`.
Arithmetic in comparison operands is an off-by-default experimental Dogwood
feature, which is consistent with run 4.

## 7. Interpretation

- **Run 1** matches the spec prediction for the buggy policy. Because the spec
  predicts $300 sequentially too, it does not by itself demonstrate a race.
- **Runs 2–3** contradict the spec prediction for the corrected policy
  ($200). Three explanations remain open:
  - **A.** The temporal predicate does not match the gateway's events.
    Validation findings were suppressed, and no run has yet shown a deny.
  - **B.** The production engine evaluates without the current request
    (non-reflexive).
  - **C.** Another deployment issue: session handling, or policy propagation.
- The controls in §5 distinguish A, B and C.

## 8. Claims and bounds

**Supported now:** on live AgentCore, both spend-cap policies, as deployed in
runs 1–3, admitted $300 against a $200 cap.

**Not yet supported:** any statement about the cause; that AgentCore deviates
from Dogwood's semantics; that the corrected policy enforces the cap live; or
that run 1 demonstrates a concurrency race.

**Scope:** one policy family, one gateway configuration, one region, a mock
backend.

## 9. Video shot list

On hold until §5 completes. Two candidate cuts:

- **Spec-level story** — the settled-sum off-by-one shown in ROTN and the
  reference interpreter, with no live claim.
- **Live story** — only after the controls and, if applicable, AWS
  disclosure.

## 10. Reproducibility and safety notes

- `out/` contains ARNs, metric names and log lines, never credentials; it is
  git-ignored.
- `70_cleanup.py` deletes every resource the scripts created.
- Run only in an account you own. Report suspected service issues to AWS
  through its vulnerability-reporting process before publishing.
