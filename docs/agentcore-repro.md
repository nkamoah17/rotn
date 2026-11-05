# GAP-4 — Real-AgentCore reproduction runbook

**What this is.** A step-by-step, fully-local reproduction of the spend-cap
race on **real AWS AgentCore**: deploy a buggy temporal policy to an AgentCore
Gateway, fire 3 parallel transfers, capture AWS's own logs showing $300
admitted over a $200 cap — then have ROTN catch the bug, fix it, and prove
the fixed policy.

**Why it matters.** Every other result in this repo is computed locally
(TLC / Apalache / policy-direct engines over the Drupe corpus). This is the
one result where the *counterfactual engine is AWS's own AgentCore Gateway
policy engine*, and the only one that answers "does this actually happen on
real AWS?" with AWS's own logs as the witness.

**Where the code lives.** [`../agentcore_repro/`](../agentcore_repro/) —
all steps are scripts; `run_all.py` drives them. This document is the
human runbook + the 60-second-video shot list.

---

## 0. Prerequisites

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

---


## 1. Step-by-step runbook

All commands from the repo root. Every step is idempotent and resumable
(state in `agentcore_repro/out/state.json`).

### Step 0 — preflight

```powershell
python agentcore_repro\00_preflight.py
```

**Expect:** `PREFLIGHT READY — 7/7 checks passed`.
**If FAIL:** fix the named item (tool missing, credentials, permissions) and
re-run. This step creates nothing.

### Step 1 — setup (roles, Lambda, engine, gateway, target)

```powershell
python agentcore_repro\10_setup.py
```

Creates (in order, reuses if present):

1. IAM roles `rot-ac-gateway-role` (trusts `bedrock-agentcore.amazonaws.com`)
   and `rot-lambda-exec`.
2. Policy engine `rot-spendcap-engine` → waits **ACTIVE**.
3. Lambda `rot-transfer-mock` (Python, mock bank transfer that logs a
   `SETTLE txId=... amount=... status=SETTLED` line) + invoke permission for
   AgentCore.
4. Gateway `rot-spendcap-gw` (protocol **MCP**, authorizer **AWS_IAM**,
   `policyEngineConfiguration {arn, mode: ENFORCE}`, `exceptionLevel: DEBUG`)
   → waits **ACTIVE**.
5. Gateway target `TransferTarget` (MCP lambda target, tool `transfer`).

**Expect:** ARNs printed + `state.json` populated.
**Troubleshooting:**
- `AccessDeniedException` → §0.3 permissions missing for that service.
- `ValidationException` on `create-gateway` → region doesn't support AgentCore
  Gateway; set `AC_REPRO_REGION` to a supported region.
- Gateway stuck in `CREATING` > 10 min → usually a role/permission issue —
  delete the gateway and re-run step 1.

### Step 2 — deploy the BUGGY policy

```powershell
python agentcore_repro\20_deploy_policy.py
```

Renders `policies/spendcap-buggy-agentcore.dw` (the AgentCore-namespace twin
of the repo's canonical `samples/spendcap-buggy.dw`), creates it in the engine
with `enforcementMode ACTIVE`, waits **ACTIVE**. The deployed statement is
printed verbatim.

**Key semantics (this is the bug):** the 24h running total sums
`Transfer::response` rows — *settled* transfers only. In-flight (authorized,
not-yet-returned) transfers are invisible to the sum.

```
when temporal {
    exists (total: Long). (
        (sum a for (a: Long). where (
            formerly within 24h (
                AgentCore::Action::"TransferTarget___transfer"::response{   // <-- BUG: ::response
                    eventResource: resource,
                    input.amount: a
                }
            )
        )) == total
        && total <= 200
    )
};
```

**Troubleshooting:** if the primary syntax candidate is rejected by the real
validator, the script automatically retries the alternate candidate
(`*-alt.dw`). If *both* fail, see **Appendix A**.

### Step 3 — fire the race (3 × $100, ONE session)

```powershell
python agentcore_repro\30_fire_parallel.py
```

Three `transfer` invokes for **$100 each**, started back-to-back, all in
**one session** (`x-amzn-bedrock-agentcore-policy-session-id`). At decision
time the buggy policy sees 0 settled (or ≤1) transfers, so all three pass
`sum <= 200` — **$300 committed over the $200 cap**.

**Expect:**
```
  fire 1 : ADMITTED  rc=0
  fire 2 : ADMITTED  rc=0
  fire 3 : ADMITTED  rc=0
  ADMITTED : 3 fire(s), $300 committed
  *** RACE CONFIRMED: $300 committed > $200 cap ***
```

**If a fire is DENIED at this stage:** the deployed policy is not the buggy
one (check `out/state.json` → `policyAcceptedForm`), or the session ids
differ (they must be identical — the script guarantees this). Re-run step 2,
then 3.


### Step 4 — capture AWS-side evidence

```powershell
python agentcore_repro\40_capture_evidence.py
```

Collects: CloudWatch decision/invoke metrics (last 15 min), the Lambda's
`SETTLE` lines (3 × $100 = **$300 actually settled**), and the saved gateway
responses. Writes `out/evidence.json` + `out/evidence.md`.

**This is the "AWS's own logs show $300 admitted" artifact.** The Lambda
`SETTLE` lines prove the transfers *executed* (money moved), not merely that
the gateway returned 200.

### Step 5 — ROTN catch / fix / prove

```powershell
python agentcore_repro\50_rot_catch_fix_prove.py
```

Runs the repo's own pipeline on the canonical Drupe-namespace policies:

| policy | expected | exit |
|---|---|---|
| `samples/spendcap-buggy.dw` | **VIOLATED** (witness: completed=0, in-flight=3, $300) | 1 |
| `samples/spendcap-correct.dw` | **PROVEN** | 0 |

…then cross-checks the local witness against the live evidence (3 admitted,
$300 > $200). Writes `out/rot-verdict.md`.

### Step 6 — deploy the FIXED policy, re-fire, prove enforced

```powershell
python agentcore_repro\60_redeploy_correct.py
```

One-word fix: `::response` → `::request` (sum *authorized* transfers,
in-flight included), via `update-policy` on the same policy id. Re-fires the
same 3 × $100 in a **fresh session** (policy updates invalidate in-flight
sessions).

**Expect:**
```
  fire 1 : ADMITTED   ($100)
  fire 2 : ADMITTED   ($200)
  fire 3 : DENIED     (would be $300 > $200)
  *** CAP ENFORCED: $200 committed <= $200, 1 denied ***
```

### Step 7 — final evidence + cleanup

```powershell
python agentcore_repro\40_capture_evidence.py   # final bundle
python agentcore_repro\70_cleanup.py            # delete everything
```

**Keep the stack up** (`run_all.py --skip-cleanup`) if you're recording the
video.

---

## 2. The story (for the writeup)

1. **Setup** — a real AgentCore Gateway (MCP) fronts a mock bank-transfer
   tool; a temporal policy enforces "24h spend ≤ $200 per session".
2. **The bug** — the policy sums *settled* (`::response`) transfers. A
   parallel burst of *authorized* transfers is invisible to the sum while it
   is in flight.
3. **The exploit** — 3 parallel $100 fires in one session. All three pass
   `sum ≤ 200`. AWS's own Lambda logs show **3 × $100 SETTLED = $300** —
   over the cap. The gateway admitted what the policy was supposed to deny.
4. **The catch** — ROTN's pipeline on the same policy (Drupe namespace)
   returns **VIOLATED** with a concrete witness (completed=0, in-flight=3,
   $300) — before anything runs.
5. **The fix** — one word: `::response` → `::request` (count authorized, not
   settled). Same 3 fires: **2 admitted, 1 denied, $200 committed**.
6. **The proof** — ROTN returns **PROVEN** for the fixed policy; the live
   run matches the local witness exactly.

**Claim (and its bound):** on real AgentCore, a temporal spend-cap policy
that aggregates over settled events is bypassable by in-flight parallel
requests; aggregating over authorized events enforces the cap. This is a
*pattern* result (one policy family, one platform, one concurrency shape),
not a general theorem about all temporal policies — say so in the writeup.


---

## 3. 60-second video — shot list

Single terminal window, top-down or screen-record; 60s total. Keep the
policy text and the numbers on screen — they are the whole story.

| # | seconds | shot | on screen |
|---|---|---|---|
| 1 | 0–6 | **Title + setup** | `10_setup.py` tail: `gateway ACTIVE`, `target ACTIVE` (pre-run, replay) |
| 2 | 6–16 | **The buggy policy** | `20_deploy_policy.py` printing the `::response` clause; zoom on `::response` + `<= 200`; `policy ACTIVE` |
| 3 | 16–30 | **The exploit** | `30_fire_parallel.py`: three `ADMITTED rc=0` lines land in under a second; `$300 committed > $200 cap` banner |
| 4 | 30–40 | **AWS's own log** | `evidence.md` (or CloudWatch Logs pane): three `SETTLE ... amount=100` lines, `$300 settled (consistent: True)` |
| 5 | 40–50 | **ROTN catches it** | `50_rot_catch_fix_prove.py`: buggy → **VIOLATED** (witness `completed=0, inflight=3`), correct → **PROVEN** |
| 6 | 50–60 | **Fix + prove** | `60_redeploy_correct.py`: `fire 3: DENIED`, `$200 committed <= $200, 1 denied`; end card: "one word: `::response` → `::request`" |

**Recording tips**
- Run steps 2–6 **live, in one take** (they take ~2 min wall-clock; speed
  up 2× in edit). Pre-run everything once so the live take is clean.
- Keep the terminal font ≥ 18pt; the policy text and the `$300` / `$200`
  numbers must be readable at 1080p.
- If a step hiccups live, the pause points in `run_all.py` let you recover
  without re-arming the audience.
- Caption the one-word diff (`::response` → `::request`) in the end card —
  it's the most quotable frame.

---

## 4. Appendix A — if the real AgentCore validator rejects both candidates

The two shipped candidates cover the two known corpus forms (explicit
`exists(total). ...` and the direct aggregate comparison). If the real
validator still rejects, work down this list (each change is one line in
`policies/spendcap-*-agentcore.dw`):

1. **Drop the explicit binding** — keep only the direct-comparison form
   (the `-alt` candidate already is this).
2. **Drop the `eventResource` match** from the filter (keep
   `input.amount` only) — some validators don't index event-resource
   fields in `formerly` filters.
3. **Simplify the time clause** — try `formerly ( ... )` without `within 24h`
   (the race is still demonstrated; note the bound changes).
4. **Switch the namespace casing** to match whatever a known-good AgentCore
   policy in your account uses (the control-plane `get-policy` on any
   existing policy is the reference).
5. **Last resort** — author the identical policy in the console's policy
   editor (it will show the exact accepted form), then paste that form into
   the two `.dw` files so the scripted path matches.

Each attempt is logged in `out/state.json` (`policyAcceptedForm`), so the
writeup can state exactly which syntax the real engine accepted.

## 5. Reproducibility & honesty notes

- **Determinism:** the exploit is a *race*, so it is near-certain but not
  logically guaranteed on any single run (it requires the three decisions to
  interleave before any settlement is recorded). If a run ever comes back
  `2 admitted / 1 denied` on the buggy policy, that is a *timing* outcome,
  not a policy difference — re-run step 3 (it is cheap) or widen the window
  by firing 4 × $100 (`30_fire_parallel.py 100 4`).
- **Session semantics:** temporal counts are per session; all fires share one
  session id. A policy update invalidates in-flight sessions (409), hence the
  fresh session in step 6.
- **Mock backend:** the "bank" is a 30-line Lambda that settles instantly.
  The race is a property of the *policy's aggregation*, not of the backend;
  the SETTLE lines are only there to prove the calls executed.
- **No secrets in artifacts:** `out/` contains ARNs, metric names, and log
  lines — never credentials. Do not commit `out/state.json` if your account
  ARN is sensitive (it is git-ignored via `out/`).