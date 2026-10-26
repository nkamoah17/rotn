# ROTN — Spend-cap CLI usage (the `.dw` policy path)

Reference for verifying AWS Dogwood spend-cap policies with `pipeline.py`.
For the walkthrough, see [`spendcap-demo.md`](spendcap-demo.md).

## One-liner

```bash
python pipeline.py --policy <file.dw> --engine symbolic
```

The `.dw` front-end (`rot.frontends.policy.dw`) lowers the policy into a
validated `ProtocolIR` with the **safety** property `spendcap_within_cap`
pinned, and the bounded model checker decides it with
`forall_reachable`. The policy is self-contained: `--tools` and `--n-steps`
are accepted for a compatible signature but unused by this family.

## Flags (the `--policy` path)

| flag | default | meaning |
|------|---------|---------|
| `--policy FILE` | — | the policy file (`.cedar` -> Cedar, `.dw` -> Dogwood spend-cap, `.json` -> Dogwood) |
| `--engine {auto,tlc,symbolic,apalache,crosscheck}` | `auto` | `symbolic` = the pure-Python SAT engine (offline, deterministic); `crosscheck` = SMT (Z3) **and** TLC, joined — a verdict requires **both** engines to agree (see below) |
| `--kind {safety,realizability,liveness}` | auto | force the property kind (auto-route: `.cedar` -> realizability, `.dw` / `.json` -> safety) |
| `--max-inflight K` | `4` | the concurrency pool bound: max in-flight requests the state space can express. Structural, not policy: shared by the correct and buggy variants. `.dw` spend-cap policies only (ignored for Cedar / `.json`) |
| `--max-states N` | `200000` | state-space budget for the bounded search |
| `--out DIR` | `out` | report output directory |
| `--quiet` | off | suppress the human summary (still writes the report) |

## Exit codes (identical to the rest of the pipeline)

| code | meaning | interpretation |
|------|---------|----------------|
| 0 | proven | the pinned property holds in every reachable state (within the bound) |
| 1 | violated | a concrete counterexample (witness) refutes it |
| 2 | unknown | the bounded search was inconclusive — never read as proven |
| 3 | error | usage / IO failure |

## Examples

```bash
# Correct policy: sums over Transfer::request (in-flight included).
python pipeline.py --policy tests/fixtures/aws_dogwood/spendcap/policies/spendcap-correct.dw
# -> spendcap_within_cap PROVEN      (exit 0)

# Buggy policy: sums over Transfer::response (in-flight invisible).
python pipeline.py --policy tests/fixtures/aws_dogwood/spendcap/policies/spendcap-buggy.dw
# -> spendcap_within_cap VIOLATED    (exit 1)
#    witness: completed=0, inflight=3   (3 parallel fires commit 300 > 200)
```

## K-sweep (`--max-inflight`)

`K` is the client-side concurrency pool bound: the max number of in-flight
requests the state space can express. It is **structural, not policy** --
both the correct and the buggy variants share it, because it bounds the
*expressibility* of the model, not the behavior of either. The bug's
visibility depends on it:

| `K` | buggy verdict | witness | why |
|-----|---------------|---------|-----|
| 1 | **PROVEN (masked)** | — | a single in-flight request (100) can never overshoot the 200 cap |
| 2 | VIOLATED | `completed=100, inflight=2` | one settled + two in-flight = 300 > 200 |
| ≥3 | VIOLATED | `completed=0, inflight=3` | the clean 3-parallel-fire signature (stable through K=6) |

```bash
# K=1: the race is structurally unexpressible -> the buggy policy looks PROVEN
python pipeline.py --policy tests/fixtures/aws_dogwood/spendcap/policies/spendcap-buggy.dw --max-inflight 1
# -> spendcap_within_cap PROVEN      (exit 0)   <- false negative, masked

# K=2: one parallel fire pair already breaks the cap
python pipeline.py --policy tests/fixtures/aws_dogwood/spendcap/policies/spendcap-buggy.dw --max-inflight 2
# -> spendcap_within_cap VIOLATED    (exit 1)
#    witness: completed=100, inflight=2

# K=3 (default 4): the clean parallel-fire witness
python pipeline.py --policy tests/fixtures/aws_dogwood/spendcap/policies/spendcap-buggy.dw --max-inflight 3
# -> spendcap_within_cap VIOLATED    (exit 1)
#    witness: completed=0, inflight=3
```

Takeaway: a `PROVEN` result for a concurrency-sensitive policy is only as
strong as its `K`. Sweeping `K` (1, 2, 3, …) separates a *masked* bug from a
genuinely safe one, and the witness shape tells you how many parallel fires
the violation needs.

## Three-engine crosscheck (`--engine crosscheck`)

Crosscheck verifies the same linearized model with **three independent
engines** — SMT (Z3, `rot.symbolic`), the TLC model checker (`rot.tlc`), and
the policy-direct SMT engine (`rot.policy_smt`) — and joins their results into
a single verdict:

| SMT/Z3 | TLC | policy-direct | joined verdict |
|--------|-----|---------------|----------------|
| proven | proven | proven | **PROVEN** |
| violated | violated | violated | **VIOLATED** (counterexample) |
| anything else | | | **UNKNOWN** (never read as proven) |

The three engines span two axes of independence: *engine* independence (SMT/Z3
and TLC are independent model checkers over the same IR state-machine) and
*model* independence (the policy-direct engine checks a different model family
— a direct Z3 encoding of the policy obligation over a bounded event sequence,
not the transition system). A soundness leak in one model family cannot hide
a bug in the other.

A single engine can never mint a verdict on its own: `PROVEN` requires
*all three* engines to prove, `VIOLATED` *all three* to violate, and a
disagreement between any engines is reported as `unknown`. The summary prints
the three engines side by side with each engine's counterexample:

```
  engine         status      counterexample
  smtz3          violated    {"completed": 0, "inflight": 3}
  tlc            violated    {"completed": 0, "inflight": 3}
  policy_direct  violated    {"completed": 0, "inflight": 3}
  agreement      smtz3=violated  tlc=violated  policy_direct=violated  joined=violated  -> AGREE
  witness        MATCH (all three engines -> same attack state)
```

Each run still writes the standard per-run report
(`<out>/<target>_<property>.json`). On top of that, the curated
**crosscheck report** is built with `python -m rot.crosscheck`, which
records the per-engine status, each engine's counterexample, the
agreement flag, and any third-party **witnesses** — e.g. an Apalache ITF
counterexample trace replayed against the pinned property through
`rot.itf`:

```bash
# 1) Run the three-engine crosscheck (writes the per-run report).
python pipeline.py --policy tests/fixtures/aws_dogwood/spendcap/policies/spendcap-buggy.dw \
    --engine crosscheck --out out

# 2) Build crosscheck_report.json, with the Apalache ITF trace as a
#    third-party witness (replayed via rot.itf; a non-refuting trace is
#    recorded as 'unknown', a broken one as 'error' — never a false pass).
python -m rot.crosscheck out/spendcap-buggy_spendcap_within_cap.json \
    --witness apalache-itf=tests/fixtures/aws_dogwood/spendcap/apalache-buggy.itf.json \
    --out out/crosscheck_report.json
```

`crosscheck_report.json` (schema v1):

```jsonc
{
  "report": "crosscheck", "version": 1,
  "target": "spendcap-buggy", "property": "spendcap_within_cap",
  "verdict": "violated",
  "engines": {
    "smtz3": { "status": "violated", "note": "..." },
    "tlc":   { "status": "violated", "note": "...", "n_states": 5 },
    "policy_direct": { "status": "violated", "note": "...",
                       "model": "direct_policy" }
  },
  "counterexamples": {
    "smtz3": { "completed": 0, "inflight": 3 },
    "tlc":   { "completed": 0, "inflight": 3 },
    "policy_direct": { "completed": 0, "inflight": 3 }
  },
  "witnesses": [
    { "name": "apalache-itf", "status": "violated",
      "note": "Apalache ITF trace '...itf.json' refutes invariant ... at state 3 of 4",
      "counterexample": { "completed": 0, "inflight": 3 },
      "source": "tests/fixtures/aws_dogwood/spendcap/apalache-buggy.itf.json" }
  ],
  "agreement": { "smtz3": "violated", "tlc": "violated", "policy_direct": "violated",
                 "joined": "violated", "agree": true, "witness_match": true },
  "note": "crosscheck: smtz3=violated tlc=violated policy_direct=violated -> violated (all three engines agree)"
}
```

Notes:

- `agree` is `true` only when **all three** engines mint the same decision;
  witnesses (Apalache ITF, ...) are *evidence alongside* the join and
  never change it — the join is a pure function of the three engine statuses.
- `witness_match` is `true` when all three engines produce the same
  counterexample state (the same attack).
- A witness replay can only refute, never prove: a trace that never
  refutes the invariant is recorded as `unknown`, and a structural parse
  failure as `error`. Both are listed verbatim in `witnesses` with their
  status; the report build and the verdict are unaffected.
- `--witness` is repeatable for multiple named witnesses
  (`--witness NAME=PATH`); without `--out` the report is written next to
  the per-run report as `crosscheck_report.json`.

## Three-facet audit (`--trifecta`)

`--trifecta` switches from a single pinned property to the three-facet audit
(safety + liveness + conformance) on the `AgentStep` model. It takes an
action policy on the command line instead of a policy file, and is mutually
exclusive with `--policy`.

| flag | meaning |
|------|---------|
| `--trifecta` | run the three-facet audit (requires `--allowed` and/or `--denied`) |
| `--allowed ACTIONS` | comma-separated allowed actions (e.g. `read_log,update_balance`) |
| `--denied ACTIONS` | comma-separated denied actions (e.g. `exfiltrate_secret`) |
| `--buggy` | audit the **adversarial** agent (denied actions left enabled) |
| `--liveness-horizon B` | bounded-liveness horizon for the liveness facet [default: 12] |
| `--manifest` | write the deterministic report to `<out>/trifecta_manifest.json` and the D6 risk flag to `<out>/trifecta_risk.json` |

```bash
# Conforming agent: all three facets proven -> exit 0.
python pipeline.py --trifecta \
    --allowed read_log,update_balance \
    --denied exfiltrate_secret \
    --manifest --out out

# Adversarial agent: safety violated -> exit 1.
python pipeline.py --trifecta \
    --allowed read_log \
    --denied exfiltrate_secret \
    --buggy

# Verify a manifest's integrity (SHA-256 manifest_id over the canonical body):
python -c "import json,sys; from rot import manifest; \
    ok,cid,note = manifest.verify_manifest(json.load(open(sys.argv[1]))); \
    print(ok, cid[:16], note)" out/trifecta_manifest.json
```

The manifest is a pure function of `(policy, environment)`: the same inputs
always yield the same `manifest_id`, so `verify` with an `expected_id`
reproduces the exact report.

### D6 "Lethal Trifecta" risk flag

`--trifecta` also runs the D6 design-time risk flag (`rot.trifecta_risk`):
a static capability check over the policy's full action set
(`allowed ∪ denied`) — no engine, no model checking, no soundness claim.
It prints one line in the summary:

| facets present in the action set | flag |
|----------------------------------|------|
| all three: `private-data-access` + `untrusted-content-intake` + `egress` | `TRIFECTA: detected (facets: private-data-access, untrusted-content-intake, egress)` |
| any facet missing | `TRIFECTA: clear` |

With `--manifest` the flag is also written to `<out>/trifecta_risk.json`
(deterministic: `detected`, `facets`, `missing`, `message`). It is
**informational only** — it never changes the audit result or the exit code.

```bash
# Two facets (private-data-access + egress) -> clear:
python pipeline.py --trifecta \
    --allowed read_log,update_balance \
    --denied exfiltrate_secret \
    --manifest --out out
# -> risk      : TRIFECTA: clear

# All three facets -> detected:
python pipeline.py --trifecta \
    --allowed read_private_ledger,fetch_external_quote,update_balance \
    --denied exfiltrate_secret \
    --manifest --out out
# -> risk      : TRIFECTA: detected (facets: private-data-access, untrusted-content-intake, egress)
```

## Related

- Fixture README (IR model, counterexample trace, atom → action mapping):
  `tests/fixtures/aws_dogwood/spendcap/README.md`
- Demo scripts: `demo.ps1` (PowerShell), `demo.sh` (bash)
- Agent Mode (Cedar / Dogwood-JSON policies): [`agent-mode.md`](agent-mode.md)
