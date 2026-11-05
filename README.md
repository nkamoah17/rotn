<p align="center">
  <img src="assets/caravel_logo.jpeg" alt="ROTN" width="160"/>
</p>

<h1 align="center">ROTN — Regression-detection Oracle via Trace Non-emptiness</h1>

> **Agents are replacing the software that used to enforce our rules. ROTN makes the rules explicit, proves the policy holds even when the model tries to break it, and coaches the agent back in bounds when it does.**

**ROTN** (R**o**gression-detection **O**racle via **T**race **N**on-emptiness) is a small, fully offline, pure-stdlib (Python 3.8+) verification engine for **AI agent tool policies**. It checks a policy against a named invariant with **three independent engines** (SMT/Z3, TLC, and policy-direct — the two independent model checkers decide, with the spend-cap-specific policy-direct engine as the third, model-independent leg and offline fallback) and a **bounded re-check** loop; on a finding it hands back a **concrete, replayable counterexample** and a **coach** that tells the agent exactly what to do to get back in bounds.

The beachhead is the **spend-cap parallel-fire bug** — a payments policy that settles spend only against *settled* responses, so a parallel burst of in-flight requests overshoots the cap, invisible to a per-request monitor.

---

## The problem

Agents now execute tool calls against real systems. Their safety is encoded in a *policy* — a Cedar or Dogwood rule, or an MCP manifest. But a policy that reads correctly on paper can still be **wrong under concurrency**, and the bug is invisible to a per-request monitor.

The spend-cap bug is the canonical example. The policy sums spend over *settled* responses, so in-flight (issued, not-yet-responded) requests are invisible to the sum. A parallel burst of three `$100` fires each passes the per-request check (each sees `sum = 0`), but the committed total is **`$300` — over the `$200` cap**.

ROTN finds this by model-checking the policy over the adversarial agent's tool-call sequences, and returns a **concrete witness**: `{"completed": 0, "inflight": 3}`.

## Six ways agent policies fail under concurrency

A policy that reads correctly on paper is still wrong when requests overlap.
ROTN names the six bug classes — the **APW catalog** — and proves each one with
a concrete, replayable witness (see [`docs/apw-catalog.md`](docs/apw-catalog.md)):

| APW | Weakness | Why a per-request monitor misses it | Witness |
|-----|----------|--------------------------------------|---------|
| **APW-1** | Settled-sum cap bypass | each in-flight fire sees settled = 0; a burst commits past the cap | `{"completed": 0, "inflight": 3}` |
| **APW-2** | Approval replay | a bare `formerly` fact is sticky — one approval admits N orders | `{"approved": true, "orders": 2}` |
| **APW-3** | Taint race | egress admitted *while* the taint is still held | `{"holding_private": true, "exfiltrated": true}` |
| **APW-4** | Distinct-count race | in-flight sends to new recipients outgrow the cap before any settle | `{"distinct": 4, "counted": 0}` |
| **APW-5** | Session splitting | the per-session counter resets per event, so N sessions each admit K | `{"session_count": 4, "scope_count": 1}` |
| **APW-6** | Window-boundary burst | the counter hard-resets at the edge → K before + K after is a 2× burst | `{"count": 1, "total": 4}` |

**The K-sweep** is the single most informative view of the bug: the buggy
policy is **VIOLATED at every K** (the corrected policy stays **PROVEN** at
every K), and the *witness shape tracks K* — K=1 the sequential off-by-one,
K≥2 the parallel-fire signature:

| K (pool) | buggy policy | witness | corrected policy |
|----------|--------------|---------|------------------|
| 1 | `VIOLATED` | `{"completed": 200, "inflight": 1}` (sequential off-by-one) | `PROVEN` |
| 2 | `VIOLATED` | `{"completed": 100, "inflight": 2}` | `PROVEN` |
| 3 | `VIOLATED` | `{"completed": 0, "inflight": 3}` (parallel fire) | `PROVEN` |

## 60-second run

```bash
pip install rotn            # pure stdlib, zero runtime deps, fully offline

# 1. The buggy policy -> VIOLATED + a concrete counterexample (exit 1)
rot check --policy samples/spendcap-buggy.dw --out out
#    verdict : VIOLATED
#    witness : {"completed": 0, "inflight": 3}

# 2. Replay the counterexample (it still holds)
rot replay out/attack.jsonl --policy samples/spendcap-buggy.dw

# 3. The corrected policy -> PROVEN (exit 0)
rot check --policy samples/spendcap-correct.dw --out out-correct

# 4. The K-sweep: the witness shape tracks K (K=1 sequential off-by-one, K>=2 parallel fire)
rot check --policy samples/spendcap-buggy.dw --max-inflight 1   # VIOLATED (witness {"completed": 200, "inflight": 1})
rot check --policy samples/spendcap-buggy.dw --max-inflight 2   # VIOLATED (witness {"completed": 100, "inflight": 2})
```

Every command is deterministic, offline, and exit-code aware (`0` proven · `1` violated · `2` unknown · `3` error). `rot demo` runs the whole story in one command.

## What it finds

- **A concrete, replayable counterexample** — not just "unsafe", but the exact state that breaks the invariant, and a replay that re-derives it.
- **Six named bug classes** — the [APW catalog](docs/apw-catalog.md): settled-sum cap bypass, approval replay, taint race, distinct-count race, session splitting, and window-boundary burst — each with a buggy/correct pair and an oracle-verified witness.
- **A K-sweep** — the buggy policy is VIOLATED at every K, and the witness shape tracks K (K=1 sequential off-by-one, K≥2 parallel-fire signature).
- **A verdict per policy** — `PROVEN` / `VIOLATED` / `UNKNOWN` (never a silent `SAFE`), with an honest coverage matrix over a whole corpus (`rot corpus`).
- **A coach** — a runtime guard that decides one live tool call against the *same guard* the offline engine proved safe; a denial is a computed remediation (`to_proceed`), not a log line.
- **A deterministic, hashed trace** — replays as an interactive proof on GitHub Pages, with a re-verify command.

## How to integrate

**CLI** (the product surface):

| command | what it does |
|---------|-------------|
| `rot check --policy FILE` | check one policy (Dogwood `.dw` / Cedar `.cedar` / MCP manifest) |
| `rot ai` | the AI-authored loop: intent → AI policy (`.rego`/`.ap2`/`.dw`) → verdict |
| `rot replay FILE --policy FILE` | replay a counterexample |
| `rot corpus --corpus-dir DIR` | classify a whole policy corpus (verdict + witness + coverage matrix) |
| `rot ci --policy FILE --out DIR` | CI gate: verdict + JUnit XML + SARIF |
| `rot demo` | the full story (rule → attack → proof → coach → attestation) |
| `rot runtime eval` | decide one live tool call (the runtime coach) |

**Python API**:

```python
from rot.frontends.policy import build_ir
from rot.modelfind import ModelFinder

ir = build_ir("samples/spendcap-buggy.dw")
holds, counter = ModelFinder.from_ir(ir).forall_reachable(ir.pinned_property.eval)
# holds   -> False   (the invariant is violated)
# counter -> {"completed": 0, "inflight": 3}
```

**CI**: the suite is pure-stdlib (no Java, no Z3, no network) and green in a bare Python env — **1025 tests**, deterministic, exit-code aware. See `.github/workflows/rotn.yml` (tests) and `.github/workflows/publish.yml` (PyPI).

## License — all Apache-2.0, one product

ROTN is **all Apache-2.0** — every line of code in this repo (the proof core
*and* the commercial service layer) is licensed under the same permissive
Apache-2.0.  There is no open-core split, no source-available tier, and no
local license gate.

The paid product is not a license on this code — it is the **hosted service**
(the cloud runtime coach, the fleet aggregate, and the signed attestations),
which is not in this repo.

| What | License |
|------|---------|
| This repo (the `rot` core **and** the `rot.commercial` layer) | **Apache-2.0** |
| The hosted service (cloud runtime coach, fleet aggregate, signed attestations) | a **service**, not a license |

`pip install rotn` (the core) · `pip install rotn-commercial` (the service layer).
See [`docs/licensing.md`](docs/licensing.md) for the full position.

## Go deeper

- [`docs/positioning.md`](docs/positioning.md) — **the positioning: AgentCore writes the policy, ROTN proves it can't be bypassed** (the two facts, the complementary-not-competing stance, the multi-language neutral checker, and the AP2 mandate mapping)
- [`docs/apw-catalog.md`](docs/apw-catalog.md) — **the APW catalog: six ways agent policies fail under concurrency** (the named bug classes, each with a buggy/correct pair, a lowering, and an oracle-verified witness)
- [`docs/architecture.md`](docs/architecture.md) — the pipeline, the engines, the bounded re-check
- [`docs/spendcap-demo.md`](docs/spendcap-demo.md) — the demo walkthrough
- [`docs/spendcap-usage.md`](docs/spendcap-usage.md) — the CLI reference
- [`docs/agent-mode.md`](docs/agent-mode.md) — the agent / policy plane
- [`docs/manifest-format.md`](docs/manifest-format.md) — the deterministic trace format
- [`docs/replay.md`](docs/replay.md) — the interactive proof
- [`docs/compliance.md`](docs/compliance.md) — SOC 2 / AIUC control mapping
- [`docs/licensing.md`](docs/licensing.md) — the full licensing position

The protocol plane (2PC / ZAB / PBFT / Payment) lives in the research repo (`rotn-research`), not this build.
