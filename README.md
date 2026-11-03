<p align="center">
  <img src="assets/caravel_logo.jpeg" alt="ROTN" width="160"/>
</p>

<h1 align="center">ROTN — Regression-detection Oracle via Trace Non-emptiness</h1>

> **Agents are replacing the software that used to enforce our rules. ROTN makes the rules explicit, proves the policy holds even when the model tries to break it, and coaches the agent back in bounds when it does.**

**ROTN** (R**o**gression-detection **O**racle via **T**race **N**on-emptiness) is a small, fully offline, pure-stdlib (Python 3.8+) verification engine for **AI agent tool policies**. It checks a policy against a named invariant with **three independent engines** (SMT/Z3, TLC, and policy-direct) and a **bounded re-check** loop; on a finding it hands back a **concrete, replayable counterexample** and a **coach** that tells the agent exactly what to do to get back in bounds.

The beachhead is the **spend-cap parallel-fire bug** — a payments policy that settles spend only against *settled* responses, so a parallel burst of in-flight requests overshoots the cap, invisible to a per-request monitor.

---

## The problem

Agents now execute tool calls against real systems. Their safety is encoded in a *policy* — a Cedar or Dogwood rule, or an MCP manifest. But a policy that reads correctly on paper can still be **wrong under concurrency**, and the bug is invisible to a per-request monitor.

The spend-cap bug is the canonical example. The policy sums spend over *settled* responses, so in-flight (issued, not-yet-responded) requests are invisible to the sum. A parallel burst of three `$100` fires each passes the per-request check (each sees `sum = 0`), but the committed total is **`$300` — over the `$200` cap**.

ROTN finds this by model-checking the policy over the adversarial agent's tool-call sequences, and returns a **concrete witness**: `{"completed": 0, "inflight": 3}`.

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

# 4. The K-sweep: the pool size is the whole story (K=1 masks, K>=2 exposes)
rot check --policy samples/spendcap-buggy.dw --max-inflight 1   # PROVEN   (masked)
rot check --policy samples/spendcap-buggy.dw --max-inflight 2   # VIOLATED (exposed)
```

Every command is deterministic, offline, and exit-code aware (`0` proven · `1` violated · `2` unknown · `3` error). `rot demo` runs the whole story in one command.

## What it finds

- **A concrete, replayable counterexample** — not just "unsafe", but the exact state that breaks the invariant, and a replay that re-derives it.
- **A K-sweep** — the pool size that masks vs. exposes the bug (K=1 masks, K≥2 exposes).
- **A verdict per policy** — `PROVEN` / `VIOLATED` / `UNKNOWN` (never a silent `SAFE`), with an honest coverage matrix over a whole corpus (`rot corpus`).
- **A coach** — a runtime guard that decides one live tool call against the *same guard* the offline engine proved safe; a denial is a computed remediation (`to_proceed`), not a log line.
- **A deterministic, hashed trace** — replays as an interactive proof on GitHub Pages, with a re-verify command.

## How to integrate

**CLI** (the product surface):

| command | what it does |
|---------|-------------|
| `rot check --policy FILE` | check one policy (Dogwood `.dw` / Cedar `.cedar` / MCP manifest) |
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

**CI**: the suite is pure-stdlib (no Java, no Z3, no network) and green in a bare Python env — **848 tests**, deterministic, exit-code aware. See `.github/workflows/rotn.yml` (tests) and `.github/workflows/publish.yml` (PyPI).

## License — open-core

ROTN is **open-core**. The proof is open (the credibility wedge); the commercial layer is **source-available** (the business).

| Layer | What's in it | License |
|-------|--------------|---------|
| **Open core** | the bounded engine, the spend-cap policy class, the deterministic counterexample + K-sweep, the tests, the one-pager generator, the CI gate | **Apache-2.0** |
| **Commercial** | the runtime coach as a service, fleet near-miss learning, risk forecasting, the agent-framework / payment / MCP integrations, attestation-as-a-service | **SSPL-1.0** or commercial |

`pip install rotn` (Apache-2.0 core) · `pip install rotn-commercial` (the commercial layer).

## Go deeper

- [`docs/architecture.md`](docs/architecture.md) — the pipeline, the engines, the bounded re-check
- [`docs/spendcap-demo.md`](docs/spendcap-demo.md) — the demo walkthrough
- [`docs/spendcap-usage.md`](docs/spendcap-usage.md) — the CLI reference
- [`docs/agent-mode.md`](docs/agent-mode.md) — the agent / policy plane
- [`docs/manifest-format.md`](docs/manifest-format.md) — the deterministic trace format
- [`docs/replay.md`](docs/replay.md) — the interactive proof
- [`docs/compliance.md`](docs/compliance.md) — SOC 2 / AIUC control mapping
- [`docs/licensing.md`](docs/licensing.md) — the full licensing position

The protocol plane (2PC / ZAB / PBFT / Payment) lives in the research repo (`rotn-research`), not this build.
