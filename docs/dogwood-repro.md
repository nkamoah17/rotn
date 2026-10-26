# Reproducing the AWS Dogwood spend-cap concurrency bug — one command

This is the end-to-end, reproducible demonstration that the seeded
`Transfer::request` vs `Transfer::response` summation bug in the AWS Dogwood
spend-cap policy is **concurrency-dependent**: it is *masked* when the model
can express only one in-flight request, and *exposed* (with a deterministic
witness) as soon as the state space can express ≥2 parallel in-flight fires.

No Java, no TLC jar, no Z3 required for the core demo — it runs entirely on
the offline symbolic engine. The three-engine crosscheck phase degrades
gracefully (skipped, not failed) when TLC or Z3 are absent.

> **Defensible claim.** ROTN does **not** claim to compile arbitrary policy
> text into an equivalent model. It **lowers the spend-cap policy class**
> (aggregate-over-events + cap) to a bounded transition system by a
> **mechanical derivation** from the parsed policy — parameterized on
> amount/cap/pool — and verifies it with **multiple independent engines**
> (Z3 SMT + TLC) **and a second, structurally different model family**
> (direct policy SMT). The three engines span two axes of independence:
> *engine* independence (SMT/Z3 and TLC are independent model checkers over
> the same IR state-machine) and *model* independence (the policy-direct
> engine checks a different model family — a direct Z3 encoding of the policy
> obligation over a bounded event sequence, not the transition system). A
> soundness leak in one model family cannot hide a bug in the other. The
> correspondence between the model and the policy is **checked**, not argued:
> `tests/test_correspondence.py` asserts `model.spend_ok_admits ==
> (policy.sum_over_events <= cap)` point-for-point over a concrete state
> battery, for both event kinds. The policy→model derivation and the
> assumptions it bakes in (uniform `AMOUNT=100`, `CAP=200`, bounded pool `K`)
> are shown explicitly by the demo's `POLICY → MODEL ABSTRACTION` block
> (`python -m rot.spendcap_display <policy.dw>`).
>
> **What we do NOT claim.** No arbitrary-policy compilation. The lowering
> (`rot/lower.py::lower_policy`) reads the parsed structure (the `Sum` node,
> the event reference's `.kind`, the `<= cap` comparison, the `input.amount`
> binding) and constructs the IR — it does not interpret arbitrary Dogwood
> text. Policies outside the spend-cap class (no `Sum` over events, no
> `<= cap` comparison, no `input.amount` binding) are not supported. The
> model's parameters (`amount`, `cap`, `max_inflight`) are canonical defaults
> (100, 200, 4) overridable via CLI flags; the policy's own threshold (e.g.
> `total > 1000` in the promoted corpus policies) is recorded in IR metadata
> but does not drive the model's threshold unless explicitly overridden.

## One command

```powershell
# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File .\demo.ps1
```

```bash
# macOS / Linux (or WSL)
bash demo.sh
```

That's it. One command, five phases, deterministic exit code.

## What the five phases assert

| Phase | Command (abridged) | Expected | Proves |
|-------|--------------------|----------|--------|
| 1 | `--policy spendcap-correct.dw` | exit 0 (PROVEN) | the correct policy is safe |
| 2 | `--policy spendcap-buggy.dw` | exit 1 (VIOLATED, witness) | the buggy policy overshoots the cap |
| 3 | `--trifecta --manifest` | exit 0 (+ manifest + D6 risk flag) | the three-facet audit is sound and reproducible |
| 4 | `--engine crosscheck` | exit 1 (SMT/Z3, TLC, **and** policy-direct agree) | the witness is not an engine *or* model artifact |
| 5 | `--policy spendcap-buggy.dw --max-inflight {1,2,3}` | 0, 1, 1 | **K-dependence**: K=1 masks, K≥2 exposes |

Phase 4 is skipped (not failed) when `java` + `tla2tools.jar` are absent
(TLC) or when Z3 is unavailable (SMT / policy-direct). The join degrades to
UNKNOWN rather than failing. Phases 1–3 and 5 are pure offline.

## The abstraction is shown, not hidden

Before any checking, the demo prints a `POLICY → MODEL ABSTRACTION` block for
each policy — the raw `.dw` text, the parsed fingerprint (event kind + cap), the
exact IR/guard/invariant the engines check, the assumptions the model bakes in
(uniform `AMOUNT=100`, `CAP=200`, bounded pool `K`), and the correspondence
argument (policy obligation → invariant). This makes the *discrimination* claim
auditable: the audience sees exactly which policy maps to which model and what
the model assumes that the raw policy does not say. It is rendered by
`python -m rot.spendcap_display <policy.dw>` (pure stdlib, deterministic, no
engine).

## The K-dependence (Phase 5) in detail

`K` (`--max-inflight`) is the client-side concurrency pool bound: the max
number of in-flight requests the state space can express. It is **structural,
not policy** — both the correct and the buggy variants share it, because it
bounds the *expressibility* of the model, not the behavior of either. The
bug's visibility depends on it:

| `K` | buggy verdict | witness | why |
|-----|---------------|---------|-----|
| 1 | **PROVEN (masked)** | — | a single in-flight request (100) can never overshoot the 200 cap |
| 2 | VIOLATED | `completed=100, inflight=2` | one settled + two in-flight = 300 > 200 |
| ≥3 | VIOLATED | `completed=0, inflight=3` | the clean 3-parallel-fire signature (stable through K=6) |

The one-word diff between the two policies is the entire seeded bug:
summing over `Transfer::request` (issued transfers, in-flight included) is
correct; summing over `Transfer::response` (settled only) lets a parallel-fire
burst of in-flight requests overshoot the cap. At `K=1` that burst is
structurally unexpressible, so the buggy policy *looks* proven — a false
negative that a K-sweep exposes.

## Reading the exit code

| code | meaning |
|------|---------|
| 0 | all phases passed (phase 4 may be skipped if TLC absent) |
| 1 | one or more phases deviated from the expected exit code |
| 3 | no Python interpreter found |

## Verifying the artifacts

Each run writes deterministic JSON under `out/`:

```
out/spendcap-correct.dw_spendcap_within_cap.json     # phase 1
out/spendcap-buggy.dw_spendcap_within_cap.json       # phase 2
out/trifecta_manifest.json                           # phase 3 (integrity-checked)
out/trifecta_risk.json                               # phase 3 (D6 facet check)
out/crosscheck_report.json                           # phase 4 (if TLC present)
```

The manifest carries a content-derived ID and a SHA-256 digest; re-running
produces byte-identical files (deterministic, offline).

## Environment overrides

```bash
ENGINE=tlc bash demo.sh        # force the real TLC for phases 1-2
OUT=out-demo bash demo.sh      # custom output dir
PY=python3 bash demo.sh        # pin the interpreter
```

## Related docs

- [`spendcap-usage.md`](spendcap-usage.md) — full CLI reference, including
  `--max-inflight` and the three-engine crosscheck.
- [`spendcap-demo.md`](spendcap-demo.md) — the human walkthrough of the bug.
