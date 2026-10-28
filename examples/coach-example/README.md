# Worked example: coaching a buggy spend-cap back in bounds, *with a proof*

This is the **third leg of the ROTN triad** (Rule → Proof → **Coach**) in
action. A policy the agent wrote is unsafe (a spend-cap that only charges
*settled* transfers, so a parallel burst of in-flight fires overshoots the
cap). Instead of a verbal "that looks wrong," ROTN produces a
**CoachingArtifact**: the violation witness, a plain-English rationale, the
*corrected* policy, and a **re-proof** that the correction is safe.

## The bug (one word)

`spendcap-buggy.dw` sums over `Transfer::response` rows (settled
completions). In-flight (issued, not-yet-responded) transfers are invisible
to the sum, so three parallel `fire(amount=100)` calls each see `sum=0` and
are each admitted — committed = 300 > the 200 cap. The one-word fix is
`response` → `request` (charge in-flight against the cap).

## Run it

```powershell
# Windows PowerShell
rot coach --policy spendcap-buggy.dw --max-inflight 3 --out coaching.json
```

```sh
# POSIX
rot coach --policy spendcap-buggy.dw --max-inflight 3 --out coaching.json
```

or, without a venv on PATH, directly:

```sh
python -m rot coach --policy spendcap-buggy.dw --max-inflight 3 --out coaching.json
```

## What you get

A deterministic, SHA-256-hashed `coaching.json` — the **CoachingArtifact**
(`caravel.coach/v1`) — recording the 5-step loop:

```
  COACHING: CLOSED
  detect    : violated {"completed": 0, "inflight": 3}
  explain   : ...the 3 in-flight requests are invisible to the decision:
              each of the 3 parallel fires sees completed=0 and is admitted,
              pushing total exposure to 300 -- past the cap of 200.
  correct   : response -> request (charge in-flight against the cap)
  recheck   : proven
  hash      : d19933b9ccbbabf7dca334e51cabb6e1a0040334e0eab17f1396dc2b57821951
```

| step    | what it records                                                        |
|---------|------------------------------------------------------------------------|
| detect  | the engine verdict on the buggy policy + the witness (the counterexample) |
| explain | the plain-English rationale, *derived from the witness*                |
| correct | the corrected policy (the `request`-sum variant) + the guard delta     |
| recheck | the engine verdict on the corrected policy (**proven**)                |
| close   | the discharge: the coaching is **closed** because the correction re-proved |

## Why "coach + proof" is the point

Reflexion and Self-Refine coach an LLM with *verbal* feedback — a critique the
model may or may not act on; neither produces a **guarantee**. Dogwood is a
runtime monitor: it decides one request against the settled trace. ROTN's
coaching is different: the correction is **discharged by a proof**. The
`recheck` step runs the same bounded-exhaustive engine that found the
violation, and the artifact is `closed` **only** when the corrected policy is
`proven` within the recorded bound. If the correction does not re-prove, the
artifact is `open` — never silently "coached" (fail-closed).

The artifact is a **pure function** of the policy + the model knobs
(`--max-inflight`, `--amount`, `--cap`, `--window`): no timestamps, no random
IDs — the same input always yields the same `hash`, so it can be referenced,
compared, and re-verified byte-for-byte, exactly like the RTF trace.