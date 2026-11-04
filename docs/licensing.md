# ROTN licensing — one license, one product

ROTN is **all Apache‑2.0** — every line of code in this repo (the proof core
*and* the commercial service layer) is licensed under the same permissive
Apache‑2.0.  There is no open‑core split, no source‑available tier, and no
local license gate.

The paid product is not a license on this code.  It is the **hosted service**:
the cloud version of the runtime coach (`rot runtime serve`), the fleet
near‑miss aggregate, the risk forecast, and the **signed attestations** —
operated as a service, with the signing keys held by the operator.  That
hosted product is **not** in this repo; this repo is the full, unredacted,
Apache‑2.0 source you can read, use, fork, and self‑host.

| What | License |
|------|---------|
| This repo (the `rot` core **and** the `rot.commercial` layer) | **Apache‑2.0** |
| The hosted service (cloud runtime coach, fleet aggregate, signed attestations) | a **service**, not a license — you buy the operation, not the code |

## Why Apache‑2.0 for everything

Apache‑2.0 is permissive like MIT, **plus** it carries the explicit **patent
grant** (and the patent‑termination defense) that MIT lacks.  A contributor's
patents are licensed to you, and if they sue you over them, the license
terminates.  That is the one "stronger than MIT" upgrade that actually matters
for a security product, and it is the license to ship for the credibility
wedge — the part that must be unambiguously free and safe to build on.

Applying it to *every* line (not just the core) is deliberate:

- **One license, no ambiguity.** A reader never has to ask "is this file the
  free core or the source‑available layer?" — it is Apache‑2.0, full stop.
- **The proof is the credibility wedge.** The counterexample, the K‑sweep, the
  attestation hash, and the re‑verify command must be unambiguously free and
  reproducible.  A single, permissive license across the whole repo makes that
  true by construction.
- **The moat is the service, not the license.** Revenue comes from operating
  the hosted service (the fleet aggregate, the signed attestations, the SLA) —
  not from restricting the code.  A license that only *deters* (like SSPL) is a
  weaker position than a permissive license plus a service that is genuinely
  hard to replicate.

## What the paid product is (and is not)

The paid product is the **hosted service**:

- The **runtime coach as a service** — `rot runtime serve` operated in the
  cloud, with the MCP `tools/call` gateway and the LangChain adapter.
- The **fleet near‑miss aggregate** — the cross‑customer learning (4.4) that no
  single self‑hoster can reproduce (they only have their own data).
- The **risk forecast** (4.3) and the **signed attestations** (Product 3) —
  the attestation is signed with the operator's keys, so the signature is a
  statement *by the operator*, not a claim you can mint yourself.

What it is **not**:

- It is **not** a license that unlocks a larger search budget.  The bounded
  engine runs at **full strength for every user** — see below.
- It is **not** a gate on the code in this repo.  Everything here is Apache‑2.0;
  you can self‑host the entire `rot.commercial` layer today.


## The audit is full-strength for everyone (no budget tiers)

There is **no free/paid budget split** and **no local license gate**.  The
bounded engine runs at **full strength for every user**:

- `resolve_budget()` returns the generous full-strength defaults
  (`FREE_LIMITS`) by default.  There is no tier to resolve and no key to
  check.
- The only thing that can *cap* a run is a **user-set depth bound**
  (`--depth` or an explicit `DepthBudget`), which may only *lower* the budget
  — it can never raise it.  That is a user choice, not a license.
- There is no public default signing key and no HMAC license check.  Signing /
  verification of attestations is a **service** capability (the operator holds
  the keys), not a budget privilege.

So a self-hosted Apache‑2.0 user gets the same proof, at the same strength, as
anyone else.  The `budget` block in an RTF v1 trace records the *source* of the
budget (`"free"` for the full-strength defaults, or a user-supplied label for a
depth-bound) — it is provenance, not a tier.

## Where this lives in the repo

- `LICENSE` (top level) — **Apache‑2.0**, governs the whole repo.
- `rot/` — the proof core (the bounded engine, the spend-cap policy class, the
  deterministic counterexample, the tests, the one-pager generator, the CI
  gate).  Apache‑2.0.
- `rot/commercial/` — the service layer (the runtime coach as a service, the
  LangChain adapter, the MCP `tools/call` gateway, the fleet aggregate, the G8
  behavioral audit, the Lethal-Trifecta risk surface).  Apache‑2.0.
- `rot/commercial/LICENSE` — **Apache‑2.0** (identical to the root `LICENSE`).
- `setup.py` — the `rotn` distribution (the core); **excludes** `rot.commercial`.
- `setup_commercial.py` — the `rotn-commercial` distribution (the service
  layer); depends on `rotn`.
- `rotn-research/` — the research plane (ZAB/PBFT/2PC/CPG‑4/A‑B), a **separate
  repo** that depends on the core and is never imported by it.

## What is and is not in this repo

**In** this repo (all Apache‑2.0): `rot demo` end-to-end, the bounded engine,
the spend-cap policy class, the deterministic counterexample + K-sweep, the
one-pager generator, the attestation hash + re-verify command, the service
layer (`rot runtime serve`, the LangChain adapter, the MCP gateway, the fleet
aggregate, the G8 behavioral audit, the Lethal-Trifecta risk surface), the
917-test product suite (count pinned by `tests/test_suite_count.py`), and the
CI gate.

**Not** in this repo: the **hosted service** — the cloud operation of the
runtime coach, the cross-customer fleet aggregate, the risk forecast, and the
**signed attestations** (the operator's signing keys and the service SLA).
That is the paid product: you buy the *operation* and the *signature*, not the
code.