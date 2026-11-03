# ROTN licensing — the open-core position

ROTN is **open-core**: the proof is open (that is the credibility wedge); the
commercial layer is **source-available** (that is the business).  Two licenses,
two layers:

| Layer | What's in it | License |
|-------|--------------|---------|
| **Open core** (the wedge + credibility) | the bounded engine, the spend‑cap policy class, the deterministic counterexample, the tests, the one‑pager generator, the CI gate | **Apache‑2.0** |
| **Commercial** (source-available, the business) | the runtime coach **as a service** (Product 2), fleet near‑miss learning (4.4), risk forecasting (4.3/DBN), the agent‑framework / payment / MCP integrations, attestation‑as‑a‑service (Product 3), the B2 generalization (sequences, flow‑proof, real liveness), enterprise support | **SSPL‑1.0** or a commercial license |

## Why Apache‑2.0 (not MIT) for the core

Apache‑2.0 is permissive like MIT, **plus** it carries the explicit **patent
grant** (and the patent‑termination defense) that MIT lacks.  That is the one
"stronger than MIT" upgrade that actually matters for a security product: a
contributor's patents are licensed to you, and if they sue you over them, the
license terminates.  For the credibility wedge — the part that must be
unambiguously free and safe to build on — that is the license to ship.

## Why SSPL‑1.0 (source-available, not proprietary) for the commercial layer

The commercial layer's source is right here in the repo — it is **source-available**,
free to read, use, and self-host.  SSPL‑1.0 is the license that keeps it that way
without going proprietary: it still lets you offer a **hosted** version, but
requires anyone who offers the software **as a service** to open‑source their
**entire service stack**, or to buy a license.  That bites the specific threat
we actually face — a competitor hosting a clone of this layer — while still
letting the core be free.

Two honest notes (do not skip these):

1. **SSPL is a deterrent, not a moat.** It still does not stop a clean‑room or
   LLM‑assisted independent build, and it can scare off some enterprise buyers
   (copyleft anxiety).  Use it on the SaaS layer only.
2. **Open‑core only pays if the commercial layer is thick.** If the commercial
   part is thin, everyone uses the free core and you earn nothing.  So the
   commercial layer must be genuinely hard to replicate.

## The fleet-data delta is the product

A self‑hosted user of the free core gets **their** near‑misses.  A customer of
the service gets the **aggregate of everyone's** — the fleet learning (4.4), the
risk forecast (4.3), the attestation pipeline.  That aggregate delta is the
product.  No single self‑hoster can reproduce it; they only have their own
data.

## The one-line license position

> **Apache‑2.0 core** (the proof is open — that's the credibility wedge),
> **SSPL‑1.0 on the service + fleet learning + integrations** (source-available,
> not proprietary).  Keep the wedge, keep the revenue, and hold a legal lever on
> the specific "hosted clone of this layer" threat.

## Where the split lives in this repo

- `LICENSE` (top level) — **Apache‑2.0**, governs the `rot` core.
- `setup.py` — the free `rotn` distribution; **excludes** `rot.commercial`.
- `rot/commercial/` — the commercial layer (source-available; `rot.commercial` + `rot.commercial.runtime`).
- `rot/commercial/LICENSE` — **SSPL‑1.0 / commercial**, governs the commercial layer.
- `setup_commercial.py` — the `rotn-commercial` distribution (depends on `rotn`).
- `rotn-research/` — the research plane (ZAB/PBFT/2PC/CPG‑4/A‑B), a **separate
  repo** that depends on the core and is never imported by it.

## The audit is full-strength for everyone (no budget tiers)

Do not confuse the **open-core split above** with a runtime budget.  The "free"
and "commercial" in this document refer to **which code is Apache‑2.0 vs SSPL**
— they are *not* audit-budget tiers.  The bounded engine itself runs at
**full strength for every user**: no license or tier unlocks a larger search
budget, and there is no public default license key (signing/verification is
simply unavailable without a `$ROTN_LICENSE_KEY`).  The only things that can
cap a run are the user's own choices — an explicit `--depth` bound, or a
license file the user supplies (the license is the highest authority and the
only thing that can shrink the budget).  So a self‑hosted Apache‑2.0 user gets
the same proof, at the same strength, as anyone else.

## What is and is not in the free core

**In** the free core (Apache‑2.0): `rot demo` end-to-end, the bounded engine,
the spend‑cap policy class, the deterministic counterexample + K‑sweep, the
one‑pager generator, the attestation hash + re‑verify command, the 848-test
product suite (count pinned by `tests/test_suite_count.py`), and the CI gate.

**Not** in the free core (commercial, SSPL‑1.0): `rot coach --aggregate`
(fleet learning), `rot runtime serve` (the MCP gateway / LangChain adapter),
`rot mcp behavior` (G8 behavioral audit), the Lethal‑Trifecta risk surface, and
attestation‑as‑a‑service.  The CLI *exposes* these commands for a commercial
install; on a core-only install they degrade to a clear "install
rotn-commercial" error rather than a raw traceback.