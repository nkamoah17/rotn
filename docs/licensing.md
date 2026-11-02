# ROTN licensing — the open-core position

ROTN is **open-core**, not "open vs. closed."  The proof is open (that is the
credibility wedge); the value is closed (that is the business).  Two licenses,
two layers:

| Layer | What's in it | License |
|-------|--------------|---------|
| **Open core** (the wedge + credibility) | the bounded engine, the spend‑cap policy class, the deterministic counterexample, the tests, the one‑pager generator, the CI gate | **Apache‑2.0** |
| **Paid / commercial** (the business) | the runtime coach **as a service** (Product 2), fleet near‑miss learning (4.4), risk forecasting (4.3/DBN), the agent‑framework / payment / MCP integrations, attestation‑as‑a‑service (Product 3), the B2 generalization (sequences, flow‑proof, real liveness), enterprise support | **SSPL‑1.0** or a commercial license |

## Why Apache‑2.0 (not MIT) for the core

Apache‑2.0 is permissive like MIT, **plus** it carries the explicit **patent
grant** (and the patent‑termination defense) that MIT lacks.  That is the one
"stronger than MIT" upgrade that actually matters for a security product: a
contributor's patents are licensed to you, and if they sue you over them, the
license terminates.  For the credibility wedge — the part that must be
unambiguously free and safe to build on — that is the license to ship.

## Why SSPL‑1.0 (not "closed") for the paid layer

SSPL‑1.0 is the closest thing to the "stronger" license that still lets you
offer a **hosted** version: it requires anyone who offers the software **as a
service** to open‑source their **entire service stack**, or to buy a license.
That bites the specific threat we actually face — a competitor hosting a clone
of the paid layer — while still letting the core be free.

Two honest notes (do not skip these):

1. **SSPL is a deterrent, not a moat.** It still does not stop a clean‑room or
   LLM‑assisted independent build, and it can scare off some enterprise buyers
   (copyleft anxiety).  Use it on the SaaS layer only.
2. **Open‑core only pays if the paid layer is thick.** If the "paid" part is
   thin, everyone uses the free core and you earn nothing.  So the paid layer
   must be genuinely hard to replicate.

## The fleet-data delta is the product

A self‑hosted user of the free core gets **their** near‑misses.  A customer of
the service gets the **aggregate of everyone's** — the fleet learning (4.4), the
risk forecast (4.3), the attestation pipeline.  That aggregate delta is the
product.  No single self‑hoster can reproduce it; they only have their own
data.

## The one-line license position

> **Apache‑2.0 core** (the proof is open — that's the credibility wedge),
> **SSPL / commercial on the service + fleet learning + integrations** (the
> value is closed).  Keep the wedge, keep the revenue, and hold a legal lever on
> the specific "hosted clone of my paid layer" threat.

## Where the split lives in this repo

- `LICENSE` (top level) — **Apache‑2.0**, governs the `rot` core.
- `setup.py` — the free `rotn` distribution; **excludes** `rot.commercial`.
- `rot/commercial/` — the paid layer (`rot.commercial` + `rot.commercial.runtime`).
- `rot/commercial/LICENSE` — **SSPL‑1.0 / commercial**, governs the paid layer.
- `setup_commercial.py` — the `rotn-commercial` distribution (depends on `rotn`).
- `rotn-research/` — the research plane (ZAB/PBFT/2PC/CPG‑4/A‑B), a **separate
  repo** that depends on the core and is never imported by it.

## What is and is not in the free core

**In** the free core (Apache‑2.0): `rot demo` end-to-end, the bounded engine,
the spend‑cap policy class, the deterministic counterexample + K‑sweep, the
one‑pager generator, the attestation hash + re‑verify command, the 844-test
product suite (count pinned by `tests/test_suite_count.py`), and the CI gate.

**Not** in the free core (paid, SSPL/commercial): `rot coach --aggregate`
(fleet learning), `rot runtime serve` (the MCP gateway / LangChain adapter),
`rot mcp behavior` (G8 behavioral audit), the Lethal‑Trifecta risk surface, and
attestation‑as‑a‑service.  The CLI *exposes* these commands for a commercial
install; on a core-only install they degrade to a clear "install
rotn-commercial" error rather than a raw traceback.