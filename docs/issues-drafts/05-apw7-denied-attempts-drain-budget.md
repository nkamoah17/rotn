# APW-7 proposal: "denied attempts drain the budget" (availability bug in request-sum caps)

## Claim

**Request-sum caps count denied attempts.** The Dogwood spec is
explicit: every event is observed before it is decided, and a recorded
request **stays in history even if evaluation then denies it** (formal
spec §6 / §6.1 — observe-before-decide; `docs/agentcore-repro.md` §2).
The APW-1 "correct" fix — summing over `::request` instead of
`::response` — therefore charges *denied* attempts into the window sum.

## The bug (availability)

A single over-cap attempt — correctly denied — drains the window budget
for the rest of the window:

- cap $200, 24h window. Fire **$300** → denied (correct), but the $300
  request stays in history;
- fire **$100** → in-window request sum is 300 + 100 > 200 → **denied**
  (wrong);
- every legitimate call for the rest of the window is denied. The budget
  is gone, spent on an attempt that never executed.

An agent (or a misconfigured client, or an attacker who can induce
calls) can **deny another agent's budget** with one rejected call. The
fail-closed monitor becomes a self-inflicted lockout — and the lockout
lasts the whole window, not the request.

## Why this is a real class, not a misconfiguration

- It is the **mirror image of APW-1**: the response-sum (buggy)
  over-admits (a safety failure); the request-sum (correct)
  under-admits (an availability failure). Neither temporal policy is
  both complete and available — that tension is structural, not
  incidental.
- It is invisible to a per-request monitor by the same mechanism as
  APW-1: each request looks fine against the settled history; only the
  whole-window accounting exposes the drain.
- It is testable in the existing machinery: the lowering + oracle already
  track settled vs. in-flight amounts; the new axis is *denied-but-
  recorded* amounts.

## Proposal (shape + oracle + pair + catalog row)

- **Buggy / correct pair** (`samples/apw7-buggy.dw` /
  `samples/apw7-correct.dw`):
  - buggy: the request-sum that counts denied attempts (the
    availability violation above);
  - correct: a shape that excludes denied attempts from the sum (e.g. a
    `::request` sum filtered on the decision, *if* Dogwood can express
    it) — otherwise the settled+in-flight accounting (ROTN's model) as
    the "correct" reference shape, status `concept` as with APW-5/6.
- **Witness shape (proposed):**
  `{"denied_attempts": 1, "blocked_after": 1, "sum_incl_denied": 400, "cap": 200}`
- **Lowering** in `rot/lower.py` + hand-written oracle in `rot/shapes.py`;
  `tests/test_apw7.py` (buggy → `VIOLATED` with the named witness;
  correct → `PROVEN`); a catalog row in `docs/apw-catalog.md`.
- **Gate status:** `UNKNOWN` until the reference can express the
  denied-attempt filter. If the reference *admits* the drain (i.e. the
  documented semantics really do charge denied attempts), that is a
  **labeled-divergence** candidate under the waiver rules
  (`CONTRIBUTING.md` → "Waiver rules") — not a silent `AGREE`.

## Open questions

1. Does the **live** AgentCore engine charge denied attempts into the
   temporal sum? This is exactly what the E2/E4 controls in ④ (the
   E1–E4 follow-up issue) measure — if the live engine does *not*, the
   live behavior diverges from the documented spec → route via
   `SECURITY.md` §3 (private vendor report first).
2. Can Dogwood express "sum over requests that were allowed" (validator
   + spec)? If not, APW-7's "correct" policy stays a concept class like
   APW-5/6.
3. Should the coach (`rot runtime eval`) *warn* about drain risk when a
   policy is request-sum-based? (Product question — separate issue.)
