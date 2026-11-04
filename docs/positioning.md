# ROTN — Positioning

> Phase 4 deliverable (Fix 4 — *verify the policies AI writes*). This is the
> positioning statement, grounded in two facts about where agent-policy
> authoring is heading. Every claim is runnable on this machine; the
> evidence commands are at the end.

## The one-liner

> **AgentCore writes your Dogwood policy. ROTN proves it can't be bypassed.**

An AI author is now good enough to *write* a correct-looking temporal
policy — that is the point of the shift. Writing a policy and proving the
policy are different jobs. ROTN is the second one.

## The two facts

**Fact 1 — the policies are increasingly written by AI.** AWS's agent stack
(AgentCore) now *authors* Dogwood policies from natural-language intent. The
human no longer hand-writes the policy; a model drafts it. That raises the
stakes of the *verification* step, not the *authoring* step: a fluent,
plausible policy is exactly what an LLM is good at producing, and
exactly what an LLM is not good at *proving correct under concurrency*.

**Fact 2 — the language's own reasoning can't close the gap.** Cedar's
automated reasoning is **point-in-time**: it decides a single request from
its context and the settled history. It has no model of *concurrent,
in-flight* activity, so it cannot check the temporal conditions that agent
policies actually need — "at most K total", "one approval, one action",
"no egress after a read" — *under concurrency*. A bare `formerly within`
fact is sticky; a settled-sum ignores the in-flight set; a per-session
counter resets on every event. Those are the six APW classes
([`apw-catalog.md`](apw-catalog.md)).

Put together: **the author is now a model, and the language's built-in
reasoning is too weak to prove the author's output.** That is the gap ROTN
fills.

## Complementary, not competing

ROTN is **not** a policy language, not an author, and not a rival to Cedar
or Dogwood. It sits *downstream* of them:

```
   intent (NL)  ──►  AI author (e.g. AgentCore)  ──►  policy  (Cedar / Dogwood / Rego / AP2)
                                                                       │
                                                                       ▼
                                                        ROTN  (narrow waist: ProtocolIR)
                                                                       │
                                                                       ▼
                                                        PROVEN / VIOLATED + witness
```

- Cedar / Dogwood **decide** a request (runtime, point-in-time). ROTN
  **proves** a policy (offline, whole-protocol, over all interleavings).
- An AI author **writes** the policy. ROTN **checks** it.
- Each APW entry is a *regression oracle*: buggy draft → `VIOLATED` with a
  named witness; corrected draft → `PROVEN`. That is a test harness for
  generated policies, not a new policy language.

So the relationship is strictly additive: use the author you have, write the
policy in the language you have, and run ROTN to prove it can't be bypassed.

## The AI-authored-policy demo loop (runnable end to end)

The canonical example is **APW-2 (approval replay)** — the exact policy an
AI authoring is most likely to emit: an approval encoded as a *bare, sticky*
temporal fact, so one cart-check admits every later order.

```
rot ai                        # intent -> apw2-buggy.rego -> VIOLATED (exit 1)
rot ai --policy samples/ai_authoring/apw2-correct.rego   # -> PROVEN (exit 0)
```

The loop (`rot/ai_loop.py`, CLI `rot ai`) does four things, in order:

1. **Intent** — reads the natural-language intent
   (`samples/ai_authoring/intent.md`).
2. **AI-authored policy** — the AI's natural first draft, here in Rego
   (`samples/ai_authoring/apw2-buggy.rego`).
3. **Neutral check** — lowers it to the `ProtocolIR` and decides the pinned
   property; cross-checks that the *Dogwood twin* (`samples/apw2-buggy.dw`)
   lowers to a structurally identical IR and the same verdict.
4. **Verdict** — `VIOLATED`, witness `{"approved": true, "orders": 2}` —
   one approval, two orders. The corrected draft is what the proof is about
   (`PROVEN`).

The cross-language check is part of the loop, not an afterthought: because
`ProtocolIR.__eq__` ignores `metadata`, "same IR" is a *structural*
assertion — the front-ends differ only in provenance (`frontend`,
`policy_source`), and the verdict is then identical by construction.

## Multi-language surface (the neutral-checker claim)

ROTN stays the **neutral checker**: the policy can be written in whatever
language the author emits; ROTN lowers it to the same `ProtocolIR` and
decides once. The surface today:

| Language | Status | How it lowers |
|----------|--------|---------------|
| **Dogwood** (`.dw`, `.json`) | full front-end | parses the policy text into the shape (the reference route) |
| **Cedar** (`.cedar`) | full front-end | per-request conformance / realizability |
| **MCP manifests** (`.json`) | full front-end | tool-catalog conformance |
| **OPA (Rego)** (`.rego`) | **stub** front-end | recognises the canonical Rego encoding of a supported shape (`# rotn:shape=`) and lowers it to the *same* `ProtocolIR` as the Dogwood twin |
| **AP2 mandate** (`.ap2`) | **stub** front-end | maps the "spend up to $X on Y" mandate onto the APW shape it instantiates and lowers through the same oracle |

The stubs are deliberately **not** Rego/AP2 interpreters. They recognise the
*canonical encoding* of the supported shapes (APW-1, APW-2, and — for AP2 —
APW-5) and delegate the model to the same oracles the Dogwood route uses
(`rot.spendcap`, `rot.shapes`). That is enough to *prove the neutral-checker
claim* — "the verdict does not depend on the language" — without building
full engines, which is exactly the audit's "freeze everything else"
guidance. The structural-identity tests are the evidence:

```
python -m pytest tests/test_opa_frontend.py tests/test_ap2_frontend.py -q
```

## AP2 mapping write-up ("spend up to $X on Y" → APW)

An **AP2 mandate** is *intent*, not a policy: it says what the agent may do
("spend up to $200 on goods_and_services"), not *how* enforcement is
sequenced over interleaved events. The natural first draft of the
enforcement instantiates one of the APW shapes. The stub
(`rot/frontends/policy/ap2.py`) maps the mandate's facets to the shape, in
priority order (most binding facet wins):

| Mandate facet | Meaning | Instantiates | Why the natural first draft is the buggy variant |
|---------------|---------|--------------|---------------------------------------------------|
| `amount_max` | "spend up to $X" | **APW-1** (settled-sum cap) | charging only *settled* responses is the per-request reading; a parallel burst commits past the cap |
| `single_use` | "one mandate, one payment" | **APW-2** (approval replay) | a bare "mandate present" fact is sticky; one mandate admits N payments |
| `session_scoped` | "up to K per session" | **APW-5** (session splitting) | a per-session counter that resets per event is always satisfied |

The mandate's `amount_max` threads the cap into the APW-1 model, and its
`enforcement` field names the implementation under test: `settled_sum`
(the natural first draft — the buggy APW-1 variant, the one an AI author
most often emits) or `request_sum` (the corrected rule). So the *same*
"spend up to $200" mandate yields:

- `enforcement: settled_sum` → APW-1 buggy → **VIOLATED**, witness
  `{"completed": 0, "inflight": 3}`;
- `enforcement: request_sum` → APW-1 correct → **PROVEN**.

That is the whole point: the mandate is intent, the enforcement is an
implementation choice, and ROTN is where the choice is *proved* — in any
of the languages above.

## What this does not claim

- ROTN does not **author** policies; it checks them.
- ROTN does not **interpret** Rego or AP2; the stubs lower the *canonical
  encoding* of a supported shape to the shared IR and stop there.
- ROTN does not prove **unbounded** (fair) liveness; it proves bounded
  safety/realizability over a bounded state space (see
  [`novelty.md`](novelty.md) for the precise boundary).
- A `PROVEN` verdict is a proof **within the model** (the pinned property,
  the bounded horizon, the discretized window) — not a proof of the real
  deployment's unbounded behavior.

## Evidence (reproducible on this machine)

```
# the demo loop, end to end
rot ai
rot ai --policy samples/ai_authoring/apw2-correct.rego

# the neutral-checker claim, structurally
python -m pytest tests/test_opa_frontend.py tests/test_ap2_frontend.py tests/test_ai_loop.py -q
```