# Intent (natural language)

> "The agent may place an order only after the cart has been confirmed,
> and one cart confirmation should authorise exactly one order."

This is the natural-language intent an AI policy author (e.g. AWS
AgentCore) turns into a concrete policy.  The canonical example is the
**APW-2 approval-replay** shape: the policy must gate `place_order` on a
cart check, and the approval must be *single-use*.

The AI author's natural first draft encodes the approval as a *bare*
temporal fact -- "a cart check happened" -- which is **sticky**: once one
cart check occurs, the fact stays true, so the same approval admits
*every* later order.  That is exactly the policy in `apw2-buggy.rego`
(and its Dogwood twin, `samples/apw2-buggy.dw`).

**ROTN's job:** prove the policy cannot be bypassed -- and show, for this
draft, that it *can* (witness: `{"approved": true, "orders": 2}`), while
the corrected draft (the `since` clause in Dogwood; the single-use
binding in Rego, `apw2-correct.rego`) is what the proof is about.

Run the whole loop:

```
rot ai                     # default: this intent + apw2-buggy.rego -> VIOLATED
rot ai --policy samples/ai_authoring/apw2-correct.rego   # -> PROVEN
```