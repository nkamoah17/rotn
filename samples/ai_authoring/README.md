# samples/ai_authoring -- the AI-authored-policy demo loop (Phase 4)

The loop: **intent (natural language) -> AI-authored policy -> ROTN
verdict** -- the "AgentCore writes your Dogwood policy. ROTN proves it
can't be bypassed." position, runnable end to end.

```
rot ai                  # intent.md + apw2-buggy.rego -> VIOLATED (exit 1)
rot ai --policy samples/ai_authoring/apw2-correct.rego   # -> PROVEN (exit 0)
```

## Files

| file | what it is |
|------|-----------|
| `intent.md` | the natural-language intent an AI author turns into a policy (the APW-2 "one cart check, one order" intent) |
| `apw2-buggy.rego` | the AI's natural first draft in Rego (APW-2, approval replay): the approval is a bare, sticky fact -> one approval admits N orders. VIOLATED, witness `{"approved": true, "orders": 2}` |
| `apw2-correct.rego` | the corrected draft: the single-use binding (the `since` clause in the Dogwood twin). PROVEN |
| `apw1-buggy.rego` | the AI's natural first draft in Rego (APW-1, settled-sum cap): charges settled responses only -> a parallel burst commits past the cap. VIOLATED, witness `{"completed": 0, "inflight": 3}` |
| `apw1-correct.rego` | the corrected draft: charges in-flight requests against the cap too. PROVEN |
| `ap2-spend-200.ap2` | an AP2 mandate ("spend up to $200 on goods_and_services") mapped onto APW-1 by the stub front-end |

## How it lowers (the neutral-checker claim)

The `.rego` / `.ap2` files are lowered by **stub** front-ends
(`rot.frontends.policy.opa` / `rot.frontends.policy.ap2`) to the **same**
`ProtocolIR` the Dogwood front-end produces for the equivalent `.dw`
policy (`samples/apw2-buggy.dw`, `samples/apw1-buggy.dw`):

* `ProtocolIR.__eq__` ignores `metadata`, so "same IR" is a *structural*
  assertion -- the front-ends differ only in provenance
  (`frontend`, `policy_source`);
* the verdict is then decided on that IR, so it is identical by
  construction;
* `rot ai` cross-checks this against the Dogwood twin and reports
  `same_ir` / `same_verdict`.

The stubs are *not* Rego/AP2 interpreters: they recognise the canonical
encoding (the `# rotn:shape=` annotations / the mandate facets) and
delegate the model to the same oracles the `.dw` route uses
(`rot.spendcap`, `rot.shapes`).  Building full engines is deliberately
out of scope -- see `docs/positioning.md`.