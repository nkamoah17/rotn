# APW-2 reference policies — provenance

These two policies are the **verbatim, practitioner-written** source for the
APW-2 "approval replay" weakness class. They are pinned here as **reference
material** (Phase 0); Phase 1 normalizes them to the repo's `Drupe` namespace
and turns them into parseable `samples/apw2-*.dw` fixtures with oracles/tests.

## Source

- **Tutorial:** Classmethod, "AgentCore Gateway Dogwood temporal policies",
  2026-09-14.
  <https://dev.classmethod.jp/articles/agentcore-gateway-dogwood-temporal-policies/>
- **Policy file in the tutorial:** `gateway/OrderAfterCartCheck.dw`
- **Namespace:** `AgentCore` (as authored). Actions:
  `ShoppingTarget___get_cart`, `ShoppingTarget___place_order`.

## The two variants

| File | Variant | Key temporal clause |
|------|---------|---------------------|
| `apw2-order-after-cart-check-buggy.dw` | buggy | `formerly within 1m get_cart::response{…}` (approval never consumed) |
| `apw2-order-after-cart-check-correct.dw` | correct | adds `!place_order::response{…} since within 1m get_cart::response{…}` (approval consumed) |

## The weakness (APW-2), framed as pattern education

> If your intent is **one approval → one action**, the buggy policy does not
> enforce it: a single `get_cart::response` authorises *every* matching
> `place_order` in the window, so a parallel burst of N orders is admitted on
> the strength of one cart-check.

Whether it is a "bug" depends on the author's intent — hence the educational
framing rather than a vulnerability disclosure.

## Notes for Phase 1

- The corrected variant uses the temporal operator **`since`**
  (`<neg-conjunct> since within <interval> <atom>`), which the current
  `rot/dw.py` parser does not yet handle.
- The scope uses `resource == AgentCore::Gateway::<GATEWAY_ARN>`, which the
  current parser does not yet handle (it accepts a bare `resource`).
- Both are normalization work for Phase 1, not blockers for pinning here.
