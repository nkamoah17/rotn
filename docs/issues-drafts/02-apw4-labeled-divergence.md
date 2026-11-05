# APW-4: relabel the reference agreement as a labeled divergence + add a waiver (per-recipient partitioned cap)

## Finding (empirically verified)

In the reference interpreter (`dogwood replay`), temporal aggregates are
**sharded by the request's pinned key** (the partition guarantee).
APW-4's `count … recipient: context.input.recipient` is therefore a
*per-recipient* count in the reference — the "correct" policy enforces a
**per-recipient (partitioned) cap**, not a global distinct-recipient
cap. So the reference does not deny the cross-recipient burst on the
correct leg: 4 ALLOW / 0 DENY (`docs/reference-replay.md`, APW-4 row +
"Honest caveats").

The current gate row reads `AGREE`, which overstates what was checked:
ROTN's **global-distinct** class is a real bug class, but it is not the
same obligation the reference's "correct" policy enforces.

## Decision (locked)

- Keep APW-4 in the catalog: the global-distinct class remains a real bug
  class that ROTN catches.
- **Relabel** the APW-4 gate row from `AGREE` to
  **`LABELED-DIVERGENCE`** — a pass *with a warning*, never a silent
  PASS.
- **Add a waiver:** owner `nkamoah17`, expiry 90 days from landing,
  reason: partition guarantee (per-recipient cap in the reference vs.
  the global-distinct class ROTN checks).

## Work items

1. Reword the catalog (`docs/apw-catalog.md`): APW-4's "correct" policy
   enforces a *per-recipient* (partitioned) cap under Dogwood's
   reference semantics; ROTN's global-distinct class stays a real bug
   class.
2. `gate/waivers.yaml`: the APW-4 / G2 entry — `owner: nkamoah17`,
   `expiry: <+90d>`, `reason: partition guarantee (per-recipient cap in
   the reference; the global-distinct class is the ROTN claim)`.
3. The gate report prints `LABELED-DIVERGENCE` for the APW-4 row with
   the waiver id + warning (depends on ① — the gate issue).
4. Tests: waiver parse/expiry; an expired waiver fails the gate; the
   report never shows a silent PASS for a waived class.
5. `docs/reference-replay.md`: the "partition guarantee" caveat becomes
   the *reason* for the labeled divergence — not a footnote under an
   `AGREE` row.

## Acceptance

- [ ] the catalog states the per-recipient vs. global-distinct
      distinction
- [ ] the APW-4 row is `LABELED-DIVERGENCE` with a waiver id, in both the
      gate report and the committed replay doc
- [ ] the waiver carries owner + expiry; expiry ⇒ gate fail (exit 1)
