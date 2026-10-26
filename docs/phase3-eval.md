# Phase 3 — ZooKeeper/ZAB Bug-Replay Evaluation (Step 3.7)

> Status (2026-10-04): **corpus ✅ · per-commit verdicts ✅ · aggregate metrics ✅ · tests ✅ (223/223, 0 failures).**
> All claims verified on this machine with `python -m rot.zk_bugs` and
> `python -m unittest tests.test_zk_bug_replay`.

## 0. Purpose & method

Step 3.7 is the headline Phase 3 evaluation. The question it answers, in one
line: **when a real ZooKeeper/ZAB bug is introduced as a change request, does
the MR gate catch it — and when a safe change is made, does it wrongly block it?**

The method is a *bug-replay* harness:

1. **A documented corpus of 6 commits.** Each commit is a `(before, after)`
   pair of `ProtocolIR`s — exactly the shape of a merge request — built from the
   real ZAB replication core (`rot/zab.py`). Three commits *introduce a bug*;
   three are *safe* (two refactors, one additive feature).
2. **Replay through the real gate.** Every commit is handed to
   `rot.mr_gate.evaluate_mr(before, after, properties=ZAB_PROPS)` — the same
   code path CI would use — producing a verdict of `PASS` / `WARN` / `BLOCK`.
3. **Classify and aggregate.** Each commit is scored against its known
   ground-truth (bug or safe) into TP / FN / FP / TN, then aggregated into the
   Step 3.7 metrics (false-block rate, blocking precision, blocking recall,
   detection recall).

The corpus is deliberately **honest**: it contains both bugs the gate *does*
catch and a real bug the gate *cannot* catch with its current invariant set,
so the report measures a genuine gap rather than a curated best case.

## 1. The invariant set (what the gate checks)

The gate checks the Phase 3.1 ZAB invariant set (`rot/invariants.py`):

| Invariant | Meaning | Pinned? | Gate behaviour |
|-----------|---------|---------|----------------|
| `zab_no_premature_apply` | `applied(i,j)=done ⇒ committed(i)=done` — a follower never applies a tx before the leader commits it | **Yes (blocking)** | violation ⇒ **BLOCK** + deterministic counterexample |
| `zab_apply_persisted` | `applied(i,j)=done ⇒ persisted(i,j)=done` — a follower applies only what it persisted | No (non-blocking) | violation ⇒ **WARN** (surfaced, not vetoed) |

Key semantic fact that drives the whole evaluation: in the ZAB core,
`commit_i` requires **all** followers to have persisted (`persisted_i_j=done`
for every `j`). So whenever `committed_i=done`, every `persisted_i_j=done` is
already guaranteed — which is why `zab_apply_persisted` holds in *both* the
correct and the buggy variant (see `tests/test_zab_target.py`).

## 2. Corpus

| Commit | Ground truth | Change (mutation on the ZAB core) | Expected |
|--------|--------------|-----------------------------------|----------|
| `ZK-001` | **bug** | Drop `committed_i` from the `apply` guard (apply before commit) | BLOCK |
| `ZK-002` | **bug** | Drop **both** `committed_i` and `persisted_i_j` from the `apply` guard (apply with no preconditions) | BLOCK |
| `ZK-003` | **bug** | Drop the all-persisted requirement from the `commit` guard (commit before quorum) | PASS |
| `ZK-S1` | safe | Reorder the `apply`-guard conjuncts (behaviour-preserving refactor) | PASS |
| `ZK-S2` | safe | Add a `leader_epoch` variable + action (additive, safety-neutral) | PASS |
| `ZK-S3` | safe | Reorder the `persist` actions (behaviour-preserving refactor) | PASS |

## 3. Per-commit results

| Commit | Verdict | Firing invariant | Classification |
|--------|---------|------------------|----------------|
| `ZK-001` | **BLOCK** | `zab_no_premature_apply` (blocking) | **TP** — caught + deterministic witness |
| `ZK-002` | **BLOCK** | `zab_no_premature_apply` (blocking) | **TP** — caught + deterministic witness |
| `ZK-003` | PASS | — | **FN** — honest coverage gap (see §5) |
| `ZK-S1` | PASS | — | **TN** |
| `ZK-S2` | PASS | — | **TN** |
| `ZK-S3` | PASS | — | **TN** |

Both true positives emit a **deterministic counterexample** (a concrete
reordering witness, `has_deterministic_test == True`), so a blocked MR comes
with a reproducible test, not just a verdict.


## 4. Aggregate metrics

| Metric | Value | Reading |
|--------|-------|---------|
| Bug commits (TP+FN) | 3 | ZK-001, ZK-002, ZK-003 |
| Safe commits (TN+FP) | 3 | ZK-S1, ZK-S2, ZK-S3 |
| **True positives** | **2** | ZK-001, ZK-002 caught and blocked |
| **False negatives** | **1** | ZK-003 missed (coverage gap) |
| **False positives** | **0** | no safe commit blocked |
| True negatives | 3 | all safe commits passed |
| **False-block rate** | **0.0%** | 0 safe commits blocked / 3 |
| **Blocking precision** | **100%** | 2 blocked, 2 real bugs |
| **Blocking recall** | **66.7%** | 2 of 3 bugs blocked |
| Detection recall | **66.7%** | 2 of 3 bugs detected (no WARN tier fired) |

Interpretation: the gate **never produces a false block** on this corpus
(false-block rate 0.0%, precision 100%), which is the property a CI gate
*must* have. Its one miss is a real, known, and *explainable* coverage gap
(ZK-003, below), not a silent failure on a bug it should have caught.

## 5. The `ZK-002` correction (why it is what it is)

`ZK-002` went through one redesign and it is worth recording.

**First draft** — "apply without persist": keep `committed_i` in the apply
guard, drop only `persisted_i_j`, expected `WARN` on the non-blocking
`zab_apply_persisted`. The gate returned **PASS**, not WARN.

**Why PASS was actually correct.** Because `commit_i` requires *all* followers
to persist, `committed_i = done` already forces `persisted_i_j = done` for
every `j`. So the mutation "drop persisted, keep committed" is a **behavioural
no-op**: the set of reachable states is identical to the correct core. The
gate was right to pass it — and it was *not* a real bug. Reporting it as a
false negative would have mis-stated the gate's accuracy.

**Resolution** — `ZK-002` is now "apply with no preconditions" (drop *both*
`committed_i` and `persisted_i_j`). That is a genuinely reachable, severe
premature-apply bug (a follower can apply a tx the leader has not committed
and it has not even persisted), the gate **BLOCKs** it via
`zab_no_premature_apply`, and it is a clean true positive.

Net effect on the story: the corpus now contains **two reachable true
positives** and **one honest, explainable false negative** (ZK-003), instead
of an unexplained "missed" case.

## 6. The ZK-003 gap, and how to close it

`ZK-003` ("commit before quorum") is the deliberate, honest coverage gap. It
is a real ZAB durability bug, but the two-invariant set does not model *quorum*:
neither `zab_no_premature_apply` nor `zab_apply_persisted` mentions how many
followers must persist before `commit_i` may fire.

Closing it is a follow-up invariant, e.g. a blocking
`zab_commit_requires_quorum`: `committed(i)=done ⇒ quorum(i) persisted=done`.
With it pinned, ZK-003 flips from FN to a blocked TP and recall rises from
66.7% to 100%. That is left as future work so this report reflects the
*current* gate, not a hypothetical one.

## 7. Limitations & follow-up

- **Two invariants, not all of ZAB.** The corpus is scored against the
  current ZAB invariant set. Bugs outside that set (ZK-003's quorum class,
  epoch/leader-election races, log truncation) are out of scope by design —
  they are reported as honest FNs, not hidden.
- **`n=2` followers.** The model is proven over *all* reachable states of the
  2-follower core. Larger `n` is supported (`replay_corpus(n=...)`) and the
  invariants are expressed universally, but the corpus was authored at `n=2`
  where every state is reachable and checks are cheap.
- **Commit corpus, not real git history.** Commits are hand-authored before/
  after IR diffs that mirror real ZAB failure modes (premature apply, commit
  before quorum). This is the same input shape `evaluate_mr` takes, so the
  pipeline is exercised end to end, but the corpus is a representative sample,
  not an exhaustive bug catalogue.
- **Follow-ups:** (1) add and pin `zab_commit_requires_quorum` and re-score
  (expected: recall → 100%, false-block rate unchanged); (2) grow the corpus
  with epoch/leader-election and log-truncation bugs; (3) add a `WARN`-tier
  corpus case that exercises the non-blocking `zab_apply_persisted` path with a
  mutation that is reachable *without* violating the blocking invariant.

## 8. Reproduce

```powershell
cd ROTN
python -m rot.zk_bugs                                   # narrative report + JSON
python -m unittest tests.test_zk_bug_replay             # 9/9 locked-in tests
python -m unittest discover -s tests                    # full suite: 223/223
```

Files: `rot/zk_bugs.py` (corpus + report), `tests/test_zk_bug_replay.py`
(lock-in tests), this document.

