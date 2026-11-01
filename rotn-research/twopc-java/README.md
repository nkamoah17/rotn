# twopc-java — Phase 2 vertical slice (Java model + agent + tests)

The Java side of the Phase 2 empirical plane: the 2PC model, the W0–W3
scheduler gate + Java agent, the W5 JUnit suite, and the W6 probe-cost
benchmark + 100× determinism gate. No Maven/Gradle — plain `javac` (model +
agent) and `org.junit.runner.JUnitCore` (tests), with JUnit 4 + hamcrest from
`..\third_party`. The Python W1–W4 acceptance layer lives one level up in `..`.

## W5 — JUnit tests (model + scheduler gate)

Phase 2 W5: a JUnit 4 test suite for the Java model and the W3 scheduler
gate. No Maven/Gradle — plain `javac` + `org.junit.runner.JUnitCore` with the
JUnit 4 + hamcrest jars in `..\third_party`.

**Scope — the W5 invariants (mirror the Phase 1 formal model):**
- **AGREE** (concurrency): the correct variant preserves participant agreement
  (both apply the same decision); the buggy variant violates it (p1 commits,
  p2 aborts). Run on the real multi-threaded model (`TwoPhaseCommit.run`).
- **never-refines** (structural + functional): the replay path
  (`com.rot.n.scheduler.*`, `com.rot.n.twopc.*`) exposes **no** refinement
  entry point, and a gate-gated deterministic replay completes with the
  correct decision (no CEGAR/abstraction/ModelFind surface, no refinement
  call).

**Test classes (`tests\com\rotn\tests\`):**

| class                  | asserts                                                                                   |
|------------------------|-------------------------------------------------------------------------------------------|
| `TwoPhaseCommitTest`   | AGREE: correct preserves agreement, buggy violates it; decision=abort; strict trace order; SPEC events present |
| `NeverRefinesTest`     | no refinement member/name on the replay path; gate-gated replay completes with correct decision |
| `ScheduleReaderTest`   | witness-schedule parse + validation (header, step order, n_steps, types, malformed → `GateException`) |
| `GateTest`             | gate match/mismatch, exhaustion, no-op when inactive, `deactivate`                         |
| `ReplayTraceTest`      | gate-gated replay emits a structurally valid W1 trace (header + strict `seq` + owner/action) |

**Run:**

```powershell
cd twopc-java
.\run_tests.ps1        # compile model + scheduler + tests, run all 5 classes
.\build.ps1            # full build: model + W0 smoke + W2 probe + W3 replay triple + W6 benchmark/determinism
.\build.ps1 -What w6   # just the W6 gate (probe-cost benchmark + 100× determinism)
```

`run_tests.ps1` is self-contained (compiles `src\com\rotn\twopc` +
`src\com\rotn\scheduler` + `tests\` and runs JUnit). It exits non-zero on any
test failure. The `..` Python suites (`rot\tests\test_phase2_w*.py`) remain the
acceptance gate for the W1–W4 layers; W5 is the Java-side unit layer.

## W6 — probe-cost benchmark + 100× determinism gate

Phase 2 W6: quantify the probe's runtime cost and prove the trace is
byte-deterministic across runs. Driven by `.\build.ps1 -What w6` (also runs in
the full build after W3).

- **W6.1 probe-cost benchmark** — `W6Bench` runs a tight loop over
  `Bus.send` → `Bus.record` (the agent-injected path) N times (default 200,000;
  `-benchN`), once with no agent (baseline) and once with `-javaagent`.
  Reports `baseline_ns`, `instrumented_ns`, `overhead_ns`, and
  `overhead_pct = (instrumented-baseline)/baseline*100`. The overhead is always
  **reported** (the gate never asserts a threshold, so a slow machine can't
  flip it red). On this machine: ~2.6 µs/record added (~927% of the
  sub-microsecond baseline — the absolute ns/record is the stable figure).
- **W6.2 100× determinism gate** — replays the **correct** variant 100× with a
  **fixed run id**, SHA256-hashes each `w6-det-<i>.jsonl`, and asserts
  **100/100 byte-identical**. Any non-zero exit or hash mismatch throws.
  Verified 2026-10-01: 100/100 exit 0, 0 mismatches, single sha256
  `20457DD6…`.

```powershell
cd twopc-java
.\build.ps1 -What w6
# → W6.1 PROBE-COST BENCHMARK: overhead reported
# → W6.2 DETERMINISM GATE: PASS (100/100 byte-identical)
# → W6 ALL CHECKS PASS
```