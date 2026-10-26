# Phase 2 — Empirical CI Plane: 2PC Vertical Slice (Implementation Plan)

> Status (2026-10-01): **W0 ✅ complete · W1 ✅ complete · W2 ✅ complete · W3 ✅ complete · W4 ✅ complete · W5 ✅ complete (27/27 JUnit) · W6 ✅ complete (bench + 100× determinism) · W7–W10 pending.**
> All claims below are verified on this machine (Temurin JDK 11.0.32.1).

## 0. Where we are (verified, with evidence)

| Check | Result | Evidence |
|-------|--------|----------|
| Phase 1 formal core | ✅ 33/33 tests, deterministic | `python -m unittest discover -s tests` |
| Seeded-bug discrimination | ✅ buggy = VIOLATED + witness, correct = PROVEN | `pipeline.py` symbolic runs |
| Exit-code contract | ✅ 0 proven / 1 violated / 3 error | `tests/test_pipeline.py` |
| JDK 11 installed | ✅ `javac 11.0.32.1` | `%LOCALAPPDATA%\Programs\Eclipse Adoptium\jdk-11.0.32.1+1` |
| ASM 8.0.1 vendored | ✅ 6 jars in `third_party/` | from `_joern_test/lib_asm8_backup/` (Maven-style coordinates, verified via Maven Central) |
| JUnit 4.13.2 + Hamcrest 1.3 | ✅ in `third_party/` | Maven Central URLs verified (`_probe/fetch_junit.log`, `fetch_hamcrest.log`) |
| **W0: `-javaagent` + ASM transform** | ✅ probe fires on `App.<init>` | `twopc-java\build.ps1 -What smoke` → `SMOKE-PROBE App.<init>` |
| **W1: 2PC race demo** | ✅ correct 0/20, buggy 20/20 violations | `twopc-java\build.ps1` → `RACE-DEMO PASS` + witness |
| **W2: probe trace emission** | ✅ header + 16 events + trailer; `gseq` strictly monotone from 0; Lamport strictly monotone and dominates `seq`; control run (no agent) emits no trace | `twopc-java\build.ps1` → `W2 STRUCTURAL TRACECHECK: PASS (2/2)` + `W2 probe trace emission PASS` |

### W1 witness (buggy variant, deterministic adversarial interleaving)

```
16 coordinator SEND ASK → p1        17 coordinator SEND ASK → p2
18 p1 RECV ASK             19 p2 RECV ASK
20 p1 vote yes             21 p1 SEND VOTE yes
22 coordinator RECV VOTE yes
23 p1 apply COMMIT (self-decided)   ← bug: participant commits from its own vote
24 coordinator decide ABORT (only 1 of 2 votes in)
25,26 coordinator SEND DECISION abort → p1, p2
27 p1 RECV abort           31 p2 RECV abort
28-30 p2 vote no, apply ABORT
→ p1=commit, p2=abort ⇒ AGREEMENT VIOLATED
```

Correct variant under the same interleaving: 0 violations over 20 runs
(p1 waits for the decision and applies `abort`, matching p2).

### Lessons captured during W0
1. **Package-name typo class of failure**: agent TARGET constants must use the
   internal name form `com/rot/n/smoke/App` — `com/rotn/...` silently never
   matches (transform is called, returns null, no error). W2's real probe must
   resolve TARGETS from the linearized model, never by hand-typed strings.
2. **PowerShell stderr**: native stderr surfaces as `RemoteException` noise and
   `Select-Object -First N` can close the pipe and kill the child (exit 1 with
   no output). Rule: CI scripts use `cmd /c` for redirection or capture via
   temp files; never truncate live native output mid-run.
3. **JDK via winget** works headlessly: `winget install --silent --accept-source-agreements --accept-package-agreements EclipseAdoptium.Temurin.11.JDK`.
4. **No build tools**: plain `javac --release 8` + `jar -cfm` is sufficient;
   ASM is bundled into the agent jar so `-javaagent` needs no classpath.
5. **Vendored ASM (8.0.1) is non-standard** — verified empirically with
   `debug/TransformDump.java`:
   - `InsnList.insert(at, insn)` inserts **after** `at` (standard ASM inserts
     before). Inserting in reverse order at a fixed reference therefore
     produces reversed bytecode. Correct pattern: re-fetch
     `anchor.getPrevious()` each iteration and insert after it (or append at
     EOF).
   - Opcode/type constant numbering differs from upstream ASM (e.g. `ATHROW`
     = 191 here vs 191/192 upstream; class types are 17/19/20/21). Do not
     hard-code literal constants — always use the `Opcodes`/`Type` symbols.
   - `ClassWriter.COMPUTE_FRAMES` works (rewrites the instruction list and
     preserves a correct insertion layout).
6. **Probe insertion point**: `Bus.record`'s monitor block is
   `monitorenter … monitorexit ; <goto end> <handler> <end> return`. The probe
   must go **between `monitorexit` and the `goto`** — not after the `goto`
   (dead code) and not in the handler (fires on exception only).

## 1. Goal

Turn Phase 1's formal verdicts into **empirical, CI-runnable evidence** for the
2PC target, using an in-house controlled scheduler + probe agent:

- **CONFORMANT** — empirical runs agree with the PROVEN verdict.
- **NON-CONFORMANT** — a deterministic failing test reproduces the violation.
- **INCONCLUSIVE** — refinement-request artifact only (never a crash, never a
  silent pass).

Replay of a model witness must **never** trigger refinement (enforced by
structure + tests).

## 2. Architecture (decided)

```
rot/linearization.py  (existing model: enabled_in / next_states / _apply_effects)
        │
        ├─ schedule JSON (buggy witness path emitted FIRST, then random/adversarial)
        │
        ▼
twopc-java/
  src/com/rotn/twopc/     correct + buggy participants (shared coordinator/bus)
  agent/                  probe: global sequence number, Lamport headers,
                          JSON trace emission (one file per run)
  scheduler/              global gate: threads block at sync points until the
                          schedule says "you may run" (forced, deterministic)
  tests/                  JUnit 4.13.2, plain javac+java (NO Maven/Gradle)
        │
rot/tracefmt.py           trace JSON schema + reader (Python 3.6, stdlib)
rot/tracecheck.py         replay witness trace → check invariant on recorded states
rot/empirical.py          orchestration: schedule → run → check → verdict artifact
```

Key properties:

- **One linearized model, two consumers**: symbolic checking (Phase 1) and
  trace replay (Phase 2) use the same `enabled_in`/`next_states`/`_apply_effects`
  operations — no second source of truth.
- **Scheduler gate is the only source of nondeterminism removal**: threads
  park at `Bus` send/receive and participant step boundaries; the gate consults
  the JSON schedule and releases exactly one thread per step.
- **Probe overhead is the only instrumentation**: one atomic global counter
  + Lamport clock per event; JSON emission buffered and flushed at run end.
- **Determinism gate**: 100× replay of the same schedule must produce
  byte-identical traces (excluding the run-id field).

## 3. File layout (to be created)

```
third_party/                       ✅ vendored jars (ASM 8.0.1 x6, JUnit 4.13.2, Hamcrest 1.3)
twopc-java/
  build.ps1                        ✅ compile + W1 demo + W0 smoke + W2 tracecheck
  run_tests.ps1                    # W5: JUnit console runner via java -cp
  agent-smoke/                     ✅ W0 artifact (kept as regression evidence)
  agent-probe/                     ✅ W2 probe agent (ProbeAgent; manifest generated by build.ps1)
  debug/                           ✅ W0/W2 harness (WalkDebug, TransformDump) — ASM semantics evidence
  src/com/rotn/twopc/              ✅ W1 target (correct/buggy/Bus/coordinator)
  src/com/rotn/probe/              ✅ W2 probe sink (Probe: gseq + lamport + JSONL writer)
  src/com/rotn/demo/               ✅ W2 single-run driver (TraceDemo)
  src/com/rotn/scheduler/          # W3: Gate, ScheduleReader, SyncPoint
  tests/com/rotn/tests/            # W4-W5: JUnit tests + determinism gate
rot/
  tracefmt.py                      # W4
  tracecheck.py                    ✅ W2 structural check (parse/header/trailer/seq/Lamport); W4 extends
  empirical.py                     # W4/W5
  tests/test_phase2_w2.py          ✅ W2 T1–T7 harness (build → emit → structural conformance)
tests/
  test_tracecheck.py               # W4 (witness replay, never-refines guard)
  test_empirical.py                # W5 (verdicts, artifacts, exit codes)
```

## 4. Work items

| WI | Scope | Exit criterion |
|----|-------|----------------|
| **W0** ✅ | JDK 11, vendor ASM/JUnit/Hamcrest, `-javaagent` hello-world | smoke test: probe fires, exit 0 |
| **W1** ✅ | concurrent 2PC (correct/buggy), race demo | buggy 20/20 violations, correct 0/20, witness printed |
| **W2** ✅ | Probe agent: global seq, Lamport headers, JSON trace file | ✅ 18-record trace parses; `gseq` strictly monotone; Lamport strictly monotone and dominates `seq` — both variants |
| **W3** | Scheduler gate + schedule JSON from `rot/linearization.py` | buggy witness schedule replays byte-identically 3×; correct schedule stays CONFORMANT |
| **W4** | `tracefmt.py`, `tracecheck.py`, `empirical.py` | witness replay → NON-CONFORMANT with failing test; correct → CONFORMANT; INCONCLUSIVE artifact only |
| **W5** | JUnit tests (concurrency, gate, never-refines), `run_tests.ps1` | full suite green; replay path has zero refinement calls (asserted by test) |
| **W6** | Probe-cost benchmark, 100× determinism gate | overhead % reported (this env: ~2.6 µs/rec added, ~927% of the sub-µs baseline — the absolute ns/rec is the stable figure); **100/100 byte-identical traces — verified 2026-10-01 (100/100 exit 0, 0 hash mismatches, single sha256 `20457DD6…`)** |

## 5. Environment & reproducibility

```powershell
# one-time (already done on this machine)
winget install --silent --accept-source-agreements --accept-package-agreements EclipseAdoptium.Temurin.11.JDK
# jars are vendored in third_party/ (ASM 8.0.1 x6, JUnit 4.13.2, Hamcrest 1.3)

# daily
twopc-java\build.ps1              # compile + W1 demo + W0 smoke + W2 probe tracecheck
python pipeline.py buggy --property agreement --engine symbolic   # Phase 1 still green
```

JDK resolution order for scripts: `javac` on PATH →
`%ProgramFiles%\Eclipse Adoptium\*\bin\javac.exe` →
`%LOCALAPPDATA%\Programs\Eclipse Adoptium\*\bin\javac.exe`.

## 6. Non-goals (this phase)

- No Maven/Gradle, no Fray, no new Python deps (stdlib only, 3.6-compatible).
- No real network 2PC; the target stays the in-memory bus model.
- No abstraction refinement from empirical runs — INCONCLUSIVE only emits a
  refinement-*request* artifact; refinement stays a Phase 1 (formal) concern.
- No coverage of `validity` / `no_spurious_abort` empirically yet — agreement
  is the discriminator; the other invariants follow the same path in a later
  phase once the harness is proven.