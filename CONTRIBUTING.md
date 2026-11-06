# Contributing to ROTN

ROTN is a zero-dependency (pure-stdlib) verification engine. Three rules
outrank everything else:

1. **Stay stdlib.** The core must install and run with no external
   packages, no Java, and no network. Optional engines (Z3, TLC,
   Apalache) and the Dogwood reference binary *degrade* to skip or an
   honest `UNKNOWN` when absent — they never block the core.
2. **Stay deterministic.** Re-runs produce byte-identical artifacts.
3. **Never let a divergence pass silently.** A disagreement between ROTN
   and the reference interpreter is fixed, labeled
   (`LABELED-DIVERGENCE`) under a waiver, or the gate fails. There is no
   fourth option.

## Setup

- Python **3.8+** (CI runs 3.10–3.13). No runtime dependencies.

```bash
git clone https://github.com/nkamoah17/rotn.git
cd rotn
python -m pip install .            # or: pip install -e .
rot --version                      # 0.2.0
```

- **Optional** cross-check engines — each absent engine simply skips:
  Z3 (the SMT leg), TLC (Java + `tla2tools.jar`), Apalache (Java).
- **The Dogwood reference binary** — needed only for the reference gate
  and the oracle replay (`rot replay --oracle dogwood …`):

```bash
git clone https://github.com/dogwood-policy/dogwood.git
cd dogwood
git checkout 4ec5e2c01b44ff3882a231ae5d315b330b38fa25   # the pinned reference
cargo build                                               # target/debug/dogwood(.exe)
```

  Point ROTN at it with `DOGWOOD_BIN` (see "The reference gate" below).

## Tests

```bash
python -m unittest discover -s tests                        # full suite (1082 tests, green in a bare env)
python -m unittest discover -s tests -p 'test_apw*.py'      # the six APW catalog legs
```

- The suite is **deterministic and pure stdlib**: no Java, no Z3, no
  network, no Dogwood binary required. Any leg that needs an external
  tool **skips rather than fails** — that is the convention that keeps
  `.github/workflows/rotn.yml` green in a bare environment.
- Site smoke tests (Node 18+): `node site/smoke_app.js && node site/smoke_h.js`.
- One-command demo: `powershell demo.ps1` (Windows) / `bash demo.sh`
  (macOS / Linux) — exit 0 = every phase as expected.

## The reference gate (`DOGWOOD_BIN`)

The gate replays each **gate-class** counterexample (APW-1, APW-2,
APW-4) against **Dogwood's own reference interpreter** (`dogwood replay`)
on the *same* trace, and requires **ROTN = VIOLATED** with the
**reference admitting** the buggy policy — "Dogwood admits it, ROTN
catches it."

```bash
DOGWOOD_BIN=/path/to/dogwood(.exe) rot replay --oracle dogwood --gate
```

- **Binary resolution order** (`rot/oracle.py::find_dogwood`): explicit
  `--dogwood PATH` > `$DOGWOOD_BIN` > known build locations (e.g.
  `C:\tools\dogwood\target\debug\dogwood.exe`) > `PATH`.
- **Exit codes:** `0` = gate PASS (all classes agree) · `1` = gate FAIL ·
  `3` = error (binary missing, bad arguments). The *test suite* skips the
  binary leg when the binary is absent (CI stays green in a bare env); the
  CLI reports the error — it does not fabricate a pass.
- **Reports:** the v2 bidirectional gate (the default for `--gate`) writes
  `out/gate/report.json` + `out/gate/report.md` (spec §6 schema). The legacy
  one-sided gate (`rot replay --oracle dogwood --gate --onesided`) writes
  `out/reference-replay.json` + `out/reference-replay.md`. The committed copy
  is [`docs/reference-replay.md`](docs/reference-replay.md) — regenerate and
  commit it whenever the binary, the fixtures, the spec, or the waivers
  change.
- **Pinned reference:** the gate's claims are made against
  `dogwood-ref@4ec5e2c01b44ff3882a231ae5d315b330b38fa25`. If you build a
  different commit, record it in the report — upstream drift is expected
  and will be tracked by a nightly job (see the gate proposal in
  [`docs/issues-drafts/01-bidirectional-reference-gate.md`](docs/issues-drafts/01-bidirectional-reference-gate.md)).

### Waiver rules (labeled divergences)

Where ROTN and the reference *legitimately* disagree, the project accepts
the divergence only under these rules. Today they are enforced by review
and by the "Honest caveats" sections of the reports; the v0.2.0 gate will
enforce them in code (`gate/waivers.yaml`):

1. **Always labeled.** An accepted divergence is reported as
   `LABELED-DIVERGENCE` — a pass *with a warning* that names the waiver —
   never as a bare PASS, and never only in a footnote. (The current
   example is the APW-4 "partition guarantee" caveat in
   `docs/reference-replay.md` — see ② in `docs/issues-drafts/`.)
2. **Waivers are data, not code.** They live in a YAML file, not in gate
   logic. The parser accepts a strict subset — `class`, `rule`, `owner`,
   `expiry`, `reason` — and rejects anything else.
3. **Owner + expiry, both mandatory.** An expired waiver makes the gate
   **fail** (exit 1). A waiver cannot lapse into a pass.
4. **Explain, don't delete.** The waiver states *why* the two engines
   disagree — e.g. the reference shards temporal aggregates by the
   request's pinned key (a per-recipient cap), while ROTN checks the
   global-distinct class. The catalog keeps the class.
5. **Re-review at expiry.** Either the engines now agree, the waiver is
   renewed with an updated reason, or the class is re-labeled.

## Conventions

- **Verdicts are engine-labeled** — every verdict records which engine(s)
  produced it; a cross-engine join degrades to `UNKNOWN`, never to a
  silent pick of one engine.
- **The LLM baseline is non-sound** and must never affect a verdict or an
  exit code — it writes an audit artifact only.
- **Claims and bounds.** Every doc states what is supported and what is
  *not* yet supported (model: `docs/agentcore-repro.md` §8). If you add a
  claim, add its bound and the evidence command.
- **Commits:** `type: summary` (`feat` / `fix` / `docs` / `chore` /
  `test`), one logical change per commit, suite green before push.
- **Changelog:** user-visible changes get an entry under
  [`CHANGELOG.md`](CHANGELOG.md) `[Unreleased]`.
- **A new APW class** is a new shape, not a new engine: a buggy/correct
  `.dw` pair → a lowering in `rot/lower.py` → a hand-written oracle in
  `rot/shapes.py` → `tests/test_apwN.py` → a catalog row
  (`docs/apw-catalog.md`). The APW-7 proposal in
  `docs/issues-drafts/05-apw7-denied-attempts-drain-budget.md` is a
  current template.
- **Security:** read [`SECURITY.md`](SECURITY.md) before touching
  anything near `agentcore_repro/` or the gate — especially §3 (the
  vendor-divergence rule).

## Where things live

| path | what |
|---|---|
| `rot/` | the engine: front-ends → IR → linearization → engines → verdict |
| `rot/oracle.py` | the reference-interpreter gate + the E4 events replay |
| `tests/` | the suite (pure stdlib; binary legs skippable) |
| `samples/`, `tests/fixtures/` | the APW buggy/correct pairs + the gate fixtures |
| `docs/` | the catalog, the runbooks, the generated reports |
| `agentcore_repro/` | the live AWS AgentCore reproduction (see `SECURITY.md` §3) |
| `site/` | the zero-dependency interactive-proof site (GitHub Pages) |
| `.github/workflows/` | `rotn.yml` (tests) · `publish.yml` (PyPI) · `pages.yml` (site) |
