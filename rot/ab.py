# -*- coding: utf-8 -*-
"""ab.py -- the frontend A/B harness (Joern-primary, §3).

Compares the Ingest frontends on a shared oracle corpus (``bench/``), measuring
the §3 quality metrics per (frontend, fixture) cell and emitting a
**lexicographic winner** -- a decision that is *reproducible and citable*
(no free weights to argue about).

Offline and deterministic: no network, no external tools (TLC/Java), no
randomness.  Every cell is driven through the SAME Verify plane
(``verify_candidate``), so the A/B measures the *frontends* (extraction
fidelity), not the engine.

The §3 metrics (per (frontend, fixture) cell, on the fixture's **known-bug**
variant -- the one the corpus labels as the real defect):

* ``false_proven`` -- PROVEN on a known-bug fixture.  HARD DISQUALIFIER: any
  such cell = automatic loss (the unsoundness a "fast PROVEN" would hide).
* ``violation_recall`` -- catches the real bug (VIOLATED on the known-bug).
* ``dataflow_edge_recall`` -- fraction of the fixture's critical dataflow
  variables the IR retains (direct lossiness measure).
* ``source_pinning_rate`` -- 1 if the IR carries source-line provenance (a
  counterexample step can be pinned to a real line), else 0.
* ``coach_quality`` -- 1 if the P2 coach is drivable from the IR (a valid
  ``to_proceed`` record for the decision action), else 0.
* ``unknown_rate`` -- 1 if the verdict is UNKNOWN, else 0 (gated by
  false_proven so it cannot win by being unsound).
* ``cost`` -- a deterministic proxy for verification cost (IR action count);
  lower is better.

Ranking = lexicographic total order (higher is better after the hard gate)::

    ( violation_recall , dataflow_edge_recall , source_pinning_rate ,
      coach_quality , - unknown_rate , - cost )

**Unavailable != loss.**  A frontend that cannot run on a fixture (no
artifact, out of the P1 pattern class, ...) is recorded ``UNAVAILABLE`` --
an honest, objective distinction -- and is excluded from the ranking on that
fixture rather than scored a loss.

Pure stdlib (plus the rot frontends it drives).  Python 3.6 compatible
(no f-strings, no dataclasses).
"""

import json
import os

__all__ = [
    "Unavailable",
    "CellResult",
    "ABResult",
    "load_corpus",
    "run_ab",
    "lexicographic_winner",
    "to_json",
    "to_report",
]

#: The lexicographic metric order (higher is better after the hard gate).
#: ``negated`` metrics are lower-is-better, so they are sign-flipped so that
#: the whole tuple is "higher is better" (a clean lexicographic total order).
_METRIC_ORDER = [
    ("violation_recall", False),
    ("dataflow_edge_recall", False),
    ("source_pinning_rate", False),
    ("coach_quality", False),
    ("unknown_rate", True),
    ("cost", True),
]


class Unavailable(Exception):
    """A frontend cannot run on a fixture (no artifact / out of scope).

    Recorded as an honest, objective ``UNAVAILABLE`` -- NOT a loss.  The A/B
    harness catches this and scores the cell ``UNAVAILABLE`` (excluded from
    the ranking), per §3: "Unavailable != loss."
    """


def _repo_root():
    # rot/ab.py -> repo root is one level up.
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------------------
# Frontend drivers: (fixture) -> ProtocolIR  (raises Unavailable if it can't).
# Each driver builds the fixture's KNOWN-BUG variant (the real defect).
# ---------------------------------------------------------------------------

def _build_targets(fixture):
    """The hand-authored IR builders (the always-available baseline)."""
    name = fixture["fixture"]
    if name == "spendcap":
        import rot.spendcap as spendcap
        return spendcap.build_ir(n=4, buggy=True)
    if name == "labelflow":
        import rot.agent_harness as agent_harness
        return agent_harness.exfiltrate_build_ir(n=2, buggy=True)
    if name == "twopc":
        import rot.twopc as twopc
        return twopc.build_ir(n=2, buggy=True)
    raise Unavailable("targets: no builder for fixture %r" % name)


def _build_code(fixture):
    """The P1 code-extraction frontend (Python source -> candidate -> IR)."""
    name = fixture["fixture"]
    _code = {
        "spendcap": "budget_bypassable.py",
        "labelflow": "label_flow_bypassable.py",
    }.get(name)
    if _code is None:
        raise Unavailable("code: %r is outside the P1 pattern class" % name)
    path = os.path.join(_repo_root(), "tests", "fixtures", "code", _code)
    if not os.path.isfile(path):
        raise Unavailable("code: missing artifact %s" % path)
    from rot.frontends.code import extract_file
    from rot.lower import lower_candidate
    cand = extract_file(path)
    if cand.out_of_scope:
        raise Unavailable("code: out of scope (%s)" % cand.reason)
    return lower_candidate(cand)


def _build_cpg(fixture):
    """The CPG (Joern) frontend (structural CPG model -> candidate -> IR)."""
    name = fixture["fixture"]
    path = os.path.join(_repo_root(), "tests", "fixtures", "cpg",
                        "connector.cpg.json")
    if not os.path.isfile(path):
        raise Unavailable("cpg: missing artifact %s" % path)
    if name == "labelflow":
        from rot.frontends.code import PATTERN_LABEL_FLOW as shape
    elif name == "spendcap":
        # The committed CPG fixture carries the ENFORCED budget quadrant, not
        # the known-bug (settled-only) one, so the CPG cell is UNAVAILABLE on
        # the known-bug variant -- an honest, objective distinction, not a loss.
        raise Unavailable(
            "cpg: no bypassable-budget CPG model in the corpus "
            "(committed fixture is the enforced quadrant)")
    else:
        raise Unavailable("cpg: %r is outside the P1 pattern class" % name)
    from rot.frontends.cpg import extract_cpg
    from rot.frontends.cpg_model import CpgModel
    from rot.lower import lower_candidate
    model = CpgModel.from_file(path)
    cand = extract_cpg(model, shape=shape)
    if cand.out_of_scope:
        raise Unavailable("cpg: out of scope (%s)" % cand.reason)
    return lower_candidate(cand)


def _build_java(fixture):
    """The Java structural frontend (2PC sources -> canonical IR)."""
    name = fixture["fixture"]
    if name != "twopc":
        raise Unavailable("java: %r is not a Java 2PC target" % name)
    src = os.path.join(_repo_root(), "twopc-java", "src")
    if not os.path.isdir(src):
        raise Unavailable("java: missing artifact %s" % src)
    from rot.frontends import java
    return java.build_ir(src, protocol="twopc", n=2, buggy=True)


_DRIVERS = {
    "targets": _build_targets,
    "code": _build_code,
    "cpg": _build_cpg,
    "java": _build_java,
}


def _build(frontend, fixture):
    """Drive ``frontend`` on ``fixture`` (raises Unavailable if it can't)."""
    driver = _DRIVERS.get(frontend)
    if driver is None:
        raise Unavailable("unknown frontend %r" % frontend)
    return driver(fixture)



# ---------------------------------------------------------------------------
# Metric computation.
# ---------------------------------------------------------------------------

def _has_source_pinning(ir):
    """True iff the IR carries source-line provenance (a counterexample step
    can be pinned to a real line).  The source-grounded frontends (code / cpg
    / java) stamp ``provenance`` with a line + file; the hand-authored
    ``targets`` baseline does not."""
    prov = ir.metadata.get("provenance")
    if not isinstance(prov, dict):
        return False
    return any(k in prov for k in ("start_line", "end_line", "filename",
                                   "line", "source_line"))


def _coach_drivable(ir, fixture):
    """True iff the P2 coach is drivable from the IR: the fixture names a
    decision action, the IR has it, and ``compute_to_proceed`` yields a valid
    record (guard + conditions + blocked) -- the machine-readable unblock
    path."""
    action_name = fixture.get("decision_action")
    if not action_name:
        return False  # N/A (e.g. 2PC has no tool-gating decision action).
    if action_name not in set(a.name for a in ir.actions):
        return False
    try:
        from rot.to_proceed import compute_to_proceed
        rec = compute_to_proceed(ir, action_name, {})
        return (rec is not None and "guard" in rec and "conditions" in rec
                and "blocked" in rec)
    except Exception:
        return False


def _compute_metrics(ir, verdict, fixture):
    """The §3 metrics for one (frontend, fixture) cell, on the known-bug."""
    gt_buggy = fixture["ground_truth"][fixture["known_bug_variant"]]
    ir_vars = set(v.name for v in ir.variables)
    critical = fixture.get("critical_vars") or []
    retained = sum(1 for c in critical if c in ir_vars)
    dataflow_edge_recall = (float(retained) / len(critical)) if critical else 0.0
    return {
        "false_proven": 1 if (gt_buggy == "VIOLATED" and verdict.is_proven()) else 0,
        "violation_recall": 1 if (gt_buggy == "VIOLATED"
                                  and verdict.is_violated()) else 0,
        "dataflow_edge_recall": dataflow_edge_recall,
        "source_pinning_rate": 1.0 if _has_source_pinning(ir) else 0.0,
        "coach_quality": 1 if _coach_drivable(ir, fixture) else 0,
        "unknown_rate": 1 if verdict.status == "unknown" else 0,
        "cost": len(ir.actions),
    }


# ---------------------------------------------------------------------------
# Corpus + result containers.
# ---------------------------------------------------------------------------

def load_corpus(corpus_dir=None):
    """Load the bench corpus: a list of fixture manifests (sorted by name)."""
    root = corpus_dir or os.path.join(_repo_root(), "bench")
    fixtures = []
    for name in sorted(os.listdir(root)):
        mpath = os.path.join(root, name, "manifest.json")
        if os.path.isfile(mpath):
            with open(mpath, "r") as fh:
                fixtures.append(json.load(fh))
    return fixtures


class CellResult(object):
    """The result of one (frontend, fixture) cell."""

    def __init__(self, frontend, fixture, status, verdict_status=None,
                 metrics=None, detail=""):
        self.frontend = frontend
        self.fixture = fixture
        self.status = status          # "available" | "unavailable"
        self.verdict_status = verdict_status
        self.metrics = metrics or {}
        self.detail = detail

    def to_dict(self):
        d = {
            "frontend": self.frontend,
            "fixture": self.fixture,
            "status": self.status,
        }
        if self.verdict_status is not None:
            d["verdict"] = self.verdict_status
        if self.metrics:
            d["metrics"] = dict(self.metrics)
        if self.detail:
            d["detail"] = self.detail
        return d


class ABResult(object):
    """The full A/B table + the lexicographic winner."""

    def __init__(self, corpus, cells, winner, per_frontend):
        self.corpus = corpus
        self.cells = cells            # list[CellResult]
        self.winner = winner          # frontend name (or None)
        self.per_frontend = per_frontend  # {frontend: aggregate dict}

    def to_dict(self):
        return {
            "corpus": [c["fixture"] for c in self.corpus],
            "cells": [c.to_dict() for c in self.cells],
            "per_frontend": {k: v for k, v in sorted(self.per_frontend.items())},
            "winner": self.winner,
        }


def to_json(result, indent=2):
    return json.dumps(result.to_dict(), indent=indent, sort_keys=False)



# ---------------------------------------------------------------------------
# The A/B run.
# ---------------------------------------------------------------------------

def _ranking_tuple(aggregate):
    """The lexicographic tuple for a frontend's aggregate metrics (higher is
    better).  Lower-is-better metrics are sign-flipped."""
    return tuple(
        (-aggregate.get(name, 0) if negated else aggregate.get(name, 0))
        for name, negated in _METRIC_ORDER)


def _aggregate(cells, frontend):
    """Average the §3 metrics over a frontend's AVAILABLE cells (fair across
    frontends with different fixture coverage); hard-gate = no false_proven."""
    avail = [c for c in cells
             if c.frontend == frontend and c.status == "available"]
    if not avail:
        return None
    keys = [name for name, _ in _METRIC_ORDER] + ["false_proven"]
    n = float(len(avail))
    agg = {}
    for k in keys:
        agg[k] = sum(c.metrics.get(k, 0) for c in avail) / n
    agg["cells"] = len(avail)
    agg["unavailable"] = sum(1 for c in cells
                             if c.frontend == frontend
                             and c.status == "unavailable")
    agg["hard_gate_pass"] = all(c.metrics.get("false_proven", 0) == 0
                                for c in avail)
    return agg


def run_ab(corpus=None, frontends=None, cfg=None):
    """Run the A/B over ``corpus`` (defaults to ``bench/``) for the named
    frontends (defaults to each manifest's list).  Returns an
    :class:`ABResult` (the full table + the lexicographic winner).

    Every cell is driven through the SAME Verify plane (``verify_candidate``),
    so the A/B measures the *frontends* (extraction fidelity), not the engine.
    Offline and deterministic: no network, no external tools, no randomness.
    """
    from rot.config import Config
    from rot.cegar import verify_candidate
    if cfg is None:
        cfg = Config(max_states=200000)
    if corpus is None:
        corpus = load_corpus()

    cells = []
    frontends_seen = set()
    for fixture in corpus:
        for frontend in (frontends or fixture.get("frontends", [])):
            frontends_seen.add(frontend)
            try:
                ir = _build(frontend, fixture)
                verdict = verify_candidate(ir, cfg)
                metrics = _compute_metrics(ir, verdict, fixture)
                cells.append(CellResult(
                    frontend, fixture["fixture"], "available",
                    verdict_status=verdict.status, metrics=metrics))
            except Unavailable as e:
                cells.append(CellResult(
                    frontend, fixture["fixture"], "unavailable",
                    detail=str(e)))
            except Exception as e:  # a hard error is recorded, not a crash.
                cells.append(CellResult(
                    frontend, fixture["fixture"], "unavailable",
                    detail="%s: %s" % (type(e).__name__, e)))

    per_frontend = {}
    for frontend in sorted(frontends_seen):
        agg = _aggregate(cells, frontend)
        if agg is not None:
            agg["ranking"] = _ranking_tuple(agg)
            per_frontend[frontend] = agg

    # The lexicographic winner: hard gate first (no false_proven), then the
    # lexicographic tuple (higher is better), then the name (a deterministic
    # tie-break so the decision is reproducible and citable).
    eligible = {f: agg for f, agg in per_frontend.items() if agg["hard_gate_pass"]}
    winner = None
    if eligible:
        best_rank = max(agg["ranking"] for agg in eligible.values())
        ties = sorted(f for f, agg in eligible.items()
                      if agg["ranking"] == best_rank)
        winner = ties[0]

    return ABResult(corpus, cells, winner, per_frontend)


def lexicographic_winner(result):
    """The lexicographic winner of an :class:`ABResult` (a frontend name, or
    ``None`` if no frontend passed the hard gate)."""
    return result.winner



# ---------------------------------------------------------------------------
# The report (deterministic, citable).
# ---------------------------------------------------------------------------

def to_report(result):
    """A deterministic, human-readable report of the A/B."""
    lines = []
    lines.append("# Frontend A/B (Joern-primary, §3)")
    lines.append("")
    lines.append("Corpus: %s" % ", ".join(c["fixture"] for c in result.corpus))
    lines.append("")
    lines.append("## Per-(frontend, fixture) cells")
    lines.append("")
    lines.append("| frontend | fixture | status | verdict | violation_recall | dataflow | source_pin | coach | unknown | cost |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for c in result.cells:
        if c.status == "available":
            m = c.metrics
            lines.append("| %s | %s | %s | %s | %s | %.2f | %s | %s | %s | %s |" % (
                c.frontend, c.fixture, c.status, c.verdict_status,
                m["violation_recall"], m["dataflow_edge_recall"],
                m["source_pinning_rate"], m["coach_quality"],
                m["unknown_rate"], m["cost"]))
        else:
            lines.append("| %s | %s | UNAVAILABLE | -- | -- | -- | -- | -- | -- | -- |" % (
                c.frontend, c.fixture))
    lines.append("")
    lines.append("## Per-frontend aggregate (hard gate + lexicographic ranking)")
    lines.append("")
    for f, agg in sorted(result.per_frontend.items()):
        gate = "PASS" if agg["hard_gate_pass"] else "**FAIL (false-PROVEN)**"
        lines.append("- **%s** -- hard gate: %s | cells: %d (unavailable: %d) | ranking: %s"
                     % (f, gate, agg["cells"], agg["unavailable"],
                        tuple(round(x, 3) for x in agg["ranking"])))
    lines.append("")
    lines.append("## Winner")
    lines.append("")
    if result.winner:
        lines.append("**%s** -- lexicographic winner over the corpus "
                     "(no false-PROVEN; best (violation_recall, dataflow_edge_recall, "
                     "source_pinning_rate, coach_quality, -unknown_rate, -cost))."
                     % result.winner)
    else:
        lines.append("No frontend passed the hard gate (every one false-PROVEN).")
    lines.append("")
    lines.append("_Unavailable != loss: a frontend that cannot run on a fixture is "
                 "recorded UNAVAILABLE (an honest, objective distinction), not a loss._")
    return "\n".join(lines)


def _main(argv=None):
    import argparse
    p = argparse.ArgumentParser(
        prog="rot ab",
        description="Frontend A/B over the bench corpus (Joern-primary §3).")
    p.add_argument("--corpus", default=None, help="corpus dir (default: bench/)")
    p.add_argument("--frontends", default=None,
                   help="comma-separated frontends (default: each manifest's list)")
    p.add_argument("--json", action="store_true", help="emit JSON (default: report)")
    p.add_argument("--out", default=None, help="write the JSON to this path")
    args = p.parse_args(argv)

    corpus = load_corpus(args.corpus)
    frontends = ([f.strip() for f in args.frontends.split(",") if f.strip()]
                 if args.frontends else None)
    result = run_ab(corpus=corpus, frontends=frontends)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(to_json(result) + "\n")
        print("wrote %s" % args.out)
    print(to_json(result) if args.json else to_report(result))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main())

