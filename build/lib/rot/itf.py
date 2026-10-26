# -*- coding: utf-8 -*-
"""itf.py -- Apalache ITF counterexample-trace parser and trace engine.

ROTN's soundness core is engine-agnostic (the narrow waist is
``rot.ir``).  This module plugs a third engine, ``apalache``, into the
same contract as ``rot.symbolic`` and ``rot.tlc``: it parses a
counterexample trace produced by the Apalache model checker in the ITF
JSON format (https://apalache-mc.org/docs/adr/015adr-trace.html) and
evaluates a pinned ``rot.invariants.Invariant`` over the trace's concrete
states.

Accepted ITF layouts (both are normalized to the same structure)
-----------------------------------------------------------------
* current ("states"): a top-level ``states`` array of flat
  ``var -> value`` objects; ``states[0]`` is the initial state and each
  later entry is the result of one more transition (per-state ``#meta``
  blocks, e.g. ``index``, are stripped);
* legacy ("init/state/action"): an ``init`` array of ``{var, value}``
  pairs plus parallel ``action`` / ``state`` arrays, where ``state[i]``
  is the post-state of the transition whose pre-state is ``action[i]``.

Both become ``ItfTrace.states``: an ordered list of state dicts with
``states[0]`` the initial state.

Engine semantics (sound by construction)
----------------------------------------
* the first trace state where the invariant evaluates to a definite
  ``False`` is a refutation -> ``EngineResult("violated", witness=state)``;
  the CEGAR recheck re-evaluates the invariant on that concrete dict, so
  the verdict survives the refinement loop;
* if the invariant never evaluates to ``False`` on the trace, the engine
  reports ``unknown`` with an explanatory note -- a single concrete path
  can REFUTE a safety property but can never PROVE it, and ROTN never
  upgrades a verdict to ``proven`` without a full-state proof.

The module depends only on the narrow waist (``rot.ir``,
``rot.symbolic``) and the standard library; it imports no frontend,
respecting the dependency rule (engines never depend on frontends).
Pure stdlib, Python 3.6 compatible.
"""

import json
import os
import sys

from .ir import Expr
from . import symbolic

__all__ = ["ItfError", "ItfTrace", "ItfEngine", "parse_itf"]


class ItfError(Exception):
    """Raised when an ITF artifact cannot be parsed into an :class:`ItfTrace`.

    The message names the offending structure so the CLI can report it
    directly to the user.
    """
    pass


class ItfTrace(object):
    """A normalized Apalache ITF trace: an ordered list of concrete states.

    ``states[0]`` is the initial state; for ``i > 0``, ``states[i]`` is
    the state after the ``i``-th transition of the trace.  ``vars`` lists
    the state variables the trace assigns (in order), ``meta`` carries
    the top-level ``#meta`` block (format description, varTypes, ...) and
    ``format_variant`` records which layout the source file used.
    """

    def __init__(self, states, vars_, meta=None, format_variant="states",
                 source_path=""):
        if not states:
            raise ItfError("ITF trace has no states")
        self.states = [dict(s) for s in states]
        self.vars = list(vars_)
        self.meta = dict(meta or {})
        self.format_variant = format_variant
        self.source_path = source_path or ""

    @property
    def init(self):
        """The initial state (``states[0]``) as a plain dict."""
        return dict(self.states[0])

    @property
    def final_state(self):
        """The last state of the trace as a plain dict."""
        return dict(self.states[-1])

    def to_dict(self):
        """JSON-serializable summary (for reports and diagnostics)."""
        return {
            "format": self.format_variant,
            "vars": self.vars,
            "meta": self.meta,
            "n_states": len(self.states),
            "init": self.init,
            "final_state": self.final_state,
            "source_path": self.source_path,
        }


def _clean_state(st, where):
    """Validate one state object and strip its ``#meta`` block."""
    if not isinstance(st, dict):
        raise ItfError("%s: a state must be a JSON object, got %s"
                       % (where, type(st).__name__))
    return {k: v for k, v in st.items() if k != "#meta"}


def _state_from_pairs(pairs, where):
    """Validate one legacy ``[{var, value}, ...]`` pair list into a dict."""
    if not isinstance(pairs, list):
        raise ItfError("%s must be an array of {var, value} pairs" % where)
    st = {}
    for k, entry in enumerate(pairs):
        if not (isinstance(entry, dict) and "var" in entry
                and "value" in entry):
            raise ItfError("%s[%d] must be an object with 'var' and 'value'"
                           % (where, k))
        name = entry["var"]
        if not isinstance(name, str) or not name:
            raise ItfError("%s[%d] has an invalid variable name" % (where, k))
        st[name] = entry["value"]
    return st


def parse_itf(path):
    """Parse an Apalache ITF JSON file into an :class:`ItfTrace`.

    Accepts the current ``states`` layout and the legacy
    ``init``/``state``/``action`` layout.  Raises :class:`ItfError` (not
    ``ValueError``/``IOError``) on any structural problem, with the
    offending location in the message.
    """
    try:
        with open(path, "r") as f:
            doc = json.load(f)
    except (IOError, OSError) as exc:
        raise ItfError("cannot read ITF file %r: %s" % (path, exc))
    except ValueError as exc:
        raise ItfError("ITF file %r is not valid JSON: %s" % (path, exc))
    if not isinstance(doc, dict):
        raise ItfError("ITF root must be a JSON object, got %s"
                       % type(doc).__name__)

    meta = doc.get("#meta")
    if not isinstance(meta, dict):
        meta = {}
    top_vars = doc.get("vars")
    if top_vars is not None and not (
            isinstance(top_vars, list)
            and all(isinstance(v, str) for v in top_vars)):
        raise ItfError("'vars' must be a list of variable names")

    if "states" in doc:
        raw = doc["states"]
        if not isinstance(raw, list) or not raw:
            raise ItfError("'states' must be a non-empty array of state objects")
        states = [_clean_state(st, "states[%d]" % i)
                  for i, st in enumerate(raw)]
        if top_vars is None:
            top_vars = list(states[0].keys())
        return ItfTrace(states, top_vars, meta,
                        format_variant="states", source_path=path)

    if "init" in doc:
        return _parse_legacy(doc, meta, path)

    raise ItfError(
        "unrecognized ITF structure: expected a 'states' array (current "
        "format) or 'init'/'state'/'action' arrays (legacy format)")


def _parse_legacy(doc, meta, path):
    """Parse the legacy ``init``/``action``/``state`` ITF layout.

    The normalized trace is ``[init] + post-states``; the ``action``
    pre-states are only used to validate the pairing lengths, since the
    engine needs post-states only (``state[0]`` succeeds the initial
    state).
    """
    init = _state_from_pairs(doc["init"], "init")
    action = doc.get("action")
    state = doc.get("state")
    if action is None or state is None:
        raise ItfError("legacy ITF needs both 'action' and 'state' arrays")
    if (not isinstance(action, list) or not isinstance(state, list)
            or len(action) != len(state)):
        def _len(x):
            return len(x) if isinstance(x, list) else "?"
        raise ItfError("'action' and 'state' must be equal-length arrays "
                       "(len(action)=%s, len(state)=%s)" % (_len(action),
                                                            _len(state)))
    states = [init] + [_state_from_pairs(st, "state[%d]" % i)
                       for i, st in enumerate(state)]
    return ItfTrace(states, list(init.keys()), meta,
                    format_variant="legacy", source_path=path)


class ItfEngine(object):
    """Trace engine: refutes invariants over a parsed Apalache ITF trace.

    Mirrors the ``rot.tlc.TlcEngine`` contract -- ``check(model, prop,
    target)`` returns a ``rot.symbolic.EngineResult`` -- so the pipeline
    can select it with ``engine="apalache"``.  ``model`` (the linear
    model) is optional: it is used only for an informational cross-check
    that the trace steps are legal successors under the ROTN
    linearization (a trace produced from a differently-encoded spec is
    still evaluated; the mismatch is only noted).
    """

    name = "apalache"

    def __init__(self, cfg, trace_path=None):
        self.cfg = cfg
        self.trace_path = trace_path or getattr(cfg, "itf_trace", None)

    def load_trace(self):
        """Parse the configured trace; raises :class:`ItfError` on problems."""
        if not self.trace_path:
            raise ItfError(
                "no ITF trace configured (pass trace_path, set "
                "Config.itf_trace, or use the pipeline's --itf option)")
        return parse_itf(self.trace_path)

    def _legality_note(self, model, trace):
        """Informational cross-check of trace steps against the linear model.

        Returns ``""`` or a note describing steps that are not exact
        successors under ``model.next_states``.  Never raises.
        """
        if model is None or len(trace.states) < 2:
            return ""
        try:
            bad = 0
            for i in range(1, len(trace.states)):
                pre = trace.states[i - 1]
                post = trace.states[i]
                if post not in model.next_states(pre):
                    bad += 1
            if bad == 0:
                return ""
            return ("; note: %d of %d trace steps are not exact successors "
                    "under the ROTN linear model (the trace may come from a "
                    "differently-encoded spec)"
                    % (bad, len(trace.states) - 1))
        except Exception:
            return ""

    def check(self, model, prop, target="model"):
        """Evaluate ``prop`` over the trace states (see module docstring).

        ``target`` is accepted for interface parity with the other
        engines (the trace is the single artifact, so it is not used
        further).  Never raises: parse failures are folded into an
        ``error`` result, evaluation surprises are treated as UNDEF.
        """
        try:
            trace = self.load_trace()
        except ItfError as exc:
            return symbolic.EngineResult(
                "error",
                note="apalache ITF engine: %s" % exc)

        states = trace.states
        n = len(states)
        legality = self._legality_note(model, trace)

        witness = None
        definite = False
        for i, st in enumerate(states):
            try:
                r = prop.expression.eval(st)
            except Exception:
                continue
            if r is Expr.UNDEF:
                continue
            definite = True
            if not r:
                witness = (i, dict(st))
                break

        if witness is not None:
            i, st = witness
            return symbolic.EngineResult(
                "violated",
                witness=st,
                n_states=n,
                complete=True,
                note="Apalache ITF trace %r refutes invariant %r at state "
                     "%d of %d%s" % (self.trace_path, prop.name, i, n,
                                    legality))
        if not definite:
            return symbolic.EngineResult(
                "unknown",
                n_states=n,
                complete=True,
                note="invariant %r is undefined (UNDEF) at all %d states of "
                     "ITF trace %r -- likely a variable-name mismatch%s"
                     % (prop.name, n, self.trace_path, legality))
        return symbolic.EngineResult(
            "unknown",
            n_states=n,
            complete=True,
            note="invariant %r holds at all %d states of ITF trace %r; a "
                 "single concrete trace can refute a property but cannot "
                 "prove it%s" % (prop.name, n, self.trace_path, legality))




def main(argv=None):
    """Standalone CLI: evaluate one invariant over one ITF trace.

    Exit codes: 0 = invariant holds at every trace state (or is
    undefined everywhere); 10 = the trace refutes the invariant (the
    witness state is printed); 2 = usage/parse error.
    """
    import argparse

    import rot.invariants as invariants

    parser = argparse.ArgumentParser(
        prog="python -m rot.itf",
        description="Evaluate a ROTN invariant over an Apalache ITF trace.")
    parser.add_argument("trace", help="path to a .itf.json trace")
    parser.add_argument("--invariant", default="agreement",
                        help="invariant name [default: agreement]")
    parser.add_argument("--participants", type=int, default=3,
                        metavar="N",
                        help="participant count for the invariant "
                             "[default: 3]")
    args = parser.parse_args(argv)

    try:
        prop = invariants.get(args.invariant, args.participants)
    except Exception as exc:
        print("ERROR: cannot load invariant %r: %s" % (args.invariant, exc))
        return 2

    try:
        trace = parse_itf(args.trace)
    except ItfError as exc:
        print("ERROR: %s" % exc)
        return 2

    res = ItfEngine(None, trace_path=args.trace).check(None, prop)
    print("status    : %s" % res.status)
    print("trace     : %s (%s format, %d states)"
          % (trace.source_path, trace.format_variant, len(trace.states)))
    if res.witness is not None:
        print("witness   : state where %r is False:" % prop.name)
        print(json.dumps(res.witness, indent=2, sort_keys=True))
    if res.note:
        print("note      : %s" % res.note)
    return 10 if res.status == "violated" else 0


if __name__ == "__main__":
    sys.exit(main())

