# -*- coding: utf-8 -*-
"""Shared helpers for the ``test_apwN.py`` APW-catalog tests.

Every APW class ships a hand-written oracle (a ``ProtocolIR`` with a pinned
property) in ``rot.shapes`` (or ``rot.spendcap`` for APW-1).  The tests decide
that property over the oracle's reachable states with the bounded-exhaustive
symbolic engine and assert:

  * the **buggy** oracle is VIOLATED, with the expected named witness;
  * the **correct** oracle is PROVEN.

This is the "oracle-based" half of each APW test; the ".dw lowers to the
oracle" half (``oracle-match``) is asserted in the individual ``test_apwN.py``
files where a ``.dw`` fixture exists (APW-1..4).

Python 3.6 compatible (no f-strings / no walrus).
"""

import os

from rot.symbolic import SymbolicEngine, PROVEN, VIOLATED, UNKNOWN

# The spendcap slice is small; a complete search is expected.  An UNKNOWN
# verdict is a test failure (the state space is too large for the slice), not
# an answer.
_MAX_STATES = 200000


def fixtures_dir():
    """Absolute path to the ``.dw`` fixture directory (APW-1..4 pairs)."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "fixtures", "aws_dogwood", "spendcap", "policies")


def fixture(name):
    """Absolute path to a named fixture (e.g. ``spendcap-buggy.dw``)."""
    return os.path.join(fixtures_dir(), name)


def decide(ir):
    """Decide ``ir.pinned_property`` over ``ir``'s reachable states.

    Returns the ``EngineResult`` (``.status`` in {proven, violated, unknown},
    ``.witness`` the counterexample state for VIOLATED, ``.note`` a reason for
    UNKNOWN).  Raises ``AssertionError`` on UNKNOWN -- the APW slices are
    small enough that a complete search must always be returned.
    """
    from rot.linearization import linearize
    model = linearize(ir)
    res = SymbolicEngine(model, max_states=_MAX_STATES).check(
        ir.pinned_property)
    if res.is_unknown():
        raise AssertionError(
            "engine returned UNKNOWN for %s (state space too large): %s"
            % (ir.name, res.note))
    return res


def assert_buggy_violated(buggy_ir, expected_witness, label):
    """Assert the buggy oracle is VIOLATED with the expected witness."""
    res = decide(buggy_ir)
    assert res.status == VIOLATED, (
        "%s buggy oracle must be VIOLATED, got %s"
        % (label, res.status))
    assert res.witness == expected_witness, (
        "%s buggy witness mismatch: got %r, want %r"
        % (label, res.witness, expected_witness))
    return res


def assert_correct_proven(correct_ir, label):
    """Assert the correct oracle is PROVEN."""
    res = decide(correct_ir)
    assert res.status == PROVEN, (
        "%s correct oracle must be PROVEN, got %s"
        % (label, res.status))
    assert res.witness is None, (
        "%s correct oracle must have no counterexample" % label)
    return res


def assert_oracle_match(fixture_path, oracle_ir, label):
    """Assert a ``.dw`` fixture lowers to exactly the hand-written oracle."""
    from rot.dw import parse_file
    lowered = parse_file(fixture_path).to_ir()
    assert lowered == oracle_ir, (
        "%s: .dw fixture %s does not lower to the oracle\n"
        "  lowered  name=%s protocol=%s\n  oracle   name=%s protocol=%s"
        % (label, os.path.basename(fixture_path), lowered.name,
           lowered.metadata.get("protocol"), oracle_ir.name,
           oracle_ir.metadata.get("protocol")))
    return lowered
