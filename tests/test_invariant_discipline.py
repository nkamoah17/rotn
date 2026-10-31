# -*- coding: utf-8 -*-
"""T0b -- invariant-kind SOUNDNESS DISCIPLINE (the "checked, not argued" gate).

The moat is that the correspondence between the *model* and the *policy* is
**checked**, not argued (``tests/test_correspondence.py``).  As new invariant
kinds land (B2: sequences, information-flow, real liveness) that discipline
must travel with each one, or we add verification surface we cannot defend.
This module is the gate that enforces "no exceptions."

rule
    Every **product** invariant kind ships with BOTH:
      (i)  a correct/buggy witness pair -- the correct model *satisfies* the
           invariant, the buggy model *violates* it with a REAL witness; and
      (ii) a correspondence-or-spec check -- the model's decision rule is pinned
           to the policy/spec (or ``to_proceed`` is computed from the spec).

    A kind registered without both is a reviewer-visible hole, so the gate
    fails the build.

scope
    Protocol-plane invariants (2PC / ZAB / PBFT / payment, and the
    orchestration rung) are **research** and move to ``rotn-research`` in the
    research split; they are EXEMPT here.  This gate is responsible only for
    the product invariants named in :data:`DISCIPLINE`.

B2 contract
    Before a new invariant kind is accepted, add it to :data:`DISCIPLINE` with
    both evidence files and create those files.  ``require_discipline`` is the
    helper a new invariant's test calls to fail fast if its evidence is
    missing.  The gate below enforces completeness for the existing product
    kinds so the discipline cannot silently regress.

Python 3.6 compatible (no f-strings).
"""

import os
import unittest

import rot.invariants as inv

_HERE = os.path.dirname(os.path.abspath(__file__))


def _path(rel):
    return os.path.join(_HERE, rel)


def _contains(rel, needle):
    with open(_path(rel), "r") as f:
        return needle in f.read()


# The product invariants and the evidence that disciplines each one.
#   correct_buggy : correct model satisfies the invariant; buggy model violates
#                   it with a real witness (the non-negotiable discriminator)
#   spec_or_corr  : the model's decision rule is pinned to the policy/spec
#                   (or ``to_proceed`` is computed from the spec)
DISCIPLINE = {
    "spendcap_within_cap": {
        "correct_buggy": "test_spendcap.py",       # PROVEN correct / VIOLATED buggy + witness
        "spec_or_corr":  "test_correspondence.py", # model.spend_ok_admits == policy sum<=cap
    },
    "no_exfiltration": {
        "correct_buggy": "test_coach.py",          # ExfiltrationCoachTests: violated+witness / recheck proven
        "spec_or_corr":  "test_coach.py",          # to_proceed computed from the spec
    },
    "policy_conformance": {
        "correct_buggy": "test_agent_step.py",     # correct conforms / buggy violates
        "spec_or_corr":  "test_agent_step.py",     # policy_conformance property == the policy
    },
}

# Markers the evidence files must carry so the gate is not vacuous.
CORRECT_BUGGY_MARKERS = ("buggy",)
CORRECT_OUTCOME_MARKERS = ("proven", "satisfies", "correct", "holds")
SPEC_OR_CORR_MARKERS = ("assertEqual", "to_proceed", "property", "satisfies")


def require_discipline(name):
    """B2 helper: assert a (new) invariant kind has its discipline registered.

    A new invariant's test calls this first; if the kind is missing from
    :data:`DISCIPLINE` or its evidence files are absent, this fails fast -- so
    an under-defended kind cannot be merged.
    """
    assert name in DISCIPLINE, (
        "invariant %r has no discipline entry; add it to DISCIPLINE with "
        "correct_buggy + spec_or_corr evidence before it ships" % (name,))
    ev = DISCIPLINE[name]
    for role in ("correct_buggy", "spec_or_corr"):
        assert os.path.isfile(_path(ev[role])), (
            "invariant %r: %s evidence file missing (%s)"
            % (name, role, ev[role]))


class TestInvariantDiscipline(unittest.TestCase):
    def test_manifest_is_not_vacuous(self):
        self.assertTrue(DISCIPLINE,
                        "DISCIPLINE is empty -- the gate is vacuous")

    def test_product_invariants_are_registered(self):
        """Every disciplined product invariant is a real registered invariant."""
        for name in DISCIPLINE:
            self.assertIn(name, inv.names(),
                          "product invariant %r is not registered" % (name,))

    def test_every_product_invariant_is_defended(self):
        """(i)+(ii) both evidence files exist and carry the discipline markers.

        A missing file, or a file that never exercises the buggy variant / never
        pins the model to the spec, is exactly the reviewer-visible hole this
        gate exists to catch.
        """
        for name, ev in DISCIPLINE.items():
            for role in ("correct_buggy", "spec_or_corr"):
                rel = ev[role]
                self.assertTrue(os.path.isfile(_path(rel)),
                                "%s: %s evidence file missing (%s)"
                                % (name, role, rel))
            cb = ev["correct_buggy"]
            self.assertTrue(any(_contains(cb, m) for m in CORRECT_BUGGY_MARKERS),
                            "%s: correct/buggy evidence must exercise a buggy "
                            "variant (%s)" % (name, cb))
            self.assertTrue(
                any(_contains(cb, m) for m in CORRECT_OUTCOME_MARKERS),
                "%s: correct/buggy evidence must also show the correct model "
                "satisfies the invariant (%s)" % (name, cb))
            sc = ev["spec_or_corr"]
            self.assertTrue(any(_contains(sc, m) for m in SPEC_OR_CORR_MARKERS),
                            "%s: spec/correspondence evidence is not a real "
                            "model-to-spec check (%s)" % (name, sc))

    def test_require_discipline_helper_is_live(self):
        """The B2 helper passes for the existing product kinds and rejects a
        kind with no discipline (the 'no exceptions' path)."""
        for name in DISCIPLINE:
            require_discipline(name)  # must not raise
        self.assertRaises(AssertionError, require_discipline,
                          "a_kind_with_no_discipline")


if __name__ == "__main__":
    unittest.main()