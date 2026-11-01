# -*- coding: utf-8 -*-
"""D5 -- the demo (and the ci/replay path) must not touch the protocol plane.

The protocol-plane modules (2PC / ZAB / PBFT / payment-consensus /
order-service) and the research modules (ladder / ab / empirical / llm /
cpg / classify) live in the separate ``rotn-research`` repo, NOT in the
product. The product's ``rot demo`` (rule -> attack -> proof -> coach ->
attestation) must be runnable with those modules ABSENT -- i.e. it must not
import them.

This test installs a ``sys.meta_path`` finder that raises ``ImportError`` for
any of the protocol-plane / research modules, clears them from ``sys.modules``,
then runs ``cmd_demo`` and asserts it still exits 0. If the demo (or anything
it transitively imports) reaches for the research plane, the import is
blocked and the test fails -- which is exactly the hole we must not have.

Run: python tests/test_demo_no_research.py
"""

import argparse
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.__main__ as m  # noqa: E402


# The protocol-plane + research modules that the demo must NOT import.
# (A module is "blocked" by its dotted name; submodules of these are not
# separately listed because the demo never imports submodules of them.)
_BLOCKED = frozenset([
    # protocol plane (consensus / payments-as-consensus):
    "rot.twopc", "rot.zab", "rot.pbft", "rot.payment",
    "rot.order_service", "rot.composition", "rot.zk_bugs",
    # research plane (rotn-research):
    "rot.ladder", "rot.ab", "rot.empirical", "rot.llm_baseline",
    "rot.cpg", "rot.classify",
])


class _Blocker(object):
    """A meta_path finder that blocks imports of the protocol-plane modules."""

    def find_spec(self, fullname, path, target=None):
        if fullname in _BLOCKED:
            raise ImportError(
                "D5: protocol-plane module %r must not be imported by the "
                "demo (the product must not depend on the research plane)"
                % fullname)
        return None


class TestDemoNoResearch(unittest.TestCase):
    def test_demo_runs_with_protocol_plane_absent(self):
        blocker = _Blocker()
        sys.meta_path.insert(0, blocker)
        # Drop any cached copies so a re-import would have to go through the
        # blocker (and be blocked).
        dropped = [n for n in sys.modules if n in _BLOCKED]
        for n in dropped:
            del sys.modules[n]
        out = tempfile.mkdtemp(prefix="rotn_d5_")
        try:
            args = argparse.Namespace(
                command="demo", beachhead="spendcap", out=out,
                key=None, license=None, tier=None, depth=None)
            code = m.cmd_demo(args)
        except ImportError as exc:  # a blocked module was reached
            self.fail("cmd_demo reached for the research plane: %s" % exc)
        finally:
            try:
                sys.meta_path.remove(blocker)
            except ValueError:
                pass
            # Restore the modules we dropped so other tests are unaffected.
            for n in dropped:
                sys.modules.pop(n, None)
        self.assertEqual(
            code, 0,
            "cmd_demo must exit 0 with the protocol plane absent (D5); "
            "got %r" % code)


if __name__ == "__main__":
    unittest.main()