# -*- coding: utf-8 -*-
"""OPA (Rego) stub front-end: ``.rego`` lowers to the SAME IR as ``.dw``.

The neutral-checker claim (Phase 4): the same policy shape, expressed in
Rego or Dogwood, lowers to a structurally identical ``ProtocolIR``
(``ProtocolIR.__eq__`` ignores metadata) and decides to the same verdict.

Run: python tests/test_opa_frontend.py
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.frontends.policy as fe  # noqa: E402
import rot.dw as dw  # noqa: E402
import rot.spendcap as spendcap  # noqa: E402
import rot.shapes as shapes  # noqa: E402
from apw_common import (assert_buggy_violated, assert_correct_proven)  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(_REPO, "samples")
AI = os.path.join(SAMPLES, "ai_authoring")

APW2_BUGGY = os.path.join(AI, "apw2-buggy.rego")
APW2_CORRECT = os.path.join(AI, "apw2-correct.rego")
APW1_BUGGY = os.path.join(AI, "apw1-buggy.rego")
APW1_CORRECT = os.path.join(AI, "apw1-correct.rego")


def _dw(name):
    return dw.parse_file(os.path.join(SAMPLES, name)).to_ir()


class OpaLoweringTests(unittest.TestCase):
    """The .rego samples lower to the SAME IR as their .dw twins."""

    def test_apw2_buggy_rego_equals_dw(self):
        self.assertEqual(fe.build_ir(APW2_BUGGY), _dw("apw2-buggy.dw"))

    def test_apw2_correct_rego_equals_dw(self):
        self.assertEqual(fe.build_ir(APW2_CORRECT), _dw("apw2-correct.dw"))

    def test_apw1_buggy_rego_equals_dw(self):
        self.assertEqual(fe.build_ir(APW1_BUGGY), _dw("apw1-buggy.dw"))

    def test_apw1_correct_rego_equals_dw(self):
        self.assertEqual(fe.build_ir(APW1_CORRECT), _dw("apw1-correct.dw"))

    def test_metadata_provenance(self):
        ir = fe.build_ir(APW2_BUGGY)
        self.assertEqual(ir.metadata["frontend"], "opa")
        self.assertEqual(ir.metadata["family"], "APPROVAL_REPLAY")
        self.assertEqual(ir.metadata["property_name"], "approval_single_use")
        self.assertEqual(ir.metadata["property_kind"], "safety")
        self.assertEqual(ir.metadata["shape"], "approval_replay")
        self.assertEqual(ir.metadata["variant"], "buggy")
        self.assertTrue(ir.metadata["policy_source"].endswith(".rego"))


class OpaVerdictTests(unittest.TestCase):
    """The lowered IRs decide like their Dogwood twins."""

    def test_apw2_buggy_violated(self):
        ir = fe.build_ir(APW2_BUGGY)
        assert_buggy_violated(ir, {"approved": True, "orders": 2}, "OPA/APW-2")

    def test_apw2_correct_proven(self):
        ir = fe.build_ir(APW2_CORRECT)
        assert_correct_proven(ir, "OPA/APW-2")

    def test_apw1_buggy_violated(self):
        ir = fe.build_ir(APW1_BUGGY)
        assert_buggy_violated(ir, {"completed": 0, "inflight": 3},
                              "OPA/APW-1")

    def test_apw1_correct_proven(self):
        ir = fe.build_ir(APW1_CORRECT)
        assert_correct_proven(ir, "OPA/APW-1")

    def test_oracle_identity(self):
        """The stub lowers to the exact oracle builders (same source)."""
        self.assertEqual(fe.build_ir(APW2_BUGGY),
                         shapes.build_approval_replay_ir(buggy=True))
        self.assertEqual(fe.build_ir(APW2_CORRECT),
                         shapes.build_approval_replay_ir(buggy=False))
        self.assertEqual(fe.build_ir(APW1_BUGGY), spendcap.build_ir(buggy=True))
        self.assertEqual(fe.build_ir(APW1_CORRECT), spendcap.build_ir(buggy=False))


class OpaErrorTests(unittest.TestCase):
    def test_missing_file(self):
        with self.assertRaises(fe.PolicyFrontendError):
            fe.build_ir(os.path.join(AI, "nope.rego"))

    def test_missing_shape_annotation(self):
        with tempfile.NamedTemporaryFile("w", suffix=".rego", delete=False) as f:
            f.write("package x\n\nallow {\n    true\n}\n")
            path = f.name
        try:
            with self.assertRaises(fe.PolicyFrontendError) as ctx:
                fe.build_ir(path)
            self.assertIn("rotn:shape", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_unsupported_shape(self):
        with tempfile.NamedTemporaryFile("w", suffix=".rego", delete=False) as f:
            f.write("# rotn:shape=quux\n\npackage x\n\nallow {\n    true\n}\n")
            path = f.name
        try:
            with self.assertRaises(fe.PolicyFrontendError) as ctx:
                fe.build_ir(path)
            self.assertIn("unsupported shape", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_bad_skeleton(self):
        with tempfile.NamedTemporaryFile("w", suffix=".rego", delete=False) as f:
            f.write("# rotn:shape=spendcap\n# rotn:variant=buggy\n\n"
                    "just some comments, no rules here\n")
            path = f.name
        try:
            with self.assertRaises(fe.PolicyFrontendError) as ctx:
                fe.build_ir(path)
            self.assertIn("skeleton", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_bad_variant(self):
        with tempfile.NamedTemporaryFile("w", suffix=".rego", delete=False) as f:
            f.write("# rotn:shape=spendcap\n# rotn:variant=bogus\n\n"
                    "package x\n\nallow {\n    true\n}\n")
            path = f.name
        try:
            with self.assertRaises(fe.PolicyFrontendError) as ctx:
                fe.build_ir(path)
            self.assertIn("variant", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_variant_override(self):
        """The CLI ``variant`` overrides the annotation."""
        self.assertEqual(
            fe.build_ir(APW2_BUGGY, variant="correct"),
            shapes.build_approval_replay_ir(buggy=False))


if __name__ == "__main__":
    unittest.main()