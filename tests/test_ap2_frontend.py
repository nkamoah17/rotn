# -*- coding: utf-8 -*-
"""AP2 mandate stub front-end: ``.ap2`` lowers to the SAME IR as ``.dw``.

"spend up to $X on Y" maps onto the APW shape it instantiates (APW-1/2/5)
and is lowered through the same oracle the Dogwood route uses, so the
verdict is language-neutral (Phase 4).

Run: python tests/test_ap2_frontend.py
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.frontends.policy as fe  # noqa: E402
import rot.frontends.policy.ap2 as ap2  # noqa: E402
import rot.spendcap as spendcap  # noqa: E402
import rot.shapes as shapes  # noqa: E402
from apw_common import (assert_buggy_violated, assert_correct_proven)  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APW1_BUGGY = os.path.join(_REPO, "samples", "apw1-buggy.dw")
APW2_BUGGY = os.path.join(_REPO, "samples", "apw2-buggy.dw")
APW5_BUGGY = os.path.join(_REPO, "samples", "apw5-buggy.dw")
SAMPLE_MANDATE = os.path.join(_REPO, "samples", "ai_authoring",
                              "ap2-spend-200.ap2")


def _write_mandate(obj, suffix=".ap2"):
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f)
    return path


class MapMandateTests(unittest.TestCase):
    """The mandate facets map onto the right APW shape."""

    def test_amount_max_maps_to_apw1(self):
        self.assertEqual(ap2.map_mandate({"amount_max": 200}), "APW-1")

    def test_single_use_maps_to_apw2(self):
        self.assertEqual(ap2.map_mandate({"single_use": True}), "APW-2")

    def test_session_scoped_maps_to_apw5(self):
        self.assertEqual(ap2.map_mandate({"session_scoped": True}), "APW-5")

    def test_priority_single_use_over_amount(self):
        self.assertEqual(
            ap2.map_mandate({"single_use": True, "amount_max": 200}), "APW-2")

    def test_priority_session_over_amount(self):
        self.assertEqual(
            ap2.map_mandate({"session_scoped": True, "amount_max": 200}),
            "APW-5")

    def test_no_facet_raises(self):
        with self.assertRaises(fe.PolicyFrontendError):
            ap2.map_mandate({"intent": "do something"})

    def test_maps_to_override(self):
        self.assertEqual(ap2.map_mandate({"amount_max": 1}), "APW-1")


class Ap2LoweringTests(unittest.TestCase):
    """The .ap2 mandate lowers to the SAME IR as the .dw sample."""

    def test_apw1_mandate_equals_dw(self):
        ir = fe.build_ir(SAMPLE_MANDATE)
        self.assertEqual(ir, spendcap.build_ir(buggy=True))

    def test_apw1_property_pinned(self):
        ir = fe.build_ir(SAMPLE_MANDATE)
        self.assertEqual(ir.metadata["ap2_apw"], "APW-1")
        self.assertEqual(ir.metadata["property_name"], "spendcap_within_cap")
        self.assertEqual(ir.metadata["property_kind"], "safety")
        self.assertEqual(ir.metadata["frontend"], "ap2")
        self.assertEqual(ir.metadata["variant"], "buggy")

    def test_apw2_mandate_equals_dw(self):
        path = _write_mandate({"single_use": True, "intent": "one payment"})
        try:
            self.assertEqual(fe.build_ir(path),
                             shapes.build_approval_replay_ir(buggy=True))
        finally:
            os.unlink(path)

    def test_apw5_mandate_equals_dw(self):
        path = _write_mandate({"session_scoped": True, "per_unit": 3})
        try:
            self.assertEqual(fe.build_ir(path),
                             shapes.build_scoped_cap_ir(buggy=True, cap=3))
        finally:
            os.unlink(path)

    def test_enforcement_request_sum_is_correct(self):
        path = _write_mandate({"amount_max": 200, "enforcement": "request_sum"})
        try:
            self.assertEqual(fe.build_ir(path), spendcap.build_ir(buggy=False))
        finally:
            os.unlink(path)

    def test_variant_override(self):
        ir = fe.build_ir(SAMPLE_MANDATE, variant="request_sum")
        self.assertEqual(ir, spendcap.build_ir(buggy=False))


class Ap2VerdictTests(unittest.TestCase):
    """The lowered IRs decide like their Dogwood twins."""

    def test_apw1_buggy_violated(self):
        ir = fe.build_ir(SAMPLE_MANDATE)
        assert_buggy_violated(ir, {"completed": 0, "inflight": 3}, "AP2/APW-1")

    def test_apw1_correct_proven(self):
        path = _write_mandate({"amount_max": 200, "enforcement": "request_sum"})
        try:
            assert_correct_proven(fe.build_ir(path), "AP2/APW-1")
        finally:
            os.unlink(path)

    def test_apw2_buggy_violated(self):
        path = _write_mandate({"single_use": True})
        try:
            assert_buggy_violated(fe.build_ir(path),
                                  {"approved": True, "orders": 2}, "AP2/APW-2")
        finally:
            os.unlink(path)

    def test_apw2_correct_proven(self):
        path = _write_mandate({"single_use": True, "enforcement": "request_sum"})
        try:
            assert_correct_proven(fe.build_ir(path), "AP2/APW-2")
        finally:
            os.unlink(path)

    def test_apw5_buggy_violated(self):
        path = _write_mandate({"session_scoped": True, "per_unit": 3})
        try:
            assert_buggy_violated(fe.build_ir(path),
                                  {"session_count": 4, "scope_count": 1},
                                  "AP2/APW-5")
        finally:
            os.unlink(path)

    def test_apw5_correct_proven(self):
        path = _write_mandate({"session_scoped": True, "per_unit": 3,
                               "enforcement": "request_sum"})
        try:
            assert_correct_proven(fe.build_ir(path), "AP2/APW-5")
        finally:
            os.unlink(path)


class Ap2ErrorTests(unittest.TestCase):
    def test_missing_file(self):
        with self.assertRaises(fe.PolicyFrontendError):
            fe.build_ir(os.path.join(_REPO, "samples", "nope.ap2"))

    def test_invalid_json(self):
        fd, path = tempfile.mkstemp(suffix=".ap2")
        with os.fdopen(fd, "w") as f:
            f.write("{ not json")
        try:
            with self.assertRaises(fe.PolicyFrontendError) as ctx:
                fe.build_ir(path)
            self.assertIn("JSON", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_not_an_object(self):
        fd, path = tempfile.mkstemp(suffix=".ap2")
        with os.fdopen(fd, "w") as f:
            f.write("[1, 2, 3]")
        try:
            with self.assertRaises(fe.PolicyFrontendError) as ctx:
                fe.build_ir(path)
            self.assertIn("object", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_bad_schema(self):
        path = _write_mandate({"schema": "ap2.mandate/v9", "amount_max": 1})
        try:
            with self.assertRaises(fe.PolicyFrontendError) as ctx:
                fe.build_ir(path)
            self.assertIn("schema", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_unsupported_mapping(self):
        path = _write_mandate({"maps_to": "APW-9", "amount_max": 1})
        try:
            with self.assertRaises(fe.PolicyFrontendError) as ctx:
                fe.build_ir(path)
            self.assertIn("mapping", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_bad_enforcement(self):
        path = _write_mandate({"amount_max": 1, "enforcement": "weird"})
        try:
            with self.assertRaises(fe.PolicyFrontendError) as ctx:
                fe.build_ir(path)
            self.assertIn("enforcement", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_bad_amount_type(self):
        path = _write_mandate({"amount_max": "lots"})
        try:
            with self.assertRaises(fe.PolicyFrontendError) as ctx:
                fe.build_ir(path)
            self.assertIn("amount_max", str(ctx.exception))
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()