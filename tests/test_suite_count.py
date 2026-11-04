# -*- coding: utf-8 -*-
"""C1: the product-suite test count is MEASURED, then PINNED (no drift).

The README and the technical report state the product-suite count. Those
numbers used to be hand-maintained and drifted (947 in the README, 629 in the
report -- neither matching the suite). This test pins the count in three
places at once:

  1. **Measured** -- discover the suite the same way CI does
     (``python -m unittest discover -s tests``) and count the test cases.
  2. **Pinned** -- the constant ``PINNED_SUITE_COUNT`` in this file, which must
     equal the measured count.
  3. **Documented** -- the README and the technical report must state that
     same number.

If the suite grows or shrinks, this test fails. The fix is to re-measure,
update ``PINNED_SUITE_COUNT`` here, and update the README + report in the same
change. That is what "pinned by a test so it can't drift" means.

Pure stdlib, Python 3.6 compatible.

Run: python tests/test_suite_count.py
"""

import os
import re
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_TESTS_DIR)

# The pinned product-suite count. Update together with the README and the
# technical report whenever the suite size changes (this test enforces it).
# NOTE: this count INCLUDES this file's single test case.
# The 80 service-plane (Product 2: LangChain / MCP gateway / fleet-aggregate)
# tests live in the commercial layer under rot/commercial/tests/ and are NOT counted
# here -- the free core suite is what this test pins.
PINNED_SUITE_COUNT = 917

# The exact documented phrasings this test checks (keep in sync with the docs).
_README_TEST_COUNT_RE = re.compile(r"\*\*(\d+) tests\*\*")
_REPORT_TEST_COUNT_RE = re.compile(r"the (\d+)-test product suite")


def _measured_count():
    """Discover the suite the way CI does and count the test cases.

    Uses the ``tests/`` directory as the start dir (no ``__init__.py``), so
    the test modules are imported top-level exactly as
    ``python -m unittest discover -s tests`` does. Counting does not execute
    the tests.
    """
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=_TESTS_DIR)
    return suite.countTestCases()


def _read(rel_path):
    path = os.path.join(_REPO_ROOT, rel_path)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


class TestSuiteCount(unittest.TestCase):
    def test_count_is_pinned_and_documented(self):
        # 1. Measured (the way CI discovers the suite) == pinned.
        measured = _measured_count()
        self.assertEqual(
            measured, PINNED_SUITE_COUNT,
            "suite count drifted: measured %d but pinned %d -- re-measure, "
            "then update PINNED_SUITE_COUNT + README + report together"
            % (measured, PINNED_SUITE_COUNT))

        # 2. README states the pinned count.
        m = _README_TEST_COUNT_RE.search(_read("README.md"))
        self.assertIsNotNone(
            m, "README no longer states a bolded 'N tests' count")
        self.assertEqual(
            int(m.group(1)), PINNED_SUITE_COUNT,
            "README states %s tests but the pinned count is %d"
            % (m.group(1), PINNED_SUITE_COUNT))

        # 3. Technical report states the pinned count.
        m = _REPORT_TEST_COUNT_RE.search(_read("ROTN_Technical_Report.md"))
        self.assertIsNotNone(
            m, "report no longer states an 'N-test product suite'")
        self.assertEqual(
            int(m.group(1)), PINNED_SUITE_COUNT,
            "report states %s-test suite but the pinned count is %d"
            % (m.group(1), PINNED_SUITE_COUNT))


if __name__ == "__main__":
    unittest.main(verbosity=2)