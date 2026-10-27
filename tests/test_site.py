# -*- coding: utf-8 -*-
"""Tests for the Phase F replay site scaffold (site/).

Covers:
  * the scaffold files exist (index.html, .nojekyll, vendor/cytoscape.min.js,
    app/{app,graph,timeline,narration,findings}.js, app/style.css);
  * index.html wires the vendored Cytoscape + app modules + the data registry;
  * app.js implements the hash routes (#/ and #/replay/<id>) and the
    file://-safe registry fallback;
  * data/*.trace.json are valid RTF v1 (required fields; the top-level hash
    is the SHA-256 of the canonical body);
  * data/traces.js is a registry that mirrors data/*.trace.json exactly
    (so the gallery works over file://, where fetch is blocked);
  * scripts/gen_site_data.py is deterministic (byte-identical on re-run).

Run: python tests/test_site.py
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = os.path.join(ROOT, "site")
DATA = os.path.join(SITE, "data")

sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import rot.trace as trace  # noqa: E402
import gen_site_data  # noqa: E402


def _trace_ids():
    return sorted(
        n[: -len(".trace.json")]
        for n in os.listdir(DATA)
        if n.endswith(".trace.json")
    )


def _read_trace(name):
    with open(os.path.join(DATA, name), "r") as fh:
        return json.load(fh)


def _registry():
    """Parse the JSON payload out of data/traces.js."""
    with open(os.path.join(DATA, "traces.js"), "r") as fh:
        text = fh.read()
    marker = "window.ROT_TRACES = "
    idx = text.index(marker)
    body = text[idx + len(marker):].rstrip()
    if body.endswith(";"):
        body = body[:-1]
    return json.loads(body)


class ScaffoldTests(unittest.TestCase):
    """F1: the site scaffold exists and is wired up."""

    def test_scaffold_files_exist(self):
        for rel in (
            "index.html",
            ".nojekyll",
            os.path.join("vendor", "cytoscape.min.js"),
            os.path.join("app", "app.js"),
            os.path.join("app", "graph.js"),
            os.path.join("app", "spendcap.js"),
            os.path.join("app", "timeline.js"),
            os.path.join("app", "narration.js"),
            os.path.join("app", "findings.js"),
            os.path.join("app", "compliance.js"),
            os.path.join("app", "compare.js"),
            os.path.join("app", "style.css"),
        ):
            path = os.path.join(SITE, rel)
            self.assertTrue(os.path.isfile(path), "missing: %s" % rel)

    def test_cytoscape_vendored(self):
        path = os.path.join(SITE, "vendor", "cytoscape.min.js")
        with open(path, "rb") as fh:
            head = fh.read(8192)
        self.assertGreater(os.path.getsize(path), 100000)
        self.assertIn(b"cytoscape", head.lower())

    def test_index_wiring(self):
        with open(os.path.join(SITE, "index.html"), "r") as fh:
            html = fh.read()
        for ref in (
            "vendor/cytoscape.min.js",
            "data/traces.js",
            "app/app.js",
            "app/graph.js",
            "app/spendcap.js",
            "app/timeline.js",
            "app/narration.js",
            "app/findings.js",
            "app/compliance.js",
            "app/compare.js",
            "app/style.css",
        ):
            self.assertIn(ref, html)
        self.assertIn('id="view"', html)
        self.assertNotIn("http://", html)
        self.assertNotIn("https://", html)

    def test_app_routing(self):
        with open(os.path.join(SITE, "app", "app.js"), "r") as fh:
            js = fh.read()
        self.assertIn("hashchange", js)
        self.assertIn("replay/", js)
        self.assertIn("ROT_TRACES", js)  # file:// registry fallback
        self.assertIn("fetch", js)  # HTTP path (GitHub Pages)


class DataTests(unittest.TestCase):
    """The gallery data is valid, hashable RTF v1."""

    _REQUIRED = (
        "schema", "manifest_id", "verdict", "engines", "horizon", "budget",
        "source", "policy", "graph", "counterexample", "decision_tree",
        "timeline", "narration", "findings",
    )

    def test_at_least_two_traces(self):
        self.assertGreaterEqual(len(_trace_ids()), 2)

    def test_traces_are_valid_rtf(self):
        for tid in _trace_ids():
            t = _read_trace(tid + ".trace.json")
            for field in self._REQUIRED:
                self.assertIn(field, t, "%s missing %s" % (tid, field))
            self.assertEqual(t["schema"], trace.SCHEMA, tid)
            self.assertIn(t["verdict"], ("proven", "violated", "unknown"), tid)
            # Hashable: top-level hash == SHA-256 of the canonical body.
            body = dict((k, v) for k, v in t.items() if k != "hash")
            self.assertEqual(t["hash"], trace.trace_hash(body), tid)

    def test_registry_mirrors_data(self):
        reg = _registry()
        self.assertEqual(sorted(reg.keys()), _trace_ids())
        for tid in _trace_ids():
            self.assertEqual(reg[tid], _read_trace(tid + ".trace.json"), tid)

    def test_generator_deterministic(self):
        tmp = tempfile.mkdtemp(prefix="rotn_site_")
        try:
            data_dir = os.path.join(tmp, "data")
            os.makedirs(data_dir)
            for tid in _trace_ids():
                with open(os.path.join(DATA, tid + ".trace.json"), "rb") as src:
                    with open(os.path.join(data_dir, tid + ".trace.json"), "wb") as dst:
                        shutil.copyfileobj(src, dst)
            gen_site_data.generate(tmp)
            with open(os.path.join(data_dir, "traces.js"), "r") as fh:
                first = fh.read()
            gen_site_data.generate(tmp)
            with open(os.path.join(data_dir, "traces.js"), "r") as fh:
                second = fh.read()
            self.assertEqual(first, second)
            # Same inputs as the committed registry -> same bytes.
            with open(os.path.join(DATA, "traces.js"), "r") as fh:
                self.assertEqual(first, fh.read())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class KsweepDataTests(unittest.TestCase):
    """Phase H: the K-sweep traces drive the compare-mode animated slider.

    K (``--max-inflight``) is structural, shared by both variants. The sweep
    must expose the masking: at K=1 the buggy policy proves clean (a false
    negative); at K>=2 it is violated while the correct policy stays proven.
    """

    def test_ksweep_traces_present(self):
        for K in (1, 2, 3):
            for variant in ("buggy", "correct"):
                tid = "spendcap-%s-k%d" % (variant, K)
                self.assertTrue(
                    tid in _trace_ids(), "missing K-sweep trace: %s" % tid)

    def test_ksweep_verdicts(self):
        # K=1: the bug is masked (buggy proves clean).
        self.assertEqual(_read_trace("spendcap-buggy-k1.trace.json")["verdict"],
                         "proven")
        self.assertEqual(_read_trace("spendcap-correct-k1.trace.json")["verdict"],
                         "proven")
        # K=2 and K=3: the bug is visible (buggy violated, correct proven).
        for K in (2, 3):
            self.assertEqual(
                _read_trace("spendcap-buggy-k%d.trace.json" % K)["verdict"],
                "violated")
            self.assertEqual(
                _read_trace("spendcap-correct-k%d.trace.json" % K)["verdict"],
                "proven")
        # Each K-sweep trace records the K it was audited under.
        for K in (1, 2, 3):
            for variant in ("buggy", "correct"):
                t = _read_trace("spendcap-%s-k%d.trace.json" % (variant, K))
                self.assertEqual(t["policy"]["max_inflight"], K)


if __name__ == "__main__":
    unittest.main(verbosity=2)
