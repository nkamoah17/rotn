# -*- coding: utf-8 -*-
"""A4 -- opt-in upstream Dogwood corpus fetch (offline-testable core).

The network layer is mocked so the whole module is exercised without
connectivity.  Covered:

* ``git_blob_sha`` -- the self-verifying hash (canonical empty-blob vector +
  determinism);
* ``local_rel_dir`` -- upstream -> local fixture path mapping;
* ``already_present`` -- idempotency detection (a policy dir with a ``.dw``);
* ``summarize`` -- provenance file counting;
* ``_provenance_record`` -- writes a valid ``PROVENANCE.json``;
* ``list_upstream_policies`` / ``fetch_policy`` / ``fetch_all`` -- the mocked
  network path: discovery, SHA-verified download, provenance, the dry-run
  (nothing written), and the "already present" skip.

Run: python tests/test_dogwood_fetch.py
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.dogwood_fetch as df  # noqa: E402


class PureHelperTests(unittest.TestCase):
    def test_git_blob_sha_known_vector(self):
        # Canonical git empty-blob hash: sha1("blob 0\0").
        self.assertEqual(
            df.git_blob_sha(b""),
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")

    def test_git_blob_sha_deterministic_and_length(self):
        h = df.git_blob_sha(b"hello dogwood")
        self.assertEqual(len(h), 40)
        self.assertEqual(h, df.git_blob_sha(b"hello dogwood"))

    def test_local_rel_dir_mapping(self):
        self.assertEqual(
            df.local_rel_dir(
                "dogwood-language/tests/passing/temporal_only/corpus/0299_x"),
            "corpus/0299_x")
        self.assertEqual(
            df.local_rel_dir(
                "dogwood-language/tests/passing/macros/corpus/mcagg_0299"),
            "corpus/mcagg_0299")

    def test_already_present(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(df.already_present(d, "x/corpus/p1"))
            pd = os.path.join(d, "corpus", "p1")
            os.makedirs(pd)
            with open(os.path.join(pd, "policy_1.dw"), "w") as fh:
                fh.write("p")
            self.assertTrue(df.already_present(d, "x/corpus/p1"))
            # A dir without a .dw file is NOT considered present.
            pd2 = os.path.join(d, "corpus", "p2")
            os.makedirs(pd2)
            with open(os.path.join(pd2, "notes.txt"), "w") as fh:
                fh.write("n")
            self.assertFalse(df.already_present(d, "x/corpus/p2"))

    def test_summarize(self):
        self.assertEqual(
            df.summarize([{"sha_verified": True}, {"sha_verified": False}]),
            (1, 2))
        self.assertEqual(df.summarize([]), (0, 0))

    def test_provenance_record_writes_valid_json(self):
        with tempfile.TemporaryDirectory() as d:
            rec = df._provenance_record(
                d, "root/pol",
                [{"name": "a.dw", "sha_verified": True, "size_bytes": 3}],
                "COMMIT", "2026-01-01")
            with open(os.path.join(d, "PROVENANCE.json")) as fh:
                data = json.load(fh)
            self.assertEqual(data["commit"], "COMMIT")
            self.assertEqual(data["files"][0]["name"], "a.dw")
            self.assertEqual(data["license"], df.LICENSE)
            self.assertEqual(rec["source_path"], "root/pol")


class _FakeUpstream(object):
    """A tiny fake upstream: one corpus root holding one new policy."""

    ROOT = "dogwood-language/tests/passing/temporal_only/corpus"
    POLICY = ROOT + "/9999_new_policy"
    FILES = {
        "policy_1.dw": b"dw content",
        "schema.cedarschema": b"schema content",
    }

    def api_get(self, url, timeout=60):
        if url.endswith("/" + self.ROOT):
            return [{"type": "dir", "path": self.POLICY}]
        if url.endswith("/" + self.POLICY):
            return [
                {"type": "file", "name": n,
                 "sha": df.git_blob_sha(b), "path": self.POLICY + "/" + n}
                for n, b in sorted(self.FILES.items())
            ]
        return []

    def http_get(self, url, accept=None, timeout=60):
        for name, body in self.FILES.items():
            if url.endswith("/" + name):
                return body
        raise AssertionError("unexpected raw url: %s" % url)


class MockedNetworkTests(unittest.TestCase):
    """Exercise discovery + SHA-verified download with the network mocked."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._fake = _FakeUpstream()
        self._orig_api = df._api_get
        self._orig_http = df._http_get
        df._api_get = self._fake.api_get
        df._http_get = self._fake.http_get

    def tearDown(self):
        df._api_get = self._orig_api
        df._http_get = self._orig_http
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_list_upstream_policies(self):
        found = df.list_upstream_policies([_FakeUpstream.ROOT])
        self.assertEqual(found, [_FakeUpstream.POLICY])

    def test_fetch_policy_sha_verified_and_writes_files(self):
        dest = os.path.join(self._tmp, "spendcap")
        record, failures = df.fetch_policy(
            _FakeUpstream.POLICY, dest, "COMMIT", "2026-01-01")
        self.assertEqual(failures, [])
        local_dir = os.path.join(dest, "corpus", "9999_new_policy")
        for name, body in _FakeUpstream.FILES.items():
            with open(os.path.join(local_dir, name), "rb") as fh:
                self.assertEqual(fh.read(), body)
        self.assertTrue(os.path.isfile(
            os.path.join(local_dir, "PROVENANCE.json")))
        for f in record["files"]:
            self.assertTrue(f["sha_verified"])
        # After fetch, the policy is "present" for idempotency.
        self.assertTrue(df.already_present(dest, _FakeUpstream.POLICY))

    def test_fetch_all_dry_run_writes_nothing(self):
        dest = os.path.join(self._tmp, "spendcap")
        os.makedirs(dest)
        fetched, skipped, failures = df.fetch_all(
            [_FakeUpstream.ROOT], dest, dry_run=True)
        self.assertEqual(fetched, [_FakeUpstream.POLICY])
        self.assertEqual(skipped, [])
        self.assertEqual(failures, [])
        # Dry-run must not create the policy directory.
        self.assertFalse(os.path.isdir(
            os.path.join(dest, "corpus", "9999_new_policy")))

    def test_fetch_all_skips_already_present(self):
        dest = os.path.join(self._tmp, "spendcap")
        # Pre-create the policy locally so fetch_all must skip it.
        local_dir = os.path.join(dest, "corpus", "9999_new_policy")
        os.makedirs(local_dir)
        with open(os.path.join(local_dir, "policy_1.dw"), "w") as fh:
            fh.write("pre")
        fetched, skipped, failures = df.fetch_all(
            [_FakeUpstream.ROOT], dest, dry_run=False)
        self.assertEqual(fetched, [])
        self.assertEqual(skipped, [_FakeUpstream.POLICY])
        self.assertEqual(failures, [])

    def test_fetch_policy_detects_sha_mismatch(self):
        # Force a mismatch: the API advertises one SHA, the bytes give another.
        dest = os.path.join(self._tmp, "spendcap")
        orig_api = self._fake.api_get

        def api_get(url, timeout=60):
            entries = orig_api(url, timeout)
            if url.endswith("/" + _FakeUpstream.POLICY):
                return [dict(e, sha="0" * 40) for e in entries]  # wrong SHA
            return entries

        df._api_get = api_get
        _record, failures = df.fetch_policy(
            _FakeUpstream.POLICY, dest, "COMMIT", "2026-01-01")
        self.assertTrue(failures)
        self.assertTrue(any("sha mismatch" in m for _p, m in failures))


if __name__ == "__main__":
    unittest.main()