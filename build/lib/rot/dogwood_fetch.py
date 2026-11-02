# -*- coding: utf-8 -*-
"""rot.dogwood_fetch -- opt-in fetch of the upstream AWS Dogwood corpus.

Phase A.4 (opt-in).  The on-disk corpus is a *subset* of the upstream
``dogwood-policy/dogwood`` corpus (pinned to a commit, every file SHA-
verified).  This module fetches the *remaining* upstream policies -- the
policy directories under the upstream corpus roots that are not yet present
locally -- with per-file git-blob-SHA provenance, so the coverage matrix can
grow from the 13 present policies toward the full upstream set.

Design notes
------------
* **Opt-in + idempotent.** Nothing is downloaded unless ``--fetch`` is passed.
  Policy directories that are already present locally are skipped, so re-running
  is safe and cheap (it only adds what is missing).
* **Provenance-first.** Every file is verified against its git blob SHA
  (``sha1("blob <len>\\0" + bytes)``) taken from the GitHub contents API at the
  pinned commit.  A mismatch is a hard failure (never silently accepted).
* **Offline-testable.** The pure pieces (blob-SHA computation, "already present"
  detection, provenance rendering) are split out and unit-tested without any
  network.  Only the HTTP layer needs connectivity.
* **Rate-limit aware.** Directory listings use the GitHub contents API; file
  bytes come from ``raw.githubusercontent.com`` (no API token needed).

Pure stdlib, Python 3.6 compatible.
"""
import hashlib
import json
import os
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor

REPO = "dogwood-policy/dogwood"
COMMIT = "4ec5e2c01b44ff3882a231ae5d315b330b38fa25"
API = "https://api.github.com/repos/%s" % REPO
RAW = "https://raw.githubusercontent.com/%s/%s/" % (REPO, COMMIT)
LICENSE = "Apache-2.0 (upstream)"

#: Upstream corpus roots (relative to the repo) whose immediate subdirectories
#: are candidate policies.  These mirror the two provenance sources already in
#: the fixtures (``temporal_only/corpus`` and ``macros/corpus``).
UPSTREAM_ROOTS = [
    "dogwood-language/tests/passing/temporal_only/corpus",
    "dogwood-language/tests/passing/macros/corpus",
]


# ---------------------------------------------------------------------------
# Pure helpers (offline-testable)
# ---------------------------------------------------------------------------

def git_blob_sha(data):
    """Git blob content SHA (``sha1("blob <len>\\0" + bytes)``).

    This is the same hash GitHub reports for a file blob and the one recorded
    in ``PROVENANCE.json``; recomputing it over the downloaded bytes is what
    makes the fetch self-verifying.
    """
    h = hashlib.sha1()
    h.update(b"blob %d\0" % len(data))
    h.update(data)
    return h.hexdigest()


def local_rel_dir(upstream_path):
    """Map an upstream policy path to its local fixture subdirectory.

    ``dogwood-language/tests/passing/temporal_only/corpus/0299_x`` ->
    ``corpus/0299_x`` (the last two path components: ``<rootname>/<policy>``).
    """
    parts = upstream_path.split("/")
    if len(parts) >= 2:
        return "/".join(parts[-2:])
    return parts[-1] if parts else "corpus"


def already_present(dest_root, upstream_path):
    """True if the upstream policy directory already exists on disk.

    A policy is considered present when its local directory contains at least
    one ``.dw`` policy file (the thing ``rot corpus`` actually runs).
    """
    local_dir = os.path.join(dest_root, *local_rel_dir(upstream_path).split("/"))
    if not os.path.isdir(local_dir):
        return False
    for dirpath, _dirnames, filenames in os.walk(local_dir):
        if any(fn.endswith(".dw") for fn in filenames):
            return True
    return False


def _provenance_record(dest_dir, repo_path, files, commit, fetch_date):
    """Write a per-directory ``PROVENANCE.json`` and return the record."""
    os.makedirs(dest_dir, exist_ok=True)
    record = {
        "source_repo": "https://github.com/%s" % REPO,
        "commit": commit,
        "source_path": repo_path,
        "source_url": "https://github.com/%s/tree/%s/%s" % (REPO, commit, repo_path),
        "fetch_date": fetch_date,
        "license": LICENSE,
        "files": files,
    }
    prov_path = os.path.join(dest_dir, "PROVENANCE.json")
    with open(prov_path, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2)
        fh.write("\n")
    return record


def summarize(files):
    """``(n_ok, n_total)`` from a provenance file list."""
    n_total = len(files)
    n_ok = sum(1 for f in files if f.get("sha_verified"))
    return n_ok, n_total


# ---------------------------------------------------------------------------
# Network layer (requires connectivity)
# ---------------------------------------------------------------------------

def _http_get(url, accept=None, timeout=60):
    headers = {"User-Agent": "rotn-dogwood-fetch"}
    if accept:
        headers["Accept"] = accept
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _api_get(url, timeout=60):
    return json.loads(_http_get(url, "application/vnd.github+json", timeout))


def _fetch_one(meta, upstream_path, dest_dir, timeout):
    """Download one file; return ``(name, bytes, expected_blob_sha)``."""
    name = meta["name"]
    data = _http_get(RAW + upstream_path + "/" + name, timeout=timeout)
    return name, data, meta.get("sha")


def list_upstream_policies(roots, timeout=60):
    """Return the sorted list of upstream policy directories under ``roots``.

    A *policy directory* is an immediate subdirectory of a corpus root that
    contains at least one ``.dw`` file.  Non-policy entries are skipped.
    """
    found = []
    for root in roots:
        entries = _api_get(API + "/contents/" + root, timeout)
        for e in entries:
            if e.get("type") != "dir":
                continue
            try:
                sub = _api_get(API + "/contents/" + e["path"], timeout)
            except Exception:  # noqa: BLE001
                continue
            if any(f["name"].endswith(".dw")
                   for f in sub if f.get("type") == "file"):
                found.append(e["path"])
    return sorted(set(found))


def fetch_policy(upstream_path, dest_root, commit, fetch_date, timeout=60):
    """Fetch one upstream policy directory with SHA-verified provenance.

    Returns ``(record, failures)``; ``failures`` is a list of
    ``(source_path, message)`` strings (empty on full success).
    """
    rel_dir = local_rel_dir(upstream_path)
    dest_dir = os.path.join(dest_root, *rel_dir.split("/"))
    os.makedirs(dest_dir, exist_ok=True)
    entries = _api_get(API + "/contents/" + upstream_path, timeout)
    files_meta = [e for e in entries if e.get("type") == "file"]
    failures = []
    files = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [(m, ex.submit(_fetch_one, m, upstream_path, dest_dir, timeout))
                for m in files_meta]
        for m, fut in futs:
            try:
                name, data, sha_expected = fut.result()
            except Exception as exc:  # noqa: BLE001
                failures.append(("%s/%s" % (upstream_path, m["name"]),
                                 "download failed: %s" % exc))
                continue
            sha_local = git_blob_sha(data)
            ok = (sha_expected is None) or (sha_local == sha_expected)
            with open(os.path.join(dest_dir, name), "wb") as fh:
                fh.write(data)
            files.append({
                "name": name,
                "source_url": RAW + upstream_path + "/" + name,
                "blob_sha": sha_expected or sha_local,
                "sha_verified": bool(ok),
                "size_bytes": len(data),
            })
            if not ok:
                failures.append(("%s/%s" % (upstream_path, name),
                                 "sha mismatch: %s != %s"
                                 % (sha_local, sha_expected)))
    files.sort(key=lambda f: f["name"])
    record = _provenance_record(dest_dir, upstream_path, files, commit,
                                fetch_date)
    return record, failures


def fetch_all(roots, dest_root, dry_run=False, commit=COMMIT, timeout=60):
    """Auto-discover and fetch the upstream corpus not already present.

    Returns ``(fetched, skipped, failures)``.  With ``dry_run`` nothing is
    downloaded; ``fetched`` lists what *would* be.
    """
    from datetime import datetime
    fetch_date = datetime.now().strftime("%Y-%m-%d")
    upstream = list_upstream_policies(roots, timeout)
    fetched, skipped, failures = [], [], []
    for path in upstream:
        if already_present(dest_root, path):
            skipped.append(path)
            continue
        if dry_run:
            fetched.append(path)
            continue
        _record, f = fetch_policy(path, dest_root, commit, fetch_date, timeout)
        if f:
            failures.extend(f)
        else:
            fetched.append(path)
    return fetched, skipped, failures


def main(argv=None):
    """CLI entry (also reachable via ``rot corpus --fetch``)."""
    import argparse
    p = argparse.ArgumentParser(description="fetch the upstream Dogwood corpus")
    p.add_argument("--dest-root", default=None, metavar="DIR",
                   help="fixture root [default: "
                        "tests/fixtures/aws_dogwood/spendcap]")
    p.add_argument("--dry-run", action="store_true",
                   help="list what would be fetched without downloading")
    p.add_argument("--timeout", type=int, default=60)
    a = p.parse_args(argv)
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dest = a.dest_root or os.path.join(here, "tests", "fixtures",
                                      "aws_dogwood", "spendcap")
    try:
        fetched, skipped, failures = fetch_all(
            UPSTREAM_ROOTS, dest, dry_run=a.dry_run, timeout=a.timeout)
    except Exception as exc:  # noqa: BLE001
        print("ERROR: upstream fetch failed (no network?): %s" % exc,
              file=sys.stderr)
        return 2
    print("Fetched (or would, in dry-run): %d" % len(fetched))
    for pth in fetched:
        print("  + %s" % pth)
    print("Already present (skipped): %d" % len(skipped))
    for f in failures:
        print("  FAIL %s: %s" % f, file=sys.stderr)
    if failures:
        return 1
    if not a.dry_run:
        print("Done. Re-run `rot corpus` to extend the coverage matrix.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
