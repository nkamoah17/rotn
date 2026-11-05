# Release: claim the `rotn` name on PyPI, register the trusted publisher, tag v0.2.0

## State

- The package name `rotn` is **not yet claimed** on PyPI — check first:
  <https://pypi.org/project/rotn/>.
- `rot.__version__` = `0.2.0`; `.github/workflows/publish.yml` exists
  (tag `v*` → `pypi-publish/pypi-publish@v2` via **OIDC trusted
  publishing** — no token stored as a secret).
- `main` is ahead of `origin/main` — the tag push will publish all the
  pending commits (the 14 that predate the WS3 docs commit, plus any
  ①/② work that lands first).
- A stale `publish` branch exists locally and on origin — confirm it is
  unused, then delete it (open recommendation from the plan).

## Steps (owner: nkamoah17)

1. **Build check:** `python -m build` — inspect the sdist/wheel: zero
   runtime deps, `rot/` included, `rot/commercial/` **excluded**,
   `tests/` not shipped.
2. **Claim the name:** one-time token publish
   (`twine upload dist/*` with a PyPI API token) — the only token step;
   it exists solely to own the name before anything else can take it.
   (If the name is free, step 4's tag publish would claim it — but
   claiming it deliberately first avoids the race.)
3. **Register the trusted publisher** at
   <https://pypi.org/project/rotn/#trusted-publishers>:
   - Username: `github`
   - Repository: `nkamoah17/rotn`
   - Environment: `main`
4. **Push + tag:** `git push origin main`, then
   `git tag v0.2.0 && git push origin v0.2.0` → `publish.yml` publishes.
5. **Smoke in a clean venv (Python 3.10+):** `pip install rotn` →
   `rot --version` == `0.2.0` → the README Python-API snippet runs
   (`build_ir` + `ModelFinder` on a spend-cap sample from the repo
   checkout — the samples are not shipped in the wheel).
6. **GitHub Release** `v0.2.0` with the `CHANGELOG.md` content.

## Acceptance

- [ ] `pip install rotn` resolves and the console script works in a clean
      venv
- [ ] the next tag (`v0.2.1`) publishes with **no token**
- [ ] the GitHub Release matches the CHANGELOG
- [ ] the `publish` branch deleted after confirming it's unused
