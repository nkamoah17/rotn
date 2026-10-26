# AWS Dogwood artifact provenance

- Source repo: https://github.com/dogwood-policy/dogwood
- Pinned commit: `4ec5e2c01b44ff3882a231ae5d315b330b38fa25`
- Fetch date: 2026-10-21
- License: Apache-2.0 (upstream)

## Artifacts

- `dogwood-language/tests/passing/temporal_only/corpus/0299_sum_resolved_filter` -> `tests/fixtures/aws_dogwood/spendcap/corpus/0299_sum_resolved_filter` (16 files, all sha-verified: True)
- `dogwood-language/tests/passing/temporal_only/corpus/0301_sum_resolved_range_filter` -> `tests/fixtures/aws_dogwood/spendcap/corpus/0301_sum_resolved_range_filter` (6 files, all sha-verified: True)
- `dogwood-language/tests/passing/macros/corpus/mcagg_0299_sum_resolved_filter` -> `tests/fixtures/aws_dogwood/spendcap/corpus/mcagg_0299_sum_resolved_filter` (16 files, all sha-verified: True)
- `dogwood-docs/examples/alert_total_transfer_over_200` -> `tests/fixtures/aws_dogwood/spendcap/examples/alert_total_transfer_over_200` (6 files, all sha-verified: True)
- `dogwood-docs/examples/cap_open_agent_prs_windowed` -> `tests/fixtures/aws_dogwood/spendcap/examples/cap_open_agent_prs_windowed` (7 files, all sha-verified: True)
- `dogwood-docs/examples/refund_budget_settled_plus_current` -> `tests/fixtures/aws_dogwood/spendcap/examples/refund_budget_settled_plus_current` (7 files, all sha-verified: True)
- `dogwood-docs/guide/08-formal-specification.md` -> `tests/fixtures/aws_dogwood/spendcap/guide` (1 files, all sha-verified: True)

Per-directory `PROVENANCE.json` sidecars carry the per-file blob SHAs and source URLs. Blob SHAs are git content hashes (`sha1('blob <len>\0' + bytes)`) from the pinned commit's tree.
