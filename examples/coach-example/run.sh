#!/bin/sh
# coach-example -- coach a buggy spend-cap back in bounds, *with a proof*.
#
# Runs the 5-step coaching loop (Detect -> Explain -> Correct -> Re-check ->
# Close) on the one-word-buggy spend-cap policy and writes the deterministic,
# hashable CoachingArtifact to coaching.json.
#
# Usage:  sh run.sh [K]        (K = bounded in-flight pool, default 3)
#
# Exit codes: 0 = closed (the corrected policy re-proved),
#             1 = open   (the correction did not re-prove -- fail-closed),
#             3 = error.
# (No `set -e`: a non-zero coach exit (OPEN) is a *result* we report, not a fault.)
set -u

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
cd "$root"

K="${1:-3}"

python -m rot coach \
    --policy "$here/spendcap-buggy.dw" \
    --max-inflight "$K" \
    --out "$here/coaching.json"

code=$?
if [ "$code" -eq 0 ]; then
    echo
    echo "  coaching closed: $here/coaching.json"
elif [ "$code" -eq 1 ]; then
    echo
    echo "  coaching OPEN (fail-closed): $here/coaching.json"
else
    echo
    echo "  coaching error (exit $code)"
fi
exit "$code"