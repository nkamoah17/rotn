#!/usr/bin/env bash
# ROTN Agent Mode -- CI / quick-start matrix.
#
# Runs the AgentStep policy-driven checks (Cedar + Dogwood front-ends, the two
# registry targets, and bounded liveness) and asserts the *expected* exit code
# for each. Exits 0 only if every check passes.
#
#   bash scripts/run_agent_mode.sh
#   ENGINE=modelfind bash scripts/run_agent_mode.sh    # different engine

set -u

# --- locate repo root (parent of this scripts/ dir) -------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT}"

# --- pick a python interpreter ----------------------------------------------
if command -v python >/dev/null 2>&1; then
  PY=python
elif command -v python3 >/dev/null 2>&1; then
  PY=python3
else
  echo "ERROR: no python interpreter found on PATH." >&2
  exit 3
fi

ENGINE="${ENGINE:-symbolic}"
PASS=0
FAIL=0

# check <description> <expected_exit> <command...>
check() {
  local desc="$1" expected="$2"
  shift 2
  local out rc
  out="$("$@" 2>&1)"
  rc=$?
  if [ "$rc" -eq "$expected" ]; then
    PASS=$((PASS + 1))
    printf '[PASS] %-54s (exit %s == expected %s)\n' "$desc" "$rc" "$expected"
  else
    FAIL=$((FAIL + 1))
    printf '[FAIL] %-54s (exit %s, expected %s)\n' "$desc" "$rc" "$expected"
    printf '%s\n' "$out" | sed 's/^/       | /'
  fi
}

echo "ROTN Agent Mode -- engine: ${ENGINE}"
echo "-----------------------------------"

# 1. Cedar policy -> realizability (non-vacuity): must be PROVEN (0).
check "cedar: policy_permits_request (realizability)" 0 \
  "$PY" pipeline.py --policy samples/agent.cedar --engine "$ENGINE"

# 2. Dogwood policy -> safety (conformance): must be PROVEN (0).
check "dogwood: policy_conformance (safety)" 0 \
  "$PY" pipeline.py --policy samples/policy.json --tools samples/tools.json --engine "$ENGINE"

# 3. Dogwood policy -> bounded liveness: PROVEN within horizon B=3 (0).
check "dogwood: bounded_eventually (liveness, B=3)" 0 \
  "$PY" pipeline.py --policy samples/policy.json --tools samples/tools.json \
      --kind liveness --engine "$ENGINE" --liveness-horizon 3

# 4. Registry target (conforming agent): must be PROVEN (0).
check "registry: agent-step policy_conformance" 0 \
  "$PY" pipeline.py agent-step --property policy_conformance --engine "$ENGINE"

# 5. Registry target (compromised agent): must be VIOLATED (1) + witness.
check "registry: agent-step-buggy policy_conformance" 1 \
  "$PY" pipeline.py agent-step-buggy --property policy_conformance --engine "$ENGINE"

echo "-----------------------------------"
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
if [ "$FAIL" -eq 0 ]; then
  echo "RESULT: PASS"
  exit 0
else
  echo "RESULT: FAIL"
  exit 1
fi
