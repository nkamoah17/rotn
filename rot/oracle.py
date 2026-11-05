# -*- coding: utf-8 -*-
"""Reference-interpreter oracle (Phase 3).

Runs an APW buggy/correct policy pair + a witness ``trace.log`` against
Dogwood's reference interpreter (``dogwood replay``) and records the
reference verdict next to ROTN's -- the "Dogwood admits it, ROTN catches it"
side-by-side that is the credibility backbone of the APW catalog.

Pure stdlib (``subprocess`` + ``re`` + ``json``), Python 3.6 compatible.
Degrades to SKIP when the ``dogwood`` binary is absent, matching the
codebase's engine-degradation convention (CI stays green without the
toolchain).

Semantics captured here (empirically verified against the local ``dogwood``
build, see ``docs/reference-replay.md``):

* The reference interpreter is **default-deny** (Cedar semantics): a
  ``forbid``-only policy set can only DENY, so "Dogwood admits the
  violation" is observable only on a **``permit``** policy -- the form a
  gateway uses to authorize an action.  ROTN's shape detection is independent
  of permit/forbid, so it still classifies the buggy policy.
* ``dogwood replay`` decides each event **before** appending it to the trace
  (an open, non-reflexive window), and **partitions** temporal aggregates
  by the request's pinned key (the partition guarantee) -- e.g. APW-4's
  ``count … recipient: context.input.recipient`` is a *per-recipient* count
  in the reference, not a global distinct-recipient count.
"""
from __future__ import print_function

import json
import os
import re
import subprocess
import sys

# Known build locations for the locally-built dogwood CLI (Phase 0), checked
# before PATH so the oracle works in a bare shell without setup.
_DEFAULT_CANDIDATES = [
    r"C:\tools\dogwood\target\debug\dogwood.exe",
    r"C:\tools\dogwood\target\release\dogwood.exe",
    "C:/tools/dogwood/target/debug/dogwood.exe",
    "C:/tools/dogwood/target/release/dogwood.exe",
]


def _repo_root():
    """Absolute path of the repository root (parent of the rot package)."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def find_dogwood(explicit=None, env=None):
    """Resolve the ``dogwood`` binary path.

    Order: explicit path > ``DOGWOOD_BIN`` env > known build locations > PATH.
    Returns an existing path, or ``None`` (callers degrade to SKIP).
    """
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    if env is None:
        env = os.environ
    envpath = env.get("DOGWOOD_BIN")
    if envpath and os.path.isfile(envpath):
        return envpath
    for cand in _DEFAULT_CANDIDATES:
        if os.path.isfile(cand):
            return cand
    try:
        from shutil import which
    except ImportError:  # pragma: no cover - shutil is stdlib
        which = None
    return which("dogwood") if which else None


def run_dogwood_replay(binary, policy, schema, trace, timeout=180):
    """Run ``dogwood replay`` on one policy + trace.

    Returns ``{"ok", "error", "decisions", "raw", "exit"}`` where
    ``decisions`` is a list of ``{"seq", "timepoint", "decision"}`` records
    (``decision`` is ``"ALLOW"`` or ``"DENY"``).
    """
    cmd = [binary, "replay", policy,
           "--policy-schema", schema, "--trace", trace]
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout)
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": "could not exec %s: %s" % (binary, exc),
                "decisions": [], "raw": "", "exit": None}
    except subprocess.SubprocessError as exc:
        return {"ok": False, "error": "subprocess error: %s" % exc,
                "decisions": [], "raw": "", "exit": None}
    raw = (proc.stdout or b"").decode("utf-8", "replace")
    return {"ok": True, "error": None,
            "decisions": parse_decisions(raw), "raw": raw,
            "exit": proc.returncode}


_DECISION_RE = re.compile(r"\s*@(\d+)\s*\(time point (\d+)\):\s*(ALLOW|DENY)")


def parse_decisions(raw):
    """Parse ``@seq (time point N): ALLOW|DENY`` lines from replay output."""
    out = []
    for line in (raw or "").splitlines():
        m = _DECISION_RE.match(line)
        if m:
            out.append({"seq": int(m.group(1)),
                        "timepoint": int(m.group(2)),
                        "decision": m.group(3)})
    return out


def summarize(decisions):
    """Count ALLOW/DENY and list the affected timepoints."""
    admitted = [d for d in decisions if d["decision"] == "ALLOW"]
    denied = [d for d in decisions if d["decision"] == "DENY"]
    return {
        "n_decisions": len(decisions),
        "n_admitted": len(admitted),
        "n_denied": len(denied),
        "admitted_timepoints": [d.get("timepoint") for d in admitted],
        "denied_timepoints": [d.get("timepoint") for d in denied],
        "admitted_any": len(admitted) > 0,
        "denied_any": len(denied) > 0,
    }


# ---------------------------------------------------------------------------
# E4 -- events.jsonl -> dogwood trace.log (pure, unit-testable)
# ---------------------------------------------------------------------------

# AgentCore namespace/type names for the recorded traces.  The principal is
# the gateway's OAuth session: the AgentCore spend-cap policies constrain
# only the action + resource scope (never the principal), so the choice of
# principal type cannot change matching -- it only has to be one of the
# action's declared principal types in the E4 schema.
AGENTCORE_NS = "AgentCore"
AGENTCORE_ACTION_ID = "TransferTarget___transfer"
AGENTCORE_PRINCIPAL_TYPE = "OAuthUser"
AGENTCORE_RESOURCE_TYPE = "Gateway"


def _cedar_ref(namespace, type_, ident):
    """A Cedar entity reference: ``Ns::Type::"id"``."""
    return '%s::%s::"%s"' % (namespace, type_, ident)


def events_to_trace(events, meta=None):
    """Build dogwood ``trace.log`` lines for a recorded E2 event sequence.

    Pure (no I/O, no binary): one ``events.jsonl`` event becomes two trace
    timepoints -- a ``::request`` line followed by its ``::response`` line --
    numbered ``@0, @1, @2, ...`` in order (fire k is the request at
    timepoint ``@2(k-1)``).  The reference decides each request timepoint;
    the response timepoints are observed into the temporal history, which is
    exactly what the buggy (response-sum) policy reads.

    Every line carries the AgentCore-namespace scope (``OAuthUser`` principal
    keyed by the recorded session, ``Gateway`` resource keyed by the gateway
    ARN), the action ``AgentCore::Action::"TransferTarget___transfer"``,
    the request context ``input: { amount: <Long> }`` (request lines only),
    and a per-event ``requestId`` so each request/response pair correlates.

    ``meta`` (``events-meta.json``) supplies the identity: ``session_id``,
    ``action`` (or a pre-rendered ``action_cedar``) and ``resource`` /
    ``gateway_arn`` (or a pre-rendered ``resource_cedar``).  ``action`` and
    the resource are required; the session defaults to ``"session"`` when
    absent (harmless: the AgentCore policies never constrain the principal).

    Raises ``ValueError`` on a malformed event or a meta without an
    action/resource.  Window semantics (reflexive vs non-reflexive) are NOT
    assumed here -- the reference's per-fire decisions are the evidence
    (``64_replay_reference.py``); this function only transcribes the
    recording into the wire format the reference parses.
    """
    meta = meta or {}
    action = meta.get("action_cedar")
    if not action:
        action = _cedar_ref(AGENTCORE_NS, "Action",
                            meta.get("action") or AGENTCORE_ACTION_ID)
    resource = meta.get("resource_cedar")
    if not resource:
        arn = meta.get("resource") or meta.get("gateway_arn")
        if not arn:
            raise ValueError(
                "events meta must carry 'resource' (or 'resource_cedar' / "
                "'gateway_arn') for the trace's scope resource")
        resource = _cedar_ref(AGENTCORE_NS, AGENTCORE_RESOURCE_TYPE, arn)
    session = meta.get("session_id") or "session"
    principal = _cedar_ref(AGENTCORE_NS, AGENTCORE_PRINCIPAL_TYPE, session)

    if not isinstance(events, (list, tuple)):
        raise ValueError("events must be a list of event objects")

    lines = []
    for idx, ev in enumerate(events):
        if not isinstance(ev, dict):
            raise ValueError("event %d is not an object: %r" % (idx + 1, ev))
        try:
            amount = str(int(ev["amount"]))
        except (KeyError, TypeError, ValueError):
            raise ValueError("event %d has no usable integer 'amount': %r"
                             % (idx + 1, ev))
        request_id = "req-%s" % ev.get("seq", idx + 1)
        scope = "scope(principal: %s, resource: %s)" % (principal, resource)
        fields = ("input: { amount: %s }, callerPrincipal: %s, "
                  "callerResource: %s, requestId: \"%s\""
                  % (amount, principal, resource, request_id))
        lines.append(
            "@%d %s request_context(input: { amount: %s }) %s::request(%s)"
            % (2 * idx, scope, amount, action, fields))
        lines.append(
            "@%d %s %s::response(%s)"
            % (2 * idx + 1, scope, action, fields))
    return lines


def _ref_block(ref):
    """Build the report block for one reference-interpreter run (or None)."""
    if ref is None:
        return None
    block = {"ok": ref["ok"], "exit": ref.get("exit")}
    if ref.get("error"):
        block["error"] = ref["error"]
    block.update(summarize(ref["decisions"]))
    block["decisions"] = ref["decisions"]
    return block


def side_by_side(rotn_verdict, rotn_witness, rotn_property,
                 ref_buggy, ref_correct=None):
    """Combine ROTN's verdict with the reference verdicts into a report dict.

    The **gate**: ``rot_violated AND reference_admitted`` -- ROTN flags the
    policy VIOLATED and the reference interpreter admits the violating
    requests on the same trace.
    """
    buggy = _ref_block(ref_buggy)
    gate = {
        "rot_violated": rotn_verdict == "violated",
        "reference_admitted": bool(buggy and buggy.get("admitted_any")),
    }
    gate["agreement"] = gate["rot_violated"] and gate["reference_admitted"]
    report = {
        "mode": "oracle-dogwood",
        "rot": {"verdict": rotn_verdict, "witness": rotn_witness,
                "property": rotn_property},
        "dogwood_reference_buggy": buggy,
        "gate": gate,
    }
    if ref_correct is not None:
        report["dogwood_reference_correct"] = _ref_block(ref_correct)
    return report


def run_rotn_check(policy, out_dir=None, max_inflight=None, timeout=180):
    """Run ``rot check`` on a policy; return ``{verdict, witness, property}``.

    Decoupled from the in-process API so this module (and its tests) can run
    without importing the CLI.  Reads the ``report.json`` that ``rot check``
    writes under ``--out``.
    """
    if out_dir is None:
        out_dir = os.path.join(_repo_root(), "out",
                               "oracle-rotn-" + os.path.basename(policy))
    cmd = [sys.executable, "-m", "rot", "check", "--policy", policy]
    if max_inflight is not None:
        cmd += ["--max-inflight", str(max_inflight)]
    cmd += ["--out", out_dir]
    try:
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=timeout, check=False)
    except subprocess.SubprocessError as exc:
        return {"verdict": "error", "witness": None, "property": None,
                "error": str(exc)}
    report_path = os.path.join(out_dir, "report.json")
    try:
        with open(report_path) as f:
            rep = json.load(f)
    except (IOError, OSError, ValueError):
        return {"verdict": "error", "witness": None, "property": None,
                "error": "no report.json at %s" % report_path}
    return {"verdict": rep.get("verdict"),
            "witness": rep.get("witness"),
            "property": rep.get("property_name"),
            "property_kind": rep.get("property_kind")}



# ---------------------------------------------------------------------------
# The Phase-3 gate classes (APW-1, APW-2, APW-4)
# ---------------------------------------------------------------------------

def gate_classes(repo_root=None):
    """The three gate classes, as path dicts (absolute).

    APW-1 uses the catalog samples (already permit-form); APW-2 and APW-4 use
    the permit-form fixtures (the reference is default-deny, so only a
    ``permit`` policy can *admit* the violation).
    """
    root = repo_root or _repo_root()
    fx = os.path.join(root, "tests", "fixtures", "apw")
    return [
        {
            "apw": "APW-1",
            "name": "Settled-sum cap bypass",
            "buggy": os.path.join(root, "samples", "apw1-buggy.dw"),
            "correct": os.path.join(root, "samples", "apw1-correct.dw"),
            "trace": os.path.join(fx, "apw1.trace.log"),
            "schema": os.path.join(fx, "schema.cedarschema"),
        },
        {
            "apw": "APW-2",
            "name": "Approval replay (approval never consumed)",
            "buggy": os.path.join(fx, "apw2-permit-buggy.dw"),
            "correct": os.path.join(fx, "apw2-permit-correct.dw"),
            "trace": os.path.join(fx, "apw2.trace.log"),
            "schema": os.path.join(fx, "schema.cedarschema"),
        },
        {
            "apw": "APW-4",
            "name": "Distinct-count race (settled-only counter)",
            "buggy": os.path.join(fx, "apw4-permit-buggy.dw"),
            "correct": os.path.join(fx, "apw4-permit-correct.dw"),
            "trace": os.path.join(fx, "apw4.trace.log"),
            "schema": os.path.join(fx, "schema.cedarschema"),
        },
    ]


def run_gate(binary, classes=None, rotn=True, timeout=180):
    """Run every gate class; return a list of side-by-side report dicts.

    ``rotn=False`` skips the ROTN leg (to exercise the reference leg alone).
    Each report carries the ROTN verdict, the reference verdict on the buggy
    (and correct) policy, and the gate (agreement) flag.
    """
    if classes is None:
        classes = gate_classes()
    reports = []
    for cls in classes:
        if rotn:
            rot = run_rotn_check(cls["buggy"])
            rot_verdict = rot.get("verdict")
            rot_witness = rot.get("witness")
            rot_property = rot.get("property")
        else:
            rot_verdict, rot_witness, rot_property = None, None, None
        if binary is None:
            ref_buggy = {"ok": False, "error": "dogwood binary not found",
                         "decisions": [], "raw": "", "exit": None}
            ref_correct = None
        else:
            ref_buggy = run_dogwood_replay(
                binary, cls["buggy"], cls["schema"], cls["trace"],
                timeout=timeout)
            ref_correct = run_dogwood_replay(
                binary, cls["correct"], cls["schema"], cls["trace"],
                timeout=timeout)
        report = side_by_side(rot_verdict, rot_witness, rot_property,
                              ref_buggy, ref_correct)
        report["apw"] = cls["apw"]
        report["name"] = cls["name"]
        report["policy_buggy"] = cls["buggy"]
        report["policy_correct"] = cls["correct"]
        report["trace"] = cls["trace"]
        reports.append(report)
    return reports


def gate_passed(reports):
    """True iff every report's gate (ROTN=VIOLATED + reference admits) holds
    and at least three gate classes were run."""
    if not reports or len(reports) < 3:
        return False
    return all(r.get("gate", {}).get("agreement") for r in reports)



# ---------------------------------------------------------------------------
# Markdown rendering (the Phase-3 artifact, docs/reference-replay.md)
# ---------------------------------------------------------------------------

def _ref_cell(ref):
    if not ref or not ref.get("ok"):
        return "n/a"
    return "%d ALLOW / %d DENY" % (ref.get("n_admitted", 0),
                                   ref.get("n_denied", 0))


def _rel(p):
    """Show a path relative to the repo root (portable, for the doc)."""
    if not p:
        return p
    root = _repo_root() + os.sep
    if p.startswith(root):
        return p[len(root):].replace(os.sep, "/")
    return p.replace(os.sep, "/")



def _decision_lines(lines, label, ref):
    if not ref or not ref.get("ok"):
        lines.append("- **%s**: (reference not run)" % label)
        return
    parts = ["@%s %s" % (d.get("timepoint", "?"), d.get("decision", "?"))
             for d in ref.get("decisions", [])]
    lines.append("- **%s**: %s" % (label,
                                   ", ".join(parts) if parts else "no events"))


def render_markdown(reports, binary=None):
    """Render the side-by-side report as Markdown."""
    lines = []
    lines.append("# Phase 3 -- Reference-interpreter replay")
    lines.append("")
    lines.append(
        "Every APW counterexample is replayed against **Dogwood's reference "
        "interpreter** (the locally-built `dogwood replay`), and the "
        "reference verdict is recorded next to ROTN's on the *same* trace -- "
        "the 'Dogwood admits it, ROTN catches it' side-by-side.")
    lines.append("")
    lines.append("## Gate")
    lines.append("")
    lines.append(
        "For each of APW-1, APW-2, APW-4 the report must show **ROTN = "
        "VIOLATED** and **Dogwood-reference = admitted** (the buggy policy "
        "admits the violating requests) on the same trace.")
    lines.append("")
    n = len(reports)
    k = sum(1 for r in reports if r.get("gate", {}).get("agreement"))
    status = "PASS" if (n >= 3 and k == n) else ("PARTIAL" if k else "FAIL")
    lines.append("**Gate: %s** -- %d of %d gate classes agree."
                 % (status, k, n))
    lines.append("")
    lines.append("| APW | class | ROTN | reference (buggy) | "
                 "reference (correct) | gate |")
    lines.append("|-----|-------|------|-------------------|"
                 "---------------------|------|")
    for r in reports:
        lines.append(
            "| %s | %s | %s | %s | %s | %s |" % (
                r.get("apw"), r.get("name"),
                (r.get("rot") or {}).get("verdict", "-").upper(),
                _ref_cell(r.get("dogwood_reference_buggy")),
                _ref_cell(r.get("dogwood_reference_correct")),
                "AGREE" if r.get("gate", {}).get("agreement") else "no"))
    lines.append("")
    lines.append("## Per-class detail")
    for r in reports:
        lines.append("")
        lines.append("### %s -- %s" % (r.get("apw"), r.get("name")))
        lines.append("")
        lines.append("- **ROTN**: `%s` (property: `%s`, witness: `%s`)"
                     % ((r.get("rot") or {}).get("verdict", "-").upper(),
                        (r.get("rot") or {}).get("property", "-"),
                        json.dumps((r.get("rot") or {}).get("witness"))))
        lines.append("- **Buggy policy**: `%s`" % _rel(r.get("policy_buggy")))
        lines.append("- **Correct policy**: `%s`" % _rel(r.get("policy_correct")))
        lines.append("- **Trace**: `%s`" % _rel(r.get("trace")))
        _decision_lines(lines, "buggy (reference)",
                        r.get("dogwood_reference_buggy"))
        _decision_lines(lines, "correct (reference)",
                        r.get("dogwood_reference_correct"))
        lines.append("")
        lines.append("  **Gate**: ROTN violated = %s, reference admitted = "
                     "%s -> **%s**" % (
                         r.get("gate", {}).get("rot_violated"),
                         r.get("gate", {}).get("reference_admitted"),
                         "AGREE" if r.get("gate", {}).get("agreement")
                         else "no"))
    lines.append("")
    lines.append("## Honest caveats (empirically verified)")
    lines.append("")
    lines.append(
        "* **default-deny.** The reference is Cedar-default-deny: a "
        "`forbid`-only policy set can only DENY, so 'admits the violation' "
        "is shown on the **permit** form (the gateway's authorize-action "
        "form). ROTN's shape detection reads the policy's *intent* "
        "(permit/forbid) to disambiguate the formerly-gated shape: a "
        "**permit** gated on a prior approval event is APW-2 (approval "
        "replay); a **forbid** on egress after a confidential read is APW-3 "
        "(taint race).")
    lines.append(
        "* **open, non-reflexive window.** `dogwood replay` decides an event "
        "*before* appending it, so the current event is not in its own "
        "temporal aggregate; the witness traces are shaped so the violation "
        "still surfaces (a 4th APW-1 request, a 3rd APW-2 order, a 4th "
        "APW-4 recipient).")
    lines.append(
        "* **partition guarantee.** Temporal aggregates are sharded by the "
        "request's pinned key; APW-4's `count … recipient: context.input."
        "recipient` is a *per-recipient* count in the reference (not a "
        "global distinct-recipient cap), so APW-4's correct policy does not "
        "deny the cross-recipient burst there -- ROTN still catches the "
        "global distinct-recipient class.")
    lines.append("")
    lines.append("_Generated by `rot replay --oracle dogwood --gate`; "
                 "dogwood binary: `%s`._" % (binary or "not found"))
    lines.append("")
    return "\n".join(lines) + "\n"

