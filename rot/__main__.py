# -*- coding: utf-8 -*-
"""rot -- ROTN temporal policy verification engine, product CLI.

Subcommands
-----------
  rot check     Verify a policy (safety / realizability / liveness); on
                VIOLATED emit a narrative + an auditable attack.jsonl.
  rot replay    Re-derive a recorded attack.jsonl against a policy -- the
                verification loop that proves the counterexample is real.
  rot ci        CI gate: verdict + JUnit XML + SARIF artifacts.
  rot demo      The 5-phase spend-cap demo (PROVEN / VIOLATED / K-sweep /
                replay), exit-code aware like demo.sh.
  rot corpus    Run the AWS Dogwood spend-cap corpus; emit a coverage matrix.
  rot trace     Emit the RTF v1 deterministic, hashable reasoning trace
                (a superset of the MCP findings report; --manifest).
  rot doctor    Diagnose the installation (Python, package, engines;
                --deep runs a real end-to-end self-test).

Exit codes
----------
  0  PROVEN / PASS
  1  VIOLATED / BLOCK
  2  UNKNOWN
  3  ERROR

Pure stdlib; Python 3.6+.
"""

from __future__ import print_function

import argparse
import json
import os
import sys

import rot

EXIT_PROVEN = 0
EXIT_VIOLATED = 1
EXIT_UNKNOWN = 2
EXIT_ERROR = 3

_BAR = "=" * 74


def _repo_root():
    """Absolute path of the repository root (parent of the rot package)."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _build_ir(policy_path, args):
    """Build a ProtocolIR from a policy file (narrow-waist front-end)."""
    import rot.frontends.policy as fe
    return fe.build_ir(
        policy_path,
        n_steps=1,
        kind=getattr(args, "kind", None),
        max_inflight=getattr(args, "max_inflight", None),
        amount=getattr(args, "amount", None),
        cap=getattr(args, "cap", None),
        window=getattr(args, "window", None),
    )


def _verify(ir, args):
    """Check the IR's pinned property.

    Returns ``(status, witness, note)`` where status is one of
    ``"proven" | "violated" | "unknown"`` and witness is the violating
    state dict (or None). Mirrors the dispatch in pipeline._cmd_policy.
    """
    from rot.modelfind import ModelFinder, SAT, UNSAT

    kind = ir.metadata.get("property_kind") or "safety"
    prop_name = ir.metadata.get("property_name") or "policy_property"
    pred = lambda s: ir.pinned_property.eval(s)

    if kind == "liveness":
        from rot.config import Config
        from rot.invariants import Invariant, KIND_LIVENESS
        from rot.linearization import linearize
        from rot.symbolic import SymbolicEngine
        from rot.cegar import cegar_liveness

        horizon = getattr(args, "liveness_horizon", None) or 12
        cfg = Config(max_states=200000, liveness_horizon=horizon)
        prop = Invariant(
            name=prop_name,
            description="bounded liveness goal pinned by the policy front-end",
            expression=ir.pinned_property,
            kind=KIND_LIVENESS)
        reach = (SymbolicEngine(linearize(ir), max_states=cfg.max_states)
                 .reach_within(prop.expression, cfg.liveness_horizon,
                               max_states=cfg.max_states))
        verdict = cegar_liveness(reach, prop, cfg, "symbolic")
        witness = (verdict.evidence or {}).get("path")
        return verdict.status, witness, verdict.note or ""

    mf = ModelFinder.from_ir(ir)
    if kind == "realizability":
        result, witness = mf.exists_reachable(pred)
        if result == SAT:
            return "proven", None, ""
        if result == UNSAT:
            return "violated", witness, ""
        return "unknown", None, ""

    result, witness = mf.forall_reachable(pred)
    if result is True:
        return "proven", None, ""
    if result is False:
        return "violated", witness, ""
    return "unknown", None, ""


def _witness_steps(ir, witness):
    """Recover the BFS step path to a violating state.

    Returns a list of ``{"step", "action", "state"}`` records (state = the
    state after that step). Empty list if the path cannot be recovered.
    """
    from rot.modelfind import ModelFinder, ProductTooLarge

    mf = ModelFinder.from_ir(ir)
    try:
        steps = mf.path_to(witness)
    except ProductTooLarge:
        return []
    out = []
    for i, (before, action, delta) in enumerate(steps):
        after = dict(before)
        for k, v in delta.items():
            after[k] = v
        out.append({"step": i, "action": action.name, "state": after})
    return out


def _ensure_dir(path):
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.isdir(d):
        os.makedirs(d)
    return d


def _write_attack_jsonl(path, meta, steps, violating_state):
    """Write the auditable counterexample file (JSONL, one record per line).

    Layout: a ``rotn-attack`` header, one record per attack step, then a
    ``rotn-attack-end`` trailer carrying the violating state.
    """
    _ensure_dir(path)
    head = dict(_meta="rotn-attack", format="v1")
    head.update(meta)
    lines = [json.dumps(head, sort_keys=True)]
    for s in steps:
        lines.append(json.dumps(s, sort_keys=True))
    lines.append(json.dumps({"_meta": "rotn-attack-end",
                             "violating_state": violating_state},
                            sort_keys=True))
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def _read_attack(path):
    """Parse an attack.jsonl. Returns (header, steps, trailer) or None."""
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except ValueError:
                pass
    header = next((r for r in records if r.get("_meta") == "rotn-attack"),
                  None)
    if header is None:
        return None
    steps = [r for r in records if "step" in r and "action" in r]
    trailer = next((r for r in records
                    if r.get("_meta") == "rotn-attack-end"), None)
    return header, steps, trailer


def _narrative(policy, target, prop, kind, status, witness, steps,
               note, report_path, attack_path):
    """Print the human-readable verdict block."""
    print(_BAR)
    print("  ROTN verdict: %s" % status.upper())
    print(_BAR)
    print("  policy    : %s" % policy)
    print("  target    : %s" % target)
    print("  property  : %s (%s)" % (prop, kind))
    if note:
        print("  note      : %s" % note)
    if witness is not None:
        try:
            w = json.dumps(witness, sort_keys=True)
        except (TypeError, ValueError):
            w = repr(witness)
        print("  witness   : %s" % w)
    if steps:
        print("  attack path (%d step%s):" % (len(steps),
                                              "s" if len(steps) != 1 else ""))
        for s in steps:
            try:
                st = json.dumps(s["state"], sort_keys=True)
            except (TypeError, ValueError):
                st = repr(s["state"])
            print("    %2d. %-16s %s" % (s["step"], s["action"], st))
    if report_path:
        print("  report    : %s" % report_path)
    if attack_path:
        print("  attack    : %s" % attack_path)
    print(_BAR)


def _code_for(status):
    return {"proven": EXIT_PROVEN, "violated": EXIT_VIOLATED,
            "unknown": EXIT_UNKNOWN}.get(status, EXIT_ERROR)



# ---------------------------------------------------------------------------
# rot check
# ---------------------------------------------------------------------------

def _read_policy_actions(policy_path):
    """Read a Dogwood ``policy.json`` -> ``(allowed, denied)`` action lists.

    Reads the JSON directly (rather than via :func:`dogwood.parse_policy`) so
    that a *contradictory* policy (overlapping allowed/denied) is not rejected
    at parse time -- the :mod:`rot.mcp_adapter` structural check is what should
    report it as a Cedar-AR ``contradictions`` finding.

    Raises
    ------
    ValueError
        If the file is missing, malformed, or lacks well-formed
        ``allowed``/``denied`` lists.
    """
    try:
        with open(policy_path, "r") as fh:
            data = json.load(fh)
    except (IOError, OSError) as exc:
        raise ValueError("could not read policy file %r: %s"
                         % (policy_path, exc))
    except ValueError as exc:  # json.JSONDecodeError subclasses ValueError
        raise ValueError("malformed JSON in policy file %r: %s"
                         % (policy_path, exc))
    if not isinstance(data, dict):
        raise ValueError(
            "policy file must be a JSON object with 'allowed' and 'denied'")
    for key in ("allowed", "denied"):
        if key not in data:
            raise ValueError("policy file missing required key %r" % key)
        raw = data[key]
        if (not isinstance(raw, list)
                or any(not isinstance(x, str) or not x for x in raw)):
            raise ValueError(
                "policy file: %r must be a list of non-empty "
                "action-name strings" % key)
    return list(data["allowed"]), list(data["denied"])


def _fmt_date(value):
    """Format a date (``datetime.date`` or ISO string) for display."""
    if value is None:
        return "n/a"
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        return iso()
    return str(value)


def _resolve_budget(args):
    """Resolve the effective tier budget (Phase D) from CLI options.

    Precedence: ``--license`` (verified, fail-closed) > ``--tier`` /
    ``--depth`` (the action-input path) > free defaults. Returns a
    :class:`rot.license.DepthBudget` (never ``None`` -- free is the floor).
    """
    import rot.license as lic

    key = getattr(args, "key", None)
    license_obj = None
    license_path = getattr(args, "license", None)
    if license_path:
        # Fail-closed: a tampered / expired / malformed license is rejected.
        license_obj = lic.load_license(license_path, key=key)

    tier = getattr(args, "tier", None)
    depth = getattr(args, "depth", None)
    return lic.resolve_budget(license=license_obj, tier=tier, depth=depth)


def _cmd_check_mcp(args):
    """Emit the Cedar-AR standardized findings report (``--mcp``).

    Reads the policy's ``allowed``/``denied`` action sets (and, if ``--tools``
    is given, the tool catalog), runs :func:`rot.mcp_adapter.audit_mcp`, writes
    the JSON artifact, and renders the blog-ready narrative.  The exit code is
    the report's gate outcome (0 PASS / 1 BLOCK / 2 OUT_OF_SCOPE).
    """
    import rot.mcp_adapter as mcp
    import rot.license as lic
    from rot.frontends.policy import dogwood

    policy_path = args.policy
    if not os.path.isfile(policy_path):
        print("ERROR: policy file not found: %s" % policy_path,
              file=sys.stderr)
        return EXIT_ERROR

    try:
        allowed, denied = _read_policy_actions(policy_path)
    except ValueError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    tools = None
    tools_path = getattr(args, "tools", None)
    if tools_path:
        if not os.path.isfile(tools_path):
            print("ERROR: tools file not found: %s" % tools_path,
                  file=sys.stderr)
            return EXIT_ERROR
        try:
            tools = dogwood.parse_tools(tools_path)
        except dogwood.DogwoodFrontendError as exc:
            print("ERROR: %s" % exc, file=sys.stderr)
            return EXIT_ERROR

    try:
        budget = _resolve_budget(args)
    except lic.LicenseError as exc:
        # Fail-closed: a tampered / expired / malformed license is rejected.
        print("REJECTED: %s" % exc, file=sys.stderr)
        return EXIT_VIOLATED

    report = mcp.audit_mcp(
        allowed, denied, tools=tools,
        horizon=getattr(args, "liveness_horizon", None) or 12,
        budget=budget,
    )

    # Write the JSON artifact (the MCP/CI artifact).
    out_dir = args.out or os.path.join(_repo_root(), "out")
    os.makedirs(out_dir, exist_ok=True)
    report_path = os.path.join(out_dir, "mcp_findings.json")
    with open(report_path, "w") as fh:
        fh.write(report.to_json() + "\n")

    if not args.quiet:
        print(mcp.render_narrative(report))
        print("  report    : %s" % report_path)
    return report.exit_code()


def _cmd_check_manifest(args):
    """Audit an MCP Manifest v1 (``--manifest``); Phase B, B2.

    Parses and validates the manifest (:mod:`rot.mcp_manifest`), runs the two
    structural checks (field permission + tenant isolation) via
    :func:`rot.mcp_adapter.audit_manifest`, writes the JSON artifact, and
    renders the blog-ready narrative. The exit code is the report's gate
    outcome (0 PASS / 1 BLOCK).
    """
    import rot.mcp_adapter as mcp
    import rot.license as lic
    import rot.mcp_manifest as mm

    manifest_path = args.manifest
    try:
        manifest = mm.parse_manifest_file(manifest_path)
    except (mm.McpManifestError, OSError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    try:
        budget = _resolve_budget(args)
    except lic.LicenseError as exc:
        # Fail-closed: a tampered / expired / malformed license is rejected.
        print("REJECTED: %s" % exc, file=sys.stderr)
        return EXIT_VIOLATED

    report = mcp.audit_manifest(manifest, budget=budget,
                                max_states=budget.max_states)

    # Write the JSON artifact (the MCP/CI artifact).
    out_dir = args.out or os.path.join(_repo_root(), "out")
    os.makedirs(out_dir, exist_ok=True)
    report_path = os.path.join(out_dir, "mcp_findings.json")
    with open(report_path, "w") as fh:
        fh.write(report.to_json() + "\n")

    if not getattr(args, "quiet", False):
        print(mcp.render_narrative(report))
        print("  report    : %s" % report_path)
    return report.exit_code()


def _trace_manifest(manifest_path, budget, horizon, tier):
    """Build the RTF v1 trace for an MCP Manifest v1 audit.

    Returns ``(result, exit_code)``; ``result`` is ``None`` on error.
    """
    import rot.mcp_adapter as mcp
    import rot.mcp_manifest as mm
    import rot.trace as trace

    if not os.path.isfile(manifest_path):
        print("ERROR: manifest file not found: %s" % manifest_path,
              file=sys.stderr)
        return None, EXIT_ERROR
    try:
        manifest = mm.parse_manifest_file(manifest_path)
    except (mm.McpManifestError, OSError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return None, EXIT_ERROR

    report = mcp.audit_manifest(manifest, budget=budget,
                                max_states=budget.max_states)
    result = trace.build_trace(
        manifest, report,
        budget=budget,
        horizon=horizon,
        tier=tier,
        source_path=manifest_path,
    )
    return result, report.exit_code()


def _coach_artifact(policy_path, max_inflight=None, amount=None, cap=None,
                    window=None):
    """Compute the full CoachingArtifact for a buggy spend-cap policy.

    The third leg of the triad (Rule -> Proof -> **Coach**): for a violated
    spend-cap policy, run the 5-step coaching loop and return the *full*
    artifact (``artifact.to_dict()`` -- the corrected policy + the plain-English
    rationale + the re-verification proof + its SHA-256 hash) so the RTF trace
    bundle is self-contained: **Rule + Proof + Coach**. A reader can re-verify
    the coaching byte-for-byte from the trace alone, and the site renders it as
    the third panel.

    Returns ``None`` when the policy is not coachable (not a spend-cap policy)
    or the coaching fails -- the trace then carries ``coaching: null``.
    """
    import rot.coach as coachmod
    import rot.dw as dw

    try:
        policy = dw.parse_file(policy_path)
    except (dw.DwParseError, IOError, OSError):
        return None
    if not hasattr(policy, "to_ir"):
        return None

    try:
        artifact = coachmod.coach(
            policy,
            max_inflight=max_inflight,
            amount=amount,
            cap=cap,
            window=window,
        )
    except (ValueError, dw.DwParseError):
        return None

    return artifact.to_dict()


def _trace_policy(policy_path, args, budget, horizon, tier):
    """Build the RTF v1 trace for a spend-cap policy audit (AWS Dogwood).

    Verifies the pinned ``spendcap_within_cap`` safety property with the
    concrete-state engine, recovers the counterexample step path (the attack
    path), and assembles the full architecture-contract trace. Returns
    ``(result, exit_code)``; ``result`` is ``None`` on error.
    """
    import rot.frontends.policy as fe
    import rot.trace as trace
    from rot.modelfind import ModelFinder

    if not os.path.isfile(policy_path):
        print("ERROR: policy file not found: %s" % policy_path,
              file=sys.stderr)
        return None, EXIT_ERROR
    try:
        ir = _build_ir(policy_path, args)
    except fe.PolicyFrontendError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return None, EXIT_ERROR
    ir.validate()

    mf = ModelFinder.from_ir(ir)
    pred = lambda s: ir.pinned_property.eval(s)
    ok, witness = mf.forall_reachable(pred)
    status = "proven" if ok else "violated"
    steps = _witness_steps(ir, witness) if (not ok) else []

    # Third leg of the triad: for a buggy (violated) spend-cap policy, embed
    # the full CoachingArtifact (the corrected policy + rationale + re-proof).
    # The RTF trace bundle is self-contained: Rule + Proof + Coach.
    coaching = None
    if status == "violated":
        md = (ir.metadata or {})
        coaching = _coach_artifact(
            policy_path,
            max_inflight=md.get("max_inflight"),
            amount=md.get("amount"),
            cap=md.get("cap"),
            window=md.get("window"),
        )

    result = trace.build_spendcap_trace(
        ir, status, witness, steps,
        budget=budget,
        horizon=horizon,
        tier=tier,
        source_path=policy_path,
        coaching=coaching,
    )
    exit_code = {"proven": EXIT_PROVEN,
                 "violated": EXIT_VIOLATED,
                 "unknown": EXIT_UNKNOWN}[status]
    return result, exit_code


def cmd_trace(args):
    """Emit the RTF v1 deterministic, hashable reasoning trace.

    Two audit kinds are supported (exactly one required):
      * ``--manifest FILE`` -- an MCP Manifest v1 audit (structural checks:
        field permission + tenant isolation);
      * ``--policy FILE``   -- a spend-cap policy audit (the AWS Dogwood
        vertical slice; the ``spendcap_within_cap`` safety property).

    Both produce the same RTF v1 trace shape -- per-step narration, the
    counterexample step path, the decision tree, provenance with ``n_states``,
    and the SOC 2 / AIUC compliance block -- and write the JSON artifact to
    ``--out`` (a file) or stdout. The exit code is the gate outcome
    (0 PROVEN / 1 VIOLATED / 2 UNKNOWN / 3 ERROR).
    """
    import rot.license as lic

    policy_path = getattr(args, "policy", None)
    manifest_path = getattr(args, "manifest", None)
    if bool(policy_path) == bool(manifest_path):
        print("ERROR: specify exactly one of --manifest FILE or --policy FILE",
              file=sys.stderr)
        return EXIT_ERROR

    try:
        budget = _resolve_budget(args)
    except lic.LicenseError as exc:
        # Fail-closed: a tampered / expired / malformed license is rejected.
        print("REJECTED: %s" % exc, file=sys.stderr)
        return EXIT_VIOLATED

    tier = getattr(args, "tier", None)
    horizon = getattr(args, "liveness_horizon", None) or 12

    if policy_path:
        result, exit_code = _trace_policy(policy_path, args, budget, horizon,
                                          tier)
    else:
        result, exit_code = _trace_manifest(manifest_path, budget, horizon,
                                            tier)
    if result is None:
        return exit_code

    out = getattr(args, "out", None)
    if out:
        out_dir = os.path.dirname(os.path.abspath(out))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(out, "w") as fh:
            fh.write(result.to_json() + "\n")
        if not getattr(args, "quiet", False):
            print("  trace     : %s" % out)
            print("  manifest  : %s" % result.manifest_id())
            print("  verdict   : %s" % result.verdict())
            print("  hash      : %s" % result.hash)
    else:
        # Stdout: emit only the JSON artifact (pipe-friendly).
        sys.stdout.write(result.to_json() + "\n")
    return exit_code


# ---------------------------------------------------------------------------
# rot coach
# ---------------------------------------------------------------------------

def cmd_coach(args):
    """Coach the agent back in bounds, *with a proof* (the CoachingArtifact).

    Runs the 5-step coaching loop (Detect -> Explain -> Correct -> Re-check ->
    Close) on a buggy policy and emits the deterministic, hashable
    :class:`rot.coach.CoachingArtifact` (the corrected policy + the
    plain-English rationale + the re-verification proof + the computed
    ``to_proceed`` list).

    Two shapes are supported (``--shape``):

    * ``spendcap`` (the default) -- a ``.dw`` spend-cap policy
      (``--policy FILE`` required);
    * ``exfiltration`` -- the NoExfiltration policy-harness shape, built from
      the general adversarial-agent model (no policy file needed).

    Exit codes: ``0`` closed (the corrected policy re-proved), ``1`` open
    (the correction did not re-prove -- fail-closed), ``3`` error.
    """
    import rot.coach as coachmod
    import rot.dw as dw

    shape = getattr(args, "shape", "spendcap")
    policy_path = None

    if shape == "exfiltration":
        # The exfiltration shape is built from the general agent-harness model
        # (the NoExfiltration rule) -- no .dw policy file is required.
        try:
            artifact = coachmod.coach_exfiltration()
        except Exception as exc:  # fail-closed on any coaching error
            print("ERROR: %s" % exc, file=sys.stderr)
            return EXIT_ERROR
    else:
        policy_path = getattr(args, "policy", None)
        if not policy_path:
            print("ERROR: specify --policy FILE (a spend-cap .dw policy)",
                  file=sys.stderr)
            return EXIT_ERROR

        try:
            policy = dw.parse_file(policy_path)
        except (dw.DwParseError, IOError, OSError) as exc:
            print("ERROR: %s" % exc, file=sys.stderr)
            return EXIT_ERROR
        if not hasattr(policy, "to_ir"):
            print("ERROR: %s is not a spend-cap policy (no to_ir)" % policy_path,
                  file=sys.stderr)
            return EXIT_ERROR

        try:
            artifact = coachmod.coach(
                policy,
                max_inflight=getattr(args, "max_inflight", None),
                amount=getattr(args, "amount", None),
                cap=getattr(args, "cap", None),
                window=getattr(args, "window", None),
            )
        except (ValueError, dw.DwParseError) as exc:
            print("ERROR: %s" % exc, file=sys.stderr)
            return EXIT_ERROR

    out = getattr(args, "out", None)
    if out:
        out_dir = os.path.dirname(os.path.abspath(out))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(out, "w") as fh:
            fh.write(artifact.to_json() + "\n")
        if not getattr(args, "quiet", False):
            print("  artifact  : %s" % out)
            print("  status    : %s" % artifact.status())
            print("  hash      : %s" % artifact.hash)
    else:
        sys.stdout.write(artifact.to_json() + "\n")

    if not getattr(args, "quiet", False):
        print(_BAR)
        print("  COACHING: %s" % artifact.status().upper())
        print("  shape     : %s" % shape)
        if policy_path:
            print("  policy    : %s" % policy_path)
        print("  detect    : %s %s" % (artifact.body["detect"]["status"],
                                      json.dumps(artifact.body["detect"]["witness"],
                                                 sort_keys=True)))
        print("  explain   : %s" % artifact.body["explain"]["rationale"])
        print("  correct   : %s" % artifact.body["correct"]["delta"])
        print("  to-proceed: %s" % "; ".join(artifact.body["to_proceed"]["conditions"]))
        print("  recheck   : %s" % artifact.body["recheck"]["status"])
        print("  hash      : %s" % artifact.hash)
        print(_BAR)

    if artifact.status() == coachmod.CLOSED:
        return EXIT_PROVEN
    return EXIT_VIOLATED


# ---------------------------------------------------------------------------
# rot site
# ---------------------------------------------------------------------------

# The canonical replay-site recipe (the Ship plane's 10 audit cases).  Each is
# a pure function of a committed sample policy + the *current* engine:
#   (trace_id, kind, source_path, max_inflight)
# ``kind`` is "policy" (a spend-cap .dw) or "manifest" (an MCP manifest JSON).
# The base spend-cap traces use K=4 (the default pool); the K-sweep traces
# expose the masking (K=1 proves clean, K>=2 reveals the violation).  The
# source paths are repo-relative (they are recorded verbatim in each trace's
# provenance, so they must be run from the repo root).
_SITE_RECIPES = (
    ("spendcap-buggy",      "policy",   "samples/spendcap-buggy.dw",      4),
    ("spendcap-correct",    "policy",   "samples/spendcap-correct.dw",    4),
    ("spendcap-buggy-k1",   "policy",   "samples/spendcap-buggy.dw",      1),
    ("spendcap-buggy-k2",   "policy",   "samples/spendcap-buggy.dw",      2),
    ("spendcap-buggy-k3",   "policy",   "samples/spendcap-buggy.dw",      3),
    ("spendcap-correct-k1", "policy",   "samples/spendcap-correct.dw",    1),
    ("spendcap-correct-k2", "policy",   "samples/spendcap-correct.dw",    2),
    ("spendcap-correct-k3", "policy",   "samples/spendcap-correct.dw",    3),
    ("bad",                 "manifest", "examples/mcp-manifest-bad.json",   None),
    ("good",                "manifest", "examples/mcp-manifest-good.json",  None),
)


def cmd_site(args):
    """Regenerate the replay site's RTF trace data + the JS registry.

    The Ship plane is a *pure function* of the committed sample policies and
    the current engine.  This command re-runs ``rot trace`` for the 10
    canonical audit cases (the spend-cap K-sweep + the MCP manifest pair) into
    ``--out`` (a ``data/`` directory, default ``site/data``), then mirrors
    them into the deterministic ``traces.js`` registry
    (``rot.sitegen.generate_data``) so the gallery works over both
    ``file://`` (registry fallback) and HTTP (fetch).

    The result is a byte-stable, hashable site bundle whose verdicts are the
    *current* engine's, and whose registry always mirrors the trace JSON files
    (the invariant ``tests/test_site.py`` enforces).

    Exit codes: ``0`` success, ``3`` error (a trace failed to generate).
    """
    root = _repo_root()
    out_dir = os.path.abspath(args.out or os.path.join(root, "site", "data"))
    os.makedirs(out_dir, exist_ok=True)

    failures = []
    for trace_id, kind, source, k in _SITE_RECIPES:
        out_path = os.path.join(out_dir, trace_id + ".trace.json")
        a = argparse.Namespace(
            policy=source if kind == "policy" else None,
            manifest=source if kind == "manifest" else None,
            max_inflight=k,
            amount=None, cap=None, window=None, kind=None,
            out=out_path,
            quiet=True,
            tier=None, depth=None, license=None, key=None,
            liveness_horizon=None,
        )
        code = cmd_trace(a)
        if code not in (EXIT_PROVEN, EXIT_VIOLATED) or not os.path.isfile(out_path):
            failures.append((trace_id, code))

    if failures:
        for trace_id, code in failures:
            print("ERROR: failed to regenerate %s (exit=%s)"
                  % (trace_id, code), file=sys.stderr)
        return EXIT_ERROR

    # Mirror the trace JSON files into the deterministic JS registry (which
    # lives in the same data/ dir).  The generator lives in the installed
    # package (rot.sitegen) so this works from a `pip install .` environment
    # where scripts/ is not on the import path.
    from rot import sitegen
    out_registry, ids = sitegen.generate_data(out_dir)

    if not getattr(args, "quiet", False):
        print(_BAR)
        print("  SITE  : regenerated %d RTF trace(s) -> %s"
              % (len(ids), out_dir))
        for trace_id in ids:
            with open(os.path.join(out_dir, trace_id + ".trace.json"), "r") as fh:
                verdict = json.load(fh)["verdict"]
            print("    %-22s %s" % (trace_id, verdict))
        print("  registry: %s" % out_registry)
        print(_BAR)
    return EXIT_PROVEN


def cmd_doctor(args):
    """Diagnose the ROTN installation and environment.

    Runs a series of read-only checks and reports PASS/FAIL for each:
      * the Python interpreter is new enough (>= 3.6);
      * the ``rot`` package is importable (and reports its version);
      * the core modules import cleanly (trace, sitegen, IR, the three
        engines, and the CEGAR loop);
      * with ``--deep``: a real end-to-end verification of the committed
        spend-cap sample (build IR -> verify -> expect PROVEN).

    This is the fastest way to confirm a ``pip install .`` (or a source
    checkout) is healthy before relying on ``rot check`` / ``rot site``.

    Exit codes: ``0`` all checks passed, ``3`` one or more checks failed.
    """
    import platform

    results = []  # list of (name, ok, detail)

    def record(name, ok, detail=""):
        results.append((name, bool(ok), detail))

    # 1) Python interpreter.
    vi = sys.version_info
    record(
        "python >= 3.6",
        vi >= (3, 6),
        "%d.%d.%d (%s)" % (vi[0], vi[1], vi[2], platform.python_implementation()),
    )

    # 2) The rot package.
    try:
        import rot as _rot
        record("rot package", True,
               "version %s" % getattr(_rot, "__version__", "?"))
    except Exception as exc:  # noqa: BLE001 -- report, don't crash
        record("rot package", False, "import failed: %s" % exc)

    # 3) Core modules import cleanly.
    for mod in ("rot.trace", "rot.sitegen", "rot.ir", "rot.tlc",
                "rot.smtz3", "rot.policy_smt", "rot.cegar"):
        try:
            __import__(mod)
            record("import %s" % mod, True, "ok")
        except Exception as exc:  # noqa: BLE001
            record("import %s" % mod, False,
                   "%s: %s" % (type(exc).__name__, exc))

    # 4) Optional deep self-test: a real end-to-end verification.
    if getattr(args, "deep", False):
        sample = os.path.join(_repo_root(), "samples", "spendcap-correct.dw")
        if not os.path.isfile(sample):
            record("engine self-test", False,
                   "sample not found: %s" % sample)
        else:
            try:
                a = argparse.Namespace(
                    kind=None, max_inflight=4, amount=None, cap=None,
                    window=None)
                ir = _build_ir(sample, a)
                status, _witness, note = _verify(ir, a)
                record("engine self-test (spendcap-correct)",
                       status == "proven",
                       "verdict=%s%s" % (status,
                                        (" (%s)" % note) if note else ""))
            except Exception as exc:  # noqa: BLE001
                record("engine self-test", False,
                       "%s: %s" % (type(exc).__name__, exc))

    # Report.
    if not getattr(args, "quiet", False):
        print(_BAR)
        print("  ROTN doctor -- %d check(s)" % len(results))
        print(_BAR)
        for name, ok, detail in results:
            line = "  [%s] %-34s" % ("PASS" if ok else "FAIL", name)
            if detail:
                line += "  --  %s" % detail
            print(line)
        print(_BAR)

    all_ok = all(ok for _name, ok, _detail in results)
    if all_ok:
        return EXIT_PROVEN
    if not getattr(args, "quiet", False):
        print("  Some checks FAILED -- see above.", file=sys.stderr)
    return EXIT_ERROR


def cmd_check(args):
    """Verify a policy; on VIOLATED emit narrative + attack.jsonl."""
    if getattr(args, "mcp", False):
        return _cmd_check_mcp(args)
    if getattr(args, "manifest", None):
        return _cmd_check_manifest(args)
    if not args.policy:
        print("ERROR: specify --policy FILE or --manifest FILE",
              file=sys.stderr)
        return EXIT_ERROR
    policy = args.policy
    import rot.frontends.policy as fe
    try:
        ir = _build_ir(policy, args)
    except fe.PolicyFrontendError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
    ir.validate()

    kind = ir.metadata.get("property_kind") or "safety"
    prop = ir.metadata.get("property_name") or "policy_property"
    target = "policy-" + os.path.basename(policy)
    status, witness, note = _verify(ir, args)
    code = _code_for(status)

    steps = []
    attack_path = None
    if status == "violated" and witness is not None:
        steps = _witness_steps(ir, witness)
        out_dir = args.out or os.path.join(_repo_root(), "out")
        attack_path = os.path.join(out_dir, "attack.jsonl")
        _write_attack_jsonl(attack_path, {
            "policy": policy,
            "target": target,
            "property": prop,
            "kind": kind,
            "verdict": "violated",
            "engine": "symbolic",
        }, steps, witness)

    report_path = None
    if args.out:
        if not os.path.isdir(args.out):
            os.makedirs(args.out)
        report_path = os.path.join(args.out, "report.json")
        report = {
            "target": target,
            "property_name": prop,
            "property_kind": kind,
            "verdict": status,
            "policy_source": ir.metadata.get("policy_source"),
            "witness": witness,
            "attack_path": steps,
        }
        if ir.metadata.get("max_inflight") is not None:
            report["max_inflight"] = ir.metadata["max_inflight"]
        if ir.metadata.get("window") is not None:
            report["window"] = ir.metadata["window"]
        if ir.metadata.get("dw_window") is not None:
            report["dw_window"] = ir.metadata["dw_window"]
        if note:
            report["note"] = note
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, sort_keys=True)

    if not args.quiet:
        _narrative(policy, target, prop, kind, status, witness, steps,
                   note, report_path, attack_path)
    return code


# ---------------------------------------------------------------------------
# rot license
# ---------------------------------------------------------------------------

def cmd_license(args):
    """License management (Phase D): verify / make / show.

    Exit codes: 0 = valid / issued, 1 = rejected (tampered / expired),
    3 = usage / I/O error.
    """
    import rot.license as lic

    key = getattr(args, "key", None)

    # --verify: the fail-closed license check (D2 "Done when" #1 / #4).
    if getattr(args, "verify", False):
        path = getattr(args, "file", None)
        if not path:
            print("ERROR: --verify requires --file LICENSE", file=sys.stderr)
            return EXIT_ERROR
        try:
            license_obj = lic.load_license(path, key=key)
        except lic.LicenseError as exc:
            print("REJECTED: %s" % exc, file=sys.stderr)
            return EXIT_VIOLATED
        print("VALID: license for %r (tier=%s, expires %s)"
              % (license_obj.org, license_obj.tier,
                 _fmt_date(license_obj.expiry)))
        return EXIT_PROVEN

    # --make: issue a signed license (for testing / the Caravel backend).
    if getattr(args, "make", False):
        org = getattr(args, "org", None) or "demo-org"
        tier = getattr(args, "tier", None) or "free"
        try:
            license_dict = lic.make_license(org, tier, key=key)
        except lic.LicenseError as exc:
            print("ERROR: %s" % exc, file=sys.stderr)
            return EXIT_ERROR
        out = getattr(args, "out", None)
        if out:
            _ensure_dir(out)
            with open(out, "w") as fh:
                fh.write(json.dumps(license_dict, indent=2,
                                   sort_keys=True) + "\n")
            print("wrote %s" % out)
        else:
            print(json.dumps(license_dict, indent=2, sort_keys=True))
        return EXIT_PROVEN

    # --show (or default when only --file is given): show a license (validated).
    if getattr(args, "show", False) or getattr(args, "file", None):
        path = getattr(args, "file", None)
        if not path:
            print("ERROR: --show requires --file LICENSE", file=sys.stderr)
            return EXIT_ERROR
        try:
            license_obj = lic.load_license(path, key=key)
        except lic.LicenseError as exc:
            print("ERROR: %s" % exc, file=sys.stderr)
            return EXIT_ERROR
        print(json.dumps(license_obj.to_dict(), indent=2, sort_keys=True))
        return EXIT_PROVEN

    print("ERROR: specify --verify, --make, or --show --file LICENSE",
          file=sys.stderr)
    return EXIT_ERROR


# ---------------------------------------------------------------------------
# rot replay
# ---------------------------------------------------------------------------

def cmd_replay(args):
    """Re-derive a recorded attack.jsonl against a policy.

    Without ``--policy`` this is a record-only inspection (prints the
    recorded attack). With ``--policy`` it re-runs the sound core and
    reports whether the counterexample reproduces -- the verification loop
    that closes the "is this attack real?" question.
    """
    path = args.attack
    if not os.path.isfile(path):
        print("ERROR: attack file not found: %s" % path, file=sys.stderr)
        return EXIT_ERROR
    parsed = _read_attack(path)
    if parsed is None:
        print("ERROR: not a rotn attack file (missing rotn-attack header): %s"
              % path, file=sys.stderr)
        return EXIT_ERROR
    header, steps, trailer = parsed
    recorded = trailer.get("violating_state") if trailer else None
    prop = header.get("property") or "policy_property"

    if not args.policy:
        print(_BAR)
        print("  ROTN replay (record-only -- no --policy given)")
        print(_BAR)
        print("  attack    : %s" % path)
        print("  property  : %s" % prop)
        print("  steps     : %d" % len(steps))
        if recorded is not None:
            try:
                r = json.dumps(recorded, sort_keys=True)
            except (TypeError, ValueError):
                r = repr(recorded)
            print("  violating : %s" % r)
        print(_BAR)
        return EXIT_VIOLATED

    import rot.frontends.policy as fe
    try:
        ir = _build_ir(args.policy, args)
    except fe.PolicyFrontendError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
    ir.validate()
    status, witness, note = _verify(ir, args)
    code = _code_for(status)

    print(_BAR)
    print("  ROTN replay")
    print(_BAR)
    print("  attack    : %s" % path)
    print("  policy    : %s" % args.policy)
    print("  property  : %s" % prop)
    if recorded is not None:
        try:
            r = json.dumps(recorded, sort_keys=True)
        except (TypeError, ValueError):
            r = repr(recorded)
        print("  recorded  : %s" % r)
    if witness is not None:
        try:
            w = json.dumps(witness, sort_keys=True)
        except (TypeError, ValueError):
            w = repr(witness)
        print("  re-derived: %s" % w)
    if status == "violated" and recorded is not None and witness == recorded:
        print("  result    : REPRODUCED -- the counterexample still holds")
    elif status == "violated":
        print("  result    : VIOLATED -- the policy is still unsafe "
              "(witness may differ)")
    elif status == "proven":
        print("  result    : NOT REPRODUCED -- the policy now proves safe")
    else:
        print("  result    : UNKNOWN -- the bounded search was inconclusive")
    if note:
        print("  note      : %s" % note)
    print(_BAR)
    return code



# ---------------------------------------------------------------------------
# rot ci
# ---------------------------------------------------------------------------

def _junit_xml(status, prop, witness):
    """Minimal JUnit XML (stdlib xml.sax.saxutils for escaping)."""
    import xml.sax.saxutils as sx
    n_fail = 1 if status == "violated" else 0
    if status == "violated":
        try:
            body = sx.escape(json.dumps(witness, sort_keys=True))
        except (TypeError, ValueError):
            body = sx.escape(repr(witness))
        case = ('    <testcase name="%s" classname="rot" time="0.0">\n'
                '      <failure message="%s" type="ROTNViolation">%s'
                '</failure>\n'
                '    </testcase>'
                % (sx.escape(prop), sx.escape("VIOLATED: %s" % prop), body))
    else:
        case = ('    <testcase name="%s" classname="rot" time="0.0"/>'
                % sx.escape(prop))
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<testsuites name="rotn" tests="1" failures="%d" errors="0" '
            'skipped="0">\n'
            '  <testsuite name="rotn" tests="1" failures="%d" errors="0" '
            'skipped="0">\n'
            '%s\n'
            '  </testsuite>\n'
            '</testsuites>\n' % (n_fail, n_fail, case))


def _sarif(status, prop, witness, policy):
    """SARIF 2.1.0 result for the verdict (stdlib json only)."""
    level = {"proven": "note", "violated": "error",
             "unknown": "warning"}.get(status, "warning")
    text = "%s: %s" % (status.upper(), prop)
    if witness is not None:
        try:
            text += "  witness=" + json.dumps(witness, sort_keys=True)
        except (TypeError, ValueError):
            text += "  witness=" + repr(witness)
    return {
        "$schema": ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                    "master/Schemata/sarif-schema-2.1.0.json"),
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ROTN", "version": "0.1.0"}},
            "artifacts": [{"location": {"uri": "file://"
                                        + policy.replace("\\", "/")}}],
            "results": [{"ruleId": "rotn.%s" % prop,
                         "level": level,
                         "message": {"text": text}}],
        }],
    }


def cmd_ci(args):
    """CI gate: verdict + JUnit XML + SARIF artifacts."""
    policy = args.policy
    if not policy:
        print("ERROR: rot ci requires --policy FILE", file=sys.stderr)
        return EXIT_ERROR
    import rot.frontends.policy as fe
    try:
        ir = _build_ir(policy, args)
    except fe.PolicyFrontendError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
    ir.validate()

    kind = ir.metadata.get("property_kind") or "safety"
    if kind != "safety":
        print("ERROR: rot ci supports safety policies only (got %r)" % kind,
              file=sys.stderr)
        return EXIT_ERROR
    prop = ir.metadata.get("property_name") or "policy_property"
    status, witness, note = _verify(ir, args)
    code = _code_for(status)

    out_dir = args.out or "ci"
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    junit_path = os.path.join(out_dir, "JUnit.xml")
    sarif_path = os.path.join(out_dir, "results.sarif")
    with open(junit_path, "w") as f:
        f.write(_junit_xml(status, prop, witness))
    with open(sarif_path, "w") as f:
        json.dump(_sarif(status, prop, witness, policy),
                  f, indent=2, sort_keys=True)

    print(_BAR)
    print("  ROTN CI: %s  (%s)" % (status.upper(), prop))
    print(_BAR)
    if witness is not None:
        try:
            w = json.dumps(witness, sort_keys=True)
        except (TypeError, ValueError):
            w = repr(witness)
        print("  witness   : %s" % w)
    if note:
        print("  note      : %s" % note)
    print("  junit     : %s" % junit_path)
    print("  sarif     : %s" % sarif_path)
    print(_BAR)
    return code



# ---------------------------------------------------------------------------
# rot demo
# ---------------------------------------------------------------------------

def cmd_demo(args):
    """The 5-phase spend-cap demo, exit-code aware (mirrors demo.sh).

    Phase 1  PROVEN    correct.dw                 -> exit 0
    Phase 2  VIOLATED  buggy.dw                   -> exit 1 (+ attack.jsonl)
    Phase 3  REPLAY    attack.jsonl vs buggy.dw   -> exit 1 (reproduced)
    Phase 5  K-SWEEP   buggy.dw K=1/2/3           -> 0 / 1 / 1
    (Phase 4 crosscheck needs TLC/Java; see ``demo.sh`` for the full run.)
    """
    root = _repo_root()
    fx = os.path.join(root, "tests", "fixtures", "aws_dogwood",
                      "spendcap", "policies")
    correct = os.path.join(fx, "spendcap-correct.dw")
    buggy = os.path.join(fx, "spendcap-buggy.dw")
    for p in (correct, buggy):
        if not os.path.isfile(p):
            print("ERROR: fixture not found: %s" % p, file=sys.stderr)
            return EXIT_ERROR
    out_dir = args.out or os.path.join(root, "out", "demo")
    failures = []
    bar = "-" * 66

    def run(title, policy, k, expect, out=None):
        a = argparse.Namespace(policy=policy, kind=None, max_inflight=k,
                               amount=None, cap=None, out=out, quiet=True,
                               liveness_horizon=None)
        code = cmd_check(a)
        ok = code == expect
        if not ok:
            failures.append(title)
        print("  [%s] %-52s exit=%d expected=%d"
              % ("PASS" if ok else "FAIL", title, code, expect))
        return code

    print(bar)
    print("Phase 1 -- PROVEN: spendcap-correct.dw")
    print(bar)
    run("Phase 1 PROVEN (correct.dw)", correct, None, EXIT_PROVEN)

    print(bar)
    print("Phase 2 -- VIOLATED: spendcap-buggy.dw (witness + attack.jsonl)")
    print(bar)
    code2 = run("Phase 2 VIOLATED (buggy.dw)", buggy, None, EXIT_VIOLATED,
                out=out_dir)

    if code2 == EXIT_VIOLATED:
        attack = os.path.join(out_dir, "attack.jsonl")
        if os.path.isfile(attack):
            print(bar)
            print("Phase 3 -- REPLAY: attack.jsonl vs spendcap-buggy.dw")
            print(bar)
            a = argparse.Namespace(attack=attack, policy=buggy,
                                   max_inflight=None, liveness_horizon=None)
            code = cmd_replay(a)
            ok = code == EXIT_VIOLATED
            if not ok:
                failures.append("Phase 3 REPLAY")
            print("  [%s] %-52s exit=%d expected=%d"
                  % ("PASS" if ok else "FAIL", "Phase 3 REPLAY (attack.jsonl)",
                     code, EXIT_VIOLATED))
        else:
            print("  [SKIP] no attack.jsonl produced in %s" % out_dir)

    print(bar)
    print("Phase 5 -- K-SWEEP: buggy policy vs the concurrency pool K")
    print(bar)
    run("Phase 5 K=1 masked (buggy.dw --max-inflight 1)", buggy, 1,
        EXIT_PROVEN)
    run("Phase 5 K=2 VIOLATED (buggy.dw --max-inflight 2)", buggy, 2,
        EXIT_VIOLATED)
    run("Phase 5 K=3 VIOLATED clean fire (buggy.dw --max-inflight 3)",
        buggy, 3, EXIT_VIOLATED)

    print(bar)
    if failures:
        print("DEMO FAILED: %d phase(s) deviated: %s"
              % (len(failures), ", ".join(failures)))
        return EXIT_VIOLATED
    print("DEMO OK: all phases behaved as expected. "
          "(Phase 4 crosscheck needs TLC/Java -- run demo.sh for it.)")
    return EXIT_PROVEN



# ---------------------------------------------------------------------------
# rot corpus
# ---------------------------------------------------------------------------

def cmd_corpus(args):
    """Run every .dw policy under the corpus dir; emit an honest coverage matrix.

    Phase B.2 deliverable. Each policy is classified as:
      - shape:       the temporal shape (spendcap / count_window / exists_sum /
                     refund_budget / taint_egress), from the IR metadata
                     ``protocol`` field.
      - lowerable:   whether the general temporal lowering produced a valid IR.
      - verdict:     PROVEN / VIOLATED / OUT_OF_SCOPE.
                     OUT_OF_SCOPE is an honest classification (the reachable
                     state space exceeded the bounded-checking budget, or the
                     shape is not yet lowerable) -- NOT a bug.
    The command exits 0 when the matrix is produced (report semantics); it
    exits non-zero only on an internal error (corpus dir missing, no policies,
    or an unexpected engine exception).
    """
    from rot.modelfind import ProductTooLarge

    root = _repo_root()
    corpus_dir = args.corpus_dir or os.path.join(
        root, "tests", "fixtures", "aws_dogwood", "spendcap")
    if not os.path.isdir(corpus_dir):
        print("ERROR: corpus dir not found: %s" % corpus_dir, file=sys.stderr)
        return EXIT_ERROR

    policies = []
    for dirpath, dirnames, filenames in os.walk(corpus_dir):
        dirnames.sort()
        for fn in sorted(filenames):
            if fn.endswith(".dw"):
                policies.append(os.path.join(dirpath, fn))
    if not policies:
        print("ERROR: no .dw policies under %s" % corpus_dir, file=sys.stderr)
        return EXIT_ERROR

    print("Discovered %d policies under %s" % (len(policies), corpus_dir))
    results = []
    for p in policies:
        name = os.path.relpath(p, corpus_dir).replace(os.sep, "/")
        a = argparse.Namespace(policy=p, kind=None,
                               max_inflight=args.max_inflight, amount=None,
                               cap=None, out=None, quiet=True,
                               liveness_horizon=None)
        entry = {
            "policy": name, "shape": None, "lowerable": False,
            "verdict": None, "witness": None, "note": None,
        }
        ir = None
        try:
            ir = _build_ir(p, a)
            ir.validate()
            entry["lowerable"] = True
            entry["shape"] = (ir.metadata.get("protocol") or "unknown").lower()
        except Exception as exc:
            # A lowering failure is an honest out-of-scope row (the shape is
            # not yet supported by the general lowering), not an internal error.
            entry["verdict"] = "out_of_scope"
            entry["note"] = "not lowerable: %s" % exc
        if entry["lowerable"]:
            kind = ir.metadata.get("property_kind") or "safety"
            if kind == "safety":
                try:
                    status, witness, note = _verify(ir, a)
                    entry["verdict"] = status
                    entry["witness"] = witness
                    if note:
                        entry["note"] = note
                except ProductTooLarge as exc:
                    # Honest out-of-scope: the reachable state space exceeds the
                    # bounded-checking budget. A known limitation, not a bug.
                    entry["verdict"] = "out_of_scope"
                    entry["note"] = "state space exceeded budget: %s" % exc
                except Exception as exc:
                    entry["verdict"] = "error"
                    entry["note"] = "engine error: %s" % exc
            else:
                entry["verdict"] = "out_of_scope"
                entry["note"] = ("property kind %r not supported by the "
                                 "corpus harness" % kind)
        results.append(entry)
        v = (entry["verdict"] or "?").upper()
        w = ""
        if entry.get("witness") is not None:
            try:
                w = json.dumps(entry["witness"], sort_keys=True)
            except (TypeError, ValueError):
                w = repr(entry["witness"])
        elif entry.get("note"):
            w = entry["note"]
        print("  %-40s %-14s %-6s %-13s %s" % (
            name[:40], entry["shape"] or "-",
            "yes" if entry["lowerable"] else "no", v, w))

    summary = {}
    for r in results:
        key = r["verdict"] or "error"
        summary[key] = summary.get(key, 0) + 1
    lowerable_count = sum(1 for r in results if r["lowerable"])

    print(_BAR)
    print("  ROTN corpus coverage matrix (%d policies, %d lowerable)"
          % (len(results), lowerable_count))
    print(_BAR)
    for k in sorted(summary):
        print("  %-14s %d" % (k, summary[k]))
    print(_BAR)

    report = {
        "corpus_dir": corpus_dir,
        "generated_by": "rot corpus (Phase B.2)",
        "policies": results,
        "summary": dict({"total": len(results),
                         "lowerable": lowerable_count}, **summary),
    }

    out_dir = args.out or os.path.join(root, "out", "corpus")
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    json_path = os.path.join(out_dir, "corpus_matrix.json")
    md_path = os.path.join(out_dir, "corpus_matrix.md")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, sort_keys=True)
    with open(md_path, "w") as f:
        f.write(_corpus_matrix_markdown(report))
    print("  matrix      : %s" % json_path)
    print("  markdown    : %s" % md_path)

    # Report semantics: exit 0 when the matrix is produced. Non-zero only on
    # an internal error (a policy that hit an unexpected engine exception).
    if summary.get("error"):
        return EXIT_ERROR
    return EXIT_PROVEN


def _corpus_matrix_markdown(report):
    """Render the coverage matrix as a Markdown table (Phase B.2 artifact)."""
    s = report["summary"]
    lines = []
    lines.append("# ROTN corpus coverage matrix (Phase B.2)")
    lines.append("")
    lines.append("Corpus: `%s`" % report["corpus_dir"])
    lines.append("")
    lines.append(
        "Summary: **%d** policies, **%d** lowerable, **%d** PROVEN, "
        "**%d** VIOLATED, **%d** OUT_OF_SCOPE, **%d** ERROR."
        % (s.get("total", 0), s.get("lowerable", 0),
           s.get("proven", 0), s.get("violated", 0),
           s.get("out_of_scope", 0), s.get("error", 0)))
    lines.append("")
    lines.append("| Policy | Shape | Lowerable | Verdict | Witness / Note |")
    lines.append("|--------|-------|-----------|---------|----------------|")
    for r in report["policies"]:
        if r["witness"] is not None:
            try:
                witness = json.dumps(r["witness"], sort_keys=True)
            except (TypeError, ValueError):
                witness = repr(r["witness"])
        else:
            witness = r["note"] or "\u2014"
        lines.append("| %s | %s | %s | %s | %s |" % (
            r["policy"], r["shape"] or "\u2014",
            "yes" if r["lowerable"] else "no",
            (r["verdict"] or "?").upper(),
            witness))
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def _add_policy_opts(p):
    p.add_argument("--policy", default=None, metavar="FILE",
                   help="policy file (.dw / .cedar / .json)")
    p.add_argument("--max-inflight", type=int, default=None, metavar="K",
                   help="bounded concurrency pool K (spend-cap .dw policies)")
    p.add_argument("--amount", type=int, default=None, metavar="N",
                   help="per-request amount override (spend-cap .dw policies)")
    p.add_argument("--cap", type=int, default=None, metavar="N",
                   help="spend cap override (spend-cap .dw policies)")
    p.add_argument("--window", type=int, default=None, metavar="W",
                   help="temporal window as a bounded event count W "
                        "(spend-cap .dw policies; the model is time-free so a "
                        "'within W' is approximated as the last W events)")
    p.add_argument("--kind", default=None,
                   choices=["safety", "realizability", "liveness"],
                   help="property kind [default: auto-route by extension]")


def main(argv=None):
    """ROTN CLI entry point. Returns the process exit code."""
    parser = argparse.ArgumentParser(
        prog="rot",
        description="ROTN -- temporal policy verification engine "
                    "(sound core, zero dependencies).")
    parser.add_argument("--version", action="version",
                        version="rot " + rot.__version__)
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser(
        "check", help="verify a policy; emit verdict + attack.jsonl")
    _add_policy_opts(p)
    p.add_argument("--out", default=None, metavar="DIR",
                   help="output dir for report.json / attack.jsonl "
                        "[default: <repo>/out]")
    p.add_argument("--liveness-horizon", type=int, default=None, metavar="H",
                   help="bounded liveness horizon (liveness policies)")
    p.add_argument("--mcp", action="store_true",
                   help="emit the Cedar-AR standardized findings report "
                        "(rot.mcp_adapter) instead of the narrative")
    p.add_argument("--tools", default=None, metavar="FILE",
                   help="tools catalog (tools.json) enabling the --mcp "
                        "'unreachable rules' structural check")
    p.add_argument("--manifest", default=None, metavar="FILE",
                   help="MCP Manifest v1 JSON file (Phase B, B2): field and "
                        "tenant structural checks via rot.mcp_adapter")
    # Tier gating (Phase D): license / tier / depth cap the bounded-search
    # budget. A tampered or expired license is rejected (fail-closed).
    p.add_argument("--license", default=None, metavar="FILE",
                   help="Caravel license file (Phase D): verified, fail-closed; "
                        "its limits cap the audit budget")
    p.add_argument("--tier", default=None, choices=["free", "paid"],
                   help="tier (Phase D): caps the audit budget when no "
                        "--license is given")
    p.add_argument("--depth", type=int, default=None, metavar="N",
                   help="max_states override (Phase D); capped to the free "
                        "maximum when tier is free")
    p.add_argument("--key", default=None, metavar="KEY",
                   help="Caravel key for license verification "
                        "[default: $CARAVEL_LICENSE_KEY or the demo key]")
    p.add_argument("--quiet", action="store_true",
                   help="suppress the human summary")

    p = sub.add_parser(
        "replay", help="re-derive a recorded attack.jsonl")
    p.add_argument("attack", metavar="ATTACK_JSONL",
                   help="attack file written by 'rot check'")
    p.add_argument("--policy", default=None, metavar="FILE",
                   help="policy to re-verify against "
                        "(record-only inspection without it)")
    p.add_argument("--max-inflight", type=int, default=None, metavar="K",
                   help="bounded concurrency pool K (spend-cap policies)")
    p.add_argument("--liveness-horizon", type=int, default=None, metavar="H",
                   help="bounded liveness horizon (liveness policies)")

    p = sub.add_parser(
        "ci", help="CI gate: verdict + JUnit XML + SARIF")
    _add_policy_opts(p)
    p.add_argument("--liveness-horizon", type=int, default=None, metavar="H",
                   help="bounded liveness horizon (liveness policies)")
    p.add_argument("--out", default="ci", metavar="DIR",
                   help="artifact dir [default: ci]")

    p = sub.add_parser("demo", help="the 5-phase spend-cap demo")
    p.add_argument("--out", default=None, metavar="DIR",
                   help="output dir [default: <repo>/out/demo]")

    p = sub.add_parser("corpus", help="run the AWS Dogwood corpus")
    p.add_argument("--corpus-dir", default=None, metavar="DIR",
                   help="corpus dir [default: "
                        "tests/fixtures/aws_dogwood/spendcap]")
    p.add_argument("--max-inflight", type=int, default=None, metavar="K",
                   help="bounded concurrency pool K")
    p.add_argument("--out", default=None, metavar="DIR",
                   help="output dir for corpus_matrix.json")

    p = sub.add_parser("license",
                       help="manage Caravel licenses (Phase D): "
                            "verify / make / show")
    p.add_argument("--file", default=None, metavar="LICENSE",
                   help="license file to verify / show")
    p.add_argument("--verify", action="store_true",
                   help="verify the license (fail-closed; exit 1 if rejected)")
    p.add_argument("--show", action="store_true",
                   help="show the license (validated)")
    p.add_argument("--make", action="store_true",
                   help="issue a signed license for --org / --tier")
    p.add_argument("--org", default=None, metavar="ORG",
                   help="licensed organization (for --make)")
    p.add_argument("--tier", default=None, choices=["free", "paid"],
                   help="tier (for --make; default free)")
    p.add_argument("--out", default=None, metavar="FILE",
                   help="write the issued license here (for --make)")
    p.add_argument("--key", default=None, metavar="KEY",
                   help="Caravel key [default: $CARAVEL_LICENSE_KEY or demo]")

    p = sub.add_parser(
        "trace",
        help="emit the RTF v1 deterministic, hashable reasoning trace")
    p.add_argument("--manifest", default=None, metavar="FILE",
                   help="MCP Manifest v1 JSON file (for a manifest audit)")
    p.add_argument("--policy", default=None, metavar="FILE",
                   help="spend-cap policy file (.dw) -- the AWS Dogwood "
                        "vertical slice (for a spend-cap audit)")
    p.add_argument("--out", default=None, metavar="FILE",
                   help="write the trace JSON here [default: stdout]")
    p.add_argument("--license", default=None, metavar="FILE",
                   help="Caravel license file (Phase D): verified, fail-closed")
    p.add_argument("--tier", default=None, choices=["free", "paid"],
                   help="tier (Phase D): caps the audit budget")
    p.add_argument("--depth", type=int, default=None, metavar="N",
                   help="max_states override (Phase D)")
    p.add_argument("--key", default=None, metavar="KEY",
                   help="Caravel key for license verification")
    p.add_argument("--liveness-horizon", type=int, default=None, metavar="H",
                   help="bounded liveness horizon (recorded for provenance)")
    p.add_argument("--max-inflight", type=int, default=None, metavar="K",
                   help="bounded concurrency pool K (spend-cap .dw policies)")
    p.add_argument("--amount", type=int, default=None, metavar="N",
                   help="per-request amount override (spend-cap .dw policies)")
    p.add_argument("--cap", type=int, default=None, metavar="N",
                   help="spend cap override (spend-cap .dw policies)")
    p.add_argument("--window", type=int, default=None, metavar="W",
                   help="temporal window W (spend-cap .dw policies)")
    p.add_argument("--kind", default=None,
                   choices=["safety", "realizability", "liveness"],
                   help="property kind [default: auto-route by extension]")
    p.add_argument("--quiet", action="store_true",
                   help="suppress the human summary")

    p = sub.add_parser(
        "coach",
        help="coach the agent back in bounds, *with a proof* "
             "(the CoachingArtifact: corrected policy + rationale + re-proof)")
    p.add_argument("--shape", default="spendcap",
                   choices=["spendcap", "exfiltration"], metavar="SHAPE",
                   help="which shape to coach: 'spendcap' (a .dw policy, the "
                        "default) or 'exfiltration' (the NoExfiltration "
                        "harness -- no policy file needed)")
    p.add_argument("--policy", default=None, metavar="FILE",
                   help="spend-cap policy file (.dw) to coach "
                        "(the AWS Dogwood vertical slice; --shape spendcap)")
    p.add_argument("--out", default=None, metavar="FILE",
                   help="write the coaching artifact JSON here [default: stdout]")
    p.add_argument("--max-inflight", type=int, default=None, metavar="K",
                   help="bounded concurrency pool K (spend-cap .dw policies)")
    p.add_argument("--amount", type=int, default=None, metavar="N",
                   help="per-request amount override (spend-cap .dw policies)")
    p.add_argument("--cap", type=int, default=None, metavar="N",
                   help="spend cap override (spend-cap .dw policies)")
    p.add_argument("--window", type=int, default=None, metavar="W",
                   help="temporal window W (spend-cap .dw policies)")
    p.add_argument("--quiet", action="store_true",
                   help="suppress the human summary")

    p = sub.add_parser(
        "site",
        help="regenerate the replay site's RTF trace data + registry "
             "(the Ship plane: a pure function of the sample policies)")
    p.add_argument("--out", default=None, metavar="DIR",
                   help="data/ dir for the traces + registry "
                        "[default: <repo>/site/data]")
    p.add_argument("--quiet", action="store_true",
                   help="suppress the human summary")

    p = sub.add_parser(
        "doctor",
        help="diagnose the ROTN installation (Python, package, engines; "
             "--deep runs a real self-test)")
    p.add_argument("--deep", action="store_true",
                   help="also run a real end-to-end verification self-test "
                        "(slower)")
    p.add_argument("--quiet", action="store_true",
                   help="suppress the human summary")

    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return EXIT_ERROR
    return {"check": cmd_check, "replay": cmd_replay, "ci": cmd_ci,
            "demo": cmd_demo, "corpus": cmd_corpus,
            "license": cmd_license, "trace": cmd_trace,
            "coach": cmd_coach, "site": cmd_site,
            "doctor": cmd_doctor}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())

