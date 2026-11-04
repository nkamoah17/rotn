# -*- coding: utf-8 -*-
"""rot -- ROTN temporal policy verification engine, product CLI.

Subcommands
-----------
  rot check     Verify a policy (safety / realizability / liveness); on
                VIOLATED emit a narrative + an auditable attack.jsonl.
  rot ai        The AI-authored demo loop (Phase 4): intent -> AI policy
                -> ROTN verdict (the "verify the policies AI writes"
                position, runnable end to end).
  rot replay    Re-derive a recorded attack.jsonl against a policy -- the
                verification loop that proves the counterexample is real.
  rot ci        CI gate: verdict + JUnit XML + SARIF artifacts.
  rot demo      The 5-phase spend-cap demo (PROVEN / VIOLATED / K-sweep /
                replay), exit-code aware like demo.sh.
  rot corpus    Run the AWS Dogwood spend-cap corpus; emit a coverage matrix.
  rot trace     Emit the RTF v1 deterministic, hashable reasoning trace
                (a superset of the MCP findings report; --manifest).
  rot coach     Coach the agent back in bounds, *with a proof* (the
                CoachingArtifact); --aggregate coaches the *rules* from a
                decision ledger (the runtime coach, B5).
  rot runtime   The runtime plane (Product 2): ``eval`` decides one live tool
                call; ``serve`` runs the MCP tools/call gateway (HTTP).
  rot doctor    Diagnose the installation (Python, package, engines;
                --deep runs a real end-to-end self-test).
  rot ab        Frontend A/B over the bench corpus (Joern-primary, Â§3):
                lexicographic winner, offline and deterministic.

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
               note, report_path, attack_path,
               adv_code=None, adv_msg=None):
    """Print the human-readable verdict block."""
    print(_BAR)
    print("  ROTN verdict: %s" % status.upper())
    print(_BAR)
    if adv_code:
        print("  WARNING   : %s" % adv_code)
        if adv_msg:
            print("             %s" % adv_msg)
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
    """Resolve the effective depth budget (full-strength) from CLI options.

    ROTN is full-strength for everyone: the budget is the generous
    :data:`rot.license.FREE_LIMITS`. ``--depth`` is an optional user-set
    ``max_states`` bound (it may only lower the budget). Returns a
    :class:`rot.license.DepthBudget` (never ``None``).
    """
    import rot.license as lic

    depth = getattr(args, "depth", None)
    return lic.resolve_budget(depth=depth)


def _cmd_check_mcp(args):
    """Emit the Cedar-AR standardized findings report (``--mcp``).

    Reads the policy's ``allowed``/``denied`` action sets (and, if ``--tools``
    is given, the tool catalog), runs :func:`rot.mcp_adapter.audit_mcp`, writes
    the JSON artifact, and renders the blog-ready narrative.  The exit code is
    the report's gate outcome (0 PASS / 1 BLOCK / 2 OUT_OF_SCOPE).
    """
    import rot.mcp_adapter as mcp
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

    budget = _resolve_budget(args)

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
    import rot.mcp_manifest as mm

    manifest_path = args.manifest
    try:
        manifest = mm.parse_manifest_file(manifest_path)
    except (mm.McpManifestError, OSError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    budget = _resolve_budget(args)

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


def _trace_manifest(manifest_path, budget, horizon):
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


def _trace_policy(policy_path, args, budget, horizon):
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
    policy_path = getattr(args, "policy", None)
    manifest_path = getattr(args, "manifest", None)
    if bool(policy_path) == bool(manifest_path):
        print("ERROR: specify exactly one of --manifest FILE or --policy FILE",
              file=sys.stderr)
        return EXIT_ERROR

    budget = _resolve_budget(args)

    horizon = getattr(args, "liveness_horizon", None) or 12

    if policy_path:
        result, exit_code = _trace_policy(policy_path, args, budget, horizon)
    else:
        result, exit_code = _trace_manifest(manifest_path, budget, horizon)
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
# rot report
# ---------------------------------------------------------------------------

def cmd_report(args):
    """The one-pager as an ATTESTATION (B3) -- not a summary.

    Two modes (exactly one required):

      * ``--one-pager --trace FILE`` -- derive the attestation (the
        underwriter's view) FROM the RTF v1 trace (the source of truth) and
        emit Markdown + HTML (byte-stable; re-runs reproduce the same bytes).
        The attestation pins the trace's SHA-256 hash + the exact re-verify
        command + the expected hash, renders the assumptions as coverage
        conditions, carries the SOC 2 / AIUC controls, the bounded caveat, and
        ``version = policy-hash + engine-version``.

      * ``--verify-trace FILE --expect HASH`` -- the re-verify step: recompute
        the trace's canonical body hash and check it against ``--expect``.
        A match re-derives the attestation byte-for-byte (exit 0); a mismatch
        means the policy/engine changed -- the attestation is STALE (exit 1).

    Exit codes: 0 (attestation emitted / hash matches), 1 (STALE -- mismatch),
    3 (error).
    """
    import rot.attestation as attmod

    # -- mode 2: the re-verify step (byte-for-byte) ------------------------
    verify_trace = getattr(args, "verify_trace", None)
    if verify_trace:
        if not os.path.isfile(verify_trace):
            print("ERROR: trace file not found: %s" % verify_trace,
                  file=sys.stderr)
            return EXIT_ERROR
        with open(verify_trace, "r") as fh:
            trace_dict = json.load(fh)
        computed = attmod.verify_trace_hash(trace_dict)
        expected = getattr(args, "expect", None)
        if expected is None:
            print("  computed trace hash : %s" % computed)
            return EXIT_PROVEN
        if computed == expected:
            print("MATCH    : %s" % computed)
            return EXIT_PROVEN
        print("MISMATCH : computed=%s expected=%s" % (computed, expected),
              file=sys.stderr)
        print("STALE -- the policy or engine changed; re-issue the "
              "attestation.", file=sys.stderr)
        return EXIT_VIOLATED

    # -- mode 1: the one-pager (the attestation) ---------------------------
    if getattr(args, "one_pager", False) and getattr(args, "trace", None):
        trace_path = args.trace
        if not os.path.isfile(trace_path):
            print("ERROR: trace file not found: %s" % trace_path,
                  file=sys.stderr)
            return EXIT_ERROR
        with open(trace_path, "r") as fh:
            trace_dict = json.load(fh)
        # Pin the trace's hash: prefer the stated top-level hash, but verify
        # it against the re-derived body hash (a mismatch means a stale trace
        # file -- warn, then re-derive from the body so the attestation is
        # always consistent with what it pins).
        stated = trace_dict.get("hash")
        computed = attmod.verify_trace_hash(trace_dict)
        if stated is not None and stated != computed:
            print("WARNING: trace hash mismatch (stated=%s computed=%s); "
                  "pinning the re-derived body hash." % (stated, computed),
                  file=sys.stderr)
            trace_dict = dict(trace_dict, hash=computed)
        # D4: the corpus coverage metric (N of M SAFE/UNSAFE/UNKNOWN), when
        # supplied via --corpus-matrix, is first-class in the attestation.
        coverage = None
        matrix_path = getattr(args, "corpus_matrix", None)
        if matrix_path:
            if not os.path.isfile(matrix_path):
                print("ERROR: corpus matrix not found: %s" % matrix_path,
                      file=sys.stderr)
                return EXIT_ERROR
            with open(matrix_path, "r") as fh:
                coverage = json.load(fh).get("summary")
        att = attmod.build_attestation(trace_dict, coverage=coverage)

        out_dir = args.out or os.path.join(_repo_root(), "out", "report")
        os.makedirs(out_dir, exist_ok=True)
        md_path = args.md or os.path.join(out_dir, "one_pager.md")
        html_path = args.html or os.path.join(out_dir, "one_pager.html")
        with open(md_path, "w") as fh:
            fh.write(att.to_markdown() + "\n")
        with open(html_path, "w") as fh:
            fh.write(att.to_html() + "\n")

        if not getattr(args, "quiet", False):
            print("  verdict    : %s" % att.verdict())
            print("  trace hash : %s" % att.body["source_trace"]["hash"])
            print("  version    : %s" % att.body["version"]["id"])
            cov = att.body.get("corpus_coverage")
            if cov:
                print("  coverage   : %s" % cov["human"])
            print("  att hash   : %s" % att.hash)
            print("  markdown   : %s" % md_path)
            print("  html       : %s" % html_path)
            print("  re-verify  : %s" % att.body["reverify"]["command"])
        return EXIT_PROVEN

    print("ERROR: specify --one-pager --trace FILE or "
          "--verify-trace FILE --expect HASH", file=sys.stderr)
    return EXIT_ERROR


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

    # The runtime coach (B5): coach the *rules* from the decision ledger.
    if getattr(args, "aggregate", False):
        return _cmd_coach_aggregate(args)

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


def _cmd_coach_aggregate(args):
    """``rot coach --aggregate``: coach the *rules* from the ledger (B5).

    Exit codes: ``0`` relaxation SAFE / not applicable, ``1`` UNSAFE,
    ``2`` UNVERIFIED (fail-closed), ``3`` error.
    """
    from rot.runtime.ledger import DecisionLedger, LedgerError
    try:
        import rot.commercial.runtime.aggregate as agg
    except ImportError:
        print("ERROR: 'rot coach --aggregate' (fleet near-miss learning) needs "
              "the commercial layer -- install rotn-commercial "
              "(pip install rotn-commercial)", file=sys.stderr)
        return EXIT_ERROR

    ledger_path = getattr(args, "ledger", None)
    if not ledger_path:
        print("ERROR: --aggregate requires --ledger FILE (a decision ledger)",
              file=sys.stderr)
        return EXIT_ERROR
    if not os.path.exists(ledger_path):
        print("ERROR: ledger not found: %s" % ledger_path, file=sys.stderr)
        return EXIT_ERROR

    rule = None
    rule_name = getattr(args, "rule", None)
    if not rule_name:
        # Default: the rule named by --shape (spendcap / exfiltration).
        rule_name = {"spendcap": "spendcap_within_cap",
                     "exfiltration": "no_exfiltration"}.get(
                         getattr(args, "shape", "spendcap"))
    if rule_name:
        from rot.runtime.rules import get_rule, RULES
        if rule_name not in RULES:
            print("ERROR: unknown rule %r (known: %s)"
                  % (rule_name, ", ".join(sorted(RULES))), file=sys.stderr)
            return EXIT_ERROR
        rule = get_rule(rule_name)

    try:
        ledger = DecisionLedger.from_file(ledger_path)
    except (LedgerError, ValueError, IOError, OSError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    result = agg.aggregate_ledger(
        ledger, rule=rule,
        max_states=getattr(args, "max_states", None) or 100000)

    out = getattr(args, "out", None)
    if out:
        out_dir = os.path.dirname(os.path.abspath(out))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(out, "w") as fh:
            fh.write(result.to_json() + "\n")
        if not getattr(args, "quiet", False):
            print("  artifact  : %s" % out)
    else:
        sys.stdout.write(result.to_json() + "\n")

    if not getattr(args, "quiet", False):
        body = result.body
        print(_BAR)
        print("  COACHING (runtime): ledger %s -- %d blocks of %d"
              % (ledger_path, body["ledger"]["blocked"],
                 body["ledger"]["entries"]))
        print("  top blockers: %s"
              % (", ".join("%s(%d)" % (b["rule"], b["count"])
                           for b in body["top_blockers"]) or "(none)"))
        print("  relaxation  : %s" % body["relaxation"]["status"])
        print("  explanation : %s" % body["relaxation"]["explanation"])
        print("  hash        : %s" % result.hash)
        print(_BAR)

    status = result.body["relaxation"]["status"]
    if status in (agg.SAFE, agg.NOT_APPLICABLE):
        return EXIT_PROVEN
    if status == agg.UNSAFE:
        return EXIT_VIOLATED
    return EXIT_UNKNOWN  # UNVERIFIED -- fail-closed


def cmd_runtime(args):
    """``rot runtime``: dispatch to ``eval`` / ``tools`` / ``serve``."""
    which = getattr(args, "runtime_command", None)
    if which == "eval":
        return cmd_runtime_eval(args)
    if which == "tools":
        return cmd_runtime_tools(args)
    if which == "serve":
        return cmd_runtime_serve(args)
    print("ERROR: specify 'rot runtime eval', 'rot runtime tools', or "
          "'rot runtime serve'", file=sys.stderr)
    return EXIT_ERROR

def _parse_kv(pairs, where):
    """Parse ``k=v`` pairs into a dict (values: JSON if possible, else str)."""
    out = {}
    for pair in (pairs or []):
        if "=" not in pair:
            print("ERROR: %s: expected k=v, got %r" % (where, pair),
                  file=sys.stderr)
            return None
        key, _, raw = pair.partition("=")
        try:
            out[key] = json.loads(raw)
        except ValueError:
            out[key] = raw
    return out


def _load_rule(args):
    """Resolve ``--rule`` (id) to a concrete rule; None on error (printed)."""
    from rot.runtime.rules import get_rule, RULES

    name = getattr(args, "rule", None) or "spendcap_within_cap"
    if name not in RULES:
        print("ERROR: unknown rule %r (known: %s)"
              % (name, ", ".join(sorted(RULES))), file=sys.stderr)
        return None
    return get_rule(name)


def cmd_runtime_eval(args):
    """``rot runtime eval``: decide one tool call with the deterministic core.

    Exit codes: ``0`` allowed, ``1`` blocked, ``3`` error.
    """
    rule = _load_rule(args)
    if rule is None:
        return EXIT_ERROR
    tool = getattr(args, "tool", None)
    if not tool:
        print("ERROR: specify --tool NAME (the tool call to decide)",
              file=sys.stderr)
        return EXIT_ERROR
    args_kv = _parse_kv(getattr(args, "arg", None), "--arg")
    if args_kv is None:
        return EXIT_ERROR
    state = {}
    state_raw = getattr(args, "state", None)
    if state_raw:
        try:
            state = json.loads(state_raw)
        except ValueError:
            print("ERROR: --state must be a JSON object, e.g. "
                  "{\"completed\": 0, \"inflight\": 3}", file=sys.stderr)
            return EXIT_ERROR
        if not isinstance(state, dict):
            print("ERROR: --state must be a JSON object", file=sys.stderr)
            return EXIT_ERROR

    from rot.runtime.core import RuntimeGuard, ALLOWED

    decision = RuntimeGuard(rule).decide(
        request={"tool": tool, "args": dict(args_kv), "state": state})
    sys.stdout.write(decision.to_json() + "\n")
    if not getattr(args, "quiet", False):
        verdict = "ALLOWED" if decision.decision == ALLOWED else "BLOCKED"
        print(_BAR)
        print("  %s: %s (rule %s)" % (verdict, tool, rule.rule_id))
        if decision.blocked:
            print("  why       : %s" % decision.refusal.why)
            print("  to-proceed: %s" % decision.refusal.to_proceed)
        print(_BAR)
    return EXIT_PROVEN if decision.allowed else EXIT_VIOLATED


def cmd_runtime_tools(args):
    """``rot runtime tools``: print the tools enabled in a state (the mask).

    The tool-masking view (thesis 4.1): for the rule's tool universe (the IR's
    decision actions), show which are **enabled** in ``state`` and which are
    **blocked**.  The mask is the same per-guard evaluation the offline engine
    proved safe -- no new proof engine, no LLM.

    Exit codes: ``0`` (the mask was printed), ``3`` error.
    """
    rule = _load_rule(args)
    if rule is None:
        return EXIT_ERROR
    state = {}
    state_raw = getattr(args, "state", None)
    if state_raw:
        try:
            state = json.loads(state_raw)
        except ValueError:
            print("ERROR: --state must be a JSON object, e.g. "
                  "{\"completed\": 0, \"inflight\": 3}", file=sys.stderr)
            return EXIT_ERROR
        if not isinstance(state, dict):
            print("ERROR: --state must be a JSON object", file=sys.stderr)
            return EXIT_ERROR

    from rot.runtime.core import RuntimeGuard

    rg = RuntimeGuard(rule)
    et = rg.enabled_tools(state)
    enabled = sorted(t for t, ok in et.items() if ok)
    blocked = sorted(t for t, ok in et.items() if not ok)
    if getattr(args, "json", False):
        sys.stdout.write(json.dumps(
            {"rule": rule.rule_id, "state": state, "enabled": enabled,
             "blocked": blocked,
             "enabled_tools": {t: et[t] for t in sorted(et)}},
            sort_keys=True, indent=2) + "\n")
    else:
        print(_BAR)
        print("  ROTN runtime tool mask (rule %s)" % rule.rule_id)
        print("  state     : %s" % json.dumps(state, sort_keys=True))
        print("  enabled   : %s" % (", ".join(enabled) if enabled else "(none)"))
        print("  blocked   : %s" % (", ".join(blocked) if blocked else "(none)"))
        print(_BAR)
    return EXIT_PROVEN


def cmd_runtime_serve(args):
    """``rot runtime serve``: the MCP ``tools/call`` gateway (HTTP, stdlib)."""
    rule = _load_rule(args)
    if rule is None:
        return EXIT_ERROR

    from rot.runtime.ledger import DecisionLedger
    try:
        from rot.commercial.runtime.mcp import McpGateway, build_http_server
    except ImportError:
        print("ERROR: 'rot runtime serve' (the MCP gateway) needs the commercial "
              "layer -- install rotn-commercial "
              "(pip install rotn-commercial)", file=sys.stderr)
        return EXIT_ERROR

    manifest = None
    manifest_path = getattr(args, "manifest", None)
    if manifest_path:
        from rot.mcp_manifest import McpManifest, McpManifestError
        try:
            with open(manifest_path, "r") as fh:
                manifest = McpManifest.from_dict(json.load(fh))
        except (IOError, OSError, ValueError, McpManifestError) as exc:
            print("ERROR: %s" % exc, file=sys.stderr)
            return EXIT_ERROR

    ledger = None
    ledger_path = getattr(args, "ledger", None)
    if ledger_path:
        from rot.runtime.ledger import LedgerError
        if os.path.exists(ledger_path):
            try:
                ledger = DecisionLedger.from_file(ledger_path)
            except (LedgerError, ValueError) as exc:
                print("ERROR: %s" % exc, file=sys.stderr)
                return EXIT_ERROR
        else:
            ledger = DecisionLedger()

    gateway = McpGateway(default_rule=rule, manifest=manifest, ledger=ledger)
    host = getattr(args, "host", "127.0.0.1")
    port = getattr(args, "port", 8765)
    server = build_http_server(gateway, host=host, port=port)
    if not getattr(args, "quiet", False):
        print(_BAR)
        print("  ROTN runtime gateway (MCP tools/call interceptor)")
        print("  rule      : %s" % rule.rule_id)
        print("  manifest  : %s" % (manifest_path or "(none)"))
        print("  ledger    : %s" % (ledger_path or "(in-memory)"))
        print("  listening : http://%s:%d/  (POST JSON-RPC; GET info)"
              % (host, server.server_address[1]))
        print(_BAR)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if ledger is not None and ledger_path:
            with open(ledger_path, "w") as fh:
                fh.write(ledger.to_jsonl())
            if not getattr(args, "quiet", False):
                print("  ledger  : %s (%d entries)"
                      % (ledger_path, len(ledger)))
    return EXIT_PROVEN


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
            depth=None,
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
        engines, and the bounded re-check loop);
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

    # K-masking advisory (A1): a cap/budget PROVEN at a K that cannot express
    # the minimal overshoot is a *silent false-negative* risk (the K=1 trap).
    # Loud, non-fatal -- it does not change the verdict or the exit code.
    from rot.verdicts import k_masking_advisory
    adv_code, adv_msg = k_masking_advisory(ir.metadata, status)

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
        if adv_code:
            report["advisory"] = adv_code
            report["advisory_message"] = adv_msg
        if note:
            report["note"] = note
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, sort_keys=True)

    if not args.quiet:
        _narrative(policy, target, prop, kind, status, witness, steps,
                   note, report_path, attack_path,
                   adv_code=adv_code, adv_msg=adv_msg)
    return code


# ---------------------------------------------------------------------------
# rot ai (Phase 4): the AI-authored-policy demo loop
# ---------------------------------------------------------------------------

def _ai_narrative(r):
    """Print the four-step demo-loop narrative (intent -> policy -> verdict)."""
    print(_BAR)
    print(" ROTN -- AI-authored policy demo loop (intent -> policy -> verdict)")
    print(_BAR)
    first = " ".join(r["intent"].split())
    print("\n 1. INTENT (natural language)")
    print("    %s%s" % (first[:140], "..." if len(first) > 140 else ""))
    print("    [%s]" % r["intent_path"])
    print("\n 2. AI-AUTHORED POLICY (as the AI authoring would emit it)")
    print("    %s" % r["policy_path"])
    print("    frontend: %s    shape: %s" % (r["frontend"], r["shape"]))
    print("\n 3. NEUTRAL CHECKER (lower to ProtocolIR, decide the property)")
    print("    property: %s (%s)" % (r["property"], r["property_kind"]))
    cross = r.get("cross_language")
    if cross:
        print("    Dogwood twin: %s" % cross["dogwood_policy"])
        print("    same IR as the Dogwood policy : %s" % cross["same_ir"])
        print("    same verdict as the Dogwood   : %s" % cross["same_verdict"])
    print("\n 4. VERDICT")
    if r["witness"] is not None:
        print("    %s   witness=%s"
              % (r["verdict"].upper(),
                 json.dumps(r["witness"], sort_keys=True)))
    else:
        print("    %s" % r["verdict"].upper())
    if r["verdict"] == "violated":
        print("\n    The AI's draft reads correctly on paper; under concurrency it")
        print("    can be bypassed. ROTN proves the bypass with a named witness;")
        print("    the corrected draft is what the proof is about.")
    print()


def cmd_ai(args):
    """Run the AI-authored demo loop (Phase 4): intent -> policy -> verdict.

    The default example is the canonical APW-2 (approval-replay) policy:
    the intent in ``samples/ai_authoring/intent.md`` and the AI's natural
    first draft in ``samples/ai_authoring/apw2-buggy.rego``.  Exit codes:
    ``0`` proven / ``1`` violated / ``2`` unknown / ``3`` error.
    """
    import rot.ai_loop as ai_loop

    try:
        result = ai_loop.run(
            intent_path=getattr(args, "intent", None),
            policy_path=getattr(args, "policy", None),
            out_dir=getattr(args, "out", None))
    except Exception as exc:  # one clear CLI error (exit 3)
        print("ERROR: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    if not args.quiet:
        _ai_narrative(result)
    return result["exit_code"]


# ---------------------------------------------------------------------------
# rot replay
# ---------------------------------------------------------------------------

def cmd_replay(args):
    """Re-derive a recorded attack.jsonl against a policy.

    Without ``--policy`` this is a record-only inspection (prints the
    recorded attack). With ``--policy`` it re-runs the sound core and
    reports whether the counterexample reproduces -- the verification loop
    that closes the "is this attack real?" question.

    With ``--oracle dogwood`` it instead replays a policy + trace against
    Dogwood's reference interpreter and records the reference verdict next to
    ROTN's (the Phase-3 "Dogwood admits it, ROTN catches it" side-by-side).
    """
    if getattr(args, "oracle", None) == "dogwood":
        return _cmd_replay_oracle_dogwood(args)
    path = args.attack
    if not path:
        print("ERROR: no attack file given (or use --oracle dogwood --gate)",
              file=sys.stderr)
        return EXIT_ERROR
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



def _cmd_replay_oracle_dogwood(args):
    """Phase 3 -- replay a policy + trace against Dogwood's reference
    interpreter and record the reference verdict next to ROTN's.

    Modes:
      * ``--gate``  : run the APW-1/2/4 gate classes (fixtures) and write the
        side-by-side report (JSON + Markdown).
      * single      : ``--policy --trace --policy-schema`` for one class.
    """
    import rot.oracle as oracle

    binary = oracle.find_dogwood(getattr(args, "dogwood", None))
    if binary is None:
        print("ERROR: dogwood binary not found -- set DOGWOOD_BIN or pass "
              "--dogwood PATH (Phase-0 build at C:\\tools\\dogwood\\target\\...)",
              file=sys.stderr)
        return EXIT_ERROR

    out_dir = args.out or os.path.join(_repo_root(), "out", "reference-replay")
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)

    if getattr(args, "gate", False):
        reports = oracle.run_gate(binary)
    else:
        if not (args.policy and args.trace and args.policy_schema):
            print("ERROR: --oracle dogwood needs --policy, --trace and "
                  "--policy-schema (or --gate to run APW-1/2/4)",
                  file=sys.stderr)
            return EXIT_ERROR
        rot = oracle.run_rotn_check(args.policy)
        ref_buggy = oracle.run_dogwood_replay(
            binary, args.policy, args.policy_schema, args.trace)
        ref_correct = None
        if getattr(args, "correct", None):
            ref_correct = oracle.run_dogwood_replay(
                binary, args.correct, args.policy_schema, args.trace)
        reports = [oracle.side_by_side(
            rot.get("verdict"), rot.get("witness"), rot.get("property"),
            ref_buggy, ref_correct)]
        reports[0]["apw"] = getattr(args, "apw", None) or "custom"
        reports[0]["name"] = "single policy"
        reports[0]["policy_buggy"] = args.policy
        reports[0]["trace"] = args.trace

    # Persist: per-class JSON, combined JSON, and the Markdown artifact.
    for r in reports:
        with open(os.path.join(out_dir,
                               "%s.reference.json" % r.get("apw", "policy")),
                  "w") as f:
            json.dump(r, f, indent=2, sort_keys=True)
    with open(os.path.join(out_dir, "reference-replay.json"), "w") as f:
        json.dump(reports, f, indent=2, sort_keys=True)
    md_path = args.md or os.path.join(out_dir, "reference-replay.md")
    with open(md_path, "w") as f:
        f.write(oracle.render_markdown(reports, binary=binary))

    # Human summary.
    is_gate = getattr(args, "gate", False)
    if is_gate:
        passed = oracle.gate_passed(reports)
        scope = "gate"
    else:
        # single mode: pass iff this one class agrees (the 3-class gate N/A)
        passed = bool(reports and reports[0].get("gate", {}).get("agreement"))
        scope = "class"
    n_agree = sum(1 for r in reports if r.get("gate", {}).get("agreement"))
    print(_BAR)
    print("  ROTN x Dogwood reference -- oracle replay")
    print(_BAR)
    for r in reports:
        g = r.get("gate", {})
        mark = "AGREE" if g.get("agreement") else "no"
        print("  %-6s %-30s ROTN=%-8s ref-admit=%-5s [%s]" % (
            r.get("apw"), r.get("name"),
            (r.get("rot") or {}).get("verdict", "-"),
            g.get("reference_admitted"), mark))
    print(_BAR)
    print("  %s      : %s (%d of %d agree)" % (
        scope, "PASS" if passed else "FAIL", n_agree, len(reports)))
    print("  json      : %s" % os.path.join(out_dir, "reference-replay.json"))
    print("  markdown  : %s" % md_path)
    print(_BAR)
    return EXIT_PROVEN if passed else EXIT_VIOLATED


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
            "tool": {"driver": {"name": "ROTN", "version": rot.__version__}},
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
    """The beachhead demo: the whole arc in ONE command (D1).

    rule -> attack -> proof -> coach -> attestation

    (1) rule         the spend-cap policy, rendered (policy -> model abstraction)
    (2) attack       the deterministic counterexample + the K-sweep
                     (K=1 masks the bug, K>=2 exposes it)
    (3) proof        the corrected policy is safe (PROVEN) + its RTF manifest + hash
    (4) coach        the runtime refusal (to_proceed + allowed_now) -- Product 2
    (5) attestation  the one-pager (path + hash + the re-verify command)

    The scope is stated explicitly (D2): the initial demo is the spend-cap
    (payments) parallel-fire bug + the coach. The MCP/trifecta story ships
    with B2.3 (not part of this demo).

    Single command, exits 0 when every beat behaves as expected, and ends
    with the attestation's SHA-256 + the re-verify command.
    """
    beachhead = getattr(args, "beachhead", None) or "spendcap"
    if beachhead != "spendcap":
        print("ERROR: unknown beachhead %r (the initial demo is the spend-cap "
              "parallel-fire bug + coach; the MCP/trifecta story ships with "
              "B2.3)" % beachhead, file=sys.stderr)
        return EXIT_ERROR

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
    os.makedirs(out_dir, exist_ok=True)
    failures = []
    bar = "=" * 66

    def beat(n, title):
        print(bar)
        print("BEAT %d -- %s" % (n, title))
        print(bar)

    def run(title, policy, k, expect, out=None):
        a = argparse.Namespace(policy=policy, kind=None, max_inflight=k,
                               amount=None, cap=None, window=None, out=out,
                               quiet=True, liveness_horizon=None)
        code = cmd_check(a)
        ok = code == expect
        if not ok:
            failures.append(title)
        print("  [%s] %-52s exit=%d expected=%d"
              % ("PASS" if ok else "FAIL", title, code, expect))
        return code

    print(bar)
    print("  rot demo --beachhead spendcap")
    print("  SCOPE (D2): the initial demo = the spend-cap (payments)")
    print("  parallel-fire bug + the coach. The MCP/trifecta story ships")
    print("  with B2.3 (not part of this demo).")
    print(bar)

    # ------------------------------------------------------------------
    # BEAT 1 -- RULE: the spend-cap policy, rendered (policy -> model)
    # ------------------------------------------------------------------
    beat(1, "RULE: the spend-cap policy (policy -> model abstraction)")
    import rot.spendcap_display as sd
    sd.render(buggy)

    # ------------------------------------------------------------------
    # BEAT 2 -- ATTACK: the deterministic counterexample + the K-sweep
    # ------------------------------------------------------------------
    beat(2, "ATTACK: the deterministic counterexample + the K-sweep")
    code2 = run("buggy.dw VIOLATED (witness + attack.jsonl)", buggy, None,
                EXIT_VIOLATED, out=out_dir)
    if code2 == EXIT_VIOLATED:
        attack = os.path.join(out_dir, "attack.jsonl")
        if os.path.isfile(attack):
            a = argparse.Namespace(attack=attack, policy=buggy,
                                   max_inflight=None, liveness_horizon=None)
            code = cmd_replay(a)
            ok = code == EXIT_VIOLATED
            if not ok:
                failures.append("replay")
            print("  [%s] %-52s exit=%d expected=%d"
                  % ("PASS" if ok else "FAIL",
                     "replay (the counterexample reproduces)", code,
                     EXIT_VIOLATED))
        else:
            print("  [SKIP] no attack.jsonl produced in %s" % out_dir)
    print("  -- K-sweep: the pool K is the whole story (K=1 masks, K>=2 exposes)")
    run("K=1 masked (buggy.dw --max-inflight 1)", buggy, 1, EXIT_PROVEN)
    run("K=2 exposes (buggy.dw --max-inflight 2)", buggy, 2, EXIT_VIOLATED)

    # ------------------------------------------------------------------
    # BEAT 3 -- PROOF: the corrected policy is safe + its RTF manifest + hash
    # ------------------------------------------------------------------
    beat(3, "PROOF: the corrected policy is safe (+ RTF manifest + hash)")
    run("correct.dw PROVEN (the fix is verifiably safe)", correct, None,
        EXIT_PROVEN)
    budget = _resolve_budget(args)
    a = argparse.Namespace(policy=correct, kind=None, max_inflight=None,
                           amount=None, cap=None, window=None,
                           liveness_horizon=None)
    trace_res, _ = _trace_policy(correct, a, budget, 12)
    if trace_res is not None:
        print("  manifest  : %s" % trace_res.manifest_id())
        print("  hash      : %s" % trace_res.hash)
    else:
        print("  [WARN] could not build the corrected-policy trace",
              file=sys.stderr)
        failures.append("proof-manifest")

    # ------------------------------------------------------------------
    # BEAT 4 -- COACH: the runtime refusal (to_proceed + allowed_now)
    # ------------------------------------------------------------------
    beat(4, "COACH: the runtime refusal (to_proceed + allowed_now) -- Product 2")
    from rot.runtime.core import RuntimeGuard
    from rot.runtime.rules import get_rule
    rule = get_rule("spendcap_within_cap")
    # A state the buggy (settled-trace) monitor does NOT see: 2 in-flight.
    state = {"completed": 0, "inflight": 2}
    decision = RuntimeGuard(rule).decide(
        state=state, request={"tool": "transfer", "args": {"amount": 100}})
    refusal = decision.refusal
    print("  state       : %s" % json.dumps(state, sort_keys=True))
    print("  blocked     : %s" % refusal.blocked)
    print("  why         : %s" % refusal.why)
    print("  to-proceed  : %s" % refusal.to_proceed)
    print("  allowed_now : %s" % refusal.allowed_now)
    print("  refusal     : %s" % refusal.hash)
    if not refusal.blocked:
        print("  [WARN] expected a BLOCKED refusal at this state",
              file=sys.stderr)
        failures.append("coach")

    # ------------------------------------------------------------------
    # BEAT 5 -- ATTESTATION: the one-pager (path + hash + re-verify command)
    # ------------------------------------------------------------------
    beat(5, "ATTESTATION: the one-pager (path + hash + re-verify command)")
    import rot.attestation as attmod
    a = argparse.Namespace(policy=buggy, kind=None, max_inflight=None,
                           amount=None, cap=None, window=None,
                           liveness_horizon=None)
    trace_res, _ = _trace_policy(buggy, a, budget, 12)
    if trace_res is None:
        print("  [WARN] could not build the buggy-policy trace",
              file=sys.stderr)
        failures.append("attestation")
    else:
        # The RTF v1 trace is the source of truth (written next to the
        # one-pager); the attestation pins its hash.
        with open(os.path.join(out_dir, "trace.json"), "w") as fh:
            fh.write(trace_res.to_json() + "\n")
        # D4: attach the corpus coverage metric (N of M SAFE/UNSAFE/UNKNOWN).
        coverage = None
        try:
            coverage = _corpus_report(os.path.dirname(fx))["summary"]
        except Exception:  # noqa: BLE001
            coverage = None
        att = attmod.build_attestation(trace_res.to_dict(), coverage=coverage)
        md_path = os.path.join(out_dir, "one_pager.md")
        html_path = os.path.join(out_dir, "one_pager.html")
        with open(md_path, "w") as fh:
            fh.write(att.to_markdown() + "\n")
        with open(html_path, "w") as fh:
            fh.write(att.to_html() + "\n")
        if coverage is not None:
            print("  coverage  : %s" % attmod.summarize_coverage(coverage)["human"])
        print("  one-pager : %s" % md_path)
        print("  html      : %s" % html_path)
        print("  att hash  : %s" % att.hash)
        print("  re-verify : %s" % att.body["reverify"]["command"])

    # ------------------------------------------------------------------
    print(bar)
    if failures:
        print("DEMO FAILED: %d beat(s) deviated: %s"
              % (len(failures), ", ".join(failures)))
        return EXIT_VIOLATED
    print("DEMO OK: rule -> attack -> proof -> coach -> attestation. "
          "Single command, exit 0; the attestation hash + re-verify "
          "command are above.")
    return EXIT_PROVEN



# ---------------------------------------------------------------------------
# rot corpus
# ---------------------------------------------------------------------------

def _corpus_report(corpus_dir, max_inflight=None):
    """Classify every .dw policy under ``corpus_dir``; return the report dict.

    The report is ``{corpus_dir, generated_by, policies, summary}`` where
    ``summary`` is the coverage metric (total / lowerable / proven / violated
    / out_of_scope / error).  No printing, no file writing -- the caller
    (``rot corpus`` or the demo) decides what to show.  This is the single
    source of the corpus classification, so the demo's coverage metric (D4)
    and ``rot corpus`` can never drift apart.
    """
    from rot.modelfind import ProductTooLarge

    policies = []
    for dirpath, dirnames, filenames in os.walk(corpus_dir):
        dirnames.sort()
        for fn in sorted(filenames):
            if fn.endswith(".dw"):
                policies.append(os.path.join(dirpath, fn))

    results = []
    for p in policies:
        name = os.path.relpath(p, corpus_dir).replace(os.sep, "/")
        a = argparse.Namespace(policy=p, kind=None,
                               max_inflight=max_inflight, amount=None,
                               cap=None, out=None, quiet=True,
                               liveness_horizon=None)
        entry = _classify_corpus_policy(p, a, ProductTooLarge)
        entry["policy"] = name
        results.append(entry)

    summary = {}
    for r in results:
        key = r["verdict"] or "error"
        summary[key] = summary.get(key, 0) + 1
    lowerable_count = sum(1 for r in results if r["lowerable"])

    return {
        "corpus_dir": corpus_dir,
        "generated_by": "rot corpus (Phase B.2)",
        "policies": results,
        "summary": dict({"total": len(results),
                         "lowerable": lowerable_count}, **summary),
    }


def _classify_corpus_policy(p, a, ProductTooLarge):
    """Classify one policy into the coverage-matrix entry (the loop body).

    OUT_OF_SCOPE is an honest classification (a lowering failure, or a state
    space over the bounded-checking budget) -- NOT a bug.  An unexpected
    engine exception is an ``error`` (the report's only non-zero gate).
    """
    entry = {
        "shape": None, "lowerable": False,
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
                # K-masking advisory (A1): a PROVEN cap/budget policy at a
                # K below the minimal overshoot is a silent false-negative
                # (the K=1 trap).  Loud, non-fatal -- the PROVEN stands.
                from rot.verdicts import k_masking_advisory
                adv_code, adv_msg = k_masking_advisory(ir.metadata, status)
                if adv_code:
                    entry["advisory"] = adv_code
                    entry["advisory_message"] = adv_msg
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
    return entry


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

    # A.4 (opt-in): fetch the remaining upstream corpus before discovering.
    # Needs network.  An explicit --fetch that cannot reach upstream is a hard
    # error (the user asked to fetch and it did not happen); --fetch-dry-run
    # degrades softly (a warning) so an offline dry-run is never blocked.
    if getattr(args, "fetch", False):
        from rot import dogwood_fetch
        try:
            fetched, skipped, failures = dogwood_fetch.fetch_all(
                dogwood_fetch.UPSTREAM_ROOTS, corpus_dir,
                dry_run=getattr(args, "fetch_dry_run", False))
            print("upstream fetch: %d new, %d already present, "
                  "%d failure(s)" % (len(fetched), len(skipped),
                                    len(failures)))
            for f in failures:
                print("  fetch FAIL %s: %s" % f, file=sys.stderr)
            if getattr(args, "fetch_dry_run", False):
                print("  (dry-run: nothing downloaded)")
        except Exception as exc:  # noqa: BLE001
            print("NOTE: upstream fetch skipped (no network?): %s" % exc,
                  file=sys.stderr)
            if not getattr(args, "fetch_dry_run", False):
                # An explicit --fetch that could not even list upstream is a
                # hard error (the user asked to fetch); dry-run degrades softly.
                return EXIT_ERROR

    report = _corpus_report(corpus_dir, max_inflight=args.max_inflight)
    results = report["policies"]
    full_summary = report["summary"]
    summary = {k: v for k, v in full_summary.items()
               if k not in ("total", "lowerable")}
    lowerable_count = full_summary.get("lowerable", 0)

    if not results:
        print("ERROR: no .dw policies under %s" % corpus_dir, file=sys.stderr)
        return EXIT_ERROR

    print("Discovered %d policies under %s" % (len(results), corpus_dir))
    for r in results:
        name = r.get("policy", "?")
        v = (r["verdict"] or "?").upper()
        w = ""
        if r.get("witness") is not None:
            try:
                w = json.dumps(r["witness"], sort_keys=True)
            except (TypeError, ValueError):
                w = repr(r["witness"])
        elif r.get("note"):
            w = r["note"]
        if r.get("advisory"):
            w = (w + "  " if w else "") + "ADVISORY: %s" % r["advisory"]
        print("  %-40s %-14s %-6s %-13s %s" % (
            name[:40], r["shape"] or "-",
            "yes" if r["lowerable"] else "no", v, w))

    print(_BAR)
    print("  ROTN corpus coverage matrix (%d policies, %d lowerable)"
          % (len(results), lowerable_count))
    print(_BAR)
    for k in sorted(summary):
        print("  %-14s %d" % (k, summary[k]))
    print(_BAR)

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


# ---------------------------------------------------------------------------
# rot ladder (Phase 3): the robustness ladder R0 -> R1 -> R2
# ---------------------------------------------------------------------------

def cmd_ladder(args):
    """Run the Phase 3 robustness ladder (R0 -> R1 -> R2) for a target.

    RESEARCH command: the ladder lives in the ``rotn-research`` repo.  In a
    product build (where the research modules are not installed) this exits 3
    with a clear message instead of failing on a missing import.
    """
    try:
        import rot.ladder as ladder          # research module (rotn-research)
    except ImportError:
        print("ERROR: 'rot ladder' is a research command and is not part of "
              "this build.\n"
              "       It lives in the rotn-research repo "
              "(pip install rotn-research).", file=sys.stderr)
        return EXIT_ERROR
    from rot.emitter import emit_refinement_chain

    target = args.target
    if target not in ladder.ladder_target_names():
        print("ERROR: unknown ladder target: %s (choose from: %s)"
              % (target, ", ".join(ladder.ladder_target_names())),
              file=sys.stderr)
        return EXIT_ERROR
    property_name = args.property or ladder.default_ladder_property(target)

    try:
        result = ladder.run_ladder(
            target=target, property_name=property_name, n=args.n,
            max_states=args.max_states, horizon=args.horizon)
    except Exception as exc:  # unknown invariant, engine error, ...
        print("ERROR: ladder run failed: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    bar = "-" * 66
    print(bar)
    print("ROTN ladder: %-14s claim=%-28s kind=%s"
          % (target, property_name, result["kind"]))
    print(bar)
    for rung in ladder.RUNGS:
        v = result["verdicts"][rung.name]
        mark = {"proven": "P", "violated": "V", "unknown": "?",
                "unsound": "U", "error": "E"}.get(v["status"], "?")
        print("  %s [%-10s] %s" % (rung.name, rung.label, v["status"]))
        if v.get("fairness_label"):
            print("       fairness: %s" % v["fairness_label"])
    print(bar)
    print("  highest discharged rung : %s"
          % (result["highest_discharged_rung"] or "none"))
    if result["monotonicity_violations"]:
        print("  MONOTONICITY VIOLATIONS : %s"
              % result["monotonicity_violations"])
    print("  non-claims:")
    for nc in result["non_claims"]:
        print("    - %s" % nc)
    print(bar)

    if args.out:
        out_dir = args.out
        if not os.path.isdir(out_dir):
            os.makedirs(out_dir)
        base = os.path.join(out_dir, "ladder_%s" % target)
        chain = ladder.refinement_chain(ladder.build_fn_for(target), args.n)
        text = emit_refinement_chain(
            chain, implication=ladder.implication_argument(), target=target)
        with open(base + ".txt", "w", encoding="utf-8") as f:
            f.write(text)
        with open(base + ".json", "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, sort_keys=False)
        print("  wrote %s.txt and %s.json" % (base, base))

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=False))

    if result["highest_discharged_rung"] == "R2":
        return EXIT_PROVEN
    return EXIT_VIOLATED


def cmd_ab(args):
    """Frontend A/B over the bench corpus (Joern-primary, Â§3).

    RESEARCH command: the A/B harness lives in the ``rotn-research`` repo.
    In a product build (where the research modules are not installed) this
    exits 3 with a clear message instead of failing on a missing import.
    """
    try:
        import rot.ab as ab                  # research module (rotn-research)
    except ImportError:
        print("ERROR: 'rot ab' is a research command and is not part of "
              "this build.\n"
              "       It lives in the rotn-research repo "
              "(pip install rotn-research).", file=sys.stderr)
        return EXIT_ERROR
    try:
        corpus = ab.load_corpus(getattr(args, "corpus", None))
    except Exception as exc:  # noqa: BLE001
        print("ab: corpus error: %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr)
        return EXIT_ERROR
    if not corpus:
        print("ab: no fixtures found in the corpus", file=sys.stderr)
        return EXIT_ERROR
    frontends = None
    if getattr(args, "frontends", None):
        frontends = [f.strip() for f in args.frontends.split(",") if f.strip()]
    try:
        result = ab.run_ab(corpus=corpus, frontends=frontends)
    except Exception as exc:  # noqa: BLE001
        print("ab: run error: %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr)
        return EXIT_ERROR
    if getattr(args, "out", None):
        with open(args.out, "w") as fh:
            fh.write(ab.to_json(result) + "\n")
        if not getattr(args, "quiet", False):
            print("wrote %s" % args.out)
    if getattr(args, "json", False):
        print(ab.to_json(result))
    elif not getattr(args, "quiet", False):
        print(ab.to_report(result))
    return EXIT_PROVEN


def _run_crosscheck(policy_path, args):
    """Run the 3-engine cross-check (SMT/Z3 + TLC + policy-direct) on a policy.

    Reuses the same wiring as ``pipeline._cmd_policy_crosscheck``: build the
    IR, the pinned safety invariant, the property-directed abstraction, the
    linear model, then run :class:`rot.crosscheck.CrossChecker`.

    Returns ``(verdict, error)`` -- ``verdict`` is the ``rot.verdicts.Verdict``
    (its ``evidence["crosscheck"]`` carries the per-engine evidence and the
    ``join_status3`` join), or ``None`` when the cross-check could not be run
    (e.g. TLC jar / Z3 absent); ``error`` is a human message in that case, else
    ``None``.  The attestation degrades to no cross-check block on error.
    """
    import rot.invariants as invariants
    from rot.config import Config
    from rot.crosscheck import CrossChecker
    from rot.linearization import linearize

    if not os.path.isfile(policy_path):
        return None, "policy file not found: %s" % policy_path
    try:
        ir = _build_ir(policy_path, args)
        ir.validate()
    except Exception as exc:  # noqa: BLE001
        return None, "could not build the IR: %s" % (exc,)

    prop_name = ir.metadata.get("property_name") or "policy_property"
    prop = invariants.Invariant(
        name=prop_name,
        description="attestation cross-check: %s" % prop_name,
        expression=ir.pinned_property,
        kind="safety",
        label=invariants.LABEL_BOUNDED,
        pinned=True,
    )
    try:
        cfg = Config(engine="crosscheck", out_dir=args.out or "out")
        if not cfg.tlc_available():
            return None, ("TLC jar + java runtime unavailable; the "
                          "three-engine cross-check was not run")
        linear_model = linearize(ir)
        verdict = CrossChecker(ir, linear_model, prop, cfg).check()
        return verdict, None
    except Exception as exc:  # noqa: BLE001
        return None, "cross-check failed: %s" % (exc,)


def cmd_attestation(args):
    """``rot attestation`` -- cross-check the corrected policy (3 engines),
    build + sign the underwriter attestation (v2), and verify it.

    Build mode:
      rot attestation --policy CORRECTED.dw [--finding-policy BUGGY.dw]
                      [--signer ID] [--key KEY.pem] [--max-inflight K]

    Verify mode:
      rot attestation --verify --attestation ATT.json
    """
    import rot.attestation as attmod

    # -- verify mode ------------------------------------------------------
    if args.verify:
        if not args.attestation:
            print("error: --verify requires --attestation FILE", file=sys.stderr)
            return EXIT_ERROR
        if not os.path.isfile(args.attestation):
            print("error: attestation file not found: %s" % args.attestation,
                  file=sys.stderr)
            return EXIT_ERROR
        with open(args.attestation, "r") as f:
            att_dict = json.load(f)
        ok, detail = attmod.verify_signature(att_dict)
        if not args.quiet:
            bar = "=" * 56
            print(bar)
            print("  ROTN attestation verification")
            print(bar)
            print("  file    : %s" % args.attestation)
            print("  result  : %s" % ("OK" if ok else "REJECTED"))
            print("  detail  : %s" % detail)
            print(bar)
        return EXIT_PROVEN if ok else EXIT_ERROR

    # -- build mode -------------------------------------------------------
    if not args.policy:
        print("error: --policy FILE is required (or use --verify)",
              file=sys.stderr)
        return EXIT_ERROR

    # 1. The subject: the corrected policy's RTF v1 trace.
    budget = _resolve_budget(args)
    correct, _code = _trace_policy(args.policy, args, budget, 12)
    if correct is None:
        return EXIT_ERROR
    correct_dict = correct.to_dict()

    # 2. The 3-engine cross-check on the corrected policy.
    crosscheck_verdict, cc_error = _run_crosscheck(args.policy, args)

    # 3. The finding (the buggy policy), when supplied.
    finding = None
    if args.finding_policy:
        if os.path.isfile(args.finding_policy):
            buggy, _bcode = _trace_policy(
                args.finding_policy, args, budget, 12)
            if buggy is not None:
                buggy_dict = buggy.to_dict()
                finding = {
                    "artifact": "buggy policy (the original)",
                    "verdict": buggy_dict.get("verdict"),
                    "counterexample": buggy_dict.get("counterexample"),
                }
                coaching = buggy_dict.get("coaching") or {}
                if coaching:
                    correct_blk = coaching.get("correct") or {}
                    finding["buggy_guard"] = correct_blk.get("buggy_guard")
                    finding["fix"] = correct_blk.get("delta")
                    finding["corrected_guard"] = correct_blk.get("guard")
                    finding["discharge"] = (
                        (coaching.get("close") or {}).get("discharge"))
        else:
            print("warning: finding policy not found: %s" % args.finding_policy,
                  file=sys.stderr)

    # 4. The signing key (if supplied).
    key_pem = None
    if args.key:
        if os.path.isfile(args.key):
            with open(args.key, "r") as f:
                key_pem = f.read()
        else:
            print("warning: key file not found: %s (degraded signature)"
                  % args.key, file=sys.stderr)

    # 5. Build the underwriter attestation (v2).
    att = attmod.build_underwriter_attestation(
        correct_dict,
        crosscheck=crosscheck_verdict,
        finding=finding,
        signer=args.signer,
        private_key_pem=key_pem)

    # 6. Write the artifacts.
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_dir = args.out or os.path.join(repo_root, "out")
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    stem = os.path.splitext(os.path.basename(args.policy))[0]
    base = os.path.join(out_dir, "attestation-%s" % stem)
    with open(base + ".json", "w") as f:
        f.write(att.to_json())
    with open(base + ".md", "w") as f:
        f.write(att.to_markdown())
    with open(base + ".html", "w") as f:
        f.write(att.to_html())

    # 7. Verify the signature we just produced.
    ok, detail = attmod.verify_signature(att.to_dict())

    if not args.quiet:
        body = att.body
        bar = "=" * 56
        print(bar)
        print("  ROTN underwriter attestation (v2)")
        print(bar)
        print("  subject   : corrected policy -- %s" % (body.get("verdict"),))
        print("  engines   : %s"
              % (", ".join(body.get("engines") or []) or "(none)"))
        if cc_error:
            print("  crosscheck: NOT RUN -- %s" % cc_error)
        sig = body.get("signature") or {}
        print("  signature : %s (degraded=%s)"
              % (sig.get("algorithm"), sig.get("degraded")))
        print("  verify    : %s -- %s" % ("OK" if ok else "REJECTED", detail))
        print("  json      : %s" % (base + ".json"))
        print("  md        : %s" % (base + ".md"))
        print("  html      : %s" % (base + ".html"))
        print(bar)
    return EXIT_PROVEN if ok else EXIT_ERROR


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
    # --depth: an optional user-set max_states bound (full-strength by default).
    p.add_argument("--depth", type=int, default=None, metavar="N",
                   help="optional max_states bound (may only lower the "
                        "full-strength budget)")
    p.add_argument("--quiet", action="store_true",
                   help="suppress the human summary")

    p = sub.add_parser(
        "ai",
        help="the AI-authored demo loop: intent -> AI policy -> ROTN "
             "verdict (Phase 4)")
    p.add_argument("--intent", default=None, metavar="FILE",
                   help="natural-language intent file "
                        "[default: samples/ai_authoring/intent.md]")
    p.add_argument("--policy", default=None, metavar="FILE",
                   help="the AI-authored policy to verify "
                        "(.rego / .dw / .ap2) "
                        "[default: samples/ai_authoring/apw2-buggy.rego]")
    p.add_argument("--out", default=None, metavar="DIR",
                   help="output dir for ai-loop-report.json")
    p.add_argument("--quiet", action="store_true",
                   help="suppress the human summary")

    p = sub.add_parser(
        "replay",
        help="re-derive a recorded attack.jsonl; --oracle dogwood replays "
             "a policy+trace against Dogwood's reference interpreter")
    p.add_argument("attack", nargs="?", default=None, metavar="ATTACK_JSONL",
                   help="attack file written by 'rot check' (omit for "
                        "--oracle dogwood / --gate)")
    p.add_argument("--policy", default=None, metavar="FILE",
                   help="policy to re-verify against "
                        "(record-only inspection without it)")
    p.add_argument("--max-inflight", type=int, default=None, metavar="K",
                   help="bounded concurrency pool K (spend-cap policies)")
    p.add_argument("--liveness-horizon", type=int, default=None, metavar="H",
                   help="bounded liveness horizon (liveness policies)")
    # Phase 3 -- reference-interpreter oracle (dogwood)
    p.add_argument("--oracle", default=None, choices=["dogwood"],
                   metavar="NAME",
                   help="run the reference interpreter as the oracle; "
                        "'dogwood' runs `dogwood replay` and records its "
                        "verdict next to ROTN's")
    p.add_argument("--gate", action="store_true",
                   help="(with --oracle dogwood) run the APW-1/2/4 gate "
                        "classes and write the side-by-side report")
    p.add_argument("--trace", default=None, metavar="FILE",
                   help="(oracle) the witness trace.log to replay")
    p.add_argument("--policy-schema", default=None, metavar="FILE",
                   help="(oracle) the Cedar schema for the policy")
    p.add_argument("--dogwood", default=None, metavar="PATH",
                   help="(oracle) path to the dogwood binary "
                        "[default: $DOGWOOD_BIN or the Phase-0 build]")
    p.add_argument("--md", default=None, metavar="PATH",
                   help="(oracle) Markdown report path "
                        "[default: <out>/reference-replay.md]")
    p.add_argument("--correct", default=None, metavar="FILE",
                   help="(oracle, single mode) the corrected policy to replay "
                        "for the side-by-side contrast")
    p.add_argument("--apw", default=None, metavar="ID",
                   help="(oracle, single mode) the APW id to label the "
                        "report row [default: custom]")
    p.add_argument("--out", default=None, metavar="DIR",
                   help="(oracle) output dir for the JSON + Markdown report "
                        "[default: <repo>/out/reference-replay]")

    p = sub.add_parser(
        "ci", help="CI gate: verdict + JUnit XML + SARIF")
    _add_policy_opts(p)
    p.add_argument("--liveness-horizon", type=int, default=None, metavar="H",
                   help="bounded liveness horizon (liveness policies)")
    p.add_argument("--out", default="ci", metavar="DIR",
                   help="artifact dir [default: ci]")

    p = sub.add_parser(
        "demo",
        help="the beachhead demo: rule -> attack -> proof -> coach -> "
             "attestation (one command)")
    p.add_argument("--beachhead", default="spendcap", choices=["spendcap"],
                   metavar="NAME",
                   help="which beachhead to demo [default: spendcap -- the "
                        "initial demo is the spend-cap (payments) "
                        "parallel-fire bug + coach; the MCP/trifecta story "
                        "ships with B2.3]")
    p.add_argument("--out", default=None, metavar="DIR",
                   help="output dir [default: <repo>/out/demo]")

    p = sub.add_parser(
        "report",
        help="the one-pager as an ATTESTATION (B3): --one-pager --trace FILE "
             "emits Markdown + HTML; --verify-trace FILE --expect HASH re-"
             "derives the trace hash (the re-verify step)")
    p.add_argument("--one-pager", action="store_true",
                   help="derive the attestation from the RTF v1 trace "
                        "(the underwriter's view)")
    p.add_argument("--trace", default=None, metavar="FILE",
                   help="the RTF v1 trace JSON (the source of truth)")
    p.add_argument("--verify-trace", default=None, metavar="FILE",
                   help="re-derive this trace's canonical body hash (the "
                        "re-verify step; the attestation's expected hash is "
                        "compared against it)")
    p.add_argument("--expect", default=None, metavar="HASH",
                   help="the expected trace hash (from the attestation's "
                        "re-verify block); a mismatch means STALE (exit 1)")
    p.add_argument("--out", default=None, metavar="DIR",
                   help="output dir for one_pager.md / one_pager.html "
                        "[default: <repo>/out/report]")
    p.add_argument("--md", default=None, metavar="PATH",
                   help="Markdown output path [default: <out>/one_pager.md]")
    p.add_argument("--html", default=None, metavar="PATH",
                   help="HTML output path [default: <out>/one_pager.html]")
    p.add_argument("--corpus-matrix", default=None, metavar="FILE",
                   help="the rot corpus matrix JSON (D4: attach the corpus "
                        "coverage metric, N of M SAFE/UNSAFE/UNKNOWN, to the "
                        "attestation)")
    p.add_argument("--quiet", action="store_true",
                   help="suppress the human summary")

    p = sub.add_parser("corpus", help="run the AWS Dogwood corpus")
    p.add_argument("--corpus-dir", default=None, metavar="DIR",
                   help="corpus dir [default: "
                        "tests/fixtures/aws_dogwood/spendcap]")
    p.add_argument("--max-inflight", type=int, default=None, metavar="K",
                   help="bounded concurrency pool K")
    p.add_argument("--out", default=None, metavar="DIR",
                   help="output dir for corpus_matrix.json")
    p.add_argument("--fetch", action="store_true",
                   help="opt-in: fetch the remaining upstream Dogwood corpus "
                        "(SHA-provenanced) before running the matrix "
                        "[needs network]")
    p.add_argument("--fetch-dry-run", action="store_true",
                   help="with --fetch: list what would be fetched, download "
                        "nothing (still needs network to list upstream)")

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
    p.add_argument("--depth", type=int, default=None, metavar="N",
                   help="optional max_states bound (may only lower the "
                        "full-strength budget)")
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
    # The runtime coach (B5): coach the *rules* from the decision ledger.
    p.add_argument("--aggregate", action="store_true",
                   help="coach the rules from the decision ledger: which "
                        "prompts/tool-descriptions cause blocks, which rules "
                        "block legitimate work, and a re-proof that any "
                        "relaxation stays safe (B5)")
    p.add_argument("--ledger", default=None, metavar="FILE",
                   help="decision ledger (JSONL or JSON) to aggregate "
                        "(required with --aggregate)")
    p.add_argument("--max-states", type=int, default=None, metavar="N",
                   help="bounded-search budget for the relaxation re-proof")
    p.add_argument("--rule", default=None, metavar="ID",
                   help="rule id for the relaxation re-proof "
                        "[default: derived from --shape]")
    p.add_argument("--quiet", action="store_true",
                   help="suppress the human summary")

    p = sub.add_parser(
        "runtime",
        help="the runtime plane (Product 2): enforce rules on live tool "
             "calls (eval / serve)")
    rt_sub = p.add_subparsers(dest="runtime_command")

    pe = rt_sub.add_parser("eval",
                           help="decide one tool call; emit the refusal JSON")
    pe.add_argument("--rule", default=None, metavar="ID",
                    help="rule id [default: spendcap_within_cap]")
    pe.add_argument("--tool", default=None, metavar="NAME",
                    help="the tool name being called (required)")
    pe.add_argument("--arg", action="append", default=None, metavar="K=V",
                    help="a tool argument (repeatable; JSON value if parseable)")
    pe.add_argument("--state", default=None, metavar="JSON",
                    help="the guard's state as a JSON object, e.g. "
                         "{\"completed\": 0, \"inflight\": 3}")
    pe.add_argument("--quiet", action="store_true",
                    help="suppress the human summary")

    pt = rt_sub.add_parser("tools",
                           help="print the tools enabled in a state (the mask)")
    pt.add_argument("--rule", default=None, metavar="ID",
                    help="rule id [default: spendcap_within_cap]")
    pt.add_argument("--state", default=None, metavar="JSON",
                    help="the guard's state as a JSON object, e.g. "
                         "{\"completed\": 0, \"inflight\": 3}")
    pt.add_argument("--json", action="store_true",
                    help="emit JSON instead of the human summary")

    ps = rt_sub.add_parser("serve",
                           help="the MCP tools/call gateway (HTTP JSON-RPC)")
    ps.add_argument("--rule", default=None, metavar="ID",
                    help="rule id [default: spendcap_within_cap]")
    ps.add_argument("--manifest", default=None, metavar="FILE",
                    help="MCP Manifest v1 JSON (first-class input: the tool "
                         "catalog this gateway governs)")
    ps.add_argument("--ledger", default=None, metavar="FILE",
                    help="decision ledger file (JSONL/JSON); appended to, "
                         "persisted on exit")
    ps.add_argument("--host", default="127.0.0.1", metavar="HOST",
                    help="bind host [default: 127.0.0.1]")
    ps.add_argument("--port", type=int, default=8765, metavar="PORT",
                    help="bind port [default: 8765]")
    ps.add_argument("--quiet", action="store_true",
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

    p = sub.add_parser(
        "attestation",
        help="cross-check the corrected policy (3 engines), build + sign the "
             "underwriter attestation (v2), and verify it")
    p.add_argument("--policy", default=None, metavar="FILE",
                   help="the CORRECTED policy to attest (the subject; "
                        "required unless --verify is given)")
    p.add_argument("--finding-policy", default=None, metavar="FILE",
                   help="the buggy policy (the finding); when given, its "
                        "violated verdict + counterexample are carried")
    p.add_argument("--signer", default=None, metavar="IDENTITY",
                   help="the signer identity (recorded in the signature "
                        "block)")
    p.add_argument("--key", default=None, metavar="FILE",
                   help="PEM private key file for the asymmetric signature "
                        "(requires the `cryptography` package)")
    p.add_argument("--max-inflight", type=int, default=None, metavar="K",
                   help="bounded concurrency pool K (spend-cap policies)")
    p.add_argument("--out", default=None, metavar="DIR",
                   help="output dir [default: <repo>/out]")
    p.add_argument("--quiet", action="store_true",
                   help="suppress the human summary")
    p.add_argument("--verify", action="store_true",
                   help="verify an EXISTING attestation file (its signature "
                        "block) instead of building one")
    p.add_argument("--attestation", default=None, metavar="FILE",
                   help="an existing attestation JSON to verify (with "
                        "--verify)")

    # RESEARCH commands: `ladder` and `ab` live in the rotn-research repo.
    # They are registered HIDDEN (absent from `rot --help`) so the product
    # build lists only product commands, yet running one still yields a clear
    # "research command, not in this build" message (exit 3) instead of an
    # opaque argparse error (the Phase A product/research boundary).
    sub.add_parser("ladder", help=argparse.SUPPRESS,
                   description=("[research] not part of the product build"))
    sub.add_parser("ab", help=argparse.SUPPRESS,
                   description=("[research] not part of the product build"))

    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return EXIT_ERROR
    return {"check": cmd_check, "ai": cmd_ai, "replay": cmd_replay,
            "ci": cmd_ci,
            "demo": cmd_demo, "corpus": cmd_corpus,
            "trace": cmd_trace,
            "report": cmd_report,
            "attestation": cmd_attestation,
            "coach": cmd_coach, "runtime": cmd_runtime,
            "site": cmd_site,
            "doctor": cmd_doctor,
            "ladder": cmd_ladder, "ab": cmd_ab}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())

