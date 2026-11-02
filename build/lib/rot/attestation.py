# -*- coding: utf-8 -*-
"""rot.attestation -- the one-pager as an ATTESTATION (not a summary).

The attestation is a deterministic, hashable, **re-issuable** underwriter view
derived FROM the RTF v1 trace (the source of truth). It is the tier an
underwriter actually reads: the verdict, the scope, the coverage conditions
(the assumptions, rendered as coverage), the counterexample (if any), the
SOC 2 / AIUC controls -- and, above all, the trace's SHA-256 hash plus the
EXACT re-verify command so the reader re-derives the verdict byte-for-byte.

Artifact hierarchy (stated once; the B3.3 contract)
---------------------------------------------------
    tier 1  RTF v1 trace  (caravel.rtf/v1)        source of truth (hash-pinned)
    tier 2  one-pager     (caravel.attestation/v1) underwriter view (THIS)
    tier 3  site          (site/data)             demo view (interactive)

Each tier is a pure, hashable view of the tier above it; the trace is the
source of truth. The one-pager adds **no verification logic**: it re-assembles
fields already present in the trace into the shape an underwriter reads, and
pins the trace's hash so it can be re-derived and re-checked.

Determinism
-----------
The attestation is a **pure function** of the trace dict (body + ``hash``):
no timestamps, no random IDs, stable ordering. Re-running on the same trace
yields byte-identical Markdown and HTML -- so the artifact is *re-issuable*
and a reader can pin it.

Staleness (re-issuable; stale attestation = liability)
-------------------------------------------------------
The attestation records the trace's hash (``source_trace.hash``). The
underwriter runs the re-verify command (which re-derives the trace from the
policy) and compares the re-derived hash to the recorded one. A mismatch means
the policy (or the engine) changed -- the attestation is **stale**: a
liability, never a silent re-proof. :func:`is_stale` performs that comparison.

Pure stdlib, Python 3.6 compatible.
"""

import json

import rot
import rot.trace as trace

__all__ = [
    "SCHEMA",
    "ARTIFACT_HIERARCHY",
    "DEFENSIBLE_CLAIM",
    "NOT_CLAIMED",
    "Attestation",
    "build_attestation",
    "attestation_hash",
    "verify_trace_hash",
    "is_stale",
    "reverify_command",
    "summarize_coverage",
    "render_markdown",
    "render_html",
]

#: The attestation schema tag (bump on breaking changes to the one-pager shape).
SCHEMA = "caravel.attestation/v1"

#: The artifact hierarchy -- stated ONCE (the B3.3 contract). Every tier is a
#: pure, hashable view of the tier above it; the trace is the source of truth.
ARTIFACT_HIERARCHY = [
    {
        "tier": 1,
        "artifact": "RTF v1 trace",
        "schema": "caravel.rtf/v1",
        "role": "source of truth (hash-pinned)",
    },
    {
        "tier": 2,
        "artifact": "one-pager",
        "schema": SCHEMA,
        "role": "underwriter view (this artifact; a pure function of the trace)",
    },
    {
        "tier": 3,
        "artifact": "site",
        "schema": "site/data",
        "role": "demo view (interactive; renders the same trace data)",
    },
]

#: The moat (D3) -- the defensible claim and its complement, stated ONCE.
#: The README carries the named section "Defensible claim / What we do NOT
#: claim"; every attestation footer carries this same text, so the claim
#: travels with the artifact it supports (the underwriter reads the footer,
#: not the repo).  Fixed text: deterministic, no timestamps.
DEFENSIBLE_CLAIM = (
    "ROTN does NOT claim to compile arbitrary policy text into an equivalent "
    "model.  It lowers the spend-cap policy class (aggregate-over-events + "
    "cap) to a bounded transition system by a mechanical derivation from the "
    "parsed policy -- parameterized on amount / cap / pool -- and verifies "
    "it with independent engines.  The policy<->model correspondence is "
    "CHECKED, not argued (tests/test_correspondence.py)."
)

NOT_CLAIMED = (
    "No arbitrary-policy compilation.  The lowering reads the parsed "
    "structure (the Sum node, the event reference's .kind, the '<= cap' "
    "comparison, the amount binding) and constructs the IR -- it does not "
    "interpret arbitrary policy text; policies outside the spend-cap class "
    "are not supported.  Every verdict is BOUNDED: it holds over the "
    "explored state space, not over all possible states."
)


# ---------------------------------------------------------------------------
# hashing + staleness (the re-issuable discipline)
# ---------------------------------------------------------------------------

def attestation_hash(body):
    """SHA-256 hex digest of the attestation body's canonical JSON.

    Reuses the RTF v1 canonical serialization (sorted keys, compact
    separators) so the attestation hash is computed under the *same* discipline
    as the trace hash it pins -- the two artifacts agree on what "canonical"
    means.
    """
    return trace.trace_hash(body)


def verify_trace_hash(trace_dict):
    """Recompute an RTF v1 trace's canonical body hash.

    ``trace_dict`` is the full trace (body + top-level ``hash``); the ``hash``
    field is excluded before hashing (it is the digest, not part of the body).
    Returns the SHA-256 hex digest of the body's canonical JSON -- the value
    the underwriter compares against the attestation's expected hash.
    """
    body = {k: v for k, v in trace_dict.items() if k != "hash"}
    return trace.trace_hash(body)


def is_stale(attestation_body, current_trace_dict):
    """True when the attestation is STALE relative to the current trace.

    The attestation pins the trace's hash (``source_trace.hash``). If the
    current trace re-derives to a DIFFERENT hash -- because the policy or the
    engine changed -- the attestation is stale: a liability, never a silent
    re-proof. A ``None`` recorded hash is always stale (nothing pinned).
    """
    recorded = (attestation_body.get("source_trace") or {}).get("hash")
    if recorded is None:
        return True
    return recorded != verify_trace_hash(current_trace_dict)


def reverify_command(policy_path, expected_hash):
    """The EXACT re-verify command (the B3.2 requirement).

    The underwriter runs this to re-derive the trace from the policy and check
    its hash against the attestation's expected hash. A match re-derives the
    attestation byte-for-byte; a mismatch means the policy (or engine) changed
    -- the attestation is stale. The command is a pure function of the trace's
    recorded policy path + expected hash, so it is stable across re-issues.
    """
    if policy_path:
        return ("rot trace --policy %s --out /tmp/rotn_reverify.json && "
                "rot report --verify-trace /tmp/rotn_reverify.json "
                "--expect %s" % (policy_path, expected_hash))
    return ("rot report --verify-trace <trace.json> --expect %s "
            "(re-derive the trace with `rot trace --policy <file>` first)"
            % expected_hash)


# ---------------------------------------------------------------------------
# body assembly (pure, deterministic helpers -- no verification logic)
# ---------------------------------------------------------------------------

def _version(policy_hash, rot_version, engines):
    """version = policy-hash + engine-version (the B3.2 requirement).

    The attestation's identity is pinned to BOTH the exact policy (its hash)
    and the exact engine (its version) -- so a re-issue under a different
    policy or a different engine is a *new* attestation, not a silent refresh
    of the old one. ``id`` is the compact, stable form: ``<16-hex policy> +
    <engine version>``.
    """
    ph = policy_hash or "unknown"
    return {
        "policy_hash": policy_hash,
        "engine_version": rot_version,
        "engines": list(engines or []),
        "id": "%s+%s" % (ph[:16], rot_version),
    }


def _scope(policy, verdict):
    """The scope: what this attestation covers (the property + its bounds)."""
    scope = {
        "property": policy.get("property"),
        "kind": policy.get("kind"),
    }
    for key in ("amount", "cap", "max_inflight"):
        if policy.get(key) is not None:
            scope[key] = policy[key]
    scope["verdict"] = verdict
    return scope


def _coverage_conditions(amount, cap, max_inflight, n_states, buggy):
    """The assumptions, rendered as coverage conditions (the B3.2 requirement).

    A bounded proof is only as good as its bounds. These are the explicit
    conditions under which the verdict holds -- the concrete CAP / AMOUNT, the
    bounded pool, the K-sweep bound, and the reachable state space explored --
    so a reader never reads a bounded ``PROVEN`` as an unbounded theorem.
    """
    conds = []
    if amount is not None:
        conds.append("AMOUNT = %d (per-request spend)" % amount)
    if cap is not None:
        conds.append("CAP = %d (the spend cap)" % cap)
    if max_inflight is not None:
        conds.append("bounded pool: max_inflight = %d "
                     "(the reachable state space is bounded)" % max_inflight)
    if buggy:
        conds.append("K >= 2 (a burst of parallel fires exposes the bug; "
                     "K = 1 masks it under settled-only accounting)")
    if n_states is not None:
        conds.append("reachable state space explored: n_states = %d" % n_states)
    return conds


def _out_of_scope(verdict, n_states):
    """What this attestation does NOT cover (stated, not implied)."""
    ns = n_states if n_states is not None else "unknown"
    return [
        "liveness (task completion) -- this is a SAFETY property; liveness is "
        "bounded only by the horizon",
        "other invariant kinds (approval ordering, information-flow) -- not in "
        "this trace",
        "state space beyond the reachable set explored (n_states = %s)" % ns,
    ]


def _controls(compliance):
    """The SOC 2 / AIUC controls the verdict touches (from the trace).

    Reuses the trace's ``compliance`` block (``controls_touched`` +
    ``controls`` labels) and splits the control IDs into the SOC 2 (``CC*``)
    and AIUC (``AIUC*``) families for the underwriter's view.
    """
    touched = list((compliance or {}).get("controls_touched") or [])
    labels = dict((compliance or {}).get("controls") or {})
    soc2 = [c for c in touched if c.startswith("CC")]
    aiuc = [c for c in touched if c.startswith("AIUC")]
    return {
        "soc2": soc2,
        "aiuc": aiuc,
        "labels": labels,
    }


def _bounded_caveat(n_states):
    """The bounded caveat (C4): always carried, never omitted.

    The tagline keeps the word "prove"; the attestation always carries the
    bounded caveat so a reader cannot read a bounded discharge as an unbounded
    theorem.
    """
    if n_states is not None:
        return ("This is a BOUNDED proof: it holds over the reachable state "
                "space explored (n_states = %d). It is not an unbounded "
                "theorem -- a larger pool or a longer horizon would require a "
                "re-issue of this attestation." % n_states)
    return ("This is a BOUNDED proof over the state space the engine "
            "explored. It is not an unbounded theorem -- a larger bound would "
            "require a re-issue of this attestation.")


def summarize_coverage(summary):
    """The corpus coverage metric (D4): N of M SAFE / UNSAFE / UNKNOWN.

    ``summary`` is the ``rot corpus`` summary dict (``total`` / ``proven`` /
    ``violated`` / ``out_of_scope`` / ``error`` / ``lowerable``).  The mapping
    is honest and fixed:

      SAFE      = ``proven``       (the invariant holds over the explored space)
      UNSAFE    = ``violated``     (a counterexample witness is attached)
      UNKNOWN   = ``out_of_scope`` (an honest non-discharge -- never read as SAFE)

    The metric is first-class in the demo, the attestation, and ``rot
    report``; it is expected to RISE as new invariant kinds (B2) land (more
    of the corpus becomes lowerable / discharged).
    """
    s = summary or {}
    total = int(s.get("total") or 0)
    safe = int(s.get("proven") or 0)
    unsafe = int(s.get("violated") or 0)
    unknown = int(s.get("out_of_scope") or 0)
    return {
        "total": total,
        "safe": safe,
        "unsafe": unsafe,
        "unknown": unknown,
        "lowerable": s.get("lowerable"),
        "human": "%d of %d SAFE, %d of %d UNSAFE, %d of %d UNKNOWN "
                 "(out of scope)"
                 % (safe, total, unsafe, total, unknown, total),
    }


def build_attestation(trace_dict, coverage=None):
    """Derive the attestation (one-pager) from an RTF v1 trace dict.

    A **pure function** of ``trace_dict`` (the trace body + its top-level
    ``hash``) and the optional ``coverage`` summary: the same inputs always
    yield the same attestation, and hence byte-identical Markdown and HTML.
    No verification logic is added; fields are re-assembled into the
    underwriter's view and the trace's hash is pinned for re-derivation.

    Parameters
    ----------
    trace_dict : dict
        The full RTF v1 trace (``TraceResult.to_dict()`` -- body + ``hash``).
    coverage : dict, optional
        The ``rot corpus`` summary dict (D4: the corpus coverage metric,
        N of M SAFE / UNSAFE / UNKNOWN).  When given, the attestation
        carries it first-class (``corpus_coverage``); when omitted, the
        attestation is exactly the trace-derived view (no coverage field).

    Returns
    -------
    Attestation
        The deterministic, hashable, re-issuable one-pager.
    """
    trace_hash = trace_dict.get("hash")
    if trace_hash is None:
        trace_hash = verify_trace_hash(trace_dict)
    policy = trace_dict.get("policy") or {}
    source = trace_dict.get("source") or {}
    provenance = trace_dict.get("provenance") or {}
    compliance = trace_dict.get("compliance") or {}
    verdict = trace_dict.get("verdict")
    policy_hash = source.get("hash") or provenance.get("policy_hash")
    policy_path = source.get("path")
    rot_version = trace_dict.get("rot_version") or rot.__version__
    engines = trace_dict.get("engines") or []
    n_states = provenance.get("n_states")
    amount = policy.get("amount")
    cap = policy.get("cap")
    max_inflight = policy.get("max_inflight")
    buggy = bool(policy.get("buggy"))

    body = {
        "schema": SCHEMA,
        "artifact_hierarchy": ARTIFACT_HIERARCHY,
        "verdict": verdict,
        "source_trace": {
            "schema": trace_dict.get("schema"),
            "manifest_id": trace_dict.get("manifest_id"),
            "hash": trace_hash,
        },
        "version": _version(policy_hash, rot_version, engines),
        "scope": _scope(policy, verdict),
        "coverage_conditions": _coverage_conditions(
            amount, cap, max_inflight, n_states, buggy),
        "out_of_scope": _out_of_scope(verdict, n_states),
        "counterexample": trace_dict.get("counterexample"),
        "controls": _controls(compliance),
        "bounded_caveat": _bounded_caveat(n_states),
        "claims": {
            "defensible": DEFENSIBLE_CLAIM,
            "not_claimed": NOT_CLAIMED,
        },
        "stale": False,
        "reverify": {
            "command": reverify_command(policy_path, trace_hash),
            "expected_hash": trace_hash,
        },
    }
    if coverage is not None:
        # D4: the corpus coverage metric (N of M SAFE/UNSAFE/UNKNOWN) is
        # first-class in the attestation (not a footnote).
        body["corpus_coverage"] = summarize_coverage(coverage)
    return Attestation(body)


class Attestation(object):
    """A deterministic, hashable, re-issuable underwriter view of a trace.

    Attributes
    ----------
    body : dict
        The attestation body (every field except the top-level ``hash``).
    hash : str
        The SHA-256 hex digest of the body's canonical JSON -- the one-pager's
        stable identity (so it, too, can be pinned and re-derived).
    """

    def __init__(self, body):
        self.body = body
        self.hash = attestation_hash(body)

    # -- queries -----------------------------------------------------------
    def verdict(self):
        """``"proven"`` / ``"violated"`` / ``"unknown"`` (the gate outcome)."""
        return self.body.get("verdict")

    def stale(self, current_trace_dict):
        """True when stale relative to ``current_trace_dict`` (see
        :func:`is_stale`)."""
        return is_stale(self.body, current_trace_dict)

    # -- serialisation -----------------------------------------------------
    def to_dict(self):
        """The full attestation dict (body + the top-level ``hash``)."""
        d = dict(self.body)
        d["hash"] = self.hash
        return d

    def to_json(self, indent=2):
        """Deterministic JSON (sorted keys) -- the one-pager artifact."""
        return trace.canonical_json(self.to_dict(), indent=indent)

    def to_markdown(self):
        """The one-pager as Markdown (deterministic; byte-stable)."""
        return render_markdown(self.to_dict())

    def to_html(self):
        """The one-pager as self-contained HTML (deterministic; byte-stable)."""
        return render_html(self.to_dict())

    def __repr__(self):
        return "Attestation(verdict=%s, hash=%s...)" % (
            self.body.get("verdict"), self.hash[:12])


# ---------------------------------------------------------------------------
# rendering (pure, deterministic -- the same attestation dict always yields
# the same bytes)
# ---------------------------------------------------------------------------

def _verdict_label(verdict):
    """The human verdict label (color-cued by the word, not the color)."""
    return {
        "proven": "PROVEN (SAFE)",
        "violated": "VIOLATED (UNSAFE)",
        "unknown": "UNKNOWN (NOT DISCHARGED)",
    }.get(verdict, verdict)


def _md_controls(controls):
    """The SOC 2 / AIUC controls as Markdown lines (deterministic)."""
    lines = []
    for family, key in (("SOC 2", "soc2"), ("AIUC", "aiuc")):
        ids = list((controls or {}).get(key) or [])
        if not ids:
            continue
        labelled = ", ".join(
            "`%s`%s" % (c, (" -- %s" % (controls["labels"][c]))
                        if c in (controls.get("labels") or {}) else "")
            for c in ids)
        lines.append("- %s: %s" % (family, labelled))
    if not lines:
        lines.append("- _no controls touched (the verdict is discharged)_")
    return lines


def render_markdown(att):
    """Render the attestation dict as Markdown (deterministic; byte-stable).

    ``att`` is the full attestation (``Attestation.to_dict()`` -- body +
    ``hash``). The output is a pure function of ``att``: no timestamps, no
    random IDs, stable ordering -- so re-rendering the same attestation yields
    byte-identical Markdown.
    """
    source = att.get("source_trace") or {}
    version = att.get("version") or {}
    scope = att.get("scope") or {}
    controls = att.get("controls") or {}
    reverify = att.get("reverify") or {}

    lines = []
    lines.append("# ROTN Attestation -- one-pager")
    lines.append("")
    lines.append("> **Artifact hierarchy (stated once).** RTF v1 trace = "
                 "source of truth (hash-pinned) -> one-pager = underwriter "
                 "view (this artifact) -> site = demo view.")
    lines.append("")
    lines.append("**Verdict:** %s" % _verdict_label(att.get("verdict")))
    lines.append("")
    lines.append("## Source of truth")
    lines.append("")
    lines.append("- Trace schema: `%s`" % source.get("schema"))
    lines.append("- Manifest ID: `%s`" % source.get("manifest_id"))
    lines.append("- Trace hash (SHA-256): `%s`" % source.get("hash"))
    lines.append("- Version: `%s` (policy-hash + engine-version)"
                 % version.get("id"))
    lines.append("")
    lines.append("## Scope")
    lines.append("")
    for key in ("property", "kind", "amount", "cap", "max_inflight"):
        if key in scope and scope[key] is not None:
            lines.append("- %s: %s" % (key, scope[key]))
    lines.append("")
    lines.append("## Coverage conditions (assumptions)")
    lines.append("")
    for c in att.get("coverage_conditions") or []:
        lines.append("- %s" % c)
    lines.append("")
    lines.append("## Out of scope")
    lines.append("")
    for c in att.get("out_of_scope") or []:
        lines.append("- %s" % c)
    lines.append("")
    cov = att.get("corpus_coverage")
    if cov:
        lines.append("## Corpus coverage (the beachhead corpus)")
        lines.append("")
        lines.append("**%s**" % cov.get("human"))
        lines.append("")
        lines.append("_first-class metric: it is expected to RISE as new "
                     "invariant kinds (B2) land._")
        lines.append("")
    lines.append("## Counterexample")
    lines.append("")
    ce = att.get("counterexample")
    if ce:
        lines.append("```json")
        lines.append(json.dumps(ce, sort_keys=True, indent=2,
                                default=str))
        lines.append("```")
    else:
        lines.append("_none -- the verdict holds over the explored state "
                     "space_")
    lines.append("")
    lines.append("## Controls (SOC 2 / AIUC)")
    lines.append("")
    lines.extend(_md_controls(controls))
    lines.append("")
    lines.append("## Bounded caveat")
    lines.append("")
    lines.append(att.get("bounded_caveat"))
    lines.append("")
    lines.append("## Re-verify (byte-for-byte)")
    lines.append("")
    lines.append("```bash")
    lines.append(reverify.get("command"))
    lines.append("```")
    lines.append("")
    lines.append("Expected trace hash: `%s`" % reverify.get("expected_hash"))
    lines.append("")
    claims = att.get("claims") or {}
    if claims.get("defensible") or claims.get("not_claimed"):
        lines.append("## Defensible claim / What we do NOT claim")
        lines.append("")
        lines.append("**Defensible claim.** %s" % claims.get("defensible"))
        lines.append("")
        lines.append("**What we do NOT claim.** %s" % claims.get("not_claimed"))
        lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("**Attestation hash (SHA-256):** `%s`" % att.get("hash"))
    lines.append("**Stale:** %s" % ("**YES -- policy or engine changed; "
                                    "re-issue required**"
                                    if att.get("stale") else "no"))
    lines.append("")
    return "\n".join(lines)


def _esc(s):
    """Minimal HTML escaping (deterministic; the 5 special chars)."""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))


def _html_list(items):
    """A deterministic ``<ul>`` from a list of strings."""
    if not items:
        return "<ul><li><em>none</em></li></ul>"
    lis = "\n".join("<li>%s</li>" % _esc(x) for x in items)
    return "<ul>\n%s\n</ul>" % lis


def _html_controls(controls):
    """The SOC 2 / AIUC controls as a deterministic HTML table fragment."""
    rows = []
    for family, key in (("SOC 2", "soc2"), ("AIUC", "aiuc")):
        ids = list((controls or {}).get(key) or [])
        if not ids:
            continue
        labels = (controls.get("labels") or {})
        cells = []
        for c in ids:
            lab = labels.get(c, "")
            cells.append("<tr><td><code>%s</code></td><td>%s</td></tr>"
                         % (_esc(c), _esc(lab)))
        rows.append("<tr><th>%s</th><td></td></tr>\n%s"
                    % (_esc(family), "\n".join(cells)))
    if not rows:
        return "<p><em>no controls touched (the verdict is discharged)</em></p>"
    return "<table>\n" + "\n".join(rows) + "\n</table>"


#: The one-pager HTML template (deterministic; filled by :func:`render_html`).
#: ``%(name)s`` placeholders are the attestation fields; the two ``%%`` are
#: literal percent signs in the CSS (width: 100%).
_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ROTN Attestation -- one-pager</title>
<style>
body{font:15px/1.55 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
margin:0;color:#1c1c1c;background:#fbfbfc}
main{max-width:860px;margin:0 auto;padding:32px 24px 64px}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:15px;margin:28px 0 8px;border-bottom:1px solid #e3e3e8;
padding-bottom:6px;text-transform:uppercase;letter-spacing:.04em;color:#555}
.verdict{display:inline-block;font-weight:700;color:#fff;background:%(tone)s;
padding:6px 14px;border-radius:6px;margin:10px 0 4px}
.hierarchy{font-size:13px;color:#555;background:#f0f0f4;border-left:3px solid
%(tone)s;padding:10px 14px;border-radius:4px}
table{border-collapse:collapse;width:100%%;font-size:14px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid #ececf0;
vertical-align:top}
th{color:#555;font-weight:600;white-space:nowrap}
code{font-family:ui-monospace,Consolas,"Liberation Mono",monospace;font-size:13px;
background:#f0f0f4;padding:1px 5px;border-radius:4px;word-break:break-all}
pre{background:#f4f4f7;border:1px solid #e3e3e8;border-radius:6px;padding:12px;
overflow-x:auto}
pre code{background:none;padding:0}
.stale{color:#b3261e;font-weight:600}
.fresh{color:#0a7d33}
.footer{margin-top:40px;padding-top:16px;border-top:2px solid #e3e3e8;
font-size:13px;color:#555}
</style>
</head>
<body>
<main>
<h1>ROTN Attestation -- one-pager</h1>
<div class="verdict">%(verdict)s</div>
<div class="hierarchy"><strong>Artifact hierarchy (stated once).</strong>
RTF v1 trace = source of truth (hash-pinned) &rarr; one-pager = underwriter
view (this artifact) &rarr; site = demo view.</div>
<h2>Source of truth</h2>
<table>
<tr><th>Trace schema</th><td><code>%(schema)s</code></td></tr>
<tr><th>Manifest ID</th><td><code>%(manifest_id)s</code></td></tr>
<tr><th>Trace hash (SHA-256)</th><td><code>%(trace_hash)s</code></td></tr>
<tr><th>Version</th><td><code>%(version)s</code> (policy-hash + engine-version)</td></tr>
</table>
<h2>Scope</h2>
<table>
%(scope_rows)s
</table>
<h2>Coverage conditions (assumptions)</h2>
%(coverage)s
<h2>Out of scope</h2>
%(out_of_scope)s
<h2>Corpus coverage (the beachhead corpus)</h2>
%(corpus)s
<h2>Counterexample</h2>
%(counterexample)s
<h2>Controls (SOC 2 / AIUC)</h2>
%(controls)s
<h2>Bounded caveat</h2>
<p>%(caveat)s</p>
<h2>Re-verify (byte-for-byte)</h2>
<pre><code>%(reverify_cmd)s</code></pre>
<p>Expected trace hash: <code>%(expected_hash)s</code></p>
<h2>Defensible claim / What we do NOT claim</h2>
%(claims)s
<div class="footer">
%(stale)s
<p><strong>Attestation hash (SHA-256):</strong> <code>%(att_hash)s</code></p>
</div>
</main>
</body>
</html>
"""


def render_html(att):
    """Render the attestation dict as self-contained HTML (deterministic).

    ``att`` is the full attestation (``Attestation.to_dict()`` -- body +
    ``hash``). The output is a pure function of ``att`` (no timestamps, no
    random IDs), so re-rendering the same attestation yields byte-identical
    HTML. The page is self-contained (inline CSS, no external assets).
    """
    source = att.get("source_trace") or {}
    version = att.get("version") or {}
    scope = att.get("scope") or {}
    controls = att.get("controls") or {}
    reverify = att.get("reverify") or {}
    verdict = att.get("verdict")
    tone = {"proven": "#0a7d33", "violated": "#b3261e",
            "unknown": "#8a6d00"}.get(verdict, "#333")

    scope_rows = "\n".join(
        "<tr><th>%s</th><td>%s</td></tr>" % (_esc(k), _esc(scope[k]))
        for k in ("property", "kind", "amount", "cap", "max_inflight")
        if k in scope and scope[k] is not None)

    ce = att.get("counterexample")
    if ce:
        ce_html = ("<pre><code>%s</code></pre>"
                   % _esc(json.dumps(ce, sort_keys=True, indent=2, default=str)))
    else:
        ce_html = ("<p><em>none -- the verdict holds over the explored "
                   "state space</em></p>")

    stale_html = ("<p class='stale'><strong>STALE</strong> -- policy or engine "
                  "changed; a re-issue is required.</p>"
                  if att.get("stale")
                  else "<p class='fresh'><strong>Stale:</strong> no</p>")

    cov = att.get("corpus_coverage")
    if cov:
        coverage_html = ("<p><strong>%s</strong></p>"
                         "<p><em>first-class metric: it is expected to RISE "
                         "as new invariant kinds (B2) land.</em></p>"
                         % _esc(cov.get("human")))
    else:
        coverage_html = "<p><em>no corpus coverage attached</em></p>"

    claims = att.get("claims") or {}
    claims_html = ("<p><strong>Defensible claim.</strong> %s</p>"
                   "<p><strong>What we do NOT claim.</strong> %s</p>"
                   % (_esc(claims.get("defensible") or ""),
                      _esc(claims.get("not_claimed") or "")))

    return _HTML_TEMPLATE % {
        "tone": tone,
        "verdict": _esc(_verdict_label(verdict)),
        "schema": _esc(source.get("schema")),
        "manifest_id": _esc(source.get("manifest_id")),
        "trace_hash": _esc(source.get("hash")),
        "version": _esc(version.get("id")),
        "scope_rows": scope_rows,
        "coverage": _html_list(att.get("coverage_conditions") or []),
        "corpus": coverage_html,
        "out_of_scope": _html_list(att.get("out_of_scope") or []),
        "counterexample": ce_html,
        "controls": _html_controls(controls),
        "caveat": _esc(att.get("bounded_caveat")),
        "reverify_cmd": _esc(reverify.get("command")),
        "expected_hash": _esc(reverify.get("expected_hash")),
        "claims": claims_html,
        "stale": stale_html,
        "att_hash": _esc(att.get("hash")),
    }
