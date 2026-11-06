# -*- coding: utf-8 -*-
"""Reference gate v2 — bidirectional conformance with Dogwood (C4 / WS4).

Spec: ``docs/reference-gate.md`` ("Reference gate v2 — bidirectional
conformance with Dogwood").

The one-sided gate in ``rot.oracle`` only checks the *violation* direction
(ROTN says VIOLATED and the reference admits it). This module adds the
missing *proof* direction and the surrounding machinery:

  * **SemanticsProfile** — the named, versioned assumptions
    (``dogwood-ref@<commit>``: reflexive windows, observe-before-decide,
    denied requests recorded in history, trace order = ingestion order).
  * **Probe set P(policy)** — the traces the gate replays (witness,
    witness-vs-correct, N sequential discriminating probes, bounded
    request/response interleavings with a fixed seed).
  * **Rules G1–G6** — violation soundness, proof soundness, decision
    agreement, non-vacuity, labeling, and "unknown is never a pass".
  * **Outcomes** — AGREE, DISAGREE-{PROVEN,VIOLATED,DECISION}, VACUOUS,
    LABELED-DIVERGENCE (waived), UNKNOWN.
  * **Waivers** — ``gate/waivers.yaml`` (owner + expiry, expired => fail,
    strict-subset parser).
  * **Report** — ``out/gate/report.{json,md}`` per the spec §6 schema.
  * **Exit codes** — ``0`` all AGREE/waived · ``1`` any DISAGREE/VACUOUS ·
    ``2`` UNKNOWN above threshold · ``3`` error.

Pure stdlib (``subprocess`` + ``re`` + ``json`` + ``datetime`` +
``hashlib``), Python 3.6 compatible. It reuses ``rot.oracle`` for binary
resolution, replay, and decision parsing, and it degrades to an honest
``UNKNOWN`` / SKIP when the ``dogwood`` binary is absent (the codebase's
engine-degradation convention: CI stays green without the toolchain, and the
CLI reports the error rather than fabricating a pass).
"""
from __future__ import print_function

import datetime
import hashlib
import json
import os
import re

import rot.oracle as oracle

# ---------------------------------------------------------------------------
# Outcomes (spec §4)
# ---------------------------------------------------------------------------
AGREE = "AGREE"
DISAGREE_PROVEN = "DISAGREE-PROVEN"
DISAGREE_VIOLATED = "DISAGREE-VIOLATED"
DISAGREE_DECISION = "DISAGREE-DECISION"
VACUOUS = "VACUOUS"
LABELED_DIVERGENCE = "LABELED-DIVERGENCE"
UNKNOWN = "UNKNOWN"

# The DISAGREE family (spec §4: these block merges unless waived).
DISAGREE_OUTCOMES = (DISAGREE_PROVEN, DISAGREE_VIOLATED, DISAGREE_DECISION)

# ---------------------------------------------------------------------------
# Exit codes (spec §5)
# ---------------------------------------------------------------------------
EXIT_OK = 0        # all AGREE or waived (LABELED-DIVERGENCE)
EXIT_DISAGREE = 1  # any DISAGREE or VACUOUS
EXIT_UNKNOWN = 2   # UNKNOWN above the configured threshold
EXIT_ERROR = 3     # error (binary missing, bad arguments, parse failure)

# ---------------------------------------------------------------------------
# The pinned reference (spec §9)
# ---------------------------------------------------------------------------
#: The full 40-char commit the gate's claims are made against.
DEFAULT_COMMIT = "4ec5e2c01b44ff3882a231ae5d315b330b38fa25"
#: The short form used in the profile name.
DEFAULT_COMMIT_SHORT = "4ec5e2c"
#: The default profile name (spec §2: ``dogwood-ref@<commit>``).
DEFAULT_PROFILE_NAME = "dogwood-ref@" + DEFAULT_COMMIT_SHORT

#: The reference engine label recorded in every verdict (spec G5).
ENGINE_LABEL = "rot-builtin-modelfinder"

#: The default fixed seed for the bounded interleaving enumeration.
DEFAULT_SEED = 20261106


# ---------------------------------------------------------------------------
# SemanticsProfile (spec §2)
# ---------------------------------------------------------------------------

class SemanticsProfile(object):
    """A named, versioned set of assumptions about the reference interpreter.

    The profile is recorded in every verdict artifact (spec G5). The default
    is ``dogwood-ref@4ec5e2c`` — Dogwood's reference interpreter at the
    pinned commit ``4ec5e2c01b44ff3882a231ae5d315b330b38fa25`` — with these
    empirically-verified assumptions:

      * **reflexive windows** — evaluation at position ``i`` reads positions
        ``j <= i`` (the current event is in its own temporal aggregate);
      * **observe-before-decide** — a request is decided, then its response
        (and any denied request) is observed into the temporal history;
      * **denied requests recorded** — a DENY decision still enters the
        reference's history (it is observed, not dropped);
      * **trace order = ingestion order** — ``@seq`` is the ingestion order.
    """

    ASSUMPTIONS = (
        "reflexive_windows",
        "observe_before_decide",
        "denied_requests_recorded",
        "trace_order_is_ingestion_order",
    )

    def __init__(self, name=DEFAULT_PROFILE_NAME, commit=DEFAULT_COMMIT,
                 assumptions=None):
        self.name = name
        self.commit = commit
        self.assumptions = tuple(
            assumptions if assumptions is not None else self.ASSUMPTIONS)

    def to_dict(self):
        """The profile as a plain dict (for the report, spec G5)."""
        return {
            "name": self.name,
            "commit": self.commit,
            "assumptions": list(self.assumptions),
        }

    def __eq__(self, other):
        return (isinstance(other, SemanticsProfile)
                and other.name == self.name
                and other.commit == self.commit)

    def __repr__(self):
        return "SemanticsProfile(name=%r, commit=%r)" % (self.name,
                                                          self.commit)


def parse_profile(spec):
    """Parse a profile spec like ``dogwood-ref@4ec5e2c`` into a profile.

    The commit may be the short or the full 40-char form. A bare
    ``dogwood-ref`` (no ``@``) defaults to the pinned commit. Anything that
    is not a string or has an ``@`` with an empty commit raises ``ValueError``
    (the gate fails closed with exit 3 rather than guessing a commit).
    """
    if spec is None:
        return SemanticsProfile()
    if not isinstance(spec, str):
        raise ValueError("profile must be a string, got %r" % (spec,))
    if "@" in spec:
        name, _, commit = spec.rpartition("@")
        if not commit:
            raise ValueError("profile %r has an empty commit" % (spec,))
        name = name or "dogwood-ref"
        return SemanticsProfile(name=name, commit=commit)
    # No '@' — a bare engine name; default to the pinned commit.
    name = spec or "dogwood-ref"
    return SemanticsProfile(name=name, commit=DEFAULT_COMMIT)


# ---------------------------------------------------------------------------
# Waivers (spec §4) — gate/waivers.yaml, strict-subset parser
# ---------------------------------------------------------------------------

#: The only keys a waiver entry may carry (CONTRIBUTING.md "Waiver rules"):
#: anything else is rejected so a waiver cannot smuggle in logic.
WAIVER_ALLOWED_KEYS = ("class", "rule", "owner", "expiry", "reason")

#: Keys every waiver entry must carry. ``reason`` is required by the spec's
#: "explain, don't delete" rule, so all five are mandatory here.
WAIVER_REQUIRED_KEYS = ("class", "rule", "owner", "expiry")

#: An ISO date is ``YYYY-MM-DD``.
_WAIVER_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class Waiver(object):
    """One labeled divergence accepted under a waiver.

    A waiver is *data, not code*: it names the class and rule it covers, the
    owner, an expiry date, and the reason. An expired waiver makes the gate
    **fail** (it cannot lapse into a pass).
    """

    def __init__(self, class_, rule, owner, expiry, reason, waiver_id=None):
        self.waiver_id = waiver_id or _waiver_id(class_, rule, owner)
        self.apw = class_  # the APW class (e.g. "APW-4"); "class" is reserved
        self.rule = rule
        self.owner = owner
        self.expiry = expiry  # a datetime.date
        self.reason = reason

    def is_expired(self, today=None):
        """True iff the waiver's expiry is strictly before ``today``."""
        if today is None:
            today = datetime.date.today()
        return self.expiry < today

    def to_dict(self):
        return {
            "id": self.waiver_id,
            "class": self.apw,
            "rule": self.rule,
            "owner": self.owner,
            "expiry": self.expiry.isoformat(),
            "reason": self.reason,
        }

    def __repr__(self):
        return ("Waiver(id=%r, class=%r, rule=%r, owner=%r, expiry=%r)"
                % (self.waiver_id, self.apw, self.rule, self.owner,
                   self.expiry))


def _waiver_id(class_, rule, owner):
    """A stable, deterministic id: ``<class>/<rule>/<owner>``."""
    return "%s/%s/%s" % (class_, rule, owner)


def _parse_expiry(text):
    """Parse a ``YYYY-MM-DD`` expiry into a ``datetime.date`` (or raise)."""
    if not _WAIVER_DATE_RE.match(text or ""):
        raise ValueError("waiver expiry %r must be YYYY-MM-DD" % (text,))
    return datetime.datetime.strptime(text, "%Y-%m-%d").date()


def parse_waivers(path):
    """Parse ``gate/waivers.yaml`` into a list of :class:`Waiver`.

    Strict-subset parser (pure stdlib, no YAML dependency): each entry starts
    with a ``- class:`` marker and is followed by indented ``key: value``
    lines. Comments (``#``) and blank lines are ignored. Any key outside
    :data:`WAIVER_ALLOWED_KEYS` raises :class:`ValueError`, and a missing
    required key raises too. An empty or missing file yields ``[]`` (no
    waivers). A malformed date or a non-dict entry raises as well — the gate
    fails closed rather than guessing.

    Returns ``(waivers, warnings)`` where ``warnings`` is a list of strings
    (e.g. an entry that is already expired at parse time).
    """
    if not path or not os.path.isfile(path):
        return [], []
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    waivers = []
    warnings = []
    current = None
    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- "):
            if current is not None:
                waivers.append(_finalize_waiver(current, warnings))
            current = {}
            stripped = stripped[2:].strip()
        if not stripped:
            continue
        if ":" not in stripped:
            raise ValueError(
                "malformed waiver line (expected 'key: value'): %r" % (line,))
        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip()
        if key not in WAIVER_ALLOWED_KEYS:
            raise ValueError(
                "waiver key %r is not allowed (allowed: %s)"
                % (key, ", ".join(WAIVER_ALLOWED_KEYS)))
        if current is None:
            raise ValueError(
                "waiver field %r appears before a '- class:' entry" % (key,))
        if key in current:
            raise ValueError("waiver key %r is repeated" % (key,))
        current[key] = value
    if current is not None:
        waivers.append(_finalize_waiver(current, warnings))
    return waivers, warnings


def _finalize_waiver(fields, warnings):
    """Validate one entry's fields and build a :class:`Waiver`."""
    for key in WAIVER_REQUIRED_KEYS:
        if key not in fields or not fields[key]:
            raise ValueError(
                "waiver entry is missing required key %r (got %r)"
                % (key, sorted(fields)))
    waiver = Waiver(
        class_=fields["class"],
        rule=fields["rule"],
        owner=fields["owner"],
        expiry=_parse_expiry(fields["expiry"]),
        reason=fields.get("reason", ""),
    )
    if waiver.is_expired():
        warnings.append(
            "waiver %s (class %s, rule %s) is EXPIRED as of today"
            % (waiver.waiver_id, waiver.apw, waiver.rule))
    return waiver


def find_waiver(waivers, class_, rule):
    """The waiver covering ``(class, rule)``, or ``None``.

    Returns the first *non-expired* waiver that matches both the class and
    the rule. An expired waiver is never returned (an expired waiver fails
    the gate; it cannot be applied).
    """
    for w in waivers:
        if w.apw == class_ and w.rule == rule and not w.is_expired():
            return w
    return None


# ---------------------------------------------------------------------------
# Per-class property metadata (the pinned invariant, spec §2)
# ---------------------------------------------------------------------------

#: For each gate class: the gated action, the policy's pinned key (field),
#: the invariant kind (sum / count / distinct), the cap, and the property name
#: (ROTN's pinned property). These let the gate evaluate the property over the
#: events the reference admitted — the "property on a trace" (spec §2).
CLASS_META = {
    "APW-1": {
        "action": "Transfer",
        "field": "amount",
        "kind": "sum",
        "cap": 200,
        "per_event": 100,
        "property": "spendcap_within_cap",
    },
    "APW-2": {
        "action": "PlaceOrder",
        "field": "cartId",
        "kind": "count",
        "cap": 1,
        "per_event": 1,
        "property": "approval_single_use",
    },
    "APW-4": {
        "action": "Send",
        "field": "recipient",
        "kind": "distinct",
        "cap": 3,
        "per_event": 1,
        "property": "distinct_within_cap",
    },
}


def property_holds(meta, admitted_events):
    """Evaluate the pinned invariant over the reference-admitted events.

    ``admitted_events`` is the list of decision events the reference ADMITTED
    (``ALLOW``), each carrying its ``action`` and pinned-key ``field`` value.
    Only the *gated action's* admitted events count toward the invariant:

      * ``sum``     — the admitted total (``sum(field)``) must be <= ``cap``;
      * ``count``   — the number of admitted gated events must be <= ``cap``;
      * ``distinct``— the number of distinct ``field`` values admitted must be
                      <= ``cap``.

    Returns a bool (True = the property holds = the invariant is *not*
    violated). Events without a parsable field value are skipped.
    """
    action = meta.get("action")
    field = meta["field"]
    kind = meta["kind"]
    cap = meta["cap"]
    gated = [e for e in admitted_events
             if e.get("action") == action and e.get(field) is not None]
    if kind == "sum":
        total = sum(e[field] for e in gated)
        return total <= cap
    if kind == "count":
        return len(gated) <= cap
    if kind == "distinct":
        return len(set(e[field] for e in gated)) <= cap
    raise ValueError("unknown property kind %r" % (kind,))


# ---------------------------------------------------------------------------
# Trace parsing (decision events = the ``::request`` lines)
# ---------------------------------------------------------------------------

#: A decision event is a ``::request`` line; ``@seq`` is its ingestion index.
_TRACE_REQ_RE = re.compile(r"@(\d+)\s+")
_TRACE_ACTION_RE = re.compile(r'Drupe::Action::"([^"]+)"::request\b')


def _extract_field(line, field):
    """Extract ``field: VALUE`` from a trace line (int if numeric, else str).

    Returns ``None`` when the field is absent (e.g. a setup event that does
    not carry the pinned key).
    """
    m = re.search(r'\b%s:\s*"?([^",}]+)"?' % re.escape(field), line)
    if not m:
        return None
    raw = m.group(1).strip()
    try:
        return int(raw)
    except ValueError:
        return raw


def trace_decision_events(trace_path, meta):
    """Parse a dogwood ``trace.log`` into its decision events (spec §2).

    The reference decides each ``::request`` event (responses are
    observation-only). Returns a list of ``{"seq", "action", <field>}`` dicts
    in ingestion order, where ``<field>`` is the class's pinned key.
    """
    with open(trace_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    field = meta["field"]
    events = []
    for line in lines:
        line = line.strip()
        if not line or "::request(" not in line:
            continue
        m = _TRACE_REQ_RE.match(line)
        if not m:
            continue
        am = _TRACE_ACTION_RE.search(line)
        events.append({
            "seq": int(m.group(1)),
            "action": am.group(1) if am else None,
            field: _extract_field(line, field),
        })
    return events


def ref_decision_by_seq(ref):
    """Map a reference replay result to ``{seq: decision}``.

    ``ref`` is the dict from ``rot.oracle.run_dogwood_replay``; its
    ``decisions`` list carries ``seq`` and ``decision`` (ALLOW / DENY).
    """
    return {d["seq"]: d["decision"] for d in ref.get("decisions", [])
            if "seq" in d}


def admitted_events(decision_events, ref):
    """The decision events the reference ADMITTED (ALLOW), in trace order."""
    by_seq = ref_decision_by_seq(ref)
    return [e for e in decision_events if by_seq.get(e["seq"]) == "ALLOW"]


# ---------------------------------------------------------------------------
# Probe set P(policy) (spec §2) — witness + bounded interleaving
# ---------------------------------------------------------------------------

def decision_events_from_lines(lines, meta):
    """Parse trace *lines* into decision events (the ``::request`` lines).

    Same shape as :func:`trace_decision_events` but operates on in-memory
    lines, so the generated interleaving probes can be evaluated without
    touching the disk.
    """
    field = meta["field"]
    events = []
    for line in lines:
        line = line.strip()
        if not line or "::request(" not in line:
            continue
        m = _TRACE_REQ_RE.match(line)
        if not m:
            continue
        am = _TRACE_ACTION_RE.search(line)
        events.append({
            "seq": int(m.group(1)),
            "action": am.group(1) if am else None,
            field: _extract_field(line, field),
        })
    return events


def concurrent_interleaving(lines, meta):
    """Reorder sequential trace lines into a **concurrent** interleaving.

    All of the gated action's requests fire *before* any of its responses
    (setup events — e.g. the APW-2 cart check — keep their order). This is the
    interleaving that exposes concurrent-replay divergences (spec §2, item 4):
    the reference decides each in-flight request against only the *settled*
    history, so N in-flight requests are all admitted, whereas a single-use or
    cap proof forbids it. Returns re-seq-numbered lines (``@0, @1, ...``).
    """
    action = meta["action"]
    setup, gated_req, gated_resp = [], [], []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if "::request(" in line:
            (gated_req if ('"%s"::request' % action) in line else setup).append(line)
        elif "::response(" in line:
            (gated_resp if ('"%s"::response' % action) in line else setup).append(line)
    reordered = setup + gated_req + gated_resp
    return [re.sub(r"^@\d+", "@%d" % i, line)
            for i, line in enumerate(reordered)]


def build_probe_set(cls, meta):
    """Build the probe set ``P`` for a gate class (spec §2).

    Returns a list of probe dicts ``{"id", "kind", "lines"}``:

      * ``witness``    — the canonical witness trace (the fixture, sequential);
      * ``concurrent`` — the same events reordered so every gated request
        precedes any gated response (the bounded interleaving, seed-fixed by
        construction so it is deterministic).

    The spec's full enumeration (N sequential discriminating probes + a
    fixed-seed interleaving sample) generalises this; for the first enabled
    run the witness + the concurrent interleaving are the discriminating
    probes that separate AGREE from DISAGREE-PROVEN.
    """
    with open(cls["trace"], "r", encoding="utf-8") as f:
        witness_lines = [l.rstrip("\n") for l in f if l.strip()]
    return [
        {"id": "witness", "kind": "witness", "lines": witness_lines},
        {"id": "concurrent", "kind": "interleaving",
         "lines": concurrent_interleaving(witness_lines, meta)},
    ]


def probe_set_sha256(probes):
    """A stable hash of the probe set (spec G5: record the probe-set hash)."""
    h = hashlib.sha256()
    for probe in probes:
        h.update(probe["id"].encode("utf-8"))
        h.update(b"\x00")
        for line in probe["lines"]:
            h.update(line.encode("utf-8"))
            h.update(b"\n")
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Rules G1-G4 (spec §3) — pure, over the reference's admitted events
# ---------------------------------------------------------------------------

def check_g1(meta, admitted):
    """G1 — violation soundness.

    ROTN reports VIOLATED with a witness. The rule holds iff the reference
    admits the gated decisions the witness relies on **and** the property is
    *false* on the reference-admitted prefix (i.e. the reference actually
    admits the violation). Otherwise: DISAGREE-VIOLATED.
    """
    reference_admitted = len(admitted) > 0
    property_false = not property_holds(meta, admitted)
    return {
        "rot_violated": True,
        "reference_admitted": reference_admitted,
        "property_false_on_admitted": property_false,
        "holds": reference_admitted and property_false,
    }


def check_g2(meta, traces):
    """G2 — proof soundness.

    ROTN reports PROVEN under its bound. The rule holds iff the property
    holds over the reference-admitted events of **every** probe trace. If any
    trace shows the reference admitting a violation, G2 fails ->
    DISAGREE-PROVEN (a false proof; critical).
    """
    holds = all(t.get("property_holds") for t in traces) if traces else False
    return {"holds": bool(holds), "traces": traces}


def check_g3(rot_decisions, ref_decisions):
    """G3 — decision agreement.

    For every decision event, ROTN's per-event decision must match the
    reference's. ``rot_decisions`` and ``ref_decisions`` are both
    ``{seq: "ALLOW"|"DENY"}`` maps. Missing (un-decided) events on either side
    are not a disagreement (the reference only decides gated actions).
    """
    rot = rot_decisions or {}
    ref = ref_decisions or {}
    mismatched = []
    for seq in sorted(set(rot) | set(ref)):
        if seq in rot and seq in ref and rot[seq] != ref[seq]:
            mismatched.append({"seq": seq, "rot": rot[seq], "ref": ref[seq]})
    return {"holds": not mismatched, "mismatched": mismatched}


def check_g4(traces, permit=True):
    """G4 — non-vacuity.

    For a permit policy the reference must both allow and deny across the probe
    set (a predicate that matches nothing is vacuous). Holds iff at least one
    decision is ALLOW and at least one is DENY. Otherwise: VACUOUS.
    """
    if not permit:
        return {"holds": True, "note": "non-permit policy; G4 not applicable"}
    admitted_any = False
    denied_any = False
    for t in traces:
        for d in t.get("reference_decisions", []):
            # ``reference_decisions`` entries are {seq, decision} records.
            decision = d.get("decision") if isinstance(d, dict) else d
            if decision == "ALLOW":
                admitted_any = True
            elif decision == "DENY":
                denied_any = True
    return {"holds": admitted_any and denied_any,
            "admitted_any": admitted_any, "denied_any": denied_any}


# ---------------------------------------------------------------------------
# Outcome determination (spec §4)
# ---------------------------------------------------------------------------

def _outcome_rank(outcome):
    order = (
        AGREE, LABELED_DIVERGENCE, UNKNOWN,
        DISAGREE_DECISION, DISAGREE_VIOLATED, VACUOUS, DISAGREE_PROVEN,
    )
    try:
        return order.index(outcome)
    except ValueError:
        return 0


def _worse_outcome(a, b):
    """The more severe of two outcomes (higher rank = worse)."""
    return a if _outcome_rank(a) >= _outcome_rank(b) else b


def determine_outcome(rules, model_verdict, permit=True, waivers=None,
                      class_=None):
    """Combine the rule results into a single outcome (spec §4).

    Precedence (worst wins): a critical DISAGREE-PROVEN dominates; then
    DISAGREE-VIOLATED / VACUOUS / DISAGREE-DECISION; then a waived divergence
    (LABELED-DIVERGENCE); then AGREE. UNKNOWN is handled by the caller (G6)
    because it is not a rule failure — it is a shape that does not lower.

    A DISAGREE on a rule covered by an *active* (non-expired) waiver is
    downgraded to LABELED-DIVERGENCE (a pass *with a warning* that names the
    waiver — never a silent PASS). An expired waiver is NOT applied (the
    divergence stays a DISAGREE and the gate fails).
    """
    waivers = waivers or []
    g1 = rules.get("G1", {})
    g2 = rules.get("G2", {})
    g3 = rules.get("G3", {})
    g4 = rules.get("G4", {})

    # Collect the failing rule(s) (only the rules that apply to this verdict).
    failed = []
    if model_verdict == "violated" and not g1.get("holds", False):
        failed.append(("G1", DISAGREE_VIOLATED))
    if model_verdict == "proven" and not g2.get("holds", False):
        failed.append(("G2", DISAGREE_PROVEN))
    if permit and not g3.get("holds", True):
        failed.append(("G3", DISAGREE_DECISION))
    if permit and not g4.get("holds", True):
        failed.append(("G4", VACUOUS))

    if not failed:
        return AGREE, None

    # Pick the worst failing rule (by outcome severity).
    failed.sort(key=lambda r: _outcome_rank(r[1]), reverse=True)
    rule, base_outcome = failed[0]

    # Apply a waiver if one covers (class, rule) and is not expired.
    waiver = find_waiver(waivers, class_, rule) if class_ else None
    if waiver is not None and base_outcome in DISAGREE_OUTCOMES:
        return LABELED_DIVERGENCE, waiver
    return base_outcome, None


# ---------------------------------------------------------------------------
# Per-class evaluation (both policy sides)
# ---------------------------------------------------------------------------

def _sha256_file(path):
    """The hex sha256 of a file (empty string if unreadable)."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except (IOError, OSError):
        return ""
    return h.hexdigest()


def _base_row(cls, meta, profile, pset_hash):
    """A fresh spec §6 report row (minimum fields).

    Non-gateable classes (APW-3/5/6) carry only ``apw``/``name``; the
    optional policy/trace keys are absent, so we default them to ``None``.
    """
    return {
        "policy": cls.get("buggy"),
        "policy_sha256": _sha256_file(cls["buggy"]) if cls.get("buggy") else None,
        "correct_policy": cls.get("correct"),
        "apw_class": cls["apw"],
        "profile": profile.to_dict(),
        "reference_commit": profile.commit,
        "engine": ENGINE_LABEL,
        "bounds": {"K": 2, "window": 4,
                   "note": "model pool bound / window (first run)"},
        "property": (meta or {}).get("property"),
        "witness": cls.get("trace"),
        "probe_set_sha256": pset_hash,
        "traces": [],
        "rules": {},
        "outcome": None,
        "waiver_id": None,
    }


def _run_probe(reference, policy_path, schema_path, probe_lines):
    """Write a probe's lines to a temp file and replay it (rot.oracle).

    ``rot.oracle.run_dogwood_replay`` reads (then rewrites) the trace file,
    so we materialise the probe first. The temp file is removed afterwards.
    """
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".log", prefix="rotn-gate-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(probe_lines) + "\n")
        return oracle.run_dogwood_replay(
            reference, policy_path, schema_path, path)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def _trace_entry(probe, admitted, ref, meta):
    """A spec §6 ``traces[]`` entry for one probe trace."""
    gated_admitted = [e for e in admitted if e.get(meta["field"]) is not None]
    return {
        "id": probe["id"],
        "kind": probe.get("kind", "witness"),
        "reference_decisions": [
            {"seq": d["seq"], "decision": d["decision"]}
            for d in ref.get("decisions", []) if "decision" in d
        ],
        "admitted_total": len(gated_admitted),
        "property_holds": property_holds(meta, admitted),
    }


def evaluate_class(cls, meta, binary, schema_path, profile, waivers):
    """Evaluate one gate class (both policy sides) against the reference.

    Returns ``(row, class_outcome)`` where ``row`` is the spec §6 report row.
    The class outcome is the *worse* of the buggy-side and correct-side
    outcomes (a single DISAGREE-PROVEN on either side blocks the class).

    Degrades to ``UNKNOWN`` (G6) when the binary is absent or a replay fails
    — an honest "not reference-interpretable", never a pass.
    """
    probes = build_probe_set(cls, meta)
    pset_hash = probe_set_sha256(probes)
    # Each class carries its own Cedar schema (oracle.gate_classes).
    schema = cls.get("schema") or schema_path
    reference = oracle.find_dogwood(binary)
    if reference is None:
        row = _base_row(cls, meta, profile, pset_hash)
        row["outcome"] = UNKNOWN
        row["note"] = ("dogwood binary not found; probes not "
                       "reference-interpretable (G6: unknown, never a pass)")
        return row, UNKNOWN

    witness = probes[0]
    witness_events = decision_events_from_lines(witness["lines"], meta)

    # Run the reference for each side on each probe.
    side_refs = {}
    for side in ("buggy", "correct"):
        policy = cls[side]
        refs = []
        for probe in probes:
            try:
                refs.append(_run_probe(
                    reference, policy, schema, probe["lines"]))
            except Exception as exc:  # one clear error (exit 3) upstream
                row = _base_row(cls, meta, profile, pset_hash)
                row["outcome"] = UNKNOWN
                row["note"] = "reference replay failed: %s" % exc
                return row, UNKNOWN
        side_refs[side] = refs

    # G1 (buggy side): violation soundness over the canonical witness.
    buggy_witness_ref = side_refs["buggy"][0]
    buggy_admitted = admitted_events(witness_events, buggy_witness_ref)
    g1 = check_g1(meta, buggy_admitted)

    # G2 (correct side): proof soundness over every probe trace.
    def _side_traces(side):
        traces = []
        for probe, ref in zip(probes, side_refs[side]):
            admitted = admitted_events(
                decision_events_from_lines(probe["lines"], meta), ref)
            traces.append(_trace_entry(probe, admitted, ref, meta))
        return traces

    buggy_traces = _side_traces("buggy")
    correct_traces = _side_traces("correct")
    g2 = check_g2(meta, correct_traces)

    # G4 (non-vacuity) is per-policy: does the reference both allow and deny
    # on each side? G3 (decision agreement) is not yet plumbed in v2 — the
    # model's per-event guard is not exposed, so it is recorded as N/A (holds)
    # rather than fabricated.
    g4_correct = check_g4(correct_traces, permit=True)
    g3 = {"holds": True, "note": "v2: per-event ROTN guard not yet plumbed"}

    # G4 (non-vacuity) constrains the *correct* side: that is the policy
    # supposed to discriminate, so "the reference never denies" there means
    # the predicate matches nothing. The buggy side is expected to be
    # permissive (it admits the violation) — flagging it VACUOUS would turn
    # the bug we detect into a gate failure (spec §7: APW-1 -> AGREE).
    buggy_rules = {"G1": g1, "G3": g3, "G4": {"holds": True}}
    correct_rules = {"G2": g2, "G3": g3, "G4": g4_correct}
    buggy_outcome, buggy_waiver = determine_outcome(
        buggy_rules, "violated", True, waivers, cls["apw"])
    correct_outcome, correct_waiver = determine_outcome(
        correct_rules, "proven", True, waivers, cls["apw"])

    class_outcome = _worse_outcome(buggy_outcome, correct_outcome)
    waiver = correct_waiver or buggy_waiver

    row = _base_row(cls, meta, profile, pset_hash)
    row["model_verdict"] = {
        "buggy": "VIOLATED",
        "correct": "PROVEN",
        "witness": cls["trace"],
    }
    # Spec §6 ``traces[]``: the proof side (G2) is the discriminating one.
    row["traces"] = correct_traces
    row["traces_buggy"] = buggy_traces
    row["rules"] = {
        "G1": {"rule": "G1", "name": "violation soundness",
               "holds": g1.get("holds", False),
               "reference_admitted": g1.get("reference_admitted"),
               "property_false_on_admitted":
                   g1.get("property_false_on_admitted")},
        "G2": {"rule": "G2", "name": "proof soundness",
               "holds": g2.get("holds", False)},
        "G3": g3,
        "G4": {"rule": "G4", "name": "non-vacuity",
               "holds": g4_correct.get("holds", False),
               "admitted_any": g4_correct.get("admitted_any"),
               "denied_any": g4_correct.get("denied_any"),
               "note": ("correct side only — the buggy side is expected "
                        "permissive (it admits the violation; see G1)")},
    }
    row["outcome"] = class_outcome
    row["waiver_id"] = waiver.waiver_id if waiver else None
    row["sides"] = {"buggy": buggy_outcome, "correct": correct_outcome}
    return row, class_outcome


# ---------------------------------------------------------------------------
# Gate orchestration (the main entry point)
# ---------------------------------------------------------------------------

def _gate_classes(repo=None):
    """The gateable + non-lowering APW classes.

    Returns ``(gateable, unknown)`` where:

    * ``gateable`` — the classes with a lowering to the reference
      (``oracle.gate_classes``: APW-1, APW-2, APW-4), joined with their
      property metadata;
    * ``unknown``  — the classes without a lowering (APW-3, APW-5, APW-6),
      reported as UNKNOWN (G6: a shape that does not lower is never a pass).
    """
    if repo is None:
        repo = oracle._repo_root()
    gateable = []
    for cls in oracle.gate_classes(repo):
        apw = cls["apw"]
        meta = CLASS_META.get(apw)
        if meta is None:
            continue
        gateable.append(dict(cls, apw=apw, meta=meta))
    # The catalog classes that do not lower to the reference interpreter
    # (APW-3's egress is data-dependent; APW-5/6 are concept / forward-looking).
    unknown = [
        {"apw": "APW-3", "name": "Taint race (\"no egress after a "
                                 "confidential read\")"},
        {"apw": "APW-5", "name": "Session splitting (cap scoped to a "
                                 "session)"},
        {"apw": "APW-6", "name": "Window-boundary burst (absolute window)"},
    ]
    return gateable, unknown


def run_bidirectional_gate(classes=None, profile=None, binary=None,
                           schema_path=None, waivers_path=None,
                           unknown_threshold=1, repo=None):
    """Run the bidirectional reference gate (spec §5) over the classes.

    Returns a dict with the spec §6 ``rows``, the per-class ``outcomes``, the
    ``unknown_count`` (and its ``unknown_threshold``), the parsed
    ``waivers``, and the computed ``exit_code`` (spec §5). ``profile`` may be
    a :class:`SemanticsProfile` or a string spec (it is parsed).

    Classes with a lowering (APW-1/2/4) are evaluated against the reference;
    classes without one (APW-3/5/6) are reported as UNKNOWN (G6).
    """
    if profile is None:
        profile = SemanticsProfile()
    elif isinstance(profile, str):
        profile = parse_profile(profile)
    if repo is None:
        repo = oracle._repo_root()
    if schema_path is None:
        # Each class carries its own Cedar schema (oracle.gate_classes); this
        # is only a fallback for callers that pass explicit classes.
        schema_path = os.path.join(
            repo, "agentcore_repro", "action.schema.json")
    if waivers_path is None:
        waivers_path = os.path.join(repo, "gate", "waivers.yaml")

    waivers, waiver_warnings = parse_waivers(waivers_path)

    rows = []
    outcomes = []
    unknown_count = 0

    if classes is None:
        gateable, unknown = _gate_classes(repo)
    else:
        gateable = [c for c in classes if CLASS_META.get(c["apw"])]
        unknown = [c for c in classes if not CLASS_META.get(c["apw"])]

    # Gateable classes: evaluated against the reference.
    for cls in gateable:
        row, outcome = evaluate_class(
            cls, CLASS_META[cls["apw"]], binary, schema_path, profile,
            waivers)
        rows.append(row)
        outcomes.append(outcome)
        if outcome == UNKNOWN:
            unknown_count += 1

    # Non-lowering classes: UNKNOWN (G6), never a pass.
    for cls in unknown:
        row = _base_row(
            cls, {"property": None, "field": None, "kind": None,
                  "cap": None, "action": None}, profile, "")
        row["property"] = None
        row["outcome"] = UNKNOWN
        row["note"] = ("no lowering to the reference interpreter; reported "
                       "UNKNOWN (G6: unknown is never a pass)")
        rows.append(row)
        outcomes.append(UNKNOWN)
        unknown_count += 1

    return {
        "profile": profile.to_dict(),
        "reference_commit": profile.commit,
        "engine": ENGINE_LABEL,
        "rows": rows,
        "outcomes": outcomes,
        "unknown_count": unknown_count,
        "unknown_threshold": unknown_threshold,
        "waivers": [w.to_dict() for w in waivers],
        "waiver_warnings": waiver_warnings,
        "exit_code": gate_exit_code(outcomes, unknown_count,
                                    unknown_threshold),
    }


def gate_exit_code(outcomes, unknown_count, unknown_threshold=1):
    """Compute the gate exit code (spec §5).

    * ``0`` — all AGREE or waived (LABELED-DIVERGENCE);
    * ``1`` — any DISAGREE or VACUOUS (merge-blocking);
    * ``2`` — UNKNOWN above the configured threshold;
    * ``3`` — reserved for errors (raised by the caller, not computed here).

    DISAGREE/VACUOUS dominate UNKNOWN (a real disagreement is worse than an
    honest "cannot interpret").
    """
    if any(o in DISAGREE_OUTCOMES for o in outcomes):
        return EXIT_DISAGREE
    if VACUOUS in outcomes:
        return EXIT_DISAGREE
    if unknown_count > unknown_threshold:
        return EXIT_UNKNOWN
    return EXIT_OK


# ---------------------------------------------------------------------------
# Report (spec §6) — out/gate/report.{json,md}
# ---------------------------------------------------------------------------

def render_markdown(result):
    """Render the gate result as a Markdown report (spec §5/§6)."""
    profile = result["profile"]
    lines = []
    lines.append("# Reference gate — bidirectional conformance report")
    lines.append("")
    lines.append("- **Profile:** `%s` (commit `%s`)"
                 % (profile["name"], result["reference_commit"]))
    lines.append("- **Engine:** %s" % result["engine"])
    lines.append("- **Spec:** `docs/reference-gate.md` (Reference gate v2)")
    lines.append("- **Exit code:** %d" % result["exit_code"])
    lines.append("")
    lines.append("| class | model | outcome | waiver |")
    lines.append("|---|---|---|---|")
    for row in result["rows"]:
        model = row.get("model_verdict") or {}
        if model.get("buggy"):
            model_cell = "%s / %s" % (model.get("buggy"), model.get("correct"))
        else:
            model_cell = "n/a (no lowering)"
        lines.append("| %s | %s | **%s** | %s |"
                     % (row.get("apw_class"), model_cell, row.get("outcome"),
                        row.get("waiver_id") or "—"))
    lines.append("")
    for row in result["rows"]:
        lines.append("## %s — %s" % (row.get("apw_class"), row.get("outcome")))
        lines.append("")
        lines.append("- property: `%s`" % (row.get("property") or "—"))
        pset = row.get("policy_sha256") or ""
        lines.append("- policy sha256: `%s…`" % (pset[:16] or "—"))
        probe = row.get("probe_set_sha256") or ""
        lines.append("- probe set: `%s…`" % (probe[:16] or "—"))
        lines.append("")
        if row.get("traces"):
            lines.append("| probe | admitted | property | reference decisions |")
            lines.append("|---|---|---|---|")
            for t in row["traces"]:
                decisions = " ".join(
                    "%s=%s" % (d["seq"], d["decision"])
                    for d in t.get("reference_decisions", []))
                lines.append("| %s | %s | %s | %s |"
                             % (t.get("id"), t.get("admitted_total"),
                                "holds" if t.get("property_holds")
                                else "VIOLATED", decisions or "—"))
            lines.append("")
        rules = row.get("rules") or {}
        if rules:
            lines.append("Rules: " + ", ".join(
                "%s %s" % (k, "PASS" if v.get("holds") else "FAIL")
                for k, v in sorted(rules.items())))
            lines.append("")
        if row.get("note"):
            lines.append("> %s" % row["note"])
            lines.append("")
        if row.get("waiver_id"):
            lines.append("> **Waived** under `%s` — LABELED-DIVERGENCE is a "
                         "pass *with a warning*, never a silent PASS."
                         % row["waiver_id"])
            lines.append("")
    lines.append("")
    lines.append("---")
    lines.append("_Generated by `rot replay --oracle dogwood --gate "
                 "--bidirectional` (`rot.gate`). A DISAGREE-PROVEN is a "
                 "false proof and is merge-blocking (critical). An expired "
                 "waiver fails the gate._")
    return "\n".join(lines) + "\n"


def write_report(result, out_dir=None):
    """Write ``out_dir/report.json`` and ``out_dir/report.md`` (spec §5).

    Returns ``(json_path, md_path)``.
    """
    out_dir = out_dir or os.path.join("out", "gate")
    try:
        os.makedirs(out_dir)
    except OSError:
        pass
    json_path = os.path.join(out_dir, "report.json")
    md_path = os.path.join(out_dir, "report.md")
    with open(json_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(result, f, indent=2, sort_keys=False)
        f.write("\n")
    with open(md_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(render_markdown(result))
    return json_path, md_path







