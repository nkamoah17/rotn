# -*- coding: utf-8 -*-
"""specdiff.py -- semantic spec diff between two ``ProtocolIR`` instances.

Given a *before* and an *after* :class:`rot.ir.ProtocolIR`, produce a
structured, *semantic* diff: not "which bytes changed" but *what changed and how
significant it is*. The diff answers the reviewer's real questions -- did the
protocol's *behaviour* change (a guard or effect), did its *shape* change (a new
action or variable), or was it only *cosmetic* (a rename or reordering)?

Diff elements (what to build):
  * added / removed / renamed / modified actions
  * added / removed / renamed / modified state variables
  * changed domain definitions (a variable whose domain changed)
  * init / pinned-property / assumption / channel changes
  * pure reordering of actions or variables

Severity (how significant):
  * ``SEMANTIC``   -- changes what the protocol does (a guard, an effect, the
                      initial state, a domain, an assumption, the property).
  * ``STRUCTURAL`` -- changes the shape (a new/removed action or variable, a
                      mode change, a new channel) without changing existing
                      semantics.
  * ``COSMETIC``   -- naming, ordering, or formatting only (a renamed action or
                      variable, a reordered action/variable list, a new
                      annotation).

Rename recognition is the key cosmetic detector: a variable rename (same
domain/mode, every reference consistently substituted) is reported as one
``COSMETIC`` rename element, not as a remove + an add. Action renames are
detected by structural identity of the action's guard/effects.

Pure stdlib, Python 3.6 compatible (no f-strings).
"""

from .ir import (Const, Var, BinOp, UnOp, If, AllOf, AnyOf,
                 StateVar, Channel, Action, ProtocolIR)

# ---------------------------------------------------------------------------
# severity model
# ---------------------------------------------------------------------------
NONE = "none"
COSMETIC = "cosmetic"
STRUCTURAL = "structural"
SEMANTIC = "semantic"

_RANK = {NONE: 0, COSMETIC: 1, STRUCTURAL: 2, SEMANTIC: 3}


def _rank(sev):
    return _RANK.get(sev, 0)


def _worst(a, b):
    return a if _rank(a) >= _rank(b) else b


def _max_severity(severities):
    out = NONE
    for s in severities:
        out = _worst(out, s)
    return out
# ---------------------------------------------------------------------------
# canonical, rename-aware structural serialisation
# ---------------------------------------------------------------------------
def _canon_expr(e, renames=None):
    """A rename-aware canonical form of an IR expression.

    ``renames`` maps a variable name to a substitute; ``Var`` nodes are renamed
    in place. Two expressions are structurally equal iff their canonical forms
    are ``==`` (order-sensitive, so it is a *syntactic* -- not algebraic --
    equality, which is exactly what we want for "guard changed?").
    """
    if renames is None:
        renames = {}
    if e is None:
        return None
    if isinstance(e, (str, int, float, bool)):
        # assumptions (and other IR fields) may be plain literals, not Exprs
        return ("literal", type(e).__name__, e)
    if isinstance(e, Const):
        return ("const", e.value)
    if isinstance(e, Var):
        return ("var", renames.get(e.name, e.name))
    if isinstance(e, BinOp):
        return ("bin", e.op, _canon_expr(e.left, renames), _canon_expr(e.right, renames))
    if isinstance(e, UnOp):
        return ("un", e.op, _canon_expr(e.child, renames))
    if isinstance(e, If):
        return ("if", _canon_expr(e.cond, renames),
                _canon_expr(e.then, renames), _canon_expr(e.els, renames))
    if isinstance(e, AllOf):
        return ("allof", e.var, _canon_expr(e.coll, renames), _canon_expr(e.body, renames))
    if isinstance(e, AnyOf):
        return ("anyof", e.var, _canon_expr(e.coll, renames), _canon_expr(e.body, renames))
    # Unknown node type: fall back to its own dict.
    return e.to_dict()


def _canon_effects(effects, renames=None):
    if renames is None:
        renames = {}
    return [(renames.get(a.var, a.var), _canon_expr(a.expr, renames)) for a in effects]


def _canon_action(a, renames=None):
    """Canonical form of an Action (name + owner + guard + effects + flags)."""
    if renames is None:
        renames = {}
    return (a.name, a.owner,
            _canon_expr(a.guard, renames),
            _canon_effects(a.effects, renames),
            a.linearization, a.env_free, a.is_initial, a.source)


def _action_core(a, renames=None):
    """The pure behaviour of an Action: its guard and effects.

    Two actions are *renames of each other* iff their guard/effects are
    structurally identical (name/owner/annotations are not part of behaviour,
    so a renamed action -- even one whose linearization text was touched -- is
    still recognised).
    """
    if renames is None:
        renames = {}
    return (_canon_expr(a.guard, renames), _canon_effects(a.effects, renames))


def _canon_var(v, renames=None):
    if renames is None:
        renames = {}
    return (renames.get(v.name, v.name), v.domain.to_dict(),
            v.mode, v.owner, v.desc)


def _canon_ir(ir, renames=None):
    """Canonical structural form of the *behavioural* part of an IR.

    Includes variables, actions, the init predicate and the pinned property --
    the things a variable rename can touch. Excludes name/metadata/source/
    assumptions/channels (not part of a rename).
    """
    if renames is None:
        renames = {}
    return (
        [_canon_var(v, renames) for v in ir.variables],
        [_canon_action(a, renames) for a in ir.actions],
        _canon_expr(ir.init, renames),
        _canon_expr(ir.pinned_property, renames),
    )


def _expr_equiv(e1, e2):
    return _canon_expr(e1) == _canon_expr(e2)


def _effects_equiv(e1, e2):
    return _canon_effects(e1) == _canon_effects(e2)


def _var_rename_holds(before, after, v_old, v_new):
    """True iff ``before`` and ``after`` are structurally identical except that
    the variable named ``v_old`` in ``before`` is named ``v_new`` in ``after``
    (same domain/mode/owner/desc and every reference consistently substituted).
    """
    tok = "\u0000ROT_RENAME_TOKEN\u0000"
    return (_canon_ir(before, {v_old: tok}) == _canon_ir(after, {v_new: tok}))
# ---------------------------------------------------------------------------
# diff elements
# ---------------------------------------------------------------------------
class DomainChange(object):
    """A changed domain definition on one variable."""

    def __init__(self, variable, before, after):
        self.variable = variable
        self.before = before  # Domain (or None)
        self.after = after    # Domain (or None)

    def to_dict(self):
        return {
            "variable": self.variable,
            "before": (self.before.to_dict() if self.before is not None else None),
            "after": (self.after.to_dict() if self.after is not None else None),
        }


class VariableDiff(object):
    """One variable-level diff element (added / removed / renamed / modified).

    ``kind`` is one of ``added`` / ``removed`` / ``renamed`` / ``modified``.
    ``old_name`` / ``new_name`` are set for renames and modified.
    ``domain_changed`` and ``domain_before/after`` make the "changed domain
    definitions" explicit.
    """

    KINDS = ("added", "removed", "renamed", "modified")

    def __init__(self, kind, old_name=None, new_name=None,
                 severity=None, reason="", domain_changed=False,
                 domain_before=None, domain_after=None,
                 before=None, after=None, fields=None):
        self.kind = kind
        self.old_name = old_name
        self.new_name = new_name
        self.severity = severity
        self.reason = reason
        self.domain_changed = domain_changed
        self.domain_before = domain_before
        self.domain_after = domain_after
        self.before = before  # StateVar (or None)
        self.after = after    # StateVar (or None)
        self.fields = list(fields or [])  # names of changed non-domain attributes

    def to_dict(self):
        return {
            "kind": self.kind,
            "old_name": self.old_name,
            "new_name": self.new_name,
            "severity": self.severity,
            "reason": self.reason,
            "domain_changed": self.domain_changed,
            "domain_before": (self.domain_before.to_dict()
                              if self.domain_before is not None else None),
            "domain_after": (self.domain_after.to_dict()
                             if self.domain_after is not None else None),
            "fields": self.fields,
        }


class ActionDiff(object):
    """One action-level diff element (added / removed / renamed / modified).

    ``kind`` is one of ``added`` / ``removed`` / ``renamed`` / ``modified``.
    ``guard_changed`` / ``effect_changed`` make the "guard changed? effect
    changed? both?" question explicit; ``reason`` explains which part changed.
    ``before`` / ``after`` carry the full Action so callers (e.g. the impact
    analysis) can reason about the concrete change.
    """

    KINDS = ("added", "removed", "renamed", "modified")

    def __init__(self, kind, name=None, old_name=None, severity=None,
                 reason="", guard_changed=False, effect_changed=False,
                 before=None, after=None, fields=None):
        self.kind = kind
        self.name = name
        self.old_name = old_name
        self.severity = severity
        self.reason = reason
        self.guard_changed = guard_changed
        self.effect_changed = effect_changed
        self.before = before  # Action (or None)
        self.after = after    # Action (or None)
        self.fields = list(fields or [])  # changed non-guard/effect attributes

    def to_dict(self):
        return {
            "kind": self.kind,
            "name": self.name,
            "old_name": self.old_name,
            "severity": self.severity,
            "reason": self.reason,
            "guard_changed": self.guard_changed,
            "effect_changed": self.effect_changed,
            "fields": self.fields,
        }
class ChannelDiff(object):
    """A channel added or removed between the two IRs."""

    def __init__(self, kind, name, severity, before=None, after=None):
        self.kind = kind   # added | removed
        self.name = name
        self.severity = severity
        self.before = before  # Channel (or None)
        self.after = after    # Channel (or None)

    def to_dict(self):
        return {
            "kind": self.kind,
            "name": self.name,
            "severity": self.severity,
        }


class DiffElement(object):
    """A top-level spec-diff element (a single thing that changed).

    ``kind`` is one of:
      ``action``      -- one action added/removed/renamed/modified (see ``action``)
      ``variable``    -- one variable added/removed/renamed/modified (see ``variable``)
      ``domain``      -- one domain definition changed (see ``domain``)
      ``channel``     -- one channel added/removed (see ``channel``)
      ``init``        -- the initial-state predicate changed
      ``property``    -- the pinned property changed
      ``assumption``  -- an assumption added/removed/changed (see ``expr``)
      ``ordering``    -- actions or variables reordered with no other change
    ``severity`` is one of ``SEMANTIC`` / ``STRUCTURAL`` / ``COSMETIC``.
    """

    KINDS = ("action", "variable", "domain", "channel",
             "init", "property", "assumption", "ordering")

    def __init__(self, kind, severity, reason="",
                 action=None, variable=None, domain=None, channel=None,
                 expr_changed=None, expr_before=None, expr_after=None,
                 expr=None, ordering_kind=None):
        self.kind = kind
        self.severity = severity
        self.reason = reason
        self.action = action            # ActionDiff
        self.variable = variable        # VariableDiff
        self.domain = domain            # DomainChange
        self.channel = channel          # ChannelDiff
        self.expr_changed = expr_changed
        self.expr_before = expr_before
        self.expr_after = expr_after
        self.expr = expr                # for assumption: Expr
        self.ordering_kind = ordering_kind  # 'actions' | 'variables'

    def to_dict(self):
        return {
            "kind": self.kind,
            "severity": self.severity,
            "reason": self.reason,
            "action": (self.action.to_dict() if self.action is not None else None),
            "variable": (self.variable.to_dict() if self.variable is not None else None),
            "domain": (self.domain.to_dict() if self.domain is not None else None),
            "channel": (self.channel.to_dict() if self.channel is not None else None),
            "expr_changed": self.expr_changed,
            "expr": (self.expr.to_dict() if self.expr is not None else None),
            "ordering_kind": self.ordering_kind,
        }


class SpecDiff(object):
    """The full semantic diff between a before and after ``ProtocolIR``."""

    def __init__(self, elements, before_name, after_name):
        self.elements = list(elements)
        self.before_name = before_name
        self.after_name = after_name

    @property
    def severity(self):
        return _max_severity([e.severity for e in self.elements])

    @property
    def is_empty(self):
        return len(self.elements) == 0

    @property
    def changed(self):
        return not self.is_empty

    def elements_of(self, kind):
        return [e for e in self.elements if e.kind == kind]

    def action_diffs(self):
        return [e.action for e in self.elements if e.kind == "action"]

    def variable_diffs(self):
        return [e.variable for e in self.elements if e.kind == "variable"]

    def domain_changes(self):
        return [e.domain for e in self.elements if e.kind == "domain"]

    def summary_counts(self):
        out = {NONE: 0, COSMETIC: 0, STRUCTURAL: 0, SEMANTIC: 0}
        for e in self.elements:
            out[e.severity] = out.get(e.severity, 0) + 1
        return out

    def to_dict(self):
        return {
            "before": self.before_name,
            "after": self.after_name,
            "severity": self.severity,
            "is_empty": self.is_empty,
            "elements": [e.to_dict() for e in self.elements],
        }

    def render(self):
        return render_diff(self)
# -- pretty printing ---------------------------------------------------------
_SEV_ICON = {SEMANTIC: "[SEMANTIC]", STRUCTURAL: "[STRUCTURAL]",
             COSMETIC: "[COSMETIC]"}


def _render_action(el):
    a = el.action
    if a.kind == "added":
        return "  + action %r (added) %s" % (a.name, _SEV_ICON[el.severity])
    if a.kind == "removed":
        return "  - action %r (removed) %s" % (a.name, _SEV_ICON[el.severity])
    if a.kind == "renamed":
        return "  ~ action %r -> %r (renamed) %s" % (a.old_name, a.name, _SEV_ICON[el.severity])
    return ("  ! action %r (modified: guard=%s effect=%s) %s"
            % (a.name, a.guard_changed, a.effect_changed, _SEV_ICON[el.severity]))


def _render_variable(el):
    v = el.variable
    if v.kind == "added":
        return "  + var %r (added) %s" % (v.new_name, _SEV_ICON[el.severity])
    if v.kind == "removed":
        return "  - var %r (removed) %s" % (v.old_name, _SEV_ICON[el.severity])
    if v.kind == "renamed":
        return "  ~ var %r -> %r (renamed) %s" % (v.old_name, v.new_name, _SEV_ICON[el.severity])
    if v.domain_changed:
        suffix = "domain"
    elif v.fields:
        suffix = "fields=" + ",".join(v.fields)
    else:
        suffix = ""
    return "  ! var %r (modified %s) %s" % (v.new_name, suffix, _SEV_ICON[el.severity])


def render_diff(d):
    """A human-readable rendering of a SpecDiff."""
    lines = ["spec diff: %r -> %r  (overall: %s)"
             % (d.before_name, d.after_name, d.severity.upper())]
    if d.is_empty:
        lines.append("  (no changes)")
        return "\n".join(lines)
    for e in d.elements:
        if e.kind == "action":
            lines.append(_render_action(e))
        elif e.kind == "variable":
            lines.append(_render_variable(e))
        elif e.kind == "domain":
            lines.append("  ! domain %r changed %s" % (e.domain.variable, _SEV_ICON[el.severity]))
        elif e.kind == "channel":
            lines.append("  %s channel %r %s" % ("+" if e.channel.kind == "added" else "-",
                                                e.channel.name, _SEV_ICON[el.severity]))
        elif e.kind == "init":
            lines.append("  ! init predicate changed %s" % _SEV_ICON[el.severity])
        elif e.kind == "property":
            lines.append("  ! pinned property changed %s" % _SEV_ICON[el.severity])
        elif e.kind == "assumption":
            lines.append("  %s assumption %s" % ("+" if e.expr is not None else "-",
                                                _SEV_ICON[el.severity]))
        elif e.kind == "ordering":
            lines.append("  ~ %s reordered %s" % (e.ordering_kind, _SEV_ICON[el.severity]))
    return "\n".join(lines)
# ---------------------------------------------------------------------------
# action diffing
# ---------------------------------------------------------------------------
def _classify_action_change(b, a, renames=None):
    """Classify a same-name action that differs.

    Returns (guard_changed, effect_changed, fields, severity, reason).
    Comparisons are made under the variable ``renames`` map so that a variable
    rename (references rewritten consistently) does not count as a guard/effect
    change.
    """
    renames = renames or {}
    guard_changed = _canon_expr(b.guard, renames) != _canon_expr(a.guard, renames)
    effect_changed = _canon_effects(b.effects, renames) != _canon_effects(a.effects, renames)
    fields = []
    if b.owner != a.owner:
        fields.append("owner")
    if b.linearization != a.linearization:
        fields.append("linearization")
    if b.env_free != a.env_free:
        fields.append("env_free")
    if b.is_initial != a.is_initial:
        fields.append("is_initial")
    if b.source != a.source:
        fields.append("source")

    changed = guard_changed or effect_changed or bool(fields)
    if not changed:
        return False, False, [], None, ""

    semantic = (guard_changed or effect_changed
                or "linearization" in fields
                or "env_free" in fields
                or "is_initial" in fields)
    severity = SEMANTIC if semantic else COSMETIC

    parts = []
    if guard_changed:
        parts.append("guard")
    if effect_changed:
        parts.append("effect")
    parts.extend(fields)
    return guard_changed, effect_changed, fields, severity, ",".join(parts)


def _diff_actions(before, after, renames=None):
    """Return a list of :class:`ActionDiff` covering added/removed/renamed/modified.

    ``renames`` maps renamed variable names (old -> new) so that a common
    action whose guard/effects only differ by that rename is treated as
    unchanged rather than modified.
    """
    renames = renames or {}
    bmap = {a.name: a for a in before}
    amap = {a.name: a for a in after}
    common = [n for n in bmap if n in amap]
    added = [n for n in amap if n not in bmap]
    removed = [n for n in bmap if n not in amap]

    # rename matching: pair removed -> added whose behaviour is identical
    pairs = []
    used = set()
    for rn in removed:
        core = _action_core(bmap[rn])
        for an in added:
            if an in used:
                continue
            if _action_core(amap[an]) == core:
                pairs.append((rn, an))
                used.add(an)
                break
    renamed_added = {an for _, an in pairs}
    renamed_removed = {rn for rn, _ in pairs}

    out = []
    for n in added:
        if n in renamed_added:
            continue
        out.append(ActionDiff("added", name=n, severity=STRUCTURAL,
                              reason="new action", after=amap[n]))
    for n in removed:
        if n in renamed_removed:
            continue
        out.append(ActionDiff("removed", name=n, severity=STRUCTURAL,
                              reason="action removed", before=bmap[n]))
    for rn, an in pairs:
        out.append(ActionDiff("renamed", name=an, old_name=rn, severity=COSMETIC,
                              reason="renamed %r -> %r (guard/effect unchanged)" % (rn, an),
                              before=bmap[rn], after=amap[an]))
    for n in common:
        b, a = bmap[n], amap[n]
        if _canon_action(b, renames) == _canon_action(a, renames):
            continue
        gc, ec, fields, sev, reason = _classify_action_change(b, a, renames)
        out.append(ActionDiff("modified", name=n, severity=sev,
                              reason=reason, guard_changed=gc,
                              effect_changed=ec, before=b, after=a, fields=fields))
    return out
# ---------------------------------------------------------------------------
# variable diffing
# ---------------------------------------------------------------------------
def _classify_var_change(b, a):
    """Classify a same-name variable that differs.

    Returns (domain_changed, fields, severity, reason).
    """
    domain_changed = (b.domain.to_dict() != a.domain.to_dict())
    fields = []
    if b.mode != a.mode:
        fields.append("mode")
    if b.owner != a.owner:
        fields.append("owner")
    if b.desc != a.desc:
        fields.append("desc")

    changed = domain_changed or bool(fields)
    if not changed:
        return False, [], None, ""

    if domain_changed:
        severity = SEMANTIC
    elif "mode" in fields:
        severity = STRUCTURAL
    else:
        severity = COSMETIC

    parts = []
    if domain_changed:
        parts.append("domain")
    parts.extend(fields)
    return domain_changed, fields, severity, ",".join(parts)


def _diff_variables(before, after, before_ir, after_ir):
    """Return a list of :class:`VariableDiff` covering added/removed/renamed/modified."""
    bmap = {v.name: v for v in before}
    amap = {v.name: v for v in after}
    added = [n for n in amap if n not in bmap]
    removed = [n for n in bmap if n not in amap]

    # rename matching: pair removed -> added when the whole IR is identical
    # under that single name substitution (same domain/mode/owner/desc and
    # every reference consistently rewritten).
    pairs = []
    used = set()
    for rn in removed:
        for an in added:
            if an in used:
                continue
            if (bmap[rn].domain.to_dict() == amap[an].domain.to_dict()
                    and bmap[rn].mode == amap[an].mode
                    and bmap[rn].owner == amap[an].owner
                    and _var_rename_holds(before_ir, after_ir, rn, an)):
                pairs.append((rn, an))
                used.add(an)
                break
    renamed_removed = {rn for rn, _ in pairs}

    out = []
    for n in added:
        if n in used:
            continue
        out.append(VariableDiff("added", new_name=n, severity=STRUCTURAL,
                                reason="new state variable", after=amap[n]))
    for n in removed:
        if n in renamed_removed:
            continue
        out.append(VariableDiff("removed", old_name=n, severity=STRUCTURAL,
                                reason="state variable removed", before=bmap[n]))
    for rn, an in pairs:
        out.append(VariableDiff("renamed", old_name=rn, new_name=an,
                                severity=COSMETIC,
                                reason="renamed %r -> %r (references rewritten)" % (rn, an),
                                before=bmap[rn], after=amap[an]))
    for n in bmap:
        if n not in amap:
            continue
        b, a = bmap[n], amap[n]
        if _canon_var(b) == _canon_var(a):
            continue
        domain_changed, fields, sev, reason = _classify_var_change(b, a)
        out.append(VariableDiff("modified", old_name=n, new_name=n, severity=sev,
                                reason=reason, domain_changed=domain_changed,
                                domain_before=(b.domain if domain_changed else None),
                                domain_after=(a.domain if domain_changed else None),
                                before=b, after=a, fields=fields))
    return out, dict(pairs)
# ---------------------------------------------------------------------------
# channels, predicates, ordering
# ---------------------------------------------------------------------------
def _channel_name(c):
    """Identity of a channel: its name (works for :class:`Channel` or a str)."""
    return c.name if hasattr(c, "name") else c


def _diff_channels(before, after):
    """Channels are added or removed (a channel change is structural)."""
    bmap = {_channel_name(c): c for c in before}
    amap = {_channel_name(c): c for c in after}
    out = []
    for n in amap:
        if n not in bmap:
            out.append(ChannelDiff("added", n, STRUCTURAL, after=amap[n]))
    for n in bmap:
        if n not in amap:
            out.append(ChannelDiff("removed", n, STRUCTURAL, before=bmap[n]))
    return out


def _diff_expr(before, after, label):
    """Compare two IR predicates (init / pinned property). Changed => SEMANTIC."""
    if _canon_expr(before) == _canon_expr(after):
        return None
    return ("predicate", label)


def _diff_assumptions(before, after):
    """Assumptions are an environment contract; added/removed => SEMANTIC.

    Assumptions are compared positionally (they are an ordered list). A change
    in length or any element is reported as a single SEMANTIC element.
    """
    b = [_canon_expr(a) for a in before]
    a = [_canon_expr(x) for x in after]
    if b == a:
        return None
    added = [x for x in a if x not in b]
    removed = [x for x in b if x not in a]
    if not added and not removed:
        # same set, different order -> cosmetic
        return ("reordered", before, after)
    return ("changed", before, after)


def _order_changed(before_seq, after_seq):
    """True iff the two sequences have the same elements but a different order."""
    return (sorted(before_seq) == sorted(after_seq)) and (before_seq != after_seq)


def _diff_ordering(before, after):
    """Report pure reordering of the action / variable lists (cosmetic)."""
    out = []
    bnames = [a.name for a in before.actions]
    anames = [a.name for a in after.actions]
    if _order_changed(bnames, anames):
        out.append(("actions",))
    bvars = [v.name for v in before.variables]
    avars = [v.name for v in after.variables]
    if _order_changed(bvars, avars):
        out.append(("variables",))
    return out
# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------
def compute_spec_diff(before, after):
    """Compute the semantic diff between two ``ProtocolIR`` instances.

    Returns a :class:`SpecDiff` whose elements each carry a ``kind`` (what
    changed) and a ``severity`` (how significant it is: ``SEMANTIC`` /
    ``STRUCTURAL`` / ``COSMETIC``). The overall severity is the maximum across
    all elements.

    The diff is order- and rename-aware: a variable rename (references rewritten
    consistently) is one ``COSMETIC`` element, not a remove + an add; reordering
    the action list is ``COSMETIC``; changing an action's guard or effect is
    ``SEMANTIC``; adding an action or variable is ``STRUCTURAL``.
    """
    if before is None:
        raise ValueError("compute_spec_diff: before IR is None")
    if after is None:
        raise ValueError("compute_spec_diff: after IR is None")

    elements = []

    # -- variables first: gives us the rename map actions need to be aware of -
    var_diffs, var_renames = _diff_variables(before.variables, after.variables,
                                             before, after)

    # -- actions (rename-aware) ----------------------------------------------
    for d in _diff_actions(before.actions, after.actions, var_renames):
        elements.append(DiffElement("action", d.severity, d.reason, action=d))

    # -- variables + domain definitions --------------------------------------
    for d in var_diffs:
        elements.append(DiffElement("variable", d.severity, d.reason, variable=d))
        if d.domain_changed:
            elements.append(DiffElement(
                "domain", SEMANTIC,
                "domain definition of %r changed" % (d.new_name,),
                domain=DomainChange(d.new_name, d.domain_before, d.domain_after)))

    # -- channels ------------------------------------------------------------
    for d in _diff_channels(before.channels, after.channels):
        elements.append(DiffElement("channel", d.severity,
                                    "%s channel" % (d.kind,), channel=d))

    # -- init predicate ------------------------------------------------------
    if _canon_expr(before.init) != _canon_expr(after.init):
        elements.append(DiffElement("init", SEMANTIC,
                                    "initial-state predicate changed",
                                    expr_changed=True,
                                    expr_before=before.init, expr_after=after.init))

    # -- pinned property -----------------------------------------------------
    if _canon_expr(before.pinned_property) != _canon_expr(after.pinned_property):
        elements.append(DiffElement("property", SEMANTIC,
                                    "pinned property changed",
                                    expr_changed=True,
                                    expr_before=before.pinned_property,
                                    expr_after=after.pinned_property))

    # -- assumptions ---------------------------------------------------------
    ad = _diff_assumptions(before.assumptions, after.assumptions)
    if ad is not None:
        kind = ad[0]
        if kind == "reordered":
            elements.append(DiffElement("assumption", COSMETIC,
                                        "assumptions reordered"))
        else:
            elements.append(DiffElement("assumption", SEMANTIC,
                                        "assumptions changed (environment contract)"))

    # -- pure reordering of action / variable lists --------------------------
    for (o,) in _diff_ordering(before, after):
        elements.append(DiffElement("ordering", COSMETIC,
                                    "%s reordered" % (o,), ordering_kind=o))

    return SpecDiff(elements, before.name, after.name)


# convenience alias so callers can read ``specdiff.diff(before, after)``
def diff(before, after):
    """Alias for :func:`compute_spec_diff`."""
    return compute_spec_diff(before, after)


__all__ = [
    "NONE", "COSMETIC", "STRUCTURAL", "SEMANTIC",
    "DomainChange", "VariableDiff", "ActionDiff", "ChannelDiff",
    "DiffElement", "SpecDiff",
    "compute_spec_diff", "diff", "render_diff",
]