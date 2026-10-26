# -*- coding: utf-8 -*-
"""design_view.py -- human-facing design views of a ``ProtocolIR``.

``ir.py`` is the *machine* view of a protocol (the canonical IR plus its
JSON form).  This module is the *human* view: the artifact a designer or
reviewer actually reads.  It provides three families of views:

JSON
    :func:`json_view` / :func:`to_json` -- a deterministic, always
    ``json.dumps``-able serialization of a whole IR.  (Raw
    ``ProtocolIR.to_dict()`` can contain ``Expr`` objects inside
    ``assumptions``; this view normalizes them to their dict form.)

Markdown
    :func:`to_markdown` -- a complete design document: overview, state
    variables, channels, per-action guards/effects, initial state, pinned
    property, assumptions, abstraction manifest and metadata.

Diff
    :func:`diff_markdown` / :func:`diff_json` / :func:`to_json_diff` -- the
    change between two IRs, built on :mod:`rot.specdiff` and tagged with the
    severity vocabulary ``SEMANTIC`` (predicate changed) / ``STRUCTURAL``
    (state space or action set changed) / ``COSMETIC`` (rename or order
    only).

Plus small rendering utilities used by the views (and handy on their own):
:func:`expr_to_str`, :func:`domain_to_str`, :func:`free_vars`.

Pure stdlib, Python 3.6 compatible (no f-strings).
"""

import json

from .ir import (Expr, Const, Var, BinOp, UnOp, If, AllOf, AnyOf,
                 ProtocolIR)
from .specdiff import (NONE, COSMETIC, STRUCTURAL, SEMANTIC,
                       compute_spec_diff)

__all__ = [
    "expr_to_str", "domain_to_str", "free_vars",
    "to_markdown", "json_view", "to_json",
    "compute_diff", "diff_markdown", "diff_json", "to_json_diff",
]

# ---------------------------------------------------------------------------
# expression rendering (TLA-flavoured ASCII)
# ---------------------------------------------------------------------------

# Precedence levels used by :func:`expr_to_str` (higher binds tighter).
# ``and``/``or`` chains are rendered flat (they are associative); every other
# operator at the *same* precedence on the right is parenthesised so that
# ``a - (b - c)`` cannot be read as ``(a - b) - c``.
_OR = 1
_AND = 2
_CMP = 3   # =  !=  <  <=  >  >=  in
_ADD = 4   # +  -
_MUL = 5   # *
_UNOP = 6  # not, neg

_PREC = {
    "or": _OR, "and": _AND,
    "=": _CMP, "!=": _CMP, "<": _CMP, "<=": _CMP, ">": _CMP, ">=": _CMP,
    "in": _CMP,
    "+": _ADD, "-": _ADD,
    "*": _MUL,
    "not": _UNOP, "neg": _UNOP,
}
_INF = 10


def _const_str(value):
    """Render a literal value TLA-style (``True``, ``42``, bare enum token)."""
    if value is True:
        return "True"
    if value is False:
        return "False"
    if value is None:
        return "UNDEF"
    if isinstance(value, str):
        # bare identifier-like tokens read like TLA enum members ("IDLE");
        # anything else is quoted so it cannot be confused with a variable.
        if value and value.isidentifier():
            return value
        return '"%s"' % value
    return str(value)


def _top_prec(e):
    """Precedence of the *outermost* operator of ``e`` (higher tighter).

    Atoms (``Const``/``Var``) return ``_INF``; structured terms (``If`` /
    ``AllOf`` / ``AnyOf``) return 0 so they are always parenthesised when
    embedded in a binary operator.
    """
    if isinstance(e, (Const, Var)):
        return _INF
    if isinstance(e, UnOp):
        return _PREC.get(e.op, _UNOP)
    if isinstance(e, BinOp):
        return _PREC.get(e.op, 0)
    return 0

def _expr_str(e, min_prec):
    """Render ``e`` with enough parentheses that its top operator binds at
    least as tightly as an operator of precedence ``min_prec``."""
    if isinstance(e, Const):
        return _const_str(e.value)
    if isinstance(e, Var):
        return e.name
    if isinstance(e, BinOp):
        p = _PREC.get(e.op, 0)
        # And()/Or() helpers nest the identity on the left ("True and x");
        # drop it so the view reads naturally.
        if e.op == "and" and isinstance(e.left, Const) and e.left.value is True:
            return _expr_str(e.right, min_prec)
        if e.op == "or" and isinstance(e.left, Const) and e.left.value is False:
            return _expr_str(e.right, min_prec)
        left = _expr_str(e.left, p)
        right = _expr_str(e.right, p)
        # A child that binds *looser* than the parent must be parenthesised
        # on either side (``(a or b) and c``, ``a and (b or c)``); on the
        # right, an equal-precedence arithmetic child must be too
        # (``a - (b - c)`` != ``(a - b) - c``).
        if _top_prec(e.left) < p:
            left = "(%s)" % left
        rp = _top_prec(e.right)
        if rp < p or (rp == p and p >= _ADD):
            right = "(%s)" % right
        return "%s %s %s" % (left, e.op, right)
    if isinstance(e, UnOp):
        body = _expr_str(e.child, _UNOP)
        # Any binary / structured child binds looser than not/neg.
        if _top_prec(e.child) < _UNOP:
            body = "(%s)" % body
        if e.op == "not":
            return "not %s" % body
        if e.op == "neg":
            return "-%s" % body
        return "%s(%s)" % (e.op, body)
    if isinstance(e, If):
        return "if %s then %s else %s" % (_expr_str(e.cond, 0),
                                          _expr_str(e.then, 0),
                                          _expr_str(e.els, 0))
    if isinstance(e, AllOf):
        return "all(%s in %s: %s)" % (e.var, _expr_str(e.coll, 0),
                                      _expr_str(e.body, 0))
    if isinstance(e, AnyOf):
        return "some(%s in %s: %s)" % (e.var, _expr_str(e.coll, 0),
                                       _expr_str(e.body, 0))
    # unknown Expr subclass: fall back to its JSON form
    return repr(e.to_dict())


def expr_to_str(expr):
    """Render an IR expression as a human-readable TLA-style string.

    Examples::

        eq(V("phase"), C("IDLE"))           ->  'phase = IDLE'
        And(V("ready"), eq(V("n"), C(0)))   ->  'ready and n = 0'
        If(c, a, b)                         ->  'if c then a else b'
        AllOf('p', coll, body)              ->  'all(p in <coll>: <body>)'

    Non-``Expr`` inputs are rendered as literals; ``None`` as ``UNDEF``.
    """
    if expr is None:
        return "UNDEF"
    if not isinstance(expr, Expr):
        return _const_str(expr)
    return _expr_str(expr, 0)


def free_vars(expr):
    """Sorted, de-duplicated list of the free variable names in ``expr``.

    Quantified variables (``AllOf``/``AnyOf``) bind their binder, so the
    binder name is *not* reported as free.
    """
    out = set()

    def _walk(e, bound):
        if e is None:
            return
        if isinstance(e, Const):
            return
        if isinstance(e, Var):
            if e.name not in bound:
                out.add(e.name)
            return
        if isinstance(e, BinOp):
            _walk(e.left, bound)
            _walk(e.right, bound)
            return
        if isinstance(e, UnOp):
            _walk(e.child, bound)
            return
        if isinstance(e, If):
            _walk(e.cond, bound)
            _walk(e.then, bound)
            _walk(e.els, bound)
            return
        if isinstance(e, (AllOf, AnyOf)):
            _walk(e.coll, bound)
            _walk(e.body, bound | {e.var})
            return

    _walk(expr, frozenset())
    return sorted(out)


def domain_to_str(domain):
    """Render a domain: ``Bool`` -> 'Bool', ``IntRange(0, 10)`` ->
    '[0 .. 10]', ``Enum(['YES', 'NO'])`` -> '{YES, NO}'."""
    if domain is None:
        return "Any"
    d = domain.to_dict()
    kind = d.get("kind")
    if kind == "bool":
        return "Bool"
    if kind == "int":
        return "[%s .. %s]" % (d.get("lo"), d.get("hi"))
    if kind == "enum":
        return "{%s}" % ", ".join(str(v) for v in d.get("values", []))
    if hasattr(domain, "to_tla"):
        return domain.to_tla()
    return str(domain)

# ---------------------------------------------------------------------------
# Markdown view
# ---------------------------------------------------------------------------


def _md(text):
    """Escape a string for use inside a Markdown table cell."""
    return str(text).replace("|", "\\|")


def _code(text):
    """Inline-code a value (backtick-fenced)."""
    return "`%s`" % str(text)


def _expr_md(expr):
    """An expression as inline code, or '_(none)_' for an empty ``True``."""
    if expr is None:
        return "_(none)_"
    if isinstance(expr, Const) and expr.value is True:
        return "_(none)_"
    return _code(expr_to_str(expr))


def _action_lines(a):
    """The ``###`` block describing one action."""
    L = []
    L.append("### %s" % _code(a.name))
    L.append("")
    bits = ["**owner:** %s" % _code(a.owner)]
    if a.is_env:
        bits.append("**environment action**")
    if a.rung is not None:
        bits.append("**rung:** %s" % a.rung)
    L.append("- " + "  ".join(bits))
    if isinstance(a.guard, Const) and a.guard.value is True:
        L.append("- **guard:** unconditional")
    else:
        L.append("- **guard:** %s" % _expr_md(a.guard))
    if a.effects:
        L.append("- **effects:**")
        for e in a.effects:
            L.append("  - %s := %s" % (_code(e.var), expr_to_str(e.expr)))
    else:
        L.append("- **effects:** _(none)_")
    if a.linearization:
        L.append("- **linearization:** %s" % _code(a.linearization))
    flags = []
    if a.env_free:
        flags.append("env-free")
    if a.is_initial:
        flags.append("initial")
    if flags:
        L.append("- **flags:** %s" % ", ".join(flags))
    if a.source:
        L.append("- **source:** %s" % _code(a.source))
    L.append("")
    return L


def _assumption_text(a):
    if isinstance(a, Expr):
        return expr_to_str(a)
    return str(a)


def to_markdown(ir, title=None):
    """Render a ``ProtocolIR`` as a complete Markdown design document.

    Sections: overview, state variables, channels, actions, initial state,
    pinned property, assumptions, (optionally) the abstraction manifest and
    metadata.  Purely presentational: no mutation of the IR, no I/O.
    """
    if not isinstance(ir, ProtocolIR):
        raise TypeError("to_markdown: expected ProtocolIR, got %s"
                        % type(ir).__name__)
    L = []
    L.append("# %s" % (title or ("Protocol: %s" % ir.name)))
    L.append("")
    if ir.source_path:
        L.append("> source: %s" % ir.source_path)
        L.append("")

    L.append("## Overview")
    L.append("")
    L.append("- **actions:** %d" % len(ir.actions))
    L.append("- **state variables:** %d" % len(ir.variables))
    L.append("- **channels:** %d" % len(ir.channels))
    if ir.assumptions:
        L.append("- **assumptions:** %d (see below)" % len(ir.assumptions))
    if ir.abstraction_manifest:
        L.append("- **abstraction manifest:** %d entries"
                 % len(ir.abstraction_manifest))
    L.append("")

    L.append("## State variables")
    L.append("")
    if ir.variables:
        L.append("| Name | Domain | Mode | Owner | Description |")
        L.append("|------|--------|------|-------|-------------|")
        for v in ir.variables:
            L.append("| %s | %s | %s | %s | %s |" % (
                _code(v.name), _code(domain_to_str(v.domain)), v.mode,
                _code(v.owner), _md(v.desc or "-")))
    else:
        L.append("_(none)_")
    L.append("")

    L.append("## Channels")
    L.append("")
    if ir.channels:
        L.append("| Name | Sender | Receiver | Description |")
        L.append("|------|--------|----------|-------------|")
        for c in ir.channels:
            L.append("| %s | %s | %s | %s |" % (
                _code(c.name), _code(c.sender), _code(c.receiver),
                _md(c.desc or "-")))
    else:
        L.append("_(none)_")
    L.append("")

    L.append("## Actions")
    L.append("")
    if ir.actions:
        for a in ir.actions:
            L.extend(_action_lines(a))
    else:
        L.append("_(none)_")
        L.append("")

    L.append("## Initial state")
    L.append("")
    if isinstance(ir.init, Const) and ir.init.value is True:
        L.append("_(unrestricted -- every state is allowed)_")
    else:
        L.append("%s" % _expr_md(ir.init))
    L.append("")

    L.append("## Pinned property")
    L.append("")
    if isinstance(ir.pinned_property, Const) and ir.pinned_property.value is True:
        L.append("_(none -- no property pinned)_")
    else:
        L.append("%s" % _expr_md(ir.pinned_property))
    L.append("")

    L.append("## Assumptions")
    L.append("")
    if ir.assumptions:
        for a in ir.assumptions:
            L.append("- %s" % _code(_assumption_text(a)))
    else:
        L.append("_(none)_")
    L.append("")

    if ir.abstraction_manifest:
        L.append("## Abstraction manifest")
        L.append("")
        L.append("| Feature | Status | Evidence | Abstraction | Risk |")
        L.append("|---------|--------|----------|-------------|------|")
        for e in ir.abstraction_manifest:
            L.append("| %s | %s | %s | %s | %s |" % (
                _md(e.feature), _md(e.status), _md(e.evidence or "-"),
                _md(e.abstraction or "-"), _md(e.risk or "-")))
        L.append("")

    if ir.metadata:
        L.append("## Metadata")
        L.append("")
        for k in sorted(ir.metadata):
            L.append("- **%s:** %s" % (_code(k), _md(ir.metadata[k])))
        L.append("")

    L.append("---")
    L.append("_generated by `rot.design_view`_")
    return "\n".join(L) + "\n"

# ---------------------------------------------------------------------------
# JSON view
# ---------------------------------------------------------------------------


def _jsonable(x):
    """Make any IR fragment JSON-serialisable (Expr -> dict, tuple -> list,
    everything else left alone)."""
    if isinstance(x, Expr):
        return x.to_dict()
    if isinstance(x, (tuple, set)):
        return [_jsonable(i) for i in x]
    if isinstance(x, list):
        return [_jsonable(i) for i in x]
    if isinstance(x, dict):
        return {k: _jsonable(v) for k, v in x.items()}
    return x


def json_view(ir):
    """A fully ``json.dumps``-able dict describing a ``ProtocolIR``.

    Same shape as ``ProtocolIR.to_dict()`` but with every ``Expr`` normalised
    to its JSON dict form and all tuples converted to lists, so the result
    round-trips cleanly through ``json.loads``.
    """
    if not isinstance(ir, ProtocolIR):
        raise TypeError("json_view: expected ProtocolIR, got %s"
                        % type(ir).__name__)
    return _jsonable(ir.to_dict())


def to_json(ir, indent=2):
    """Serialise a ``ProtocolIR`` to a pretty-printed JSON string."""
    return json.dumps(json_view(ir), indent=indent, sort_keys=True)

# ---------------------------------------------------------------------------
# diff views (built on rot.specdiff)
# ---------------------------------------------------------------------------

_SEV_BADGE = {
    SEMANTIC: "SEMANTIC",
    STRUCTURAL: "STRUCTURAL",
    COSMETIC: "COSMETIC",
    NONE: "NONE",
}


def compute_diff(before, after):
    """Compute the semantic diff between two ``ProtocolIR`` instances.

    Thin wrapper around :func:`rot.specdiff.compute_spec_diff`; the
    resulting ``SpecDiff`` carries the two IRs' own ``name`` fields as
    ``before_name``/``after_name``.
    """
    return compute_spec_diff(before, after)


def _effects_inline(effects):
    out = []
    for e in effects:
        out.append("%s := %s" % (e.var, expr_to_str(e.expr)))
    return "; ".join(out)


def _element_dict(el):
    """JSON-safe dict for one diff element.

    Superset of specdiff's ``DiffElement.to_dict``: the full ``before`` /
    ``after`` actions, variables and channels, plus the
    ``expr_before`` / ``expr_after`` predicates (which specdiff's ``to_dict``
    omits), are included and normalised to plain dicts."""
    d = {"kind": el.kind, "severity": el.severity}
    if el.reason:
        d["reason"] = el.reason
    if el.action is not None:
        a = el.action
        d["action"] = {
            "kind": a.kind,
            "name": a.name,
            "old_name": a.old_name,
            "reason": a.reason,
            "guard_changed": a.guard_changed,
            "effect_changed": a.effect_changed,
            "fields": list(a.fields),
            "before": a.before.to_dict() if a.before is not None else None,
            "after": a.after.to_dict() if a.after is not None else None,
        }
    if el.variable is not None:
        v = el.variable
        d["variable"] = {
            "kind": v.kind,
            "old_name": v.old_name,
            "new_name": v.new_name,
            "reason": v.reason,
            "domain_changed": v.domain_changed,
            "domain_before": (v.domain_before.to_dict()
                              if v.domain_before is not None else None),
            "domain_after": (v.domain_after.to_dict()
                             if v.domain_after is not None else None),
            "fields": list(v.fields),
            "before": v.before.to_dict() if v.before is not None else None,
            "after": v.after.to_dict() if v.after is not None else None,
        }
    if el.domain is not None:
        d["domain"] = el.domain.to_dict()
    if el.channel is not None:
        c = el.channel
        d["channel"] = {
            "kind": c.kind,
            "name": c.name,
            "before": c.before.to_dict() if c.before is not None else None,
            "after": c.after.to_dict() if c.after is not None else None,
        }
    if el.expr is not None:
        d["expr"] = (el.expr.to_dict()
                     if isinstance(el.expr, Expr) else el.expr)
    if el.expr_before is not None:
        d["expr_before"] = el.expr_before.to_dict()
    if el.expr_after is not None:
        d["expr_after"] = el.expr_after.to_dict()
    if el.ordering_kind is not None:
        d["ordering_kind"] = el.ordering_kind
    return d


def diff_json(diff, indent=None):
    """A fully ``json.dumps``-able dict of a ``SpecDiff`` plus per-severity
    ``counts`` (``SpecDiff.to_dict`` intentionally omits both).  Pass an
    ``indent`` to get the pretty-printed JSON string instead."""
    out = {
        "severity": diff.severity,
        "before": diff.before_name,
        "after": diff.after_name,
        "elements": [_element_dict(el) for el in diff.elements],
        "counts": diff.summary_counts(),
    }
    if indent is not None:
        return json.dumps(out, indent=indent, sort_keys=True)
    return out


def to_json_diff(diff, indent=2):
    """Pretty-printed JSON string for a ``SpecDiff`` (same content as
    :func:`diff_json`)."""
    return diff_json(diff, indent=indent)


def _element_line(el):
    """One bullet describing a diff element in Markdown."""
    if el.kind == "action" and el.action is not None:
        a = el.action
        if a.kind == "added":
            act = a.after
            line = "**added** action `%s`" % a.name
            if act is not None:
                line += " (owner `%s`)" % act.owner
                if act.is_env:
                    line += " [env]"
                if (act.guard is not None and not (isinstance(act.guard, Const)
                                                   and act.guard.value is True)):
                    line += " -- guard: `%s`" % expr_to_str(act.guard)
                if act.effects:
                    line += " -- effects: %s" % _effects_inline(act.effects)
            return line
        if a.kind == "removed":
            act = a.before
            line = "**removed** action `%s`" % a.name
            if act is not None:
                line += " (owner `%s`)" % act.owner
                if act.is_env:
                    line += " [env]"
            return line
        if a.kind == "renamed":
            return "**renamed** action `%s` -> `%s`" % (a.old_name, a.name)
        # modified
        line = "**modified** action `%s`" % a.name
        what = []
        if a.guard_changed and a.before is not None and a.after is not None:
            what.append("guard `%s` -> `%s`" % (
                expr_to_str(a.before.guard), expr_to_str(a.after.guard)))
        if a.effect_changed and a.before is not None and a.after is not None:
            before = _effects_inline(a.before.effects) or "_(none)_"
            after = _effects_inline(a.after.effects) or "_(none)_"
            what.append("effects `%s` -> `%s`" % (before, after))
        if a.fields:
            what.append("fields: %s" % ", ".join(a.fields))
        if what:
            line += " -- " + "; ".join(what)
        return line

    if el.kind == "variable" and el.variable is not None:
        v = el.variable
        if v.kind == "added":
            sv = v.after
            line = "**added** variable `%s`" % (v.new_name or v.old_name)
            if sv is not None:
                line += " -- domain `%s` (%s, %s)" % (
                    domain_to_str(sv.domain), sv.owner, sv.mode)
            return line
        if v.kind == "removed":
            sv = v.before
            line = "**removed** variable `%s`" % (v.old_name or v.new_name)
            if sv is not None:
                line += " -- domain `%s` (%s, %s)" % (
                    domain_to_str(sv.domain), sv.owner, sv.mode)
            return line
        if v.kind == "renamed":
            line = ("**renamed** variable `%s` -> `%s`"
                    % (v.old_name, v.new_name))
            if v.domain_changed:
                line += " **with domain change**"
            return line
        # modified
        line = "**modified** variable `%s`" % (v.new_name or v.old_name)
        what = []
        if (v.domain_changed and v.domain_before is not None
                and v.domain_after is not None):
            what.append("domain `%s` -> `%s`" % (
                domain_to_str(v.domain_before), domain_to_str(v.domain_after)))
        if v.fields:
            what.append("fields: %s" % ", ".join(v.fields))
        if what:
            line += " -- " + "; ".join(what)
        return line

    if el.kind == "domain" and el.domain is not None:
        d = el.domain
        line = "**modified** domain of variable `%s`" % d.variable
        if d.before is not None and d.after is not None:
            line += " -- `%s` -> `%s`" % (
                domain_to_str(d.before), domain_to_str(d.after))
        return line

    if el.kind == "channel" and el.channel is not None:
        c = el.channel
        ch = c.after if c.after is not None else c.before
        ends = ""
        if ch is not None and getattr(ch, "sender", None):
            ends = " (%s -> %s)" % (ch.sender, ch.receiver)
        return "**%s** channel `%s`%s" % (
            "added" if c.kind == "added" else "removed", c.name, ends)

    if el.kind == "assumption":
        # specdiff carries assumption changes as a reason string
        # ("assumptions reordered" / "assumptions changed (environment
        # contract)") rather than as before/after exprs.
        if el.reason:
            return "**%s**" % el.reason
        return "**modified** assumptions"

    if el.kind in ("init", "property"):
        if el.expr_before is not None and el.expr_after is not None:
            return "**modified** %s: `%s` -> `%s`" % (
                el.kind, expr_to_str(el.expr_before),
                expr_to_str(el.expr_after))
        if el.expr is not None:
            return "**changed** %s: `%s`" % (el.kind, expr_to_str(el.expr))
        return "**modified** %s" % el.kind

    if el.kind == "ordering" and el.ordering_kind:
        return "**reordered** %s" % el.ordering_kind

    return "**%s**" % el.kind


def diff_markdown(diff, before_name=None, after_name=None):
    """Render a ``SpecDiff`` as a Markdown change report.

    Sections: a severity summary, one ``###`` group per severity level
    (only non-empty ones), with one bullet per changed element.
    """
    b = before_name if before_name is not None else diff.before_name
    a = after_name if after_name is not None else diff.after_name
    L = []
    L.append("# Protocol change report")
    L.append("")
    L.append("- **before:** %s" % _code(b or "unnamed"))
    L.append("- **after:** %s" % _code(a or "unnamed"))
    L.append("- **overall severity:** **%s**" % _SEV_BADGE.get(
        diff.severity, diff.severity))
    L.append("")

    counts = diff.summary_counts()
    parts = ["%s: %d" % (k, v) for k, v in counts.items() if v]
    L.append("**counts:** %s" % (", ".join(parts) if parts else "none"))
    L.append("")

    if not diff.elements:
        L.append("_(no differences -- the two designs are identical)_")
        return "\n".join(L) + "\n"

    for sev in (SEMANTIC, STRUCTURAL, COSMETIC):
        els = [e for e in diff.elements if e.severity == sev]
        if not els:
            continue
        L.append("## %s" % _SEV_BADGE[sev])
        L.append("")
        if sev == SEMANTIC:
            L.append("_predicates changed -- verification results do not "
                     "carry over_")
        elif sev == STRUCTURAL:
            L.append("_state space or action set changed -- re-verify_")
        else:
            L.append("_naming / ordering only -- review is optional_")
        L.append("")
        for el in els:
            L.append("- %s" % _element_line(el))
        L.append("")

    L.append("---")
    L.append("_generated by `rot.design_view` from `rot.specdiff`_")
    return "\n".join(L) + "\n"

