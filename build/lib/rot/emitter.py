# -*- coding: utf-8 -*-
"""emitter.py -- emit a bounded TLA+ module + .cfg from a LinearModel.

The TLA+ engine (rot.tlc) needs a concrete .tla spec and a .cfg config. This
module is the *single* place that turns the deterministic LinearModel (the
shared linearisation from rot.linearization) into TLA+, so the symbolic engine
and the TLC engine cannot drift: both are built from the same LinearModel.

What it emits (first version -- minimal but complete for the vertical slice):
  * one ``VARIABLE`` per state variable (bounded domain from the IR),
  * ``Init`` from the init action's concrete effects,
  * one TLA+ operator per linearised action (guard /\ effects /\ UNCHANGED),
  * ``Next == \\/ action1 \/ action2 ...``,
  * ``Spec == Init /\ [][Next]_vars``,
  * the pinned invariant as a named operator (checked via ``INVARIANT`` in the
    .cfg, or ``PROPERTY`` -- see ``cfg``/``emit``).

Soundness note: this is a *bounded* model. Every domain is finite and every
action is a concrete transition, so TLC's exhaustive model check over the
reachable state space is a genuine proof (or a genuine counterexample).

Pure stdlib, Python 3.6 compatible (no f-strings).
"""

import re

from .ir import (Const, Var, BinOp, UnOp, If, AllOf, AnyOf)
from .ir import IntRange, Bool, Enum

# TLA+ reserved words we must never use as a bare identifier.
_RESERVED = set([
    "VARIABLES", "VARIABLE", "CONSTANTS", "CONSTANT", "DEFINE",
    "IF", "THEN", "ELSE", "TRUE", "FALSE", "BOOL", "STRING", "NAT",
    "Int", "REAL", "SUBSET", "SUBSEQ", "DOMAIN", "UNION", "CHOOSE",
    "EXCEPT", "RECORD", "UNCHANGED", "PROPERTY", "THEOREM", "THEOREMS",
    "LEMMAS", "LIVE", "INIT", "NEXT", "SPEC", "Init", "Next", "Spec",
    "vars", "pc",
])

# binary op -> TLA+ infix operator (in no particular precedence order).
_BINOP = {
    "and": " /\\ ",
    "or": " \\/ ",
    "=": " = ",
    "!=": " /= ",
    "<": " < ",
    "<=": " <= ",
    ">": " > ",
    ">=": " >= ",
    "+": " + ",
    "-": " - ",
    "*": " * ",
    "in": " \\in ",
}


#: IR operator names that translate to TLC operators defined in the
#: ``Integers`` module (integer arithmetic / ordering: ``+ - * < <= > >=`` and
#: unary ``neg``).  Core TLA+ and the ``TLC`` module do NOT provide these, so a
#: spec that uses any of them must import the module (``EXTENDS Integers``).
_INTEGERS_OPS = frozenset(["+", "-", "*", "<", "<=", ">", ">=", "neg"])


def _is_atomic(e):
    return isinstance(e, (Const, Var))


def _is_true_expr(e):
    return isinstance(e, Const) and e.value is True


class Emitter(object):
    """Emit bounded TLA+ (module + cfg) from a :class:`rot.linearization.LinearModel`."""

    def __init__(self, model, module_name="TwoPC"):
        self.model = model
        self.module_name = module_name
        self._var_names = list(model.var_names)
        self._action_names = [a.name for a in model.actions]
        # Reserved/op-name set for collision checks.
        self._taken = set(self._var_names) | set(self._action_names) | set(_RESERVED)
        # raw name -> sanitized TLA+ identifier (consistent + collision-free).
        self._name_map = {}
        # name -> IR domain (IntRange / Bool / Enum). Drives the per-variable
        # Apalache @type annotation emitted in the VARIABLE block.
        self._domain_by_name = {v.name: getattr(v, "domain", None)
                                for v in model.variables}

    # -- naming --------------------------------------------------------------
    def _tla_name(self, name):
        """A safe, collision-free TLA+ identifier for a variable or action.

        ROTN action names carry a ``<service>.<action>`` namespace (see
        rot.composition), and a dot is not legal in a TLA+ operator name. This
        sanitises every illegal character to ``_`` (so ``order.order_place``
        becomes ``order_order_place``), keeps the mapping consistent for a given
        input, and avoids collisions with reserved words and already-emitted
        names.
        """
        if name in self._name_map:
            return self._name_map[name]
        n = re.sub(r"[^A-Za-z0-9_]", "_", name)
        if not n or not re.match(r"^[A-Za-z_]", n):
            n = "_" + n
        if n in _RESERVED:
            n = "_" + n
        # Avoid collisions with already-emitted (sanitized) identifiers only --
        # NOT against the raw-name set, which would make every name collide with
        # itself. (Two raw names sanitising to the same token is the only real
        # risk, e.g. ``a.b`` and ``a_b`` -> both ``a_b``.)
        taken = set(self._name_map.values())
        base = n
        k = 2
        while n in taken:
            n = "%s%d" % (base, k)
            k += 1
        self._name_map[name] = n
        return n

    def _tla_type(self, name):
        """Apalache/SANY type annotation for one state variable.

        Derived from the variable's IR domain: an ``IntRange`` is ``Int``, a
        ``Bool`` domain is ``Bool``, and an ``Enum`` is the type of its
        (homogeneous) values. ROTN domains are always one of these three and
        their values are homogeneous, so a single primitive type suffices.
        ``bool`` is checked before ``int`` (bool subclasses int in Python).
        """
        domain = self._domain_by_name.get(name)
        if isinstance(domain, IntRange):
            return "Int"
        if isinstance(domain, Bool):
            return "Bool"
        if isinstance(domain, Enum):
            for val in domain.values:
                if isinstance(val, bool):
                    return "Bool"
            for val in domain.values:
                if isinstance(val, int):
                    return "Int"
            for val in domain.values:
                if isinstance(val, str):
                    return "Str"
        # Default: strings are the most common ROTN value kind (phases/votes).
        return "Str"

    def _op_name(self, name):
        """A safe TLA+ operator name for an invariant (title-cased)."""
        parts = [p for p in re.split(r"[_\-\s]+", name) if p]
        base = "".join(p[:1].upper() + p[1:] for p in parts) or "Property"
        n = base
        k = 2
        while n in self._taken or n in _RESERVED:
            n = "%s%d" % (base, k)
            k += 1
        return n

    # -- scalar / constant translation ---------------------------------------
    def _tla_str(self, s):
        out = s.replace("\\", "\\\\").replace('"', '\\"')
        return '"' + out + '"'

    def _tla_scalar(self, value):
        if value is True:
            return "TRUE"
        if value is False:
            return "FALSE"
        if isinstance(value, bool):
            return "TRUE" if value else "FALSE"
        if isinstance(value, int):
            return str(value)
        if isinstance(value, float):
            return str(value)
        if isinstance(value, str):
            return self._tla_str(value)
        if isinstance(value, (list, tuple)):
            return "{ " + ", ".join(self._tla_scalar(v) for v in value) + " }"
        if isinstance(value, dict):
            pairs = ", ".join("[%s |-> %s]" % (self._tla_scalar(k),
                                               self._tla_scalar(v))
                              for k, v in value.items())
            return "[" + pairs + "]"
        return self._tla_str(str(value))

    def _paren(self, e):
        s = self.to_tla(e)
        return s if _is_atomic(e) else "(" + s + ")"

    # -- expression -> TLA+ --------------------------------------------------
    def to_tla(self, e):
        if isinstance(e, Const):
            return self._tla_scalar(e.value)
        if isinstance(e, Var):
            return self._tla_name(e.name)
        if isinstance(e, UnOp):
            if e.op == "not":
                # ~TRUE -> FALSE, ~FALSE -> TRUE (avoid "NOT TRUE" in TLA+).
                if isinstance(e.child, Const):
                    return self._tla_scalar(not e.child.value)
                return "~" + self._paren(e.child)
            if e.op == "neg":
                return "-" + self._paren(e.child)
            raise ValueError("unknown un op %r" % (e.op,))
        if isinstance(e, BinOp):
            if e.op not in _BINOP:
                raise ValueError("unknown bin op %r" % (e.op,))
            # Drop identity elements (And folds from TRUE, Or from FALSE).
            if e.op == "and" and isinstance(e.left, Const) and e.left.value is True:
                return self.to_tla(e.right)
            if e.op == "and" and isinstance(e.right, Const) and e.right.value is True:
                return self.to_tla(e.left)
            if e.op == "or" and isinstance(e.left, Const) and e.left.value is False:
                return self.to_tla(e.right)
            if e.op == "or" and isinstance(e.right, Const) and e.right.value is False:
                return self.to_tla(e.left)
            return self._paren(e.left) + _BINOP[e.op] + self._paren(e.right)
        if isinstance(e, If):
            # The whole IF expression MUST be parenthesised: TLC's THEN/ELSE
            # branches are greedy, so an unparenthesised `IF c THEN a ELSE b`
            # followed by `/\ x' = ...` would swallow the next clause into the
            # ELSE branch, dropping assignments (see _probe/min_tlc.py).
            return ("(IF " + self._paren(e.cond)
                    + " THEN " + self._paren(e.then)
                    + " ELSE " + self._paren(e.els) + ")")
        if isinstance(e, AllOf):
            return ("\\A " + self._tla_name(e.var)
                    + " \\in " + self._paren(e.coll)
                    + " : " + self._paren(e.body))
        if isinstance(e, AnyOf):
            return ("\\E " + self._tla_name(e.var)
                    + " \\in " + self._paren(e.coll)
                    + " : " + self._paren(e.body))
        raise ValueError("cannot translate expression node %r" % (type(e),))

    # -- module emission -----------------------------------------------------
    def _action_body(self, a):
        """Emit the TLA+ operator body for one linearised action."""
        assigned = set(e.var for e in a.effects)
        unchanged = [v for v in self._var_names if v not in assigned]
        parts = []
        guard = a.guard
        if guard is not None and not _is_true_expr(guard):
            parts.append(self.to_tla(guard))
        for e in a.effects:
            parts.append("%s' = %s" % (self._tla_name(e.var), self.to_tla(e.expr)))
        if unchanged:
            parts.append("UNCHANGED << %s >>"
                         % ", ".join(self._tla_name(v) for v in unchanged))
        lines = []
        for i, p in enumerate(parts):
            sep = "  " if i == 0 else "  /\\ "
            lines.append("%s%s" % (sep, p))
        return lines

    def _model_needs_integers(self, invariant_expr):
        """Whether the emitted spec needs ``EXTENDS Integers``.

        True when any state variable has an ``IntRange`` domain (integer state)
        or any expression (init value, action guard, effect, or the invariant
        under test) uses an integer arithmetic / ordering operator. Pure-Bool /
        Str specs stay import-free.
        """
        if any(isinstance(d, IntRange) for d in self._domain_by_name.values()):
            return True
        init = self.model.init() or {}
        for e in init.values():
            if _expr_uses_integers(e):
                return True
        for a in self.model.actions:
            if a.guard is not None and _expr_uses_integers(a.guard):
                return True
            for eff in a.effects:
                if _expr_uses_integers(eff.expr):
                    return True
        if invariant_expr is not None and _expr_uses_integers(invariant_expr):
            return True
        return False

    def emit(self, invariant_name, invariant_expr):
        """Return (module_source, invariant_op_name) for the pinned invariant."""
        m = self.model
        vars_line = ", ".join(self._tla_name(v) for v in self._var_names)
        op = self._op_name(invariant_name)

        L = []
        L.append("---- MODULE %s ----" % self.module_name)
        L.append("")
        # Integer arithmetic / ordering (<=, +, ...) are defined in TLC's
        # Integers module, not in core TLA+, so import it only when the spec
        # actually uses integer state or integer operators.
        if self._model_needs_integers(invariant_expr):
            L.append("EXTENDS Integers")
            L.append("")
        # Apalache (Snowcat) requires a per-variable type annotation: a
        # `\* @type: <Type>;` line-comment placed immediately BEFORE each
        # variable name in the VARIABLE list. A single annotation for the whole
        # list, or a named payload (`phase: Str`), is rejected by this build.
        # Verified against apalache 0.62.3: `apalache typecheck` accepts the
        # form below and ENFORCES it (a string variable annotated as Int fails).
        L.append("VARIABLE")
        for i, v in enumerate(self._var_names):
            comma = "," if i < len(self._var_names) - 1 else ""
            L.append("  \\* @type: %s;" % self._tla_type(v))
            L.append("  %s%s" % (self._tla_name(v), comma))
        L.append("")

        # Init (concrete initial state from the init action's effects).
        L.append("Init ==")
        init = m.init() or {}
        if not init:
            L.append("  TRUE")
        else:
            for i, (k, e) in enumerate(init.items()):
                sep = "  " if i == 0 else "  /\\ "
                L.append("%s%s = %s" % (sep, self._tla_name(k), self.to_tla(e)))
        L.append("")

        # One operator per linearised (non-initial) action.
        for a in m.actions:
            aname = self._tla_name(a.name)
            L.append("%s ==" % aname)
            L.extend(self._action_body(a))
            L.append("")

        # A totalising self-loop ("busy"): from every state the system may also
        # just stay put (UNCHANGED). Without it, TLC reports "Error: Deadlock
        # reached." at any legitimate terminal state (e.g. the 2PC 'done' state)
        # and exits non-zero even when the invariant holds. The self-loop adds no
        # new reachable states, so it does not affect invariant checking -- it
        # only makes the transition relation total, as the docstring promises.
        busy_name = "busy"
        if busy_name in self._taken or busy_name in _RESERVED:
            busy_name = "_busy"
        L.append("%s ==" % busy_name)
        L.append("  UNCHANGED << %s >>" % vars_line)
        L.append("")

        # Next as the disjunction of all actions (plus the totalising self-loop).
        L.append("Next ==")
        anames = [self._tla_name(a.name) for a in m.actions] + [busy_name]
        for i, n in enumerate(anames):
            sep = "  " if i == 0 else "  \\/ "
            L.append("%s%s" % (sep, n))
        L.append("")

        # vars tuple + Spec.
        # Snowcat (Apalache 0.62.3) cannot infer the type of a stuttering tuple
        # whose components are ALL the same type: the tuple `<< v1, ..., vn >>`
        # matches both the n-tuple type `<< T, ..., T >>` and `Seq(T)`, so it
        # reports "Annotation required. Found 2 matching operator signatures"
        # and "Error when computing the type of vars". Pinning the operator with
        # an explicit tuple-type annotation disambiguates it and makes both
        # `apalache typecheck` and `apalache check` succeed. (Inlined-tuple and
        # no-annotation variants both fail; the annotated `vars` form is the one
        # that passes -- verified locally against this exact build.)
        L.append("\\* @type: << %s >>;"
                 % ", ".join(self._tla_type(v) for v in self._var_names))
        L.append("vars == << %s >>" % vars_line)
        L.append("")
        L.append("Spec ==")
        L.append("  Init")
        L.append("  /\\ [][Next]_vars")
        L.append("")

        # The pinned invariant as a named operator.
        L.append("%s ==" % op)
        L.append("  %s" % self.to_tla(invariant_expr))
        L.append("")
        # Module terminator. THIS TLC/SANY build tokenises a run of '-' as the
        # minus operator (so '----' here is a parse error: "expecting ==== or
        # more Module body"), and instead expects the module-end token to be a
        # run of '='. Verified empirically against this exact tla2tools.jar:
        # a '====' terminator parses and checks; '----' does not. (The header
        # on the first line still uses dashes, which this build accepts.)
        L.append("====")
        return "\n".join(L) + "\n", op

    def cfg(self, invariant_op_name):
        """A .cfg referencing SPECIFICATION (Spec) and the invariant.

        No leading blank line (TLC rejects it). References both ``Spec`` and the
        invariant operator so the model check is explicit and auditable.
        """
        return ("SPECIFICATION Spec\n"
                "INVARIANT %s\n" % invariant_op_name)

    def write(self, out_dir, invariant_name, invariant_expr,
              base=None):
        """Write <base>.tla and <base>.cfg into out_dir; return (tla, cfg, op)."""
        import os
        # THIS TLC/SANY build requires the file base name to equal the top-level
        # module name ("File name ... does not match the name ... of the top
        # level module it contains"), so default base to the module name.
        base = base or self.module_name
        if out_dir and not os.path.isdir(out_dir):
            os.makedirs(out_dir)
        prefix = os.path.join(out_dir, base) if out_dir else base
        src, op = self.emit(invariant_name, invariant_expr)
        tla_path = prefix + ".tla"
        cfg_path = prefix + ".cfg"
        with open(tla_path, "w") as f:
            f.write(src)
        with open(cfg_path, "w") as f:
            f.write(self.cfg(op))
        return tla_path, cfg_path, op


def _expr_uses_integers(e):
    """True if an IR expression tree uses any operator that lives in TLC's
    ``Integers`` module (integer arithmetic / ordering)."""
    if isinstance(e, BinOp):
        return (e.op in _INTEGERS_OPS
                or _expr_uses_integers(e.left)
                or _expr_uses_integers(e.right))
    if isinstance(e, UnOp):
        return e.op in _INTEGERS_OPS or _expr_uses_integers(e.child)
    if isinstance(e, If):
        return (_expr_uses_integers(e.cond)
                or _expr_uses_integers(e.then)
                or _expr_uses_integers(e.els))
    if isinstance(e, (AllOf, AnyOf)):
        return _expr_uses_integers(e.coll) or _expr_uses_integers(e.body)
    return False


def _expr_free_vars(expr):
    """Free variable names referenced anywhere in an IR expression tree."""
    out = set()

    def walk(e):
        if e is None:
            return
        if isinstance(e, Var):
            out.add(e.name)
        elif isinstance(e, BinOp):
            walk(e.left); walk(e.right)
        elif isinstance(e, UnOp):
            walk(e.child)
        elif isinstance(e, If):
            walk(e.cond); walk(e.then); walk(e.els)
        elif isinstance(e, (AllOf, AnyOf)):
            walk(e.coll); walk(e.body)

    walk(expr)
    out.discard("pc")
    return out


def _delta_shared_state(delta_ir, invariant_expr=None):
    """Variables the delta spec must declare.

    Union of (a) the free variables of the delta's *transition* actions (the
    shared state the changed actions actually read/write) and (b) the variables
    the invariant under test references. Including the invariant's variables is
    essential so the emitted property is always well-defined (never references
    an undeclared variable); when the invariant is scoped to the affected slice
    this yields a truly minimal schema, and when it is global it degrades safely
    to keeping the extra (constant) variables -- which still keeps the spec
    focused, since un-changed actions are absent from ``Next`` and so their
    variables never change.
    """
    shared = set()
    for a in delta_ir.actions:
        if a.is_initial:
            continue
        shared |= _expr_free_vars(a.guard)
        for e in a.effects:
            shared |= _expr_free_vars(e.expr)
    if invariant_expr is not None:
        shared |= _expr_free_vars(invariant_expr)
    shared.discard("pc")
    return shared


def emit_delta(delta_ir, invariant_name, invariant_expr, module_name=None):
    """Emit a *focused* TLA+ spec from a delta IR (the incremental translation).

    Emits only the delta's shared state (the variables its changed actions and
    the invariant under test reference) plus the delta's actions. The init
    action's effects are pruned to that shared state so ``Init`` stays
    well-defined over exactly the variables we declare. This is the TLA+
    fragment that changed, not the whole spec, so TLC/Apalache can check it
    quickly.

    ``delta_ir`` should already contain only the impacted actions (see
    ``rot.incremental.build_delta_ir``). Returns ``(module_source, op_name,
    emitter)``; call ``emitter.cfg(op)`` / ``emitter.write(...)`` for files.
    """
    from .linearization import linearize
    from .ir import ProtocolIR, Action

    shared = _delta_shared_state(delta_ir, invariant_expr)
    focused_vars = [v for v in delta_ir.variables if v.name in shared]

    # Rebuild the init action with only the shared-state effects.
    new_actions = []
    for a in delta_ir.actions:
        if a.is_initial:
            new_effects = [e for e in a.effects if e.var in shared]
            new_actions.append(Action(
                name=a.name, owner=a.owner, guard=a.guard,
                effects=new_effects, is_initial=True))
        else:
            new_actions.append(a)

    focused_ir = ProtocolIR(
        name=delta_ir.name,
        variables=focused_vars,
        actions=new_actions,
        init=delta_ir.init,
        pinned_property=delta_ir.pinned_property,
        assumptions=list(delta_ir.assumptions),
        metadata=dict(delta_ir.metadata),
    )

    model = linearize(focused_ir)
    mod = module_name or (delta_ir.name[:40] if delta_ir.name else "Delta")
    em = Emitter(model, module_name=mod)
    src, op = em.emit(invariant_name, invariant_expr)
    return src, op, em


__all__ = ["Emitter", "emit_delta"]


