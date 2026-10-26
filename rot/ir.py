# -*- coding: utf-8 -*-
"""ir.py -- the typed intermediate representation (IR): ROTN's narrow waist.

The IR is the *sole* intermediate artifact of the whole system.  It is the
strict architectural boundary ("narrow waist") between what a protocol *is*
and how it is verified:

  * Every front-end (``rot.frontends``: the Java/Joern CPG pipeline today,
    other languages or formats later) has exactly one job: produce a
    ``ProtocolIR``.  A front-end must never import or touch ``rot.emitter``,
    ``rot.tlc``, or ``rot.cegar`` -- that coupling is forbidden and enforced
    by ``tests/test_narrow_waist.py``.
  * Every downstream engine consumes *only* a ``ProtocolIR``: the TLA+
    emitter (``rot.emitter``), the TLC pipeline (``rot.tlc``), the bounded
    CEGAR loop (``rot.cegar``), the property-directed abstraction, and the
    symbolic model checker.  None of them knows how the IR was built --
    whether from a Java CPG, a hand-authored fixture, or another language.

Design principles (sound spec core):
  * Language-agnostic: an IR can be produced by CPG analysis of Java, or
    authored by hand (fixture). Downstream stages (symbolic, emitter, CEGAR)
    only ever see this IR.
  * Sound by construction: every state variable that can influence a pinned
    property is either ``precise`` (translated exactly) or ``existential``
    (over-approximated: "any value in the domain"). We never *delete* a
    variable, because deleting behaviours is an *under*-approximation and is
    UNSOUND for safety. This is enforced by the type and recorded in the
    AbstractionManifest.
  * Bounded: all domains are finite, so TLC can exhaustively check the emitted
    TLA+ and our SAT solver can decide counterexample feasibility.
  * Stable contract: small, explicit, and fully serializable (``to_dict`` /
    ``from_dict``) so it can cross process and language boundaries
    (Python <-> Java/TLC) without either side depending on the other.

Pure stdlib, Python 3.6 compatible (no f-strings).
"""


# ---------------------------------------------------------------------------
# Assurance ladder: severity rungs and gate permissions
# ---------------------------------------------------------------------------
#: Gate *permissions*, ordered by strength.  A violation of an invariant may
#: only reach the permission level the invariant's rung allows.
PERM_ALERT = 0   # informational note only -- never changes the verdict
PERM_WARN  = 1   # flagged, non-blocking
PERM_BLOCK = 2   # may BLOCK the MR (when the invariant is blocking-eligible)

#: Severity *rungs* of the assurance ladder, ordered by scope.
RUNG_STRUCTURAL = 0   # well-formedness / hygiene of the model itself
RUNG_LOCAL      = 1   # per-actor / per-node property (single participant)
RUNG_PROTOCOL   = 2   # intra-protocol safety (the default rung)
RUNG_E2E        = 3   # cross-service / end-to-end property (composition plane)
#: Environment-asynchrony rung.  An alias of :data:`RUNG_LOCAL`: environment
#: fragments (at-least-once queue, lossy channel, crash-recoverable disk) are
#: verified only to the local rung, so a violation whose witness path ends in
#: an env action can never drive a BLOCK (``RUNG_CEILING[RUNG_ENV] == PERM_WARN``).
RUNG_ENV = RUNG_LOCAL

ALL_RUNGS = (RUNG_STRUCTURAL, RUNG_LOCAL, RUNG_PROTOCOL, RUNG_E2E)

#: The ceiling on the gate permission a violation of an invariant on this
#: rung may have.  A rung can only *lower* the permission an invariant
#: declares (via its label and pinning) -- never raise it.
RUNG_CEILING = {
    RUNG_STRUCTURAL: PERM_ALERT,
    RUNG_LOCAL:      PERM_WARN,
    RUNG_PROTOCOL:   PERM_BLOCK,
    RUNG_E2E:        PERM_BLOCK,
}

#: Human-readable names of the permissions (for artifacts and justifications).
PERMISSION_NAMES = {
    PERM_ALERT: "alert",
    PERM_WARN:  "warn",
    PERM_BLOCK: "block",
}


# ---------------------------------------------------------------------------
# domains
# ---------------------------------------------------------------------------
class Domain(object):
    def contains(self, value):
        raise NotImplementedError

    def to_tla(self):
        raise NotImplementedError

    def to_dict(self):
        raise NotImplementedError

    @classmethod
    def from_dict(cls, d):
        kind = d["kind"]
        if kind == "int":
            return IntRange(d["lo"], d["hi"])
        if kind == "bool":
            return Bool()
        if kind == "enum":
            return Enum(d["values"])
        raise ValueError("unknown domain kind: %r" % (kind,))


class IntRange(Domain):
    def __init__(self, lo, hi):
        self.lo = int(lo)
        self.hi = int(hi)
        if self.lo > self.hi:
            raise ValueError("IntRange lo>hi")

    def contains(self, value):
        return isinstance(value, int) and not isinstance(value, bool) and self.lo <= value <= self.hi

    def to_tla(self):
        return "[%d .. %d]" % (self.lo, self.hi)

    def to_dict(self):
        return {"kind": "int", "lo": self.lo, "hi": self.hi}


class Bool(Domain):
    def contains(self, value):
        return isinstance(value, bool)

    def to_tla(self):
        return "BOOL"

    def to_dict(self):
        return {"kind": "bool"}


class Enum(Domain):
    def __init__(self, values):
        vals = list(values)
        if not vals:
            raise ValueError("Enum needs >= 1 value")
        self.values = vals

    def contains(self, value):
        return value in self.values

    def to_tla(self):
        return "UNION {" + ", ".join(str(v) for v in self.values) + "}"

    def to_dict(self):
        return {"kind": "enum", "values": list(self.values)}


# ---------------------------------------------------------------------------
# expressions (semantic layer over bounded state)
# ---------------------------------------------------------------------------
class Expr(object):
    """Base for the semantic expression AST.

    Expressions evaluate over a concrete *state* (dict var->value). The
    sentinel ``Expr.UNDEF`` is returned when a value cannot be evaluated
    (e.g. it depends on an unmodelled environment atom). Callers must treat
    UNDEF as UNKNOWN -- never as True or False -- which is exactly the plan's
    sound fallback (UNKNOWN -> do not refine, surface to a human).
    """

    UNDEF = object()

    def eval(self, state):
        raise NotImplementedError

    def to_dict(self):
        raise NotImplementedError

    @classmethod
    def from_dict(cls, d):
        tag = d["tag"]
        if tag == "const":
            return Const(d["value"])
        if tag == "var":
            return Var(d["name"])
        if tag == "bin":
            return BinOp(d["op"], Expr.from_dict(d["left"]), Expr.from_dict(d["right"]))
        if tag == "un":
            return UnOp(d["op"], Expr.from_dict(d["child"]))
        if tag == "if":
            return If(Expr.from_dict(d["cond"]), Expr.from_dict(d["then"]), Expr.from_dict(d["else"]))
        if tag == "allof":
            return AllOf(d["var"], Expr.from_dict(d["coll"]), Expr.from_dict(d["body"]))
        if tag == "anyof":
            return AnyOf(d["var"], Expr.from_dict(d["coll"]), Expr.from_dict(d["body"]))
        raise ValueError("unknown expr tag: %r" % (tag,))


class Const(Expr):
    def __init__(self, value):
        self.value = value

    def eval(self, state):
        return self.value

    def to_dict(self):
        return {"tag": "const", "value": self.value}


class Var(Expr):
    def __init__(self, name):
        self.name = name

    def eval(self, state):
        if self.name in state:
            return state[self.name]
        return Expr.UNDEF

    def to_dict(self):
        return {"tag": "var", "name": self.name}


def _as_expr(x):
    """Coerce a raw Python value into a ``Const`` so the IR tolerates both
    strict (``C("x")``) and lenient (``"x"``) construction styles. ``Expr``
    instances pass through unchanged."""
    if isinstance(x, Expr):
        return x
    return Const(x)


class BinOp(Expr):
    OPS = ("and", "or", "+", "-", "*", "=", "!=", "<", "<=", ">", ">=", "in")

    def __init__(self, op, left, right):
        if op not in BinOp.OPS:
            raise ValueError("bad bin op %r" % (op,))
        self.op = op
        self.left = _as_expr(left)
        self.right = _as_expr(right)

    def eval(self, state):
        if self.op == "and":
            l = self.left.eval(state)
            if l is Expr.UNDEF:
                return Expr.UNDEF
            if not l:
                return False
            r = self.right.eval(state)
            return Expr.UNDEF if r is Expr.UNDEF else r
        if self.op == "or":
            l = self.left.eval(state)
            if l is Expr.UNDEF:
                return Expr.UNDEF
            if l:
                return True
            r = self.right.eval(state)
            return Expr.UNDEF if r is Expr.UNDEF else r
        l = self.left.eval(state)
        r = self.right.eval(state)
        if l is Expr.UNDEF or r is Expr.UNDEF:
            return Expr.UNDEF
        if self.op == "+":
            return l + r
        if self.op == "-":
            return l - r
        if self.op == "*":
            return l * r
        if self.op == "=":
            return l == r
        if self.op == "!=":
            return l != r
        if self.op == "<":
            return l < r
        if self.op == "<=":
            return l <= r
        if self.op == ">":
            return l > r
        if self.op == ">=":
            return l >= r
        if self.op == "in":
            return l in r
        raise ValueError(self.op)

    def to_dict(self):
        return {"tag": "bin", "op": self.op,
                "left": self.left.to_dict(), "right": self.right.to_dict()}


class UnOp(Expr):
    OPS = ("not", "neg")

    def __init__(self, op, child):
        if op not in UnOp.OPS:
            raise ValueError("bad un op %r" % (op,))
        self.op = op
        self.child = _as_expr(child)

    def eval(self, state):
        c = self.child.eval(state)
        if c is Expr.UNDEF:
            return Expr.UNDEF
        if self.op == "not":
            return (not c)
        if self.op == "neg":
            return -c
        raise ValueError(self.op)

    def to_dict(self):
        return {"tag": "un", "op": self.op, "child": self.child.to_dict()}


class If(Expr):
    def __init__(self, cond, then, els):
        self.cond = _as_expr(cond)
        self.then = _as_expr(then)
        self.els = _as_expr(els)

    def eval(self, state):
        c = self.cond.eval(state)
        if c is Expr.UNDEF:
            return Expr.UNDEF
        return (self.then if c else self.els).eval(state)

    def to_dict(self):
        return {"tag": "if", "cond": self.cond.to_dict(),
                "then": self.then.to_dict(), "else": self.els.to_dict()}


class AllOf(Expr):
    """Universal quantification of ``var`` over a concrete collection.

    e.g. ``AllOf('p', participants, vote[p] = YES)`` == "all participants
    voted YES". The collection is a CONCRETE value in the IR, so bounded.
    """

    def __init__(self, var, coll, body):
        self.var = var
        self.coll = _as_expr(coll)
        self.body = _as_expr(body)

    def eval(self, state):
        c = self.coll.eval(state)
        if c is Expr.UNDEF:
            return Expr.UNDEF
        for v in c:
            s = dict(state)
            s[self.var] = v
            r = self.body.eval(s)
            if r is Expr.UNDEF:
                return Expr.UNDEF
            if not r:
                return False
        return True

    def to_dict(self):
        return {"tag": "allof", "var": self.var,
                "coll": self.coll.to_dict(), "body": self.body.to_dict()}


class AnyOf(Expr):
    def __init__(self, var, coll, body):
        self.var = var
        self.coll = _as_expr(coll)
        self.body = _as_expr(body)

    def eval(self, state):
        c = self.coll.eval(state)
        if c is Expr.UNDEF:
            return Expr.UNDEF
        for v in c:
            s = dict(state)
            s[self.var] = v
            r = self.body.eval(s)
            if r is Expr.UNDEF:
                return Expr.UNDEF
            if r:
                return True
        return False

    def to_dict(self):
        return {"tag": "anyof", "var": self.var,
                "coll": self.coll.to_dict(), "body": self.body.to_dict()}


# -- ergonomic constructors -------------------------------------------------
def T(v=True):
    return Const(bool(v))


def F():
    return Const(False)


def eq(a, b):
    return BinOp("=", a, b)


def neq(a, b):
    return BinOp("!=", a, b)


def And(*xs):
    out = T()
    for x in xs:
        out = BinOp("and", out, x)
    return out


def Or(*xs):
    out = F()
    for x in xs:
        out = BinOp("or", out, x)
    return out


def Not(x):
    return UnOp("not", x)


def V(name):
    return Var(name)


def C(value):
    return Const(value)


# ---------------------------------------------------------------------------
# state, channels, actions
# ---------------------------------------------------------------------------
MODE_PRECISE = "precise"
MODE_EXISTENTIAL = "existential"
_MODES = (MODE_PRECISE, MODE_EXISTENTIAL)


# ---------------------------------------------------------------------------
# solver / model-finder result codes
# ---------------------------------------------------------------------------
# The SAT model-finder and the bounded model-finder both return one of these
# three tokens for a reachability / feasibility query.  They are defined here
# (in the narrow waist) so front-ends, tests, and downstream engines can
# compare outcomes against one shared source.  (`rot.sat` and
# `rot.modelfind` carry identical local copies for historical reasons.)
SAT = "SAT"
UNSAT = "UNSAT"
UNKNOWN = "UNKNOWN"


class StateVar(object):
    """A protocol state variable.

    ``mode`` is either ``precise`` (translated exactly) or ``existential``
    (over-approx: "any value in the domain"). There is deliberately NO
    ``deleted`` mode: removing behaviours would be an under-approximation and
    is unsound for safety, so the type makes that impossible.
    """

    def __init__(self, name, domain, mode=MODE_PRECISE, owner="global", desc=""):
        if mode not in _MODES:
            raise ValueError(
                "bad mode %r -- a variable must be precise or existential; "
                "we never delete a variable (unsound for safety)" % (mode,))
        self.name = name
        self.domain = domain
        self.mode = mode
        self.owner = owner
        self.desc = desc

    def to_dict(self):
        return {"name": self.name, "domain": self.domain.to_dict(),
                "mode": self.mode, "owner": self.owner, "desc": self.desc}

    @classmethod
    def from_dict(cls, d):
        return cls(d["name"], Domain.from_dict(d["domain"]),
                   d.get("mode", MODE_PRECISE), d.get("owner", "global"), d.get("desc", ""))


class Channel(object):
    """An abstract message channel; delivery is non-deterministic (existential)."""

    def __init__(self, name, sender, receiver, desc=""):
        self.name = name
        self.sender = sender
        self.receiver = receiver
        self.desc = desc

    def to_dict(self):
        return {"name": self.name, "sender": self.sender,
                "receiver": self.receiver, "desc": self.desc}

    @classmethod
    def from_dict(cls, d):
        return cls(d["name"], d["sender"], d["receiver"], d.get("desc", ""))


class Assignment(object):
    """A post-state update: ``var := expr`` (expr may reference pre-state)."""

    def __init__(self, var, expr):
        self.var = var
        self.expr = _as_expr(expr)

    def to_dict(self):
        return {"var": self.var, "expr": self.expr.to_dict()}

    @classmethod
    def from_dict(cls, d):
        return cls(d["var"], Expr.from_dict(d["expr"]))


class Action(object):
    """One linearised protocol action.

    ``guard`` is the precondition (an Expr over state). ``effects`` are the
    post-state assignments. ``linearization`` records the external effect that
    makes this a commit point (e.g. "send(commit)"), and ``env_free`` flags
    that the action depends on an environment (existential) choice.
    """

    def __init__(self, name, owner, guard=None, effects=None,
                 linearization="", env_free=False, is_initial=False, source="",
                 rung=None, is_env=False):
        self.name = name
        self.owner = owner
        self.guard = _as_expr(guard) if guard is not None else Const(True)
        self.effects = [Assignment(e[0], e[1]) if isinstance(e, (tuple, list)) else e
                        for e in (effects or [])]
        self.linearization = linearization
        self.env_free = env_free
        self.is_initial = is_initial
        self.source = source
        # rung: assurance-ladder rung this action is verified at (int or None).
        # See rot.invariants.RUNG_CEILING for the permission ceiling each rung
        # imposes on the MR gate.  None means "not rung-annotated" (the
        # invariant's own rung governs, as before).
        self.rung = rung
        # is_env: True when this action models *environment* asynchrony
        # (at-least-once queue, lossy channel, crash-recoverable disk) rather
        # than the service's own state machine.  Env actions are expected to
        # sit at or below RUNG_ENV and can never drive a BLOCK verdict.
        self.is_env = bool(is_env)

    def to_dict(self):
        return {
            "name": self.name, "owner": self.owner,
            "guard": self.guard.to_dict(),
            "effects": [e.to_dict() for e in self.effects],
            "linearization": self.linearization,
            "env_free": self.env_free,
            "is_initial": self.is_initial,
            "source": self.source,
            "rung": self.rung,
            "is_env": self.is_env,
        }

    @classmethod
    def from_dict(cls, d):
        return cls(d["name"], d["owner"], Expr.from_dict(d["guard"]),
                   [Assignment.from_dict(e) for e in d.get("effects", [])],
                   d.get("linearization", ""), d.get("env_free", False),
                   d.get("is_initial", False), d.get("source", ""),
                   d.get("rung", None), d.get("is_env", False))


class AbstractionEntry(object):
    """One row of the AbstractionManifest (the auditability contract).

    ``status`` is one of ``covered`` / ``assumed`` / ``unverified``.
    """

    STATUSES = ("covered", "assumed", "unverified")

    def __init__(self, feature, status, evidence="", abstraction="", risk=""):
        if status not in AbstractionEntry.STATUSES:
            raise ValueError("bad abstraction status %r" % (status,))
        self.feature = feature
        self.status = status
        self.evidence = evidence
        self.abstraction = abstraction
        self.risk = risk

    def to_dict(self):
        return {"feature": self.feature, "status": self.status,
                "evidence": self.evidence, "abstraction": self.abstraction,
                "risk": self.risk}

    @classmethod
    def from_dict(cls, d):
        return cls(d["feature"], d["status"], d.get("evidence", ""),
                   d.get("abstraction", ""), d.get("risk", ""))


class AdversarialPolicy(object):
    """An agent action policy: which actions the agent is permitted to take.

    This is the narrow-waist primitive for adversarial agent verification (the
    ``AgentStep`` family). A policy partitions the agent's action space into a
    disjoint ``allowed`` set and a ``denied`` set. It is *data*, not an
    ``Expr``: the ``AgentStep`` IR's existential choice ranges over
    ``allowed ∪ denied`` (so an adversarial agent can *try* a denied action),
    while the ``policy_conformance`` safety invariant -- built from ``denied``
    -- must hold in every reachable state.

    The two sets are disjoint by construction: an action cannot be both
    permitted and forbidden. Both are frozen, so a policy is an immutable
    value that serialises to a stable, order-independent dict (sorted) and
    round-trips through :meth:`ProtocolIR.to_dict` / :meth:`from_dict`.
    """

    def __init__(self, allowed, denied=()):
        a = frozenset(allowed)
        d = frozenset(denied)
        overlap = a & d
        if overlap:
            raise ValueError(
                "AdversarialPolicy allowed/denied overlap: %r"
                % (sorted(overlap),))
        self.allowed = a
        self.denied = d

    def allows(self, action):
        """True if the policy permits ``action``."""
        return action in self.allowed

    def denies(self, action):
        """True if the policy forbids ``action``."""
        return action in self.denied

    def actions(self):
        """The full action space ``allowed ∪ denied`` (the choice domain)."""
        return sorted(self.allowed | self.denied)

    def to_dict(self):
        return {"allowed": sorted(self.allowed), "denied": sorted(self.denied)}

    @classmethod
    def from_dict(cls, d):
        return cls(d.get("allowed", ()), d.get("denied", ()))

    def __repr__(self):
        return "AdversarialPolicy(allowed=%r, denied=%r)" % (
            sorted(self.allowed), sorted(self.denied))


class ProtocolIR(object):
    """The top-level, language-agnostic protocol model.

    This is the single contract between the CPG extraction stage and the
    symbolic/emitter/CEGAR stages. It is fully serialisable (to_dict/from_dict)
    so an IR can be authored by hand (fixture) or produced by JoernCPG analysis.
    """

    def __init__(self, name, variables=None, channels=None, actions=None,
                 init=None, pinned_property=None, assumptions=None,
                 abstraction_manifest=None, source_path="", metadata=None,
                 policy=None):
        self.name = name
        self.variables = list(variables or [])
        self.channels = list(channels or [])
        self.actions = list(actions or [])
        self.init = init if init is not None else Const(True)
        self.pinned_property = pinned_property if pinned_property is not None else Const(True)
        self.assumptions = list(assumptions or [])
        self.abstraction_manifest = list(abstraction_manifest or [])
        self.source_path = source_path
        self.metadata = dict(metadata or {})
        # Optional adversarial agent policy (the AgentStep family). ``None`` for
        # every existing target -- the narrow waist stays backward compatible.
        self.policy = policy

    # -- structural equality -------------------------------------------------
    # ``metadata`` is provenance (which ``.dw`` file produced the model, or a
    # hand-authored tag) and is deliberately excluded: two models that encode
    # the same protocol must compare equal regardless of provenance. That is
    # exactly what lets the ``.dw`` bridge be asserted to reproduce the
    # hand-written ``spendcap`` model while still carrying its ``dw_*`` tags.
    def __eq__(self, other):
        if not isinstance(other, ProtocolIR):
            return NotImplemented
        return self._structural() == other._structural()

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def _structural(self):
        d = self.to_dict()
        d.pop("metadata", None)
        return d

    __hash__ = None

    # -- accessors -----------------------------------------------------------
    def var(self, name):
        for v in self.variables:
            if v.name == name:
                return v
        return None

    def action(self, name):
        for a in self.actions:
            if a.name == name:
                return a
        return None

    def vars_in(self, expr):
        """Names of StateVars referenced by ``expr`` (shallow walk)."""
        out = []

        def walk(e):
            if isinstance(e, Var):
                if e.name not in out:
                    out.append(e.name)
            elif isinstance(e, BinOp):
                walk(e.left); walk(e.right)
            elif isinstance(e, UnOp):
                walk(e.child)
            elif isinstance(e, If):
                walk(e.cond); walk(e.then); walk(e.els)
            elif isinstance(e, (AllOf, AnyOf)):
                walk(e.coll); walk(e.body)
        if expr is not None:
            walk(expr)
        return out

    def all_referenced_vars(self):
        names = []
        for a in self.actions:
            for n in self.vars_in(a.guard):
                if n not in names:
                    names.append(n)
            for e in a.effects:
                if e.var not in names:
                    names.append(e.var)
                for n in self.vars_in(e.expr):
                    if n not in names:
                        names.append(n)
        for n in self.vars_in(self.init):
            if n not in names:
                names.append(n)
        for n in self.vars_in(self.pinned_property):
            if n not in names:
                names.append(n)
        return names

    def to_dict(self):
        return {
            "name": self.name,
            "variables": [v.to_dict() for v in self.variables],
            "channels": [c.to_dict() for c in self.channels],
            "actions": [a.to_dict() for a in self.actions],
            "init": self.init.to_dict(),
            "pinned_property": self.pinned_property.to_dict(),
            "assumptions": list(self.assumptions),
            "abstraction_manifest": [m.to_dict() for m in self.abstraction_manifest],
            "policy": self.policy.to_dict() if self.policy is not None else None,
            "source_path": self.source_path,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, d):
        return cls(
            d["name"],
            variables=[StateVar.from_dict(v) for v in d.get("variables", [])],
            channels=[Channel.from_dict(c) for c in d.get("channels", [])],
            actions=[Action.from_dict(a) for a in d.get("actions", [])],
            init=Expr.from_dict(d.get("init", {"tag": "const", "value": True})),
            pinned_property=Expr.from_dict(d.get("pinned_property", {"tag": "const", "value": True})),
            assumptions=list(d.get("assumptions", [])),
            abstraction_manifest=[AbstractionEntry.from_dict(m) for m in d.get("abstraction_manifest", [])],
            policy=AdversarialPolicy.from_dict(d["policy"]) if d.get("policy") is not None else None,
            source_path=d.get("source_path", ""),
            metadata=dict(d.get("metadata", {})),
        )

    # -- validation ----------------------------------------------------------
    def validate(self):
        errs = []
        if not self.actions:
            errs.append("no actions")
        for v in self.variables:
            if v.name == "pc" or v.name.startswith("__"):
                errs.append("reserved var name: %s" % v.name)
        seen = set()
        for a in self.actions:
            if a.name in seen:
                errs.append("duplicate action: %s" % a.name)
            seen.add(a.name)
            for e in a.effects:
                if e.var != "pc" and self.var(e.var) is None:
                    errs.append("action %s writes undeclared var %s" % (a.name, e.var))
        for n in self.all_referenced_vars():
            if n != "pc" and self.var(n) is None:
                errs.append("referenced but undeclared var: %s" % n)
        # -- rung annotations -------------------------------------------------
        # RUNG_* / ALL_RUNGS are module-level constants defined above, so no
        # lazy import of rot.invariants is needed here -- which also removes
        # the last import edge from this module into the invariant registry.
        for a in self.actions:
            if a.rung is not None and a.rung not in ALL_RUNGS:
                errs.append("action %s has unknown rung %r" % (a.name, a.rung))
            if a.is_env and a.rung is not None and a.rung > RUNG_ENV:
                errs.append("env action %s is annotated rung %r above RUNG_ENV"
                            % (a.name, a.rung))
        return errs


class IRFileError(Exception):
    """Raised when an IR file cannot be parsed or validated."""


def load_ir(path):
    """Load a ProtocolIR from a JSON file. Raises IRFileError on parse/validate error."""
    import json
    try:
        with open(path, "r") as f:
            d = json.load(f)
    except Exception as e:
        raise IRFileError("cannot read IR at %s: %s" % (path, e))
    try:
        ir = ProtocolIR.from_dict(d)
    except Exception as e:
        raise IRFileError("invalid IR structure in %s: %s" % (path, e))
    errs = ir.validate()
    if errs:
        raise IRFileError("IR validation failed in %s: %s" % (path, "; ".join(errs)))
    ir.source_path = path
    return ir


def save_ir(ir, path):
    """Write a ProtocolIR to a JSON file."""
    import json
    with open(path, "w") as f:
        json.dump(ir.to_dict(), f, indent=2, sort_keys=False)


__all__ = [
    "PERM_ALERT", "PERM_WARN", "PERM_BLOCK",
    "RUNG_STRUCTURAL", "RUNG_LOCAL", "RUNG_PROTOCOL", "RUNG_E2E",
    "RUNG_ENV", "ALL_RUNGS", "RUNG_CEILING", "PERMISSION_NAMES",
    "Domain", "IntRange", "Bool", "Enum",
    "Expr", "Const", "Var", "BinOp", "UnOp", "If", "AllOf", "AnyOf",
    "T", "F", "eq", "neq", "And", "Or", "Not", "V", "C",
    "MODE_PRECISE", "MODE_EXISTENTIAL",
    "StateVar", "Channel", "Assignment", "Action",
    "AbstractionEntry", "AdversarialPolicy", "ProtocolIR", "IRFileError",
    "load_ir", "save_ir",
]