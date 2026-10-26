# -*- coding: utf-8 -*-
"""sat.py -- a small, self-contained SAT solver plus 3-valued evaluation.

Why this exists: the hardened plan discharges per-action *simulation
obligations* and counterexample *feasibility* with an SMT/SAT solver
("bounded where necessary"). There is no Z3/cvc5 on this machine and internet
access is limited, so this module is the offline substitute. It is deliberately
small and provably correct (unit-tested against brute force), and it exposes a
three-valued evaluator so that unmodelled / environment atoms degrade to
``UNKNOWN`` rather than silently becoming True or False -- which is exactly the
plan's sound fallback (``UNKNOWN -> do NOT refine, surface to a human``).

Two layers:
  * propositional formula nodes (``Lit``/``And``/``Or``/``Not``) with a DPLL
    ``solve()`` returning SAT/UNSAT and a model.
  * ``eval3()``: Kleene 3-valued evaluation of a formula over a *concrete*
    assignment where some atoms are flagged unknown -> True/False/UNKNOWN.

Pure stdlib, Python 3.6 compatible (no f-strings).
"""

UNKNOWN = "UNKNOWN"
SAT = "SAT"
UNSAT = "UNSAT"

# ---------------------------------------------------------------------------
# propositional nodes
# ---------------------------------------------------------------------------
TRUE = True
FALSE = False


class Lit(object):
    """A propositional variable (neg=False) or its negation (neg=True)."""

    __slots__ = ("var", "neg")

    def __init__(self, var, neg=False):
        self.var = var
        self.neg = neg

    def __eq__(self, other):
        return (
            isinstance(other, Lit)
            and other.var == self.var
            and other.neg == self.neg
        )

    def __hash__(self):
        return hash((self.var, self.neg))

    def __repr__(self):
        return ("~" if self.neg else "") + "p" + str(self.var)


class And(object):
    __slots__ = ("children",)

    def __init__(self, children):
        self.children = tuple(children)

    def __repr__(self):
        return "(" + " & ".join(repr(c) for c in self.children) + ")"


class Or(object):
    __slots__ = ("children",)

    def __init__(self, children):
        self.children = tuple(children)

    def __repr__(self):
        return "(" + " | ".join(repr(c) for c in self.children) + ")"


class Not(object):
    __slots__ = ("child",)

    def __init__(self, child):
        self.child = child

    def __repr__(self):
        return "~(" + repr(self.child) + ")"


# ---------------------------------------------------------------------------
# normalising constructors
# ---------------------------------------------------------------------------
def AndOf(*children):
    out = []
    for c in children:
        if c is FALSE:
            return FALSE
        if c is TRUE:
            continue
        if isinstance(c, And):
            out.extend(c.children)
        else:
            out.append(c)
    seen = set()
    res = []
    for c in out:
        k = _idkey(c)
        if k in seen:
            continue
        seen.add(k)
        res.append(c)
    if not res:
        return TRUE
    if len(res) == 1:
        return res[0]
    return And(res)


def OrOf(*children):
    out = []
    for c in children:
        if c is TRUE:
            return TRUE
        if c is FALSE:
            continue
        if isinstance(c, Or):
            out.extend(c.children)
        else:
            out.append(c)
    seen = set()
    res = []
    for c in out:
        k = _idkey(c)
        if k in seen:
            continue
        seen.add(k)
        res.append(c)
    if not res:
        return FALSE
    if len(res) == 1:
        return res[0]
    return Or(res)


def NotOf(f):
    if f is TRUE:
        return FALSE
    if f is FALSE:
        return TRUE
    if isinstance(f, Not):
        return f.child
    if isinstance(f, And):
        return OrOf(*[NotOf(c) for c in f.children])
    if isinstance(f, Or):
        return AndOf(*[NotOf(c) for c in f.children])
    if isinstance(f, Lit):
        return Lit(f.var, not f.neg)
    return Not(f)


def Imp(a, b):
    """a => b  (sugar for Or(Not(a), b))."""
    return OrOf(NotOf(a), b)


def _idkey(f):
    if f is TRUE:
        return ("T",)
    if f is FALSE:
        return ("F",)
    if isinstance(f, Lit):
        return ("L", f.var, f.neg)
    if isinstance(f, And):
        return ("A", tuple(_idkey(c) for c in f.children))
    if isinstance(f, Or):
        return ("O", tuple(_idkey(c) for c in f.children))
    if isinstance(f, Not):
        return ("N", _idkey(f.child))
    return ("?", repr(f))


def is_formula(f):
    return (
        f is TRUE
        or f is FALSE
        or isinstance(f, (Lit, And, Or, Not))
    )


# ---------------------------------------------------------------------------
# DPLL
# ---------------------------------------------------------------------------
def _simplify(f, model):
    if f is TRUE or f is FALSE:
        return f
    if isinstance(f, Lit):
        if f.var in model:
            return (not f.neg) is model[f.var] and TRUE or FALSE
        return f
    if isinstance(f, And):
        return AndOf(*[_simplify(c, model) for c in f.children])
    if isinstance(f, Or):
        return OrOf(*[_simplify(c, model) for c in f.children])
    if isinstance(f, Not):
        s = _simplify(f.child, model)
        if s is TRUE or s is FALSE:
            return NotOf(s)
        return Not(s)
    return f


def _pick_literal(f):
    """Return one propositional variable occurrence from a non-constant formula."""
    if isinstance(f, Lit):
        return f
    if isinstance(f, And):
        return _pick_literal(f.children[0])
    if isinstance(f, Or):
        return _pick_literal(f.children[0])
    if isinstance(f, Not):
        return _pick_literal(f.child)
    raise TypeError("no literal found in %r" % (f,))


def solve(formula, _model=None):
    """DPLL by literal branching + simplification.

    Correct (backtracking) DPLL that works on arbitrary (not just CNF)
    formulas: it picks one variable occurrence, branches on both truth values,
    and re-simplifies the whole formula under the growing assignment. This
    avoids the model-threading flaw where a tautological disjunct would commit
    a variable and poison a sibling conjunct.

    Returns (status, model) with status in {SAT, UNSAT}.
    """
    if _model is None:
        _model = {}
    model = dict(_model)
    f = _simplify(formula, model)
    if f is TRUE:
        return (SAT, model)
    if f is FALSE:
        return (UNSAT, None)
    lit = _pick_literal(f)
    if lit.var in model:
        return (UNSAT, None)
    # branch 1: lit is true
    m1 = dict(model)
    m1[lit.var] = not lit.neg
    status, m2 = solve(formula, m1)
    if status == SAT:
        return (SAT, m2)
    # branch 2: lit is false
    m2b = dict(model)
    m2b[lit.var] = lit.neg
    return solve(formula, m2b)


# ---------------------------------------------------------------------------
# evaluators
# ---------------------------------------------------------------------------
def eval2(formula, model):
    """2-valued evaluation of a formula under a total assignment to its vars."""
    if formula is TRUE:
        return True
    if formula is FALSE:
        return False
    if isinstance(formula, Lit):
        return (not formula.neg) is model[formula.var]
    if isinstance(formula, And):
        return all(eval2(c, model) for c in formula.children)
    if isinstance(formula, Or):
        return any(eval2(c, model) for c in formula.children)
    if isinstance(formula, Not):
        return not eval2(formula.child, model)
    raise TypeError("not a propositional formula: %r" % (formula,))


def eval3(formula, grounded, unknown_vars):
    """Kleene 3-valued evaluation.

    ``grounded`` maps var-id -> True/False for atoms we can decide from a
    concrete state. ``unknown_vars`` is the set of var-ids we cannot decide
    (environment / unmodelled). Returns True / False / UNKNOWN.
    """
    if formula is TRUE:
        return True
    if formula is FALSE:
        return False
    if isinstance(formula, Lit):
        if formula.var in unknown_vars:
            return UNKNOWN
        val = grounded[formula.var]
        return val is not formula.neg
    if isinstance(formula, And):
        vals = [eval3(c, grounded, unknown_vars) for c in formula.children]
        if any(v is False for v in vals):
            return False
        if any(v is UNKNOWN for v in vals):
            return UNKNOWN
        return True
    if isinstance(formula, Or):
        vals = [eval3(c, grounded, unknown_vars) for c in formula.children]
        if any(v is True for v in vals):
            return True
        if any(v is UNKNOWN for v in vals):
            return UNKNOWN
        return False
    if isinstance(formula, Not):
        v = eval3(formula.child, grounded, unknown_vars)
        if v is UNKNOWN:
            return UNKNOWN
        return not v
    raise TypeError("not a propositional formula: %r" % (formula,))


# ---------------------------------------------------------------------------
# context: map semantic atoms -> propositional var ids
# ---------------------------------------------------------------------------
class SatContext(object):
    """Assigns a stable integer id to each distinct semantic atom.

    An *atom* is any (variable, operator, value) triple coming from the IR.
    Each becomes one propositional variable in the low-level formula.
    """

    def __init__(self):
        self._to_id = {}
        self._id_to_atom = {}
        self._next = 0

    def id_for(self, atom):
        key = self._norm(atom)
        if key not in self._to_id:
            self._to_id[key] = self._next
            self._id_to_atom[self._next] = atom
            self._next += 1
        return self._to_id[key]

    def atom_for(self, vid):
        return self._id_to_atom[vid]

    def _norm(self, atom):
        if isinstance(atom, tuple):
            return tuple(self._norm(a) for a in atom)
        if isinstance(atom, bool):
            return ("b", atom)
        if isinstance(atom, int):
            return ("i", atom)
        if isinstance(atom, float):
            return ("f", atom)
        if isinstance(atom, str):
            return ("s", atom)
        return ("o", repr(atom))

    def vars(self):
        return list(range(self._next))


# ---------------------------------------------------------------------------
# brute force (for tests / cross-checks)
# ---------------------------------------------------------------------------
def formula_vars(formula):
    acc = set()

    def rec(f):
        if isinstance(f, Lit):
            acc.add(f.var)
        elif isinstance(f, And):
            for c in f.children:
                rec(c)
        elif isinstance(f, Or):
            for c in f.children:
                rec(c)
        elif isinstance(f, Not):
            rec(f.child)

    rec(formula)
    return sorted(acc)


def brute_force(formula, var_list):
    """Try every assignment. Returns (status, model)."""
    n = len(var_list)
    for mask in range(1 << n):
        model = {}
        for i, v in enumerate(var_list):
            model[v] = bool((mask >> i) & 1)
        if eval2(formula, model):
            return (SAT, model)
    return (UNSAT, None)
