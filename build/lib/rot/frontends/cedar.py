# -*- coding: utf-8 -*-
"""rot.frontends.cedar -- a Cedar policy-language front-end for ROT.

Parses a *bounded subset* of the Cedar policy language and emits a
``rot.ir.ProtocolIR`` that downstream engines (SAT layer, model finder,
emitters) consume.

Narrow waist: this module imports only the standard library and ``rot.ir``.
It never touches ``rot.sat`` / ``rot.emitter`` / ``rot.tlc`` /
``rot.cegar`` (enforced by ``tests/test_narrow_waist.py``).

Supported subset
================

Declarations::

    entity <Type> ;                       # entity type
    entity <Type> in <SuperType> ;        # hierarchy (subtype of SuperType)
    action <name> ;                       # action (request slot value)

Policies (``allow``/``deny`` accepted as aliases)::

    permit (principal, action, resource) [when { <expr> }] ;
    forbid (principal, action, resource) [when { <expr> }] ;

Expressions (Cedar precedence)::

    <or>    := <and> { "||" <and> }
    <and>   := <not> { "&&" <not> }
    <not>   := "!" <not> | <cmp>
    <cmp>   := <term> { <cmp-op> <term> | "has" <ident> }   # == != < <= > >= in is contains
    <term>  := <primary> { "." <ident> }      # attribute access
    <primary> := true | false | <int> | <string>
                 | <Type> "::" <string>       # entity reference
                 | principal | resource | action
                 | <action-name>
                 | <Type>                     # right side of "is" only
                 | "(" <expr> ")"

Bounded verification model
==========================

* The entity universe is bounded to the entity references and declared type
  names appearing in the policy set.  ``principal``/``resource`` are
  existential state variables over that universe.
* Every attribute read (``x.attr``) becomes an existential state variable
  keyed by its syntactic scope (``resource.attr`` / ``<Type>.attr``); its
  domain is the set of literals it is compared against (an ``IntRange`` if
  every compared value is an integer).  ``has`` reads hold in the model.
* ``x in Y`` (Y an entity reference) is membership in Y's bounded subtree
  (Y itself plus every entity of Y's type or a subtype).
* ``x is T`` is membership in the entities of exactly type T.
* Request choice is linearised as a staged action family (the ROT
  "choice = action family" pattern): pick principal -> action -> resource ->
  each attribute, then the policy actions fire.
* Cedar evaluation is preserved: ``forbid`` wins over ``permit`` and the
  default decision is ``deny``.

Pure stdlib + ``rot.ir``, Python 3.6 compatible (no f-strings).
"""

import os
import re

import rot.ir as ir


class CedarError(ValueError):
    """A Cedar front-end error (lexical/syntactic/semantic), with a line."""

    def __init__(self, message, line=None):
        if line is not None:
            message = "line %d: %s" % (line, message)
        super(CedarError, self).__init__(message)


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------
_TOKEN_RE = re.compile(
    r"""
      (?P<comment>//[^\n]*)
    | (?P<ws>\s+)
    | (?P<string>"(?:\\.|[^"\\\n])*")
    | (?P<int>[0-9]+)
    | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
    | (?P<op>==|!=|<=|>=|&&|\|\||::|!|<|>|\(|\)|,|;|\{|\}|\.)
    """,
    re.VERBOSE,
)

_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f",
    '"': '"', "'": "'", "\\": "\\",
}


def _decode_string(raw):
    body = raw[1:-1]
    out = []
    i = 0
    n = len(body)
    while i < n:
        c = body[i]
        if c == "\\" and i + 1 < n:
            nxt = body[i + 1]
            if nxt in _ESCAPES:
                out.append(_ESCAPES[nxt])
                i += 2
                continue
            if nxt == "u" and i + 6 <= n:
                hexs = body[i + 2:i + 6]
                if len(hexs) == 4 and all(
                        h in "0123456789abcdefABCDEF" for h in hexs):
                    out.append(chr(int(hexs, 16)))
                    i += 6
                    continue
            raise CedarError("bad string escape '\\%s'" % nxt)
        out.append(c)
        i += 1
    return "".join(out)


def tokenize(text):
    """Tokenize Cedar source into ``[(kind, value, line)]``.

    ``kind`` is one of ``"str"``, ``"int"``, ``"id"``, ``"op"``.
    """
    toks = []
    pos = 0
    line = 1
    n = len(text)
    while pos < n:
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise CedarError("unexpected character %r" % text[pos], line=line)
        kind = m.lastgroup
        val = m.group()
        pos = m.end()
        line += val.count("\n")
        if kind in ("ws", "comment"):
            continue
        if kind == "string":
            toks.append(("str", _decode_string(val), line))
        elif kind == "int":
            toks.append(("int", int(val), line))
        elif kind == "ident":
            toks.append(("id", val, line))
        else:
            toks.append(("op", val, line))
    return toks


# ---------------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------------
class _Node(object):
    def __repr__(self):
        return self.__class__.__name__ + "(" + ", ".join(
            "%s=%r" % (k, v) for k, v in sorted(self.__dict__.items())
        ) + ")"


class AConst(_Node):
    def __init__(self, value):
        self.value = value


class AVar(_Node):
    """A request slot: principal / resource / action."""

    def __init__(self, name):
        self.name = name


class AEntity(_Node):
    """An entity reference ``Type::"id"``."""

    def __init__(self, type_name, entity_id, line=None):
        self.type_name = type_name
        self.entity_id = entity_id
        self.line = line


class AAction(_Node):
    """A declared action used as a value."""

    def __init__(self, name, line=None):
        self.name = name
        self.line = line


class ATy(_Node):
    """An entity type name (valid only as the right side of ``is``)."""

    def __init__(self, name, line=None):
        self.name = name
        self.line = line


class AAttr(_Node):
    """Attribute access ``<base>.<name>`` (base is AVar or AEntity)."""

    def __init__(self, base, name):
        self.base = base
        self.name = name


class AHas(_Node):
    """Attribute-presence test ``<base> has <name>``."""

    def __init__(self, base, name):
        self.base = base
        self.name = name


class AUnary(_Node):
    def __init__(self, op, child):
        self.op = op
        self.child = child


class ABin(_Node):
    def __init__(self, op, left, right):
        self.op = op
        self.left = left
        self.right = right


class _Policy(object):
    """One parsed ``permit``/``forbid`` statement."""

    def __init__(self, index, effect, cond, header, line):
        self.index = index
        self.effect = effect          # "permit" or "forbid"
        self.cond = cond              # boolean AST (_Node)
        self.header = header          # list of request-slot names
        self.line = line

    @property
    def name(self):
        return "policy_%d" % self.index

    @property
    def is_forbid(self):
        return self.effect == "forbid"


_REQUEST_SLOTS = ("principal", "action", "resource")

#: sentinel: an attribute was compared against a request slot, so its domain
#: must cover the whole entity universe
REQUEST_UNIVERSE = object()

#: comparison operators in Cedar syntax (pre-IR)
_CMP_OPS = ("==", "!=", "<", "<=", ">", ">=", "in", "is")


# ---------------------------------------------------------------------------
# Parser (recursive descent)
# ---------------------------------------------------------------------------
class _Parser(object):
    """Parses token lists into Cedar declarations and policies."""

    def __init__(self, toks):
        self.toks = toks
        self.pos = 0
        self.declared_types = {}        # type name -> (super_type, line)
        self.entity_refs = {}           # type name -> set of entity ids
        self.action_names = set()
        self.actions = []               # [(name, line)]

    # -- token helpers -------------------------------------------------------
    def _peek(self):
        if self.pos < len(self.toks):
            return self.toks[self.pos]
        return None

    def _advance(self):
        tok = self.toks[self.pos]
        self.pos += 1
        return tok

    def _expect(self, kind, value=None):
        tok = self._peek()
        if tok is None or tok[0] != kind or (value is not None and tok[1] != value):
            got = "end of input" if tok is None else repr(tok[1])
            want = repr(value) if value is not None else kind
            raise CedarError("expected %s, got %s" % (want, got),
                             line=None if tok is None else tok[2])
        return self._advance()

    def _at_kw(self, *words):
        tok = self._peek()
        return tok is not None and tok[0] == "id" and tok[1] in words

    def _last_line(self):
        idx = self.pos - 1 if self.pos > 0 else 0
        return self.toks[idx][2]

    # -- program -------------------------------------------------------------
    def parse_program(self):
        policies = []
        index = 0
        while self._peek() is not None:
            tok = self._peek()
            if tok[0] != "id":
                raise CedarError("expected a declaration, got %r" % tok[1], line=tok[2])
            word = tok[1]
            if word == "entity":
                self._parse_entity()
            elif word == "action":
                self._parse_action()
            elif word in ("permit", "allow", "forbid", "deny"):
                index += 1
                policies.append(self._parse_policy(index, word))
            else:
                raise CedarError(
                    "unsupported keyword %r (supported: entity, action, "
                    "permit, allow, forbid, deny)" % word, line=tok[2])
        self._check_declared()
        return policies

    def _parse_entity(self):
        self._expect("id", "entity")
        name = self._expect("id")[1]
        super_type = None
        if self._at_kw("in"):
            self._advance()
            super_type = self._expect("id")[1]
        self._expect("op", ";")
        if name in self.declared_types:
            raise CedarError("duplicate entity type %r" % name, line=self._last_line())
        if name in _REQUEST_SLOTS:
            raise CedarError("entity type %r shadows a request slot" % name)
        self.declared_types[name] = (super_type, self._last_line())

    def _parse_action(self):
        self._expect("id", "action")
        name = self._expect("id")[1]
        self._expect("op", ";")
        if name in self.action_names:
            raise CedarError("duplicate action %r" % name, line=self._last_line())
        self.action_names.add(name)
        self.actions.append((name, self._last_line()))

    def _check_declared(self):
        """Subtype chains must close over declared types only, acyclically."""
        for ty, (sup, line) in sorted(self.declared_types.items()):
            seen = set([ty])
            cur = sup
            while cur is not None:
                if cur not in self.declared_types:
                    raise CedarError(
                        "entity type %r is a subtype of undeclared type %r"
                        % (ty, cur), line=line)
                if cur in seen:
                    raise CedarError(
                        "entity hierarchy cycle through %r" % cur, line=line)
                seen.add(cur)
                cur = self.declared_types[cur][0]

    # -- policies ------------------------------------------------------------
    def _parse_policy(self, index, effect_word):
        line = self.toks[self.pos][2]
        effect = "forbid" if effect_word in ("forbid", "deny") else "permit"
        self._advance()
        header = self._parse_header()
        cond = True
        if self._at_kw("when"):
            self._advance()
            self._expect("op", "{")
            cond = self._parse_expr()
            self._expect("op", "}")
        self._expect("op", ";")
        if len(header) != 3 or sorted(header) != sorted(_REQUEST_SLOTS):
            raise CedarError(
                "policy header must be (principal, action, resource)", line=line)
        return _Policy(index, effect, cond, header, line)

    def _parse_header(self):
        self._expect("op", "(")
        slots = []
        for i in range(3):
            tok = self._peek()
            if tok is None or tok[0] != "id" or tok[1] not in _REQUEST_SLOTS:
                raise CedarError(
                    "policy header must list request slots "
                    "(principal, action, resource)",
                    line=None if tok is None else tok[2])
            slots.append(self._advance()[1])
            if i < 2:
                self._expect("op", ",")
        self._expect("op", ")")
        return slots

    # -- terms and primaries ---------------------------------------------------
    def _parse_term(self):
        node = self._parse_primary()
        while self._peek_is("op", "."):
            self._advance()
            attr = self._expect("id")[1]
            node = AAttr(node, attr)
        return node

    def _parse_primary(self):
        tok = self._peek()
        if tok is None:
            raise CedarError("unexpected end of input in expression")
        kind, val, line = tok
        if kind == "op":
            if val == "(":
                self._advance()
                node = self._parse_expr()
                self._expect("op", ")")
                return node
            raise CedarError("unexpected %r in expression" % val, line=line)
        if kind == "str":
            self._advance()
            return AConst(val)
        if kind == "int":
            self._advance()
            return AConst(val)
        if val in ("true", "false"):
            self._advance()
            return AConst(val == "true")
        if val in _REQUEST_SLOTS:
            self._advance()
            return AVar(val)
        if val in self.action_names:
            self._advance()
            return AAction(val)
        if val in self.declared_types:
            nxt = self.toks[self.pos + 1] \
                if self.pos + 1 < len(self.toks) else None
            if nxt is not None and nxt[0] == "op" and nxt[1] == "::":
                self._advance()           # type name
                self._advance()           # "::"
                idtok = self._expect("str")
                return AEntity(val, idtok[1], line)
            # A bare type name is only legal as the RHS of ``is`` / ``in``;
            # _parse_cmp_rhs intercepts those, so anything else is an error.
            raise CedarError(
                "entity type %r is only valid in 'is'/'in' or as "
                "Type::\"id\"" % val, line=line)
        raise CedarError("unknown identifier %r" % val, line=line)

    # -- expression parsing (Cedar precedence) ---------------------------------
    def _peek_is(self, kind, value):
        tok = self._peek()
        return tok is not None and tok[0] == kind and tok[1] == value

    def _parse_expr(self):
        return self._parse_or()

    def _parse_or(self):
        node = self._parse_and()
        while self._peek_is("op", "||"):
            self._advance()
            node = ABin("or", node, self._parse_and())
        return node

    def _parse_and(self):
        node = self._parse_not()
        while self._peek_is("op", "&&"):
            self._advance()
            node = ABin("and", node, self._parse_not())
        return node

    def _parse_not(self):
        if self._peek_is("op", "!"):
            self._advance()
            return AUnary("not", self._parse_not())
        return self._parse_cmp()

    def _parse_cmp(self):
        node = self._parse_term()
        while True:
            tok = self._peek()
            if tok is None:
                return node
            # Comparison operators come in two token shapes:
            #   * ``== != < <= > >=`` are operator (``op``) tokens,
            #   * ``is`` / ``in`` are word (``id``) tokens (like the ``in``
            #     already accepted in ``_parse_entity``).
            if tok[0] == "op" and tok[1] in _CMP_OPS:
                op = tok[1]
            elif tok[0] == "id" and tok[1] in ("is", "in", "contains"):
                op = tok[1]
            elif tok[0] == "id" and tok[1] == "has":
                # "has <attr>": attribute presence read; holds in the model.
                self._advance()
                name = self._expect("id")[1]
                node = AHas(node, name)
                continue
            else:
                return node
            line = tok[2]
            self._advance()
            node = self._build_cmp(op, node, self._parse_cmp_rhs(op), line)

    def _build_cmp(self, op, left, right, line):
        if op == "is":
            self._check_is(left, right, line)
            return ABin("is", left, right)
        if op == "in":
            self._check_in(left, right, line)
            return ABin("in", left, right)
        if op == "contains":
            self._check_contains(left, right, line)
            return ABin("contains", left, right)
        return ABin(op, left, right)

    def _check_is(self, left, right, line):
        if not isinstance(left, (AVar, AEntity)):
            raise CedarError(
                "left of 'is' must be a request slot or entity reference",
                line=line)
        if not isinstance(right, (ATy, AEntity, AVar, AConst)):
            raise CedarError(
                "right of 'is' must be an entity type or entity reference",
                line=line)

    def _check_in(self, left, right, line):
        if not isinstance(left, (AVar, AEntity)):
            raise CedarError(
                "left of 'in' must be a request slot or entity reference",
                line=line)
        if not isinstance(right, (ATy, AEntity, AVar)):
            raise CedarError(
                "right of 'in' must be an entity type, entity reference, "
                "or request slot", line=line)

    def _check_contains(self, left, right, line):
        if not isinstance(left, (AAttr, AEntity, AVar)):
            raise CedarError(
                "left of 'contains' must be an attribute, entity, or slot",
                line=line)
        if not isinstance(right, (AConst, AEntity, AVar, AAction)):
            raise CedarError(
                "right of 'contains' must be a value", line=line)

    def _parse_cmp_rhs(self, op):
        """Right-hand side of a comparison. ``is``/``in`` may take a bare
        entity type name, which is only a value in those positions."""
        if op in ("is", "in"):
            tok = self._peek()
            if (tok is not None and tok[0] == "id"
                    and tok[1] in self.declared_types):
                self._advance()
                return ATy(tok[1], tok[2])
        return self._parse_term()


# ---------------------------------------------------------------------------
# Bounded semantics: entity sets, universes, attribute domains
# ---------------------------------------------------------------------------

#: Representative value when a program has no entities or types at all.
_UNIVERSE_FALLBACK = "_unmodelled_entity_"
#: Representative value when a program has no declared actions.
_ACTION_FALLBACK = "_unmodelled_action_"

#: Sentinel: an attribute is compared against another attribute read.
_CROSS = object()


def _entity_key(node):
    """Canonical state value of an entity reference ``Type::"id"``."""
    return '%s::"%s"' % (node.type_name, node.entity_id)


def _attr_name(node):
    """Canonical name of the existential variable backing an attribute read.

    ``resource.owner``            -> "resource.owner"
    ``User::"a1".balance``        -> 'User::"a1".balance'
    ``resource.owner.name``       -> "resource.owner.name"
    """
    if isinstance(node.base, AVar):
        base = node.base.name
    elif isinstance(node.base, AEntity):
        base = _entity_key(node.base)
    else:  # AAttr: chained read
        base = _attr_name(node.base)
    return base + "." + node.name


def _collect_refs(node, refs, attr_names):
    """Walk a condition AST, recording entity refs and attribute reads.

    ``refs`` maps canonical entity keys to their declared type name;
    ``attr_names`` collects the canonical attribute variable names.
    """
    if node is None or node is True:
        return
    if isinstance(node, (AConst, AVar, AAction, ATy)):
        return
    if isinstance(node, AEntity):
        refs[_entity_key(node)] = node.type_name
        return
    if isinstance(node, AAttr):
        attr_names.add(_attr_name(node))
        _collect_refs(node.base, refs, attr_names)
        return
    if isinstance(node, AHas):
        # "has" presence reads hold in the model; no variable is needed.
        _collect_refs(node.base, refs, attr_names)
        return
    if isinstance(node, AUnary):
        _collect_refs(node.child, refs, attr_names)
        return
    if isinstance(node, ABin):
        _collect_refs(node.left, refs, attr_names)
        _collect_refs(node.right, refs, attr_names)
        return
    raise CedarError("cannot collect refs from node %r" % (node,))


class _Semantics(object):
    """Bounded-model entity semantics over the declared type hierarchy.

    A type name denotes the set {type} plus one representative entity per
    declared type under it (plus any entity refs of that type). An entity
    reference ``Type::"id"`` heads its own subtree: the reference itself
    plus everything its declared type denotes.
    """

    def __init__(self, declared_types, entity_refs):
        self.types = dict(declared_types)        # name -> (super, line)
        self.entity_type = dict(entity_refs)     # entity key -> type name

    def subtypes(self, t):
        """``t`` plus every declared type transitively under it."""
        out = set([t])
        changed = True
        while changed:
            changed = False
            for name, (sup, _line) in self.types.items():
                if sup in out and name not in out:
                    out.add(name)
                    changed = True
        return out

    def is_set(self, t):
        """Entities of exactly type ``t`` (plus ``t``'s representative)."""
        s = set([t])
        for key, ty in self.entity_type.items():
            if ty == t:
                s.add(key)
        return s

    def in_set(self, t):
        """``t`` and its subtypes, plus every entity of those types."""
        subs = self.subtypes(t)
        s = set(subs)
        for key, ty in self.entity_type.items():
            if ty in subs:
                s.add(key)
        return s

    def entity_subtree(self, ekey):
        """An entity reference plus the whole subtree it heads."""
        ty = self.entity_type.get(ekey)
        s = set([ekey])
        if ty is not None:
            s.update(self.in_set(ty))
        return s


def _values_of(node, out):
    """Collect the values an operand expression can denote (sentinel-marked).

    Attribute reads compare against other attributes (``_CROSS``); slot
    reads (principal/action/resource) range over the request universe
    (``REQUEST_UNIVERSE``); everything else denotes its literal value.
    """
    if isinstance(node, AConst):
        out.add(node.value)
    elif isinstance(node, AEntity):
        out.add(_entity_key(node))
    elif isinstance(node, AAction):
        out.add(node.name)
    elif isinstance(node, ATy):
        out.add(node.name)
    elif isinstance(node, AVar):
        out.add(REQUEST_UNIVERSE)
    elif isinstance(node, AAttr):
        out.add(_CROSS)
    else:  # AUnary / ABin operand: could denote any slot value
        out.add(REQUEST_UNIVERSE)


def _collect_cmp_values(node, attr, out):
    """Gather every value ``attr`` is compared against, across the AST.

    Only ``== != < <= > >=`` comparisons contribute values; ``and``/``or``
    chains are walked recursively.
    """
    if node is None or node is True or not isinstance(node, (AUnary, ABin)):
        return
    if isinstance(node, ABin):
        if node.op in ("==", "!=", "<", "<=", ">", ">=", "contains"):
            if isinstance(node.left, AAttr) and _attr_name(node.left) == attr:
                _values_of(node.right, out)
            if isinstance(node.right, AAttr) and _attr_name(node.right) == attr:
                _values_of(node.left, out)
        _collect_cmp_values(node.left, attr, out)
        _collect_cmp_values(node.right, attr, out)
        return
    _collect_cmp_values(node.child, attr, out)


def _attr_domain(attr, policies, slot_domain, action_names):
    """Domain for one existential attribute variable.

    Values come from the literals the attribute is compared against; a
    comparison against a slot adds the whole request universe (slot
    values plus action names); a comparison against another attribute
    adds the cross-attribute sentinels ``0`` and ``1``. Falls back to
    ``Bool`` when the attribute is never compared against a value.
    """
    vals = set()
    for p in policies:
        _collect_cmp_values(p.cond, attr, vals)
    base = set(v for v in vals
               if v is not REQUEST_UNIVERSE and v is not _CROSS)
    if REQUEST_UNIVERSE in vals:
        base.update(slot_domain)
        base.update(action_names)
    if _CROSS in vals:
        base.add(0)
        base.add(1)
    if not base:
        return ir.Bool()
    if all(isinstance(v, int) and not isinstance(v, bool) for v in base):
        return ir.IntRange(min(base) - 1, max(base) + 1)
    ordered = sorted(base, key=lambda v: (type(v).__name__, str(v)))
    return ir.Enum(ordered)


def _domain_values(domain):
    """Expand an IR domain into its concrete value list (front-end-local).

    ``rot.modelfind`` owns domain enumeration for its own purposes; the
    staged protocol must know its action set at build time, so the
    front-end expands the domains it chose itself.
    """
    if isinstance(domain, ir.IntRange):
        return list(range(domain.lo, domain.hi + 1))
    if isinstance(domain, ir.Bool):
        return [True, False]
    if isinstance(domain, ir.Enum):
        return list(domain.values)
    if isinstance(domain, (list, tuple)):
        return list(domain)
    return list(domain)

class _Builder(object):
    """Lower a parsed Cedar program to a ``rot.ir.ProtocolIR``.

    The request is exposed as existential state variables (``principal``,
    ``action``, ``resource`` plus one per attribute read) and the choice of
    each is linearised as a staged family of actions.  A final ``decide``
    action evaluates the policy set -- forbid overrides permit, default deny
    -- and writes the ``decision`` variable (``True`` = permitted).

    Every ``Var`` referenced in a guard or an effect is written by the
    initial action or by a preceding staged pick, so every guard/effect
    expression evaluates concretely (no ``Expr.UNDEF``) in the state where
    it fires, as required by the model finder / SAT engine.
    """

    def __init__(self, policies, universe, action_names, semantics, attr_vars):
        self.policies = policies
        self.universe = universe              # ordered entity values
        self.action_names = action_names      # ordered action names
        self.sem = semantics
        self.attr_vars = attr_vars            # attr name -> ir domain
        self.attr_exprs = {}
        for name in attr_vars:
            self.attr_exprs[name] = ir.Var(name)

    # -- condition denotation -------------------------------------------

    def eval(self, node):
        """Return the IR expression denoting a condition AST node."""
        if node is True:
            return ir.T()
        if node is False:
            return ir.F()
        if isinstance(node, AConst):
            return ir.C(node.value)
        if isinstance(node, AVar):
            return ir.Var(node.name)
        if isinstance(node, AEntity):
            return ir.C(_entity_key(node))
        if isinstance(node, AAction):
            return ir.C(node.name)
        if isinstance(node, ATy):
            return ir.C(node.name)
        if isinstance(node, AHas):
            # Presence reads hold in the bounded model.
            return ir.T()
        if isinstance(node, AAttr):
            name = _attr_name(node)
            if name in self.attr_exprs:
                return self.attr_exprs[name]
            return ir.C(0)
        if isinstance(node, AUnary):
            return ir.Not(self.eval(node.child))
        if isinstance(node, ABin):
            return self._bin(node)
        raise CedarError("cannot lower node %r to IR" % (node,))

    def _bin(self, node):
        """Map a binary condition node onto IR expressions."""
        op = node.op
        if op == "and":
            return ir.And(self.eval(node.left), self.eval(node.right))
        if op == "or":
            return ir.Or(self.eval(node.left), self.eval(node.right))
        if op == "is" or op == "in":
            return self._membership(node)
        left = self.eval(node.left)
        right = self.eval(node.right)
        if op in ("==", "contains"):
            # ``contains`` is a bounded set-membership read; with scalar
            # attribute variables it reduces to equality (the attribute
            # holds the value).
            return ir.BinOp("=", left, right)
        if op == "!=":
            return ir.BinOp("!=", left, right)
        if op == "<":
            return ir.BinOp("<", left, right)
        if op == "<=":
            return ir.BinOp("<=", left, right)
        if op == ">":
            return ir.BinOp(">", left, right)
        if op == ">=":
            return ir.BinOp(">=", left, right)
        raise CedarError("unsupported operator %r" % (op,))

    def _membership(self, node):
        """Expand ``x is T`` / ``x in Y`` into a disjunction of equalities.

        Membership is bounded to the declared sets: ``is T`` ranges over
        ``sem.is_set(T)`` and ``in Y`` over ``sem.entity_subtree(Y)`` /
        ``sem.in_set(T)``.
        """
        left = self.eval(node.left)
        members = self._membership_set(node)
        if not members:
            return ir.F()
        clauses = [ir.eq(left, ir.C(m)) for m in sorted(members, key=str)]
        return ir.Or(*clauses)

    def _membership_set(self, node):
        """Concrete member set for an ``is``/``in`` RHS, bounded to the
        declared types and referenced entities."""
        right = node.right
        if node.op == "is":
            if isinstance(right, ATy):
                return self.sem.is_set(right.name)
            if isinstance(right, AEntity):
                ty = self.sem.entity_type.get(_entity_key(right))
                if ty is not None:
                    return self.sem.is_set(ty)
                return set([_entity_key(right)])
            if isinstance(right, (AVar, AConst, AAction)):
                return set([self._concrete(right)])
            return set()
        # op == "in"
        if isinstance(right, AEntity):
            return self.sem.entity_subtree(_entity_key(right))
        if isinstance(right, ATy):
            return self.sem.in_set(right.name)
        if isinstance(right, (AVar, AConst, AAction)):
            return set([self._concrete(right)])
        return set()

    @staticmethod
    def _concrete(node):
        """Best-effort concrete value for a node used as a membership set."""
        if isinstance(node, AConst):
            return node.value
        if isinstance(node, AVar):
            return node.name
        if isinstance(node, AEntity):
            return _entity_key(node)
        if isinstance(node, AAction):
            return node.name
        return node
    # -- IR assembly ------------------------------------------------------

    def build(self):
        """Assemble and return the ``ProtocolIR`` for the program."""
        last_stage = 3 + len(self.attr_vars)

        variables = [
            ir.StateVar("stage", ir.IntRange(0, last_stage),
                        mode=ir.MODE_PRECISE, desc="choice staging counter"),
            ir.StateVar("principal", ir.Enum(self.universe),
                        mode=ir.MODE_EXISTENTIAL, desc="request principal"),
            ir.StateVar("action", ir.Enum(self.action_names),
                        mode=ir.MODE_EXISTENTIAL, desc="request action"),
            ir.StateVar("resource", ir.Enum(self.universe),
                        mode=ir.MODE_EXISTENTIAL, desc="request resource"),
        ]
        for name in sorted(self.attr_vars):
            variables.append(ir.StateVar(
                name, self.attr_vars[name], mode=ir.MODE_EXISTENTIAL,
                desc="attribute value for %s" % name))
        variables.append(ir.StateVar(
            "decision", ir.Bool(), mode=ir.MODE_PRECISE,
            desc="policy decision (True = permitted)"))

        actions = [ir.Action(
            name="init", owner="cedar", is_initial=True, guard=ir.T(),
            effects=[("stage", ir.C(0)), ("decision", ir.F())])]

        stage = 0
        stage = self._pick_stage(actions, "principal", self.universe, stage)
        stage = self._pick_stage(actions, "action", self.action_names, stage)
        stage = self._pick_stage(actions, "resource", self.universe, stage)
        for name in sorted(self.attr_vars):
            stage = self._pick_stage(
                actions, name, _domain_values(self.attr_vars[name]), stage)

        # Final stage: evaluate the policy set (forbid > permit > deny).
        actions.append(ir.Action(
            name="decide", owner="cedar",
            guard=ir.eq(ir.Var("stage"), ir.C(stage)),
            effects=[("decision", self._decision_expr())]))

        return ir.ProtocolIR(
            name="cedar_policy",
            variables=variables,
            actions=actions,
            init=ir.T(),
        )

    def _pick_stage(self, actions, var, values, stage):
        """Emit one pick action per value of ``var`` at ``stage``; return
        the next stage number."""
        for v in values:
            actions.append(ir.Action(
                name="pick_%s_%s" % (var, _safe_name(v)),
                owner="cedar",
                guard=ir.eq(ir.Var("stage"), ir.C(stage)),
                effects=[(var, ir.C(v)), ("stage", ir.C(stage + 1))]))
        return stage + 1

    def _decision_expr(self):
        """IR expression for the final decision.

        Cedar is default-deny and ``forbid`` overrides ``permit``: a request
        is permitted iff some permit policy matches and no forbid policy
        matches.
        """
        permit_clauses = []
        forbid_clauses = []
        for p in self.policies:
            cond = self.eval(p.cond)
            if p.is_forbid:
                forbid_clauses.append(cond)
            else:
                permit_clauses.append(cond)
        forbid = ir.Or(*forbid_clauses) if forbid_clauses else ir.F()
        permit = ir.Or(*permit_clauses) if permit_clauses else ir.F()
        return ir.And(ir.Not(forbid), permit)


def _safe_name(value):
    """Sanitise a value into a readable IR action-name fragment."""
    s = str(value)
    out = "".join(c if (c.isalnum() or c == "_") else "_" for c in s)
    return out or "x"


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def _build_program(parser, policies):
    """Wire a parsed program (parser state + policies) into a ProtocolIR."""
    declared_types = parser.declared_types
    action_names = set(parser.action_names)
    if not action_names:
        action_names = set([_ACTION_FALLBACK])

    refs = {}
    attr_names = set()
    for p in policies:
        _collect_refs(p.cond, refs, attr_names)

    semantics = _Semantics(declared_types, refs)

    universe = set(refs.keys())
    universe.update(declared_types.keys())
    if not universe:
        universe = set([_UNIVERSE_FALLBACK])
    universe = sorted(universe)
    action_names = sorted(action_names)

    attr_vars = {}
    for name in sorted(attr_names):
        attr_vars[name] = _attr_domain(
            name, policies, set(universe), set(action_names))

    builder = _Builder(policies, universe, action_names, semantics, attr_vars)
    return builder.build()


def parse_cedar(source):
    """Parse Cedar ``source`` text into a ``rot.ir.ProtocolIR``.

    The returned IR exposes the request (``principal`` / ``action`` /
    ``resource`` plus any attribute reads) as existential state variables and
    evaluates the policy set (forbid overrides permit, default deny) into the
    ``decision`` variable, ready for ``rot.modelfind.ModelFinder`` or
    ``rot.sat``.
    """
    if not isinstance(source, str):
        raise CedarError("parse_cedar expects a source string")
    toks = tokenize(source)
    parser = _Parser(toks)
    policies = parser.parse_program()
    return _build_program(parser, policies)


def parse_cedar_file(path):
    """Read ``path`` and :func:`parse_cedar` it into a ``ProtocolIR``."""
    with open(path, "r") as fh:
        source = fh.read()
    return parse_cedar(source)

