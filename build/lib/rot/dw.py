# -*- coding: utf-8 -*-
"""A total parser for the Dogwood ``.dw`` policy surface.

This module tokenises and parses the full Cedar/Dogwood ``.dw`` policy
language -- ``permit``/``forbid`` policies, ``def temporal`` definitions,
``sum``/``count``/``exists`` aggregates, ``formerly within`` temporal
windows, namespaced action references, event maps, range filters, and
``let_`` macro calls -- producing a faithful AST.

The two shipped spend-cap fixtures (``spendcap-correct.dw`` /
``spendcap-buggy.dw``) are detected by their **spend-cap shape**
(``sum`` + ``tp(t)`` + ``<= const``) and routed to the legacy
:class:`rot.spendcap` IR so that all existing ``test_dw.py`` tests keep
passing.  Every other shape gets a faithful general IR.

Python 3.6 compatible (no f-strings, no walrus, no dataclasses).
"""

import re

import rot.spendcap as spendcap
from rot.lower import lower_policy


class DwParseError(ValueError):
    """Raised when a ``.dw`` policy cannot be parsed or is outside the
    supported subset."""


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

class Token(object):
    """A single token in the ``.dw`` token stream."""

    __slots__ = ("kind", "value", "line", "col")

    def __init__(self, kind, value, line=0, col=0):
        self.kind = kind    # "kw" | "ident" | "num" | "str" | "op" | "punct" | "time"
        self.value = value
        self.line = line
        self.col = col

    def __repr__(self):
        return "Token(%s, %r, %d:%d)" % (self.kind, self.value, self.line, self.col)

    def __eq__(self, other):
        if not isinstance(other, Token):
            return NotImplemented
        return self.kind == other.kind and self.value == other.value


_KEYWORDS = frozenset([
    "permit", "forbid", "def", "temporal", "when", "sum", "count",
    "exists", "formerly", "within", "where", "for",
    "principal", "action", "resource",
    "request", "response",
    "Long", "Timepoint",
])

# Order matters: longer / more specific patterns first.
_TOKEN_RE = re.compile(r"""
    (?P<ws>\s+)
  | (?P<comment>//[^\n]*)
  | (?P<at>@)
  | (?P<coloncolon>::)
  | (?P<op2>==|!=|<=|>=|&&|\|\|)
  | (?P<qid>\?[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op1>[+\-*/!<>=?])
  | (?P<punct>[()\[\]{}.,;:])
  | (?P<str>"[^"]*")
  | (?P<time>\d+[hmd])
  | (?P<num>\d+)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
""", re.VERBOSE)


def tokenize(text):
    """Tokenise ``.dw`` source text into a list of :class:`Token`.

    Raises :class:`DwParseError` on unexpected characters.
    """
    if not isinstance(text, str):
        raise DwParseError("expected str policy text, got %s"
                           % type(text).__name__)
    tokens = []
    line, col = 1, 1
    pos = 0
    n = len(text)
    while pos < n:
        m = _TOKEN_RE.match(text, pos)
        if m is None:
            raise DwParseError(
                "unexpected character %r at line %d, col %d"
                % (text[pos], line, col))
        kind = m.lastgroup
        value = m.group()
        if kind == "ws":
            for ch in value:
                if ch == "\n":
                    line += 1
                    col = 1
                else:
                    col += 1
            pos = m.end()
            continue
        if kind == "comment":
            for ch in value:
                if ch == "\n":
                    line += 1
                    col = 1
                else:
                    col += 1
            pos = m.end()
            continue
        if kind == "at":
            tokens.append(Token("punct", "@", line, col))
        elif kind == "coloncolon":
            tokens.append(Token("op", "::", line, col))
        elif kind == "op2":
            tokens.append(Token("op", value, line, col))
        elif kind == "op1":
            tokens.append(Token("op", value, line, col))
        elif kind == "punct":
            tokens.append(Token("punct", value, line, col))
        elif kind == "str":
            tokens.append(Token("str", value[1:-1], line, col))
        elif kind == "time":
            tokens.append(Token("time", value, line, col))
        elif kind == "num":
            tokens.append(Token("num", value, line, col))
        elif kind == "qid":
            tokens.append(Token("ident", value, line, col))
        elif kind == "ident":
            k = "kw" if value in _KEYWORDS else "ident"
            tokens.append(Token(k, value, line, col))
        col += len(value)
        pos = m.end()
    return tokens


class DwPolicy(object):
    """A parsed Dogwood spend-cap policy (the one shape this parser supports).

    Attributes
    ----------
    policy_id : str
        The ``@id("...")`` annotation value.
    action : str
        The Drupe action name, e.g. ``"Transfer"``.
    event_kind : str
        ``"request"`` (counts in-flight) or ``"response"`` (counts completed).
    cap : int
        The spend cap bound (the ``sum ... <= <cap>`` right-hand side).
    window : str or None
        The temporal window token, e.g. ``"24h"`` (kept verbatim).
    source : str or None
        Where the policy text came from (e.g. a file path), if known.
    """

    def __init__(self, policy_id, action, event_kind, cap,
                 window=None, source=None, when=None):
        if event_kind not in ("request", "response"):
            raise DwParseError(
                "unsupported event kind %r (expected 'request' or 'response')"
                % (event_kind,))
        self.policy_id = policy_id
        self.action = action
        self.event_kind = event_kind
        self.cap = int(cap)
        self.window = window
        self.source = source
        # The parsed temporal ``when`` expression (a :class:`Node`).  Carried
        # so :meth:`to_ir` can delegate to the derivation-based lowering
        # (:func:`rot.lower.lower_policy`), which reads the event kind from
        # this structure.  ``None`` when the policy was constructed directly
        # (not via :func:`extract_spendcap`).
        self.when = when

    # -- semantics ----------------------------------------------------------
    @property
    def is_buggy(self):
        """``True`` if the policy guards on ``response`` (counts completed).

        In this project's framing, the ``response`` variant under-counts (it
        ignores in-flight spends) and is therefore the "buggy" side of the
        cross-verification.
        """
        return self.event_kind == "response"

    def matches_model(self, buggy):
        """``True`` if this policy's semantics match a ``build_ir(buggy=...)`` model."""
        return self.is_buggy == bool(buggy)

    # -- bridge to the IR ---------------------------------------------------
    def to_ir(self, max_inflight=spendcap.MAX_INFLIGHT, amount=None, cap=None,
              window=None):
        """Build the :class:`rot.ir.ProtocolIR` this policy describes.

        Delegates to the derivation-based lowering
        (:func:`rot.lower.lower_policy`), which reads the event kind from the
        parsed ``when`` expression and constructs the ``StateVar``s, the
        ``spend_ok`` / ``respond`` actions (the guard is built from the event
        kind -- which term to charge), and the pinned property.

        ``max_inflight`` (``K``) parameterizes the client-side request-pool
        bound; it defaults to :data:`rot.spendcap.MAX_INFLIGHT` and is recorded
        in the IR metadata (``max_inflight``) so reports state the ``K`` a
        verdict was produced under.  ``amount`` / ``cap`` override the model's
        per-request amount and cap; ``None`` defaults ``amount`` to
        :data:`rot.spendcap.AMOUNT` and ``cap`` to this policy's own ``cap``.

        Raises:
            DwParseError: if ``cap`` is not explicitly overridden and this
                policy's ``cap`` does not match the model's canonical cap
                (:data:`rot.spendcap.CAP`).
        """
        k = spendcap.MAX_INFLIGHT if max_inflight is None else max_inflight
        amt = spendcap.AMOUNT if amount is None else amount
        w = spendcap.MAX_WINDOW if window is None else window
        if cap is None:
            if self.cap != spendcap.CAP:
                raise DwParseError(
                    "policy cap %d does not match the model's canonical cap %d; "
                    "pass cap=... to override" % (self.cap, spendcap.CAP))
            cp = self.cap
        else:
            cp = cap
        model = lower_policy(self.when, amount=amt, cap=cp, max_inflight=k,
                             window=w)
        model.metadata.update({
            "dw_policy_id": self.policy_id,
            "dw_event_kind": self.event_kind,
            "dw_cap": self.cap,
            "dw_window": self.window,
            "dw_source": self.source,
        })
        return model


    # -- introspection ------------------------------------------------------
    def summary(self):
        """A plain-dict summary (for reports / debugging)."""
        return {
            "policy_id": self.policy_id,
            "action": self.action,
            "event_kind": self.event_kind,
            "cap": self.cap,
            "window": self.window,
            "buggy": self.is_buggy,
        }

    def __repr__(self):
        return ("DwPolicy(policy_id=%r, action=%r, event_kind=%r, cap=%d, "
                "window=%r, buggy=%s)"
                % (self.policy_id, self.action, self.event_kind, self.cap,
                   self.window, self.is_buggy))


# ---------------------------------------------------------------------------
# AST node classes
# ---------------------------------------------------------------------------

class Node(object):
    """Base class for all AST nodes."""

    def _fields(self):
        return []

    def __repr__(self):
        parts = ", ".join("%s=%r" % (k, v) for k, v in self._fields())
        return "%s(%s)" % (type(self).__name__, parts)


class Num(Node):
    def __init__(self, value):
        self.value = value

    def _fields(self):
        return [("value", self.value)]


class Str(Node):
    def __init__(self, value):
        self.value = value

    def _fields(self):
        return [("value", self.value)]


class Bool(Node):
    def __init__(self, value):
        self.value = value

    def _fields(self):
        return [("value", self.value)]


class Ident(Node):
    def __init__(self, name):
        self.name = name

    def _fields(self):
        return [("name", self.name)]


class Qualified(Node):
    """A namespaced reference like ``Drupe::Action``."""

    def __init__(self, parts):
        self.parts = parts  # list of str

    def _fields(self):
        return [("parts", self.parts)]


class Dotted(Node):
    """A dotted field access like ``context.input.user``."""

    def __init__(self, parts):
        self.parts = parts  # list of str (e.g. ["context", "input", "user"])

    def _fields(self):
        return [("parts", self.parts)]


class EventRef(Node):
    """An event reference like ``Drupe::Action::"Transfer"::request{...}``."""

    def __init__(self, namespace, action, kind, fields):
        self.namespace = namespace  # list of str
        self.action = action        # str
        self.kind = kind            # str
        self.fields = fields        # list of (str, Node)

    def _fields(self):
        return [("namespace", self.namespace), ("action", self.action),
                ("kind", self.kind), ("fields", self.fields)]


class LetCall(Node):
    """A macro call like ``let_(total, <sum>, total > 1000)``."""

    def __init__(self, name, args):
        self.name = name
        self.args = args  # list of Node

    def _fields(self):
        return [("name", self.name), ("args", self.args)]


class BinaryOp(Node):
    def __init__(self, op, left, right):
        self.op = op
        self.left = left
        self.right = right

    def _fields(self):
        return [("op", self.op), ("left", self.left), ("right", self.right)]


class UnaryOp(Node):
    def __init__(self, op, operand):
        self.op = op
        self.operand = operand

    def _fields(self):
        return [("op", self.op), ("operand", self.operand)]


class Sum(Node):
    def __init__(self, summand, bindings, where):
        self.summand = summand
        self.bindings = bindings
        self.where = where

    def _fields(self):
        return [("summand", self.summand), ("bindings", self.bindings),
                ("where", self.where)]


class Count(Node):
    def __init__(self, bindings, where):
        self.bindings = bindings
        self.where = where

    def _fields(self):
        return [("bindings", self.bindings), ("where", self.where)]


class Exists(Node):
    def __init__(self, binding, body):
        self.binding = binding
        self.body = body

    def _fields(self):
        return [("binding", self.binding), ("body", self.body)]


class FormerlyWithin(Node):
    def __init__(self, window, body):
        self.window = window
        self.body = body

    def _fields(self):
        return [("window", self.window), ("body", self.body)]


def _has_aggregation(node):
    """Return ``True`` if ``node`` contains a ``sum`` or ``count`` aggregate."""
    if node is None:
        return False
    if isinstance(node, (Sum, Count)):
        return True
    if isinstance(node, BinaryOp):
        return _has_aggregation(node.left) or _has_aggregation(node.right)
    if isinstance(node, UnaryOp):
        return _has_aggregation(node.operand)
    if isinstance(node, Exists):
        return _has_aggregation(node.body)
    if isinstance(node, LetCall):
        return any(_has_aggregation(a) for a in node.args)
    if isinstance(node, FormerlyWithin):
        return _has_aggregation(node.body)
    return False


class Policy(Node):
    def __init__(self, id, effect, scope, when):
        self.id = id
        self.effect = effect
        self.scope = scope
        self.when = when

    def _fields(self):
        return [("id", self.id), ("effect", self.effect),
                ("scope", self.scope), ("when", self.when)]

    def to_ir(self, max_inflight=spendcap.MAX_INFLIGHT, amount=None, cap=None,
              window=None):
        """Lower this policy to the :class:`rot.ir.ProtocolIR`.

        Delegates to the derivation-based lowering
        (:func:`rot.lower.lower_policy`), which reads the event kind from the
        parsed ``when`` expression and constructs the ``StateVar``s, the
        ``spend_ok`` / ``respond`` actions (the guard is built from the event
        kind -- which term to charge), and the pinned property.

        ``max_inflight`` (``K``) is the client-side request-pool bound;
        ``None`` defaults to :data:`rot.spendcap.MAX_INFLIGHT` (4).  ``amount``
        / ``cap`` override the model's per-request amount and cap; ``None``
        defaults to :data:`rot.spendcap.AMOUNT` / :data:`rot.spendcap.CAP`.
        All are passed through to :func:`rot.lower.lower_policy` and recorded
        in the IR metadata.
        """
        k = spendcap.MAX_INFLIGHT if max_inflight is None else max_inflight
        amt = spendcap.AMOUNT if amount is None else amount
        cp = spendcap.CAP if cap is None else cap
        w = spendcap.MAX_WINDOW if window is None else window
        model = lower_policy(self.when, amount=amt, cap=cp, max_inflight=k,
                             window=w)
        event_ref = _find_event_ref(self.when)
        model.metadata.update({
            "dw_policy_id": self.id,
            "dw_effect": self.effect,
            "dw_event_kind": event_ref.kind if event_ref else None,
        })
        return model


class Def(Node):
    def __init__(self, name, params, body):
        self.name = name
        self.params = params
        self.body = body

    def _fields(self):
        return [("name", self.name), ("params", self.params), ("body", self.body)]


class Document(Node):
    def __init__(self, policies, defs, source=None):
        self.policies = policies
        self.defs = defs
        self.source = source

    def _fields(self):
        return [("policies", self.policies), ("defs", self.defs),
                ("source", self.source)]

    def to_ir(self, max_inflight=spendcap.MAX_INFLIGHT, amount=None, cap=None,
              window=None):
        """Lower this document to the :class:`rot.ir.ProtocolIR`.

        Finds the policy with a ``sum``/``count`` aggregate (the spend-cap
        decision) and lowers it via the derivation-based lowering
        (:func:`rot.lower.lower_policy`).  Falls back to the first policy if
        none has an aggregate, and to the "correct" model if there are no
        policies.

        ``max_inflight`` (``K``) is the client-side request-pool bound;
        ``None`` defaults to :data:`rot.spendcap.MAX_INFLIGHT` (4).  ``amount``
        / ``cap`` override the model's per-request amount and cap; ``None``
        defaults to :data:`rot.spendcap.AMOUNT` / :data:`rot.spendcap.CAP`.
        All are passed through to :func:`rot.lower.lower_policy` and recorded
        in the IR metadata.
        """
        k = spendcap.MAX_INFLIGHT if max_inflight is None else max_inflight
        amt = spendcap.AMOUNT if amount is None else amount
        cp = spendcap.CAP if cap is None else cap
        w = spendcap.MAX_WINDOW if window is None else window
        policy = None
        for p in self.policies:
            if _has_aggregation(p.when):
                policy = p
                break
        if policy is None:
            policy = self.policies[0] if self.policies else None
        when = policy.when if policy is not None else None
        model = lower_policy(when, amount=amt, cap=cp, max_inflight=k,
                             window=w)
        event_ref = _find_event_ref(when) if when else None
        model.metadata.update({
            "dw_policy_id": policy.id if policy else None,
            "dw_effect": policy.effect if policy else None,
            "dw_event_kind": event_ref.kind if event_ref else None,
            "dw_source": self.source,
        })
        return model


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class Parser(object):
    """A recursive-descent parser for the ``.dw`` policy language."""

    def __init__(self, tokens, source=None):
        self.tokens = tokens
        self.pos = 0
        self.source = source

    def peek(self, offset=0):
        idx = self.pos + offset
        if idx < len(self.tokens):
            return self.tokens[idx]
        return None

    def advance(self):
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def at_end(self):
        return self.pos >= len(self.tokens)

    def expect(self, kind, value=None):
        tok = self.peek()
        if tok is None:
            raise DwParseError("unexpected end of input (expected %s)"
                               % (value or kind))
        if tok.kind != kind or (value is not None and tok.value != value):
            raise DwParseError(
                "expected %s but got %r (line %d, col %d)"
                % (value or kind, tok.value, tok.line, tok.col))
        return self.advance()

    def match(self, kind, value=None):
        tok = self.peek()
        if tok is not None and tok.kind == kind and (value is None or tok.value == value):
            return self.advance()
        return None

    # -- top-level ----------------------------------------------------------

    def parse_document(self):
        policies = []
        defs = []
        while not self.at_end():
            tok = self.peek()
            # An @id("...") annotation may precede a policy statement.
            pre_id = None
            if tok.kind == "punct" and tok.value == "@":
                pre_id = self.parse_id_annotation()
                tok = self.peek()
            if tok.kind == "kw" and tok.value == "def":
                defs.append(self.parse_def())
            elif tok.kind == "kw" and tok.value in ("permit", "forbid"):
                policies.append(self.parse_policy_stmt(pre_id=pre_id))
            else:
                raise DwParseError(
                    "expected 'def' or 'permit'/'forbid' but got %r "
                    "(line %d, col %d)" % (tok.value, tok.line, tok.col))
        return Document(policies=policies, defs=defs, source=self.source)

    def parse_id_annotation(self):
        """Parse an ``@id("...")`` annotation and return its string value."""
        self.expect("punct", "@")
        self.expect("ident", "id")
        self.expect("punct", "(")
        policy_id = self.expect("str").value
        self.expect("punct", ")")
        return policy_id

    def parse_name_token(self):
        """Accept an identifier *or* keyword token as a name.

        Type names (``Long``/``Timepoint``) and event kinds (``request``/
        ``response``) are classified as keywords by the tokenizer, but they
        legitimately appear where a plain name is expected (binding type
        annotations, ``::``-qualified segments, etc.).
        """
        tok = self.peek()
        if tok is None:
            raise DwParseError("unexpected end of input (expected a name)")
        if tok.kind not in ("ident", "kw"):
            raise DwParseError(
                "expected a name but got %r (line %d, col %d)"
                % (tok.value, tok.line, tok.col))
        return self.advance().value

    def parse_def(self):
        self.expect("kw", "def")
        self.expect("kw", "temporal")
        name = self.expect("ident").value
        self.expect("punct", "(")
        params = []
        if not (self.peek().kind == "punct" and self.peek().value == ")"):
            while True:
                tok = self.peek()
                if tok.kind == "ident" and tok.value.startswith("?"):
                    self.advance()
                    params.append(tok.value[1:])
                else:
                    raise DwParseError(
                        "expected param but got %r (line %d, col %d)"
                        % (tok.value, tok.line, tok.col))
                if self.match("punct", ","):
                    continue
                break
        self.expect("punct", ")")
        self.expect("punct", "{")
        body = self.parse_temporal_expr()
        self.expect("punct", "}")
        self.expect("punct", ";")
        return Def(name=name, params=params, body=body)

    def parse_policy_stmt(self, pre_id=None):
        effect = self.advance().value  # "permit" or "forbid"
        self.expect("punct", "(")
        scope = []
        if not (self.peek().kind == "punct" and self.peek().value == ")"):
            while True:
                scope.append(self.parse_scope_item())
                if self.match("punct", ","):
                    continue
                break
        self.expect("punct", ")")

        # Optional @id annotation: either already parsed by the caller
        # (when it preceded the policy keyword) or written inline here.
        policy_id = pre_id
        if policy_id is None and self.peek() is not None \
                and self.peek().kind == "punct" and self.peek().value == "@":
            policy_id = self.parse_id_annotation()

        self.expect("kw", "when")
        self.expect("kw", "temporal")
        self.expect("punct", "{")
        when = self.parse_temporal_expr()
        self.expect("punct", "}")
        self.expect("punct", ";")
        return Policy(id=policy_id, effect=effect, scope=scope, when=when)

    def parse_scope_item(self):
        """Parse a scope item: ``principal``, ``action == Drupe::Action::"Read"``,
        or ``resource``."""
        tok = self.peek()
        if tok.kind == "kw" and tok.value in ("principal", "resource"):
            self.advance()
            return Ident(tok.value)
        if tok.kind == "kw" and tok.value == "action":
            self.advance()
            self.expect("op", "==")
            parts = []
            parts.append(self.parse_name_token())
            while self.peek() is not None and self.peek().kind == "op" and self.peek().value == "::":
                self.advance()
                nxt = self.peek()
                if nxt.kind == "str":
                    self.advance()
                    parts.append(nxt.value)
                else:
                    parts.append(self.parse_name_token())
            return BinaryOp("==", Ident("action"), Qualified(parts))
        raise DwParseError(
            "expected scope item but got %r (line %d, col %d)"
            % (tok.value, tok.line, tok.col))

    # -- temporal expressions -----------------------------------------------

    def parse_temporal_expr(self):
        """Parse a temporal expression (the body of ``when temporal { ... }``)."""
        return self.parse_or()

    def parse_or(self):
        left = self.parse_and()
        while self.peek() is not None and self.peek().kind == "op" and self.peek().value == "||":
            self.advance()
            right = self.parse_and()
            left = BinaryOp("||", left, right)
        return left

    def parse_and(self):
        left = self.parse_comparison()
        while self.peek() is not None and self.peek().kind == "op" and self.peek().value == "&&":
            self.advance()
            right = self.parse_comparison()
            left = BinaryOp("&&", left, right)
        return left

    def parse_comparison(self):
        left = self.parse_additive()
        tok = self.peek()
        if tok is not None and tok.kind == "op" and tok.value in ("==", "!=", "<=", ">=", "<", ">"):
            self.advance()
            right = self.parse_additive()
            return BinaryOp(tok.value, left, right)
        return left

    def parse_additive(self):
        left = self.parse_multiplicative()
        while self.peek() is not None and self.peek().kind == "op" and self.peek().value in ("+", "-"):
            op = self.advance().value
            right = self.parse_multiplicative()
            left = BinaryOp(op, left, right)
        return left

    def parse_multiplicative(self):
        left = self.parse_unary()
        while self.peek() is not None and self.peek().kind == "op" and self.peek().value in ("*", "/"):
            op = self.advance().value
            right = self.parse_unary()
            left = BinaryOp(op, left, right)
        return left

    def parse_unary(self):
        tok = self.peek()
        if tok is not None and tok.kind == "op" and tok.value in ("!", "-"):
            self.advance()
            operand = self.parse_unary()
            return UnaryOp(tok.value, operand)
        return self.parse_primary()

    def parse_primary(self):
        tok = self.peek()
        if tok is None:
            raise DwParseError("unexpected end of input (expected expression)")

        # Parenthesized expression.
        if tok.kind == "punct" and tok.value == "(":
            self.advance()
            expr = self.parse_or()
            self.expect("punct", ")")
            return expr

        # Numeric literal.
        if tok.kind == "num":
            self.advance()
            return Num(tok.value)

        # String literal.
        if tok.kind == "str":
            self.advance()
            return Str(tok.value)

        # Time literal (e.g. "1h").
        if tok.kind == "time":
            self.advance()
            return Str(tok.value)

        # Keywords that start expressions.
        if tok.kind == "kw":
            if tok.value == "sum":
                return self.parse_sum()
            if tok.value == "count":
                return self.parse_count()
            if tok.value == "exists":
                return self.parse_exists()
            if tok.value == "formerly":
                return self.parse_formerly()
            if tok.value in ("true", "false"):
                self.advance()
                return Bool(tok.value == "true")

        # Identifier (possibly qualified, possibly an event ref, possibly a let_ call).
        if tok.kind == "ident":
            return self.parse_ident_expr()

        raise DwParseError(
            "expected expression but got %r (line %d, col %d)"
            % (tok.value, tok.line, tok.col))

    # -- aggregates & bindings ----------------------------------------------

    def parse_sum(self):
        self.expect("kw", "sum")
        summand = self.parse_primary()
        self.expect("kw", "for")
        bindings = self.parse_bindings()
        self.expect("punct", ".")
        self.expect("kw", "where")
        where = self.parse_or()
        return Sum(summand=summand, bindings=bindings, where=where)

    def parse_count(self):
        self.expect("kw", "count")
        self.expect("kw", "for")
        bindings = self.parse_bindings()
        self.expect("punct", ".")
        self.expect("kw", "where")
        where = self.parse_or()
        return Count(bindings=bindings, where=where)

    def parse_exists(self):
        self.expect("kw", "exists")
        self.expect("punct", "(")
        name = self.parse_name_token()
        self.expect("punct", ":")
        type_name = self.parse_name_token()
        self.expect("punct", ")")
        self.expect("punct", ".")
        body = self.parse_or()
        return Exists(binding=(name, type_name), body=body)

    def parse_formerly(self):
        self.expect("kw", "formerly")
        self.expect("kw", "within")
        window = self.expect("time").value
        body = self.parse_or()
        return FormerlyWithin(window=window, body=body)

    def parse_bindings(self):
        """Parse a comma-separated list of individually-parenthesized bindings:
        ``(a: Long), (t: Timepoint)`` (or a single ``(a: Long)``)."""
        bindings = []
        while True:
            self.expect("punct", "(")
            name = self.parse_name_token()
            self.expect("punct", ":")
            type_name = self.parse_name_token()
            self.expect("punct", ")")
            bindings.append((name, type_name))
            if self.match("punct", ","):
                continue
            break
        return bindings

    def parse_ident_expr(self):
        """Parse an identifier expression.

        Handles dotted field access (``context.input.user``), ``::``-qualified
        names (``Drupe::Action``), event references
        (``Drupe::Action::"Transfer"::request{...}``, including empty ``{}``),
        ``let_`` macro calls, and plain identifiers.
        """
        base = self.expect("ident").value

        # Dotted field access (e.g. context.input.user).
        if (self.peek() is not None and self.peek().kind == "punct"
                and self.peek().value == "."):
            parts = [base]
            while (self.peek() is not None and self.peek().kind == "punct"
                    and self.peek().value == "."):
                self.advance()
                parts.append(self.expect("ident").value)
            return Dotted(parts)

        parts = [base]

        # Check for qualified name (e.g. Drupe::Action).
        while self.peek() is not None and self.peek().kind == "op" and self.peek().value == "::":
            self.advance()
            nxt = self.peek()
            if nxt.kind == "str":
                self.advance()
                parts.append(nxt.value)
            else:
                parts.append(self.parse_name_token())

        # Check for event ref (e.g. Drupe::Action::"Transfer"::request{...}).
        if (len(parts) >= 3 and isinstance(parts[-1], str)
                and parts[-1] in ("request", "response")):
            # This is an event ref.
            namespace = parts[:-2]
            action = parts[-2]
            kind = parts[-1]
            fields = []
            if self.peek() is not None and self.peek().kind == "punct" and self.peek().value == "{":
                self.advance()
                # The field map may be empty (e.g. ``response{}``).
                if not (self.peek() is not None and self.peek().kind == "punct" and self.peek().value == "}"):
                    while True:
                        field_name = self.expect("ident").value
                        # Parse dotted field name (e.g. input.user).
                        while self.peek() is not None and self.peek().kind == "punct" and self.peek().value == ".":
                            self.advance()
                            field_name += "." + self.expect("ident").value
                        self.expect("punct", ":")
                        field_value = self.parse_or()
                        fields.append((field_name, field_value))
                        if self.match("punct", ","):
                            continue
                        break
                self.expect("punct", "}")
            return EventRef(namespace=namespace, action=action, kind=kind, fields=fields)

        # Check for let_ call (e.g. let_(total, <sum>, total > 1000)).
        if len(parts) == 1 and self.peek() is not None and self.peek().kind == "punct" and self.peek().value == "(":
            self.advance()
            args = []
            if not (self.peek().kind == "punct" and self.peek().value == ")"):
                while True:
                    args.append(self.parse_or())
                    if self.match("punct", ","):
                        continue
                    break
            self.expect("punct", ")")
            return LetCall(name=parts[0], args=args)

        # Qualified name.
        if len(parts) > 1:
            return Qualified(parts)

        # Simple identifier.
        return Ident(parts[0])


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_document(text, source=None):
    """Parse a ``.dw`` document into a :class:`Document` AST."""
    if not isinstance(text, str):
        raise DwParseError("expected str policy text, got %s" % type(text).__name__)
    tokens = tokenize(text)
    parser = Parser(tokens, source=source)
    return parser.parse_document()


def _find_event_ref(node):
    """Recursively find the first :class:`EventRef` in an AST node."""
    if isinstance(node, EventRef):
        return node
    if isinstance(node, BinaryOp):
        left = _find_event_ref(node.left)
        if left is not None:
            return left
        return _find_event_ref(node.right)
    if isinstance(node, UnaryOp):
        return _find_event_ref(node.operand)
    if isinstance(node, Sum):
        return _find_event_ref(node.where)
    if isinstance(node, Count):
        return _find_event_ref(node.where)
    if isinstance(node, Exists):
        return _find_event_ref(node.body)
    if isinstance(node, FormerlyWithin):
        return _find_event_ref(node.body)
    if isinstance(node, LetCall):
        for arg in node.args:
            ref = _find_event_ref(arg)
            if ref is not None:
                return ref
    return None


def extract_spendcap(doc):
    """Extract a :class:`DwPolicy` from a :class:`Document` if it's a spend-cap shape.

    Returns ``None`` if the document is not a spend-cap shape.
    Raises :class:`DwParseError` if the document is a spend-cap shape but the
    event kind is invalid.
    """
    if not isinstance(doc, Document):
        return None
    if len(doc.policies) != 1 or doc.defs:
        return None
    policy = doc.policies[0]
    when = policy.when
    if not isinstance(when, BinaryOp) or when.op not in ("<=", ">=", "<", ">", "=="):
        return None
    left = when.left
    right = when.right
    if not isinstance(left, Sum):
        return None
    if not isinstance(right, Num):
        return None
    cap = int(right.value)
    where = left.where
    if not isinstance(where, FormerlyWithin):
        return None
    window = where.window
    body = where.body
    event_ref = _find_event_ref(body)
    if event_ref is None:
        return None
    action = event_ref.action
    event_kind = event_ref.kind
    if not policy.id:
        return None
    # At this point, the policy is a spend-cap shape.
    # Create the DwPolicy (which validates the event kind).  The parsed
    # ``when`` expression is carried so :meth:`DwPolicy.to_ir` can delegate to
    # the derivation-based lowering (:func:`rot.lower.lower_policy`).
    return DwPolicy(
        policy_id=policy.id,
        action=action,
        event_kind=event_kind,
        cap=cap,
        window=window,
        source=doc.source,
        when=when,
    )


def parse_policy(text, source=None):
    """Parse a Dogwood policy from ``text``.

    If the policy is a spend-cap shape, returns a :class:`DwPolicy`.
    Otherwise, returns a :class:`Document` AST.

    ``source`` (optional) records where the text came from (e.g. a file path).

    Raises:
        DwParseError: if the policy cannot be parsed or is invalid.
    """
    if not isinstance(text, str):
        raise DwParseError("expected str policy text, got %s" % type(text).__name__)
    doc = parse_document(text, source=source)
    # If the document is a single policy (no defs), it's a spend-cap shape.
    if len(doc.policies) == 1 and not doc.defs:
        policy = doc.policies[0]
        if not policy.id:
            raise DwParseError("missing @id annotation")
        # Try to extract a DwPolicy.
        dw_policy = extract_spendcap(doc)
        if dw_policy is not None:
            return dw_policy
        # If it's not a spend-cap shape, return the policy.
        return policy
    return doc


def parse_file(path):
    """Parse a Dogwood ``.dw`` policy file."""
    with open(path, "r") as f:
        text = f.read()
    return parse_policy(text, source=str(path))