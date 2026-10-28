# -*- coding: utf-8 -*-
"""Derivation-based lowering: a parsed ``.dw`` temporal policy -> ``ProtocolIR``.

This is the **production** lowering path (Phase 2).  It reads the parsed
structure and *constructs* the :class:`rot.ir.ProtocolIR`: the ``StateVar``s,
the actions (event-arrival transitions + decision actions), and the pinned
property.

Supported shapes (detected by duck-typed traversal of the ``.dw`` AST):

1. **Spend-cap** (``Sum + <= cap`` with ``input.amount`` binding):
   the original shape; the event kind (``request`` / ``response``) drives
   the decision rule (in-flight vs. settled-only accounting).

2. **Count-window arithmetic** (``Count - Count < cap``):
   e.g. ``cap_open_agent_prs_windowed`` -- a cap on concurrently open PRs,
   measured as opens minus completed reviews in a time window.

3. **Filtered sum** (``Exists(total, Sum == total && total > cap)``):
   e.g. corpus ``0299`` / ``0301`` -- a forbid rule on the total transfer
   amount in a window, optionally filtered by ``context.`` bindings.

4. **Refund budget** (``Sum + context.input.amount <= cap``):
   e.g. ``refund_budget_settled_plus_current`` -- a cap on settled refunds
   plus the current request's amount.

5. **Taint-egress** (``formerly within <window> <event>``):
   a bare temporal *trigger* predicate (not wrapped in an aggregate and not
   compared to a cap) -- the thesis's "never contact outsiders after touching
   confidential data" shape (temporal + data-dependent).  The trigger event
   taints the agent's context; the policy's scope names the egress action
   that is forbidden while the taint is held.

:func:`rot.spendcap.build_ir` (``buggy=...``) is retained as a **test oracle**
for shape 1 -- the expected output this lowering must reproduce -- not the
production path.  The two are asserted equal in ``tests/test_dw.py``
(``test_to_ir_matches_spendcap_build_ir``).

The module deliberately does **not** import :mod:`rot.dw` (which imports this
module) -- it locates nodes by duck-typed traversal of the ``.dw`` AST.

Python 3.6 compatible (no f-strings, no walrus, no dataclasses).
"""

import rot.ir as ir
import rot.spendcap as spendcap

__all__ = ["lower_policy"]


def _find_event_kind(node):
    """Locate the first event reference's ``.kind`` in a ``.dw`` ``when`` tree.

    Duck-typed on purpose: an event reference is the first node that carries
    both a ``kind`` and an ``action`` attribute (the :class:`rot.dw.EventRef`
    shape).  We recurse through the known child slots of the ``.dw`` AST node
    classes (``BinaryOp`` / ``UnaryOp`` / ``Sum`` / ``Count`` / ``Exists`` /
    ``FormerlyWithin`` / ``LetCall``) without importing :mod:`rot.dw`, which
    would create a circular import (``rot.dw`` imports this module).

    Returns the ``kind`` string (``"request"`` / ``"response"``) or ``None``
    if no event reference is present.
    """
    if node is None:
        return None
    kind = getattr(node, "kind", None)
    if kind is not None and getattr(node, "action", None) is not None:
        return kind
    for attr in ("left", "right", "operand", "where", "body",
                 "summand", "args", "coll"):
        child = getattr(node, attr, None)
        if child is None:
            continue
        if isinstance(child, (list, tuple)):
            for item in child:
                found = _find_event_kind(item)
                if found is not None:
                    return found
        else:
            found = _find_event_kind(child)
            if found is not None:
                return found
    return None


def _find_window(node):
    """Locate the first ``FormerlyWithin`` window token in a ``.dw`` ``when`` tree.

    Duck-typed on purpose: a window token is the first node that carries a
    non-``None`` ``window`` attribute (the :class:`rot.dw.FormerlyWithin`
    shape, e.g. ``"24h"``).  We recurse through the known child slots of the
    ``.dw`` AST node classes (``BinaryOp`` / ``UnaryOp`` / ``Sum`` / ``Count``
    / ``Exists`` / ``FormerlyWithin`` / ``LetCall``) without importing
    :mod:`rot.dw`, which would create a circular import (``rot.dw`` imports
    this module).

    Returns the window token (e.g. ``"24h"``) or ``None`` if no
    ``FormerlyWithin`` node is present (the policy is not time-bounded).
    """
    if node is None:
        return None
    window = getattr(node, "window", None)
    if window is not None:
        return window
    for attr in ("left", "right", "operand", "where", "body",
                 "summand", "args", "coll"):
        child = getattr(node, attr, None)
        if child is None:
            continue
        if isinstance(child, (list, tuple)):
            for item in child:
                found = _find_window(item)
                if found is not None:
                    return found
        else:
            found = _find_window(child)
            if found is not None:
                return found
    return None


# ---------------------------------------------------------------------------
# Duck-typed shape predicates (no :mod:`rot.dw` import -- see module docstring)
# ---------------------------------------------------------------------------

def _is_binary(node):
    """True if ``node`` looks like a :class:`rot.dw.BinaryOp`."""
    return (node is not None
            and getattr(node, "op", None) is not None
            and getattr(node, "left", None) is not None
            and getattr(node, "right", None) is not None)


def _is_num(node):
    """True if ``node`` looks like a :class:`rot.dw.Num` literal.

    The parser stores numerals as **strings** (e.g. ``"3"``), so a value that
    is an ``int`` / ``float`` *or* a numeric string is accepted (a ``bool``
    is excluded, as is a non-numeric string).
    """
    if node is None:
        return False
    if not hasattr(node, "value"):
        return False
    if hasattr(node, "op"):
        return False
    v = getattr(node, "value", None)
    if isinstance(v, bool):
        return False
    if isinstance(v, (int, float)):
        return True
    if isinstance(v, str):
        try:
            float(v)
            return True
        except (TypeError, ValueError):
            return False
    return False


def _is_sum(node):
    """True if ``node`` looks like a :class:`rot.dw.Sum` (has a summand)."""
    return (node is not None
            and getattr(node, "summand", None) is not None
            and getattr(node, "where", None) is not None)


def _is_count(node):
    """True if ``node`` looks like a :class:`rot.dw.Count` (no summand)."""
    return (node is not None
            and getattr(node, "summand", None) is None
            and getattr(node, "bindings", None) is not None
            and getattr(node, "where", None) is not None)


def _is_exists(node):
    """True if ``node`` looks like a :class:`rot.dw.Exists`."""
    return (node is not None
            and getattr(node, "binding", None) is not None
            and getattr(node, "body", None) is not None)


def _is_dotted(node):
    """True if ``node`` looks like a :class:`rot.dw.Dotted` (e.g. ``context.x``)."""
    return (node is not None
            and getattr(node, "parts", None) is not None
            and not hasattr(node, "op"))


def _collect_event_refs(node, out=None):
    """Collect all event-reference nodes in a ``.dw`` tree, in left-to-right order.

    Duck-typed: an event reference carries both a ``kind`` and an ``action``
    attribute (the :class:`rot.dw.EventRef` shape).
    """
    if out is None:
        out = []
    if node is None:
        return out
    if (getattr(node, "kind", None) is not None
            and getattr(node, "action", None) is not None):
        out.append(node)
        return out
    for attr in ("left", "right", "operand", "where", "body",
                 "summand", "args", "coll"):
        child = getattr(node, attr, None)
        if child is None:
            continue
        if isinstance(child, (list, tuple)):
            for item in child:
                _collect_event_refs(item, out)
        else:
            _collect_event_refs(child, out)
    return out



def _has_context_ref(node):
    """True if the tree contains a ``context.`` dotted reference.

    ``Dotted.parts`` is a list of ``str`` (e.g. ``["context", "input",
    "user"]``), so the first part is compared directly.
    """
    if node is None:
        return False
    if _is_dotted(node) and getattr(node, "parts", None):
        if node.parts[0] == "context":
            return True
    for attr in ("left", "right", "operand", "where", "body",
                 "summand", "args", "coll"):
        child = getattr(node, attr, None)
        if child is None:
            continue
        if isinstance(child, (list, tuple)):
            if any(_has_context_ref(item) for item in child):
                return True
        elif _has_context_ref(child):
            return True
    return False


def _unwrap_conjunction(node):
    """Flatten a right-nested ``&&`` chain into a list of conjuncts."""
    conjuncts = []
    while _is_binary(node) and node.op == "&&":
        conjuncts.append(node.left)
        node = node.right
    conjuncts.append(node)
    return conjuncts


def _find_comparison(node):
    """Return ``(op, left, right)`` if ``node`` is a relational comparison
    against a :class:`rot.dw.Num` literal, else ``None``.

    Recognised operators: ``<``, ``<=``, ``>``, ``>=``, ``==``.
    """
    if not _is_binary(node):
        return None
    if node.op not in ("<", "<=", ">", ">=", "=="):
        return None
    if _is_num(node.right):
        return (node.op, node.left, node.right)
    if _is_num(node.left):
        # normalise to ``left op right`` with the literal on the right
        flip = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "=="}
        return (flip[node.op], node.right, node.left)
    return None


def _event_ref_signature(ref):
    """A comparable ``(action, kind)`` signature of an event reference."""
    return (getattr(ref, "action", None), getattr(ref, "kind", None))



# ---------------------------------------------------------------------------
# Shape 1: spend-cap (``Sum + <= cap``)
# ---------------------------------------------------------------------------

def _lower_spendcap(node, amount, cap, max_inflight, window=None, dw_window=None):
    """Lower the spend-cap shape (``Sum + <= cap``) to a :class:`ProtocolIR`.

    This is the original shape; see the module docstring for the event-kind
    derivation.  Returns a :class:`rot.ir.ProtocolIR` structurally identical
    to :func:`rot.spendcap.build_ir` for the same parameters.
    (``ProtocolIR.__eq__`` ignores ``metadata``, so the provenance tags the
    ``.dw`` front-end adds do not affect that equality.)

    Raises:
        ValueError: if ``max_inflight`` is not an integer >= 1, or the event
            kind is present but not ``request`` / ``response``.
    """
    kind = _find_event_kind(node)
    if kind is not None and kind not in ("request", "response"):
        raise ValueError(
            "unsupported event kind %r (expected 'request' or 'response')"
            % (kind,))
    # ``response`` -> settled-only accounting (the "buggy" side); ``request``
    # (or an absent event reference) -> in-flight accounting (the "correct"
    # side).  This is the derivation: the guard is built from the event kind,
    # not from a hard-coded ``buggy`` flag.
    buggy = (kind == "response")

    k = int(max_inflight)
    if k < 1:
        raise ValueError(
            "max_inflight (K) must be an integer >= 1 (got %r)"
            % (max_inflight,))

    if buggy:
        name = "spendcap-buggy"
        decision = spendcap.spend_ok_guard_buggy(amount, cap)
    else:
        name = "spendcap-correct"
        decision = spendcap.spend_ok_guard_correct(amount, cap)

    # The structural client-side bound (request-pool resource limit) is shared
    # by both variants; it is not the policy decision.  It also keeps the
    # concrete state space finite, since the concrete engines do not enforce
    # variable domains.
    spend_ok_guard = ir.And(decision, ir.BinOp("<", ir.V("inflight"), ir.C(k)))
    # spend_deny is the other branch of the same policy decision: enabled
    # exactly where the seeded rule rejects the request.  It carries no effect
    # (a no-op outcome action), so the concrete engines generate no transition
    # for it -- it makes the decision plane explicit in the IR.
    spend_deny_guard = ir.Not(decision)

    variables = [
        ir.StateVar("completed", ir.IntRange(0, cap), ir.MODE_PRECISE, "service",
                    "settled amount (sum of responded requests)"),
        ir.StateVar("inflight", ir.IntRange(0, k), ir.MODE_PRECISE,
                    "service", "approved-but-unsettled (in-flight) request count"),
    ]
    actions = [
        ir.Action(name="init", owner="service", guard=ir.T(),
                  effects=[ir.Assignment("completed", ir.C(0)),
                           ir.Assignment("inflight", ir.C(0))],
                  is_initial=True,
                  source="spendcap.py:init"),
        ir.Action(name="spend_ok", owner="service", guard=spend_ok_guard,
                  effects=[ir.Assignment("inflight",
                                         ir.BinOp("+", ir.V("inflight"), ir.C(1)))],
                  linearization="send(spend_ok)",
                  source="spendcap.py:spend_ok"),
        ir.Action(name="spend_deny", owner="service", guard=spend_deny_guard,
                  effects=[],
                  source="spendcap.py:spend_deny"),
        ir.Action(name="respond", owner="service",
                  guard=ir.BinOp(">=", ir.V("inflight"), ir.C(1)),
                  effects=[ir.Assignment("inflight",
                                         ir.BinOp("-", ir.V("inflight"), ir.C(1))),
                           ir.Assignment("completed",
                                         ir.BinOp("+", ir.V("completed"), ir.C(amount)))],
                  linearization="send(respond)",
                  source="spendcap.py:respond"),
    ]
    return ir.ProtocolIR(
        name=name,
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
        # The pinned property the soundness core must check: settled +
        # in-flight never exceeds the cap (the parallel-fire guarantee).
        # Delegates to :func:`rot.spendcap.within_cap_property` so the
        # lowered IR is structurally identical to the hand-written oracle.
        pinned_property=spendcap.within_cap_property(amount, cap),
        source_path="tests/fixtures/aws_dogwood/spendcap",
        metadata={"protocol": "SPENDCAP", "target": "spendcap",
                  "buggy": buggy, "amount": amount, "cap": cap,
                  "max_inflight": k, "window": window,
                  "dw_window": dw_window},
    )



# ---------------------------------------------------------------------------
# Shape 2: count-window arithmetic (``Count - Count < cap``)
# ---------------------------------------------------------------------------

def _detect_count_window(node):
    """Detect the count-window shape.

    Returns ``(cap, open_ref, close_ref)`` if ``node`` matches
    ``(Count - Count) <op> cap`` (``<op>`` in ``<`` / ``<=``) with at least
    one event reference in each count, else ``None``.
    """
    cmp = _find_comparison(node)
    if cmp is None:
        return None
    op, left, right = cmp
    if op not in ("<", "<="):
        return None
    cap = int(right.value)
    if cap < 1:
        return None
    if not (_is_binary(left) and left.op == "-"):
        return None
    if not (_is_count(left.left) and _is_count(left.right)):
        return None
    open_refs = _collect_event_refs(left.left)
    close_refs = _collect_event_refs(left.right)
    if not open_refs or not close_refs:
        return None
    return (cap, open_refs[0], close_refs[0])


def _norm_action_name(name):
    """Normalise a policy action name to a lowercase IR identifier."""
    out = "".join(c if (c.isalnum() or c == "_") else "_"
                  for c in str(name).lower())
    out = out.strip("_")
    return out or "event"



def _lower_count_window(node, detected, window=None, dw_window=None):
    """Lower the count-window shape to a :class:`ProtocolIR`.

    ``detected`` is the ``(cap, open_ref, close_ref)`` tuple from
    :func:`_detect_count_window`.

    The IR models the net open count (opens minus completed reviews in the
    window) as a single state variable ``open``.  The ``open_pr`` action is
    the service decision (allow the open while ``open < cap``; it is what
    lands the PR and increments the count); ``complete_review`` is the
    environment transition that decrements it.  The pinned property is the
    cap condition ``open < cap``.
    """
    cap, open_ref, close_ref = detected
    open_action = getattr(open_ref, "action", "open") or "open"
    close_action = getattr(close_ref, "action", "close") or "close"

    variables = [
        ir.StateVar("open", ir.IntRange(0, cap), ir.MODE_PRECISE, "service",
                    "net open count (opens minus completed reviews in window)"),
    ]
    actions = [
        ir.Action(name="init", owner="service", guard=ir.T(),
                  effects=[ir.Assignment("open", ir.C(0))],
                  is_initial=True,
                  source="lower.py:init"),
        # Service decision: allow the open only while the cap is not reached
        # (the guard runs before the new PR lands, so ``< cap`` now means at
        # most ``cap`` open afterwards).
        ir.Action(name="open_pr", owner="service",
                  guard=ir.BinOp("<", ir.V("open"), ir.C(cap)),
                  effects=[ir.Assignment("open",
                                         ir.BinOp("+", ir.V("open"), ir.C(1)))],
                  linearization="send(open_pr)",
                  source="lower.py:open_pr"),
        # The other branch of the decision: deny when the cap is reached.
        ir.Action(name="deny_open", owner="service",
                  guard=ir.BinOp(">=", ir.V("open"), ir.C(cap)),
                  effects=[],
                  source="lower.py:deny_open"),
        # Environment: a review completes, decrementing the open count.
        ir.Action(name="complete_review", owner="service",
                  guard=ir.BinOp(">=", ir.V("open"), ir.C(1)),
                  effects=[ir.Assignment("open",
                                         ir.BinOp("-", ir.V("open"), ir.C(1)))],
                  linearization="send(complete_review)",
                  source="lower.py:complete_review"),
    ]
    pinned = ir.BinOp("<", ir.V("open"), ir.C(cap))

    return ir.ProtocolIR(
        name="count-window",
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
        pinned_property=pinned,
        source_path="tests/fixtures/aws_dogwood/spendcap",
        metadata={"protocol": "COUNT_WINDOW", "target": "count_window",
                  "cap": cap,
                  "open_event": "%s::%s" % (open_action,
                                           getattr(open_ref, "kind", "?")),
                  "close_event": "%s::%s" % (close_action,
                                             getattr(close_ref, "kind", "?")),
                  "window": window, "dw_window": dw_window},
    )



# ---------------------------------------------------------------------------
# Shape 3: filtered sum (``Exists(total, Sum == total && total <op> cap)``)
# ---------------------------------------------------------------------------

def _is_ident(node, name=None):
    """True if ``node`` looks like a :class:`rot.dw.Ident` (bare name).

    If ``name`` is given, the identifier must also match it.  An ``Ident``
    carries a ``name`` and none of ``op`` / ``parts`` / ``value`` (which
    distinguish it from ``BinaryOp`` / ``Dotted`` / ``Num``).
    """
    if node is None:
        return False
    if getattr(node, "op", None) is not None:
        return False
    if getattr(node, "parts", None) is not None:
        return False
    if getattr(node, "value", None) is not None:
        return False
    n = getattr(node, "name", None)
    if n is None:
        return False
    return name is None or n == name


def _find_sum(node):
    """Return the first :class:`rot.dw.Sum` node in the tree, else ``None``."""
    if node is None:
        return None
    if _is_sum(node):
        return node
    for attr in ("left", "right", "operand", "where", "body",
                 "summand", "args", "coll"):
        child = getattr(node, attr, None)
        if child is None:
            continue
        if isinstance(child, (list, tuple)):
            for item in child:
                found = _find_sum(item)
                if found is not None:
                    return found
        else:
            found = _find_sum(child)
            if found is not None:
                return found
    return None


def _find_cap_comparison(node, binding):
    """Find ``Ident(binding) <op> Num(cap)`` in the tree.

    Returns ``(op, cap)`` (``cap`` an ``int``) for the first comparison whose
    one side is the ``Exists`` binding and the other a :class:`rot.dw.Num`,
    normalised so the literal is on the right; else ``(None, None)``.
    """
    if node is None:
        return (None, None)
    if _is_binary(node) and node.op in ("<", "<=", ">", ">=", "=="):
        left, right = node.left, node.right
        if _is_ident(left, binding) and _is_num(right):
            return (node.op, int(right.value))
        if _is_ident(right, binding) and _is_num(left):
            flip = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "=="}
            return (flip[node.op], int(left.value))
    for attr in ("left", "right", "operand", "where", "body",
                 "summand", "args", "coll"):
        child = getattr(node, attr, None)
        if child is None:
            continue
        if isinstance(child, (list, tuple)):
            for item in child:
                op, cap = _find_cap_comparison(item, binding)
                if op is not None:
                    return (op, cap)
        else:
            op, cap = _find_cap_comparison(child, binding)
            if op is not None:
                return (op, cap)
    return (None, None)



def _binding_name(binding):
    """Extract the identifier name from an ``Exists`` binding.

    The parser stores the binding either as a plain string (``"total"``) or as
    a ``(name, type)`` tuple (``("total", "Long")``).  Returns the name (a
    non-empty ``str``) or ``None``.
    """
    if isinstance(binding, str):
        return binding or None
    if isinstance(binding, (list, tuple)) and binding:
        first = binding[0]
        if isinstance(first, str):
            return first or None
        return getattr(first, "name", None) or None
    return None


def _detect_exists_sum(node):
    """Detect the exists-sum shape.

    Returns ``(op, cap, sum_node)`` if ``node`` is either:

    (a) an ``Exists`` whose body contains a :class:`rot.dw.Sum` and a
        comparison ``<binding> <op> <cap>`` (the ``Sum == <binding>`` conjunct
        that ties the sum to the bound is tolerated on either side of ``==``);
    or

    (b) a ``let_(?n, ?A, ?B)`` :class:`rot.dw.LetCall` macro call whose ``?A``
        is a :class:`rot.dw.Sum` and whose ``?B`` contains ``?n <op> <cap>``
        (the macro expands to the same ``Exists`` structure),

    else ``None``.
    """
    # Case (a): a direct ``Exists``.
    if _is_exists(node):
        binding = _binding_name(node.binding)
        if not binding:
            return None
        body = node.body
        sum_node = _find_sum(body)
        if sum_node is None:
            return None
        op, cap = _find_cap_comparison(body, binding)
        if op is None:
            return None
        return (op, cap, sum_node)
    # Case (b): a ``let_`` macro call (parser leaves it unexpanded).
    if (hasattr(node, "args") and len(node.args) == 3
            and getattr(node, "name", None) == "let_"
            and _is_ident(node.args[0]) and _is_sum(node.args[1])):
        binding = node.args[0].name
        sum_node = node.args[1]
        op, cap = _find_cap_comparison(node.args[2], binding)
        if op is None:
            return None
        return (op, cap, sum_node)
    return None



def _lower_exists_sum(node, detected, k, window=None, dw_window=None):
    """Lower the exists-sum shape to a :class:`ProtocolIR`.

    ``detected`` is the ``(op, cap, sum_node)`` tuple from
    :func:`_detect_exists_sum`; ``k`` is the client-side request-pool bound
    (``max_inflight``).

    The exists-sum shape (``exists total. (sum == total && total <op> cap)``)
    is the *same protocol* as the spend-cap shape, expressed with an explicit
    ``total`` binding over the windowed sum.  The event kind the sum
    quantifies over drives the decision rule -- the SAFE / UNSAFE distinction:

    * **request-sum** (SAFE): the sum includes in-flight requests (the window
      is closed / reflexive, so the current request is already in the sum).
      The policy therefore charges in-flight against the cap; the decision is
      the *correct* guard (``completed + inflight * amount + amount <= cap``)
      and the within-cap invariant is maintained in every reachable state.
    * **response-sum** (UNSAFE): the sum covers settled responses only, so
      in-flight requests are invisible to the guard.  The decision is the
      *buggy* guard (``completed + amount <= cap``); a parallel burst of
      ``spend_ok`` (none settled yet) is admitted regardless of how much is
      already in flight, so the in-flight amount overshoots the cap -- the
      parallel-fire race.

    The state (``completed`` / ``inflight``), the actions
    (``spend_ok`` / ``spend_deny`` / ``respond``), and the pinned property
    (``completed + inflight * amount <= cap``) are shared with the spend-cap
    class -- the two shapes are the same protocol, so the same sound core
    classifies both.  The per-request ``amount`` is a representative value
    (``cap // 2``) chosen so the parallel-fire race is expressible with a
    small burst (consistent with the spend-cap class's ``amount / cap = 0.5``
    ratio); the verdict is driven by the event kind, not the amount.
    """
    op, cap, sum_node = detected
    # The event kind the sum quantifies over drives the decision rule.
    kind = _find_event_kind(sum_node)
    # A representative per-request amount: large enough that a small parallel
    # burst can exceed the cap (the parallel-fire race), consistent with the
    # spend-cap class's amount / cap = 0.5 ratio.
    amount = max(1, cap // 2)

    if kind == "request":
        # request-sum: the policy charges in-flight against the cap (SAFE).
        decision = spendcap.spend_ok_guard_correct(amount, cap)
        buggy = False
    else:
        # response-sum (default): the policy charges settled only (UNSAFE).
        decision = spendcap.spend_ok_guard_buggy(amount, cap)
        buggy = True

    # The structural client-side bound (request-pool resource limit) is shared
    # by both variants; it is not the policy decision.
    spend_ok_guard = ir.And(decision, ir.BinOp("<", ir.V("inflight"), ir.C(k)))
    spend_deny_guard = ir.Not(decision)

    variables = [
        ir.StateVar("completed", ir.IntRange(0, cap), ir.MODE_PRECISE, "service",
                    "settled amount (sum of responded requests)"),
        ir.StateVar("inflight", ir.IntRange(0, k), ir.MODE_PRECISE, "service",
                    "approved-but-unsettled (in-flight) request count"),
    ]
    actions = [
        ir.Action(name="init", owner="service", guard=ir.T(),
                  effects=[ir.Assignment("completed", ir.C(0)),
                           ir.Assignment("inflight", ir.C(0))],
                  is_initial=True,
                  source="lower.py:init"),
        ir.Action(name="spend_ok", owner="service", guard=spend_ok_guard,
                  effects=[ir.Assignment("inflight",
                                         ir.BinOp("+", ir.V("inflight"), ir.C(1)))],
                  linearization="send(spend_ok)",
                  source="lower.py:spend_ok"),
        ir.Action(name="spend_deny", owner="service", guard=spend_deny_guard,
                  effects=[],
                  source="lower.py:spend_deny"),
        ir.Action(name="respond", owner="service",
                  guard=ir.BinOp(">=", ir.V("inflight"), ir.C(1)),
                  effects=[ir.Assignment("inflight",
                                         ir.BinOp("-", ir.V("inflight"), ir.C(1))),
                           ir.Assignment("completed",
                                         ir.BinOp("+", ir.V("completed"), ir.C(amount)))],
                  linearization="send(respond)",
                  source="lower.py:respond"),
    ]
    refs = _collect_event_refs(sum_node)
    ref_sig = _event_ref_signature(refs[0]) if refs else ("?", "?")

    return ir.ProtocolIR(
        name="exists-sum",
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
        # The pinned property the soundness core must check: settled + in-flight
        # never exceeds the cap (the parallel-fire guarantee).  Shared with the
        # spend-cap class -- the two shapes are the same protocol.
        pinned_property=spendcap.within_cap_property(amount, cap),
        source_path="tests/fixtures/aws_dogwood/spendcap",
        metadata={"protocol": "EXISTS_SUM", "target": "exists_sum",
                  "op": op, "cap": cap, "amount": amount,
                  "max_inflight": k, "buggy": buggy,
                  "dw_event_kind": kind,
                  "event": "%s::%s" % ref_sig,
                  "context_bound": _has_context_ref(sum_node),
                  "window": window, "dw_window": dw_window},
    )



# ---------------------------------------------------------------------------
# Shape 4: refund budget (``(Sum + context.*) <op> cap``)
# ---------------------------------------------------------------------------

def _detect_refund_budget(node):
    """Detect the refund-budget shape.

    Returns ``(op, cap, sum_node, context_ref)`` if ``node`` is a comparison
    whose one side is a :class:`rot.dw.Num` and the other is an addition of a
    :class:`rot.dw.Sum` and a ``context.*`` :class:`rot.dw.Dotted` reference
    (the in-flight term), else ``None``.
    """
    cmp = _find_comparison(node)
    if cmp is None:
        return None
    op, left, right = cmp
    if op not in ("<", "<=", ">=", ">"):
        return None
    cap = int(right.value)
    if cap < 1:
        return None
    if not (_is_binary(left) and left.op == "+"):
        return None
    # The sum side and the context side may appear in either order.
    if _is_sum(left.left) and _is_dotted(left.right):
        sum_node, context_ref = left.left, left.right
    elif _is_dotted(left.left) and _is_sum(left.right):
        sum_node, context_ref = left.right, left.left
    else:
        return None
    if not _has_context_ref(context_ref):
        return None
    if not _collect_event_refs(sum_node):
        return None
    return (op, cap, sum_node, context_ref)



def _lower_refund_budget(node, detected, window=None, dw_window=None):
    """Lower the refund-budget shape to a :class:`ProtocolIR`.

    ``detected`` is the ``(op, cap, sum_node, context_ref)`` tuple from
    :func:`_detect_refund_budget`.

    The policy permits a refund while the already-settled amount plus the
    current in-flight amount stay within the cap.  The IR tracks two state
    variables: ``settled`` (accumulated windowed sum of settled refunds,
    clamped at ``cap + 1``) and ``current`` (the in-flight request amount,
    likewise clamped).  The decision is the sum of the two against the cap.
    """
    op, cap, sum_node, context_ref = detected
    decision = ir.BinOp(op, ir.BinOp("+", ir.V("settled"), ir.V("current")), ir.C(cap))
    op_name = {"<": "lt", "<=": "le", ">": "gt", ">=": "ge"}.get(op, "cmp")

    variables = [
        ir.StateVar("settled", ir.IntRange(0, cap + 1), ir.MODE_PRECISE, "service",
                    "accumulated settled refunds (clamped at cap + 1)"),
        ir.StateVar("current", ir.IntRange(0, cap + 1), ir.MODE_PRECISE, "service",
                    "in-flight refund amount (clamped at cap + 1)"),
    ]
    actions = [
        ir.Action(name="init", owner="service", guard=ir.T(),
                  effects=[ir.Assignment("settled", ir.C(0)),
                           ir.Assignment("current", ir.C(0))],
                  is_initial=True,
                  source="lower.py:init"),
        # Environment: a settled refund is paid out, adding to the running sum.
        ir.Action(name="settle", owner="service",
                  guard=ir.BinOp("<", ir.V("settled"), ir.C(cap + 1)),
                  effects=[ir.Assignment("settled",
                                         ir.BinOp("+", ir.V("settled"), ir.C(1)))],
                  linearization="send(settle)",
                  source="lower.py:settle"),
        # Environment: a new refund request arrives, setting the in-flight amount.
        ir.Action(name="request", owner="service",
                  guard=ir.T(),
                  effects=[ir.Assignment("current",
                                         ir.BinOp("+", ir.V("current"), ir.C(1)))],
                  linearization="send(request)",
                  source="lower.py:request"),
        # Service decision: the budget permits the refund.
        ir.Action(name="decision_%s" % op_name, owner="service",
                  guard=decision,
                  effects=[],
                  source="lower.py:decision"),
        # The other branch: the budget is exceeded.
        ir.Action(name="decision_not_%s" % op_name, owner="service",
                  guard=ir.Not(decision),
                  effects=[],
                  source="lower.py:decision_not"),
    ]
    refs = _collect_event_refs(sum_node)
    ref_sig = _event_ref_signature(refs[0]) if refs else ("?", "?")

    return ir.ProtocolIR(
        name="refund-budget",
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
        pinned_property=decision,
        source_path="tests/fixtures/aws_dogwood/spendcap",
        metadata={"protocol": "REFUND_BUDGET", "target": "refund_budget",
                  "op": op, "cap": cap,
                  "event": "%s::%s" % ref_sig,
                  "context_ref": ".".join(context_ref.parts),
                  "window": window, "dw_window": dw_window},
    )


# ---------------------------------------------------------------------------
# Shape 5: taint-egress (``formerly within <window> <event>``)
# ---------------------------------------------------------------------------

def _is_formerly_within(node):
    """True if ``node`` looks like a :class:`rot.dw.FormerlyWithin`."""
    return (node is not None
            and getattr(node, "window", None) is not None
            and getattr(node, "body", None) is not None)


def _detect_taint_egress(node):
    """Detect the taint-egress shape.

    Returns ``(trigger_ref, formerly_within_node)`` if ``node`` is a bare
    ``formerly within <window> <event_ref>`` predicate -- a *temporal trigger*
    predicate, not wrapped in an aggregate (sum / count / exists) and not
    compared to a cap -- else ``None``.

    This is the thesis's "never contact outsiders after touching confidential
    data" shape (temporal + data-dependent): the body is the confidential-data
    event that *triggers* the obligation, and the policy's scope names the
    egress action that is forbidden once the trigger has fired.
    """
    if not _is_formerly_within(node):
        return None
    body = node.body
    # Exclude the aggregate shapes (their body wraps a Sum / Count / Exists);
    # the taint-egress body is a bare event reference (or a simple predicate
    # over one).
    if _is_sum(body) or _is_count(body) or _is_exists(body):
        return None
    refs = _collect_event_refs(body)
    if not refs:
        return None
    return (refs[0], node)


def _lower_taint_egress(node, detected, window=None, dw_window=None):
    """Lower the taint-egress shape to a :class:`ProtocolIR`.

    ``detected`` is the ``(trigger_ref, formerly_within_node)`` tuple from
    :func:`_detect_taint_egress`.

    The IR is the exfiltration model (the same one as
    :func:`rot.agent_harness.exfiltrate_build_ir`): the trigger (touching
    confidential data) sets ``holding_private``; the egress (contacting an
    outsider) sets ``exfiltrated`` iff the agent is holding private data; the
    pinned property is ``NOT exfiltrated`` (NoExfiltration).

    The correct / buggy distinction is driven by the event kind of the
    trigger, mirroring the spend-cap shape:

    * **request-trigger** (SAFE): the egress is admitted only when the agent
      is NOT holding private data (the ``NoExfiltration`` rule holds);
    * **response-trigger** (UNSAFE): the egress is always admitted (the hole:
      private data can reach an unapproved channel while held).
    """
    trigger_ref, _fw = detected
    kind = getattr(trigger_ref, "kind", None)
    trigger_action = getattr(trigger_ref, "action", "ReadConfidential")

    if kind == "request":
        # request-trigger (SAFE): the egress is guarded by NoExfiltration.
        egress_guard = ir.Not(ir.V("holding_private"))
        deny_guard = ir.V("holding_private")
        buggy = False
    else:
        # response-trigger (UNSAFE): the egress is unguarded (the hole).
        egress_guard = ir.T()
        deny_guard = ir.F()
        buggy = True

    variables = [
        ir.StateVar("holding_private", ir.Bool(), ir.MODE_PRECISE, "service",
                    "the agent currently holds private (confidential) data"),
        ir.StateVar("exfiltrated", ir.Bool(), ir.MODE_PRECISE, "service",
                    "private data has been sent to an unapproved channel"),
    ]
    actions = [
        ir.Action(name="init", owner="service", guard=ir.T(),
                  effects=[ir.Assignment("holding_private", ir.C(False)),
                           ir.Assignment("exfiltrated", ir.C(False))],
                  is_initial=True,
                  source="lower.py:init"),
        # The trigger: the agent touches confidential data (taints context).
        ir.Action(name="touch_confidential", owner="service", guard=ir.T(),
                  effects=[ir.Assignment("holding_private", ir.C(True))],
                  linearization="send(touch_confidential)",
                  source="lower.py:touch_confidential"),
        # The egress (the thing under test): contacting an outsider.  If the
        # agent is holding private data this is an exfiltration.
        ir.Action(name="contact_outsider", owner="service", guard=egress_guard,
                  effects=[ir.Assignment("exfiltrated",
                                         ir.Or(ir.V("exfiltrated"),
                                               ir.V("holding_private")))],
                  linearization="send(contact_outsider)",
                  source="lower.py:contact_outsider"),
        # The other branch of the decision: deny the egress.
        ir.Action(name="contact_deny", owner="service", guard=deny_guard,
                  effects=[],
                  source="lower.py:contact_deny"),
        # The clear: the agent strips private data from its context.
        ir.Action(name="redact", owner="service", guard=ir.T(),
                  effects=[ir.Assignment("holding_private", ir.C(False))],
                  linearization="send(redact)",
                  source="lower.py:redact"),
    ]
    pinned = ir.Not(ir.V("exfiltrated"))
    ref_sig = _event_ref_signature(trigger_ref)

    return ir.ProtocolIR(
        name="taint-egress",
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
        pinned_property=pinned,
        source_path="tests/fixtures/aws_dogwood/spendcap",
        metadata={"protocol": "TAINT_EGRESS", "target": "taint_egress",
                  "buggy": buggy,
                  "dw_event_kind": kind,
                  "event": "%s::%s" % (ref_sig[0], ref_sig[1]),
                  "egress_event": "Send",
                  "window": window, "dw_window": dw_window},
    )


# ---------------------------------------------------------------------------
# Public dispatcher
# ---------------------------------------------------------------------------

def lower_policy(node, amount=None, cap=None, max_inflight=None, window=None):
    """Lower a parsed ``when`` expression to a :class:`rot.ir.ProtocolIR`.

    The five temporal-policy shapes are tried in order, most specific first:

    1. count-window arithmetic (``Count - Count < cap``);
    2. refund budget (``Sum + context.* <op> cap``);
    3. exists-sum (``Exists(total, Sum == total && total <op> cap)`` or the
       equivalent ``let_`` macro call);
    4. taint-egress (``formerly within <window> <event>`` -- a bare temporal
       trigger predicate; the "never contact outsiders after touching
       confidential data" shape);
    5. spend-cap (``Sum <op> cap``) -- the fallback and the original shape.

    Args:
        node: the parsed ``when`` expression (a :class:`rot.dw` AST node).
        amount: the per-transaction amount (spend-cap shape only); defaults to
            :data:`rot.spendcap.AMOUNT`.
        cap: the spend-cap budget (spend-cap shape only); defaults to
            :data:`rot.spendcap.CAP`.  The other shapes read their cap from
            the AST, so this argument is ignored for them.
        max_inflight: the in-flight bound (spend-cap shape only); defaults to
            :data:`rot.spendcap.MAX_INFLIGHT`.

    Returns:
        rot.ir.ProtocolIR: the lowered protocol model.

    Raises:
        ValueError: if the spend-cap fallback rejects the event kind or the
            in-flight bound (see :func:`_lower_spendcap`).
    """
    # Defaults mirror the spend-cap canonical parameters; the spend-cap shape
    # is the only one that consumes them.
    amt = spendcap.AMOUNT if amount is None else amount
    cp = spendcap.CAP if cap is None else cap
    k = spendcap.MAX_INFLIGHT if max_inflight is None else max_inflight
    # The temporal window is approximated as a bounded event count ``W`` (the
    # model is time-free); the original time token (e.g. ``"24h"``) is
    # preserved verbatim as provenance.  Both are recorded in the IR metadata
    # for every shape so the abstraction manifest states the discretization a
    # verdict was produced under (see :data:`rot.spendcap.MAX_WINDOW`).
    w = spendcap.MAX_WINDOW if window is None else int(window)
    dw_window = _find_window(node)

    detected = _detect_count_window(node)
    if detected is not None:
        return _lower_count_window(node, detected,
                                   window=w, dw_window=dw_window)

    detected = _detect_refund_budget(node)
    if detected is not None:
        return _lower_refund_budget(node, detected,
                                    window=w, dw_window=dw_window)

    detected = _detect_exists_sum(node)
    if detected is not None:
        return _lower_exists_sum(node, detected, k,
                                 window=w, dw_window=dw_window)

    detected = _detect_taint_egress(node)
    if detected is not None:
        return _lower_taint_egress(node, detected,
                                   window=w, dw_window=dw_window)

    # Fallback: the basic spend-cap shape (``Sum <op> cap``).
    return _lower_spendcap(node, amt, cp, k,
                           window=w, dw_window=dw_window)
