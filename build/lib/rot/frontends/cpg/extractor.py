# -*- coding: utf-8 -*-
"""extractor.py -- generic CPG -> Candidate producer (CPG-2; P1 shapes).

The second code-grounded producer of the narrow waist (spec §7, D3).
``rot.frontends.code`` reads *Python source* (name heuristics over the AST);
this front-end reads a language-agnostic
:class:`rot.frontends.cpg_model.CpgModel` scrape and recognizes the P1
shapes from **CPG structure** -- dataflow edges, call edges, field
read/write sets, and declared types.  It emits the *same*
:class:`Candidate` contract (imported from ``rot.frontends.code`` -- one
contract, one class), so both producers feed the same
``lower_candidate`` -> Verify pipeline, and the A/B gate
(``tests/test_cpg_extraction.py``) checks that both lower to a
``to_dict()``-identical ``ProtocolIR`` for the same control.

Shapes (P1 class, lighthouse shapes):

* **budget** (lighthouse ``SpendCap``): a *decision method* -- returns a
  boolean (``CpgMethod.ret_type``), writes no field, calls nothing (the
  control is inline, no helper indirection) -- that combines >= 2 distinct
  inputs (fields / parameters, per REACHING_DEF / ARGUMENT edges) into a
  local, and checks that local against exactly one read candidate (a field
  or a parameter) that does NOT flow into it (the cap).  The enforced /
  bypassable split is read from **which fields the sum is over** -- the
  ``java/ir_builder.detect_apply_mode`` idea generalized: the split is a
  property of the field set, not of the method's name.  In-flight quantity
  in the sum -> enforced; settled-only sum -> bypassable; neither
  vocabulary -> not recognized (E2, never a silent UNKNOWN).

* **label_flow** (lighthouse ``NoExfiltration``): a classified private
  source (a parameter / field) with a dataflow ``taint_path`` to a
  classified egress sink (a call).  The egress caller is *enforced* iff it
  reads a boolean-typed field that some other method writes (a mutable
  gate -- a type-based test; the egress receiver is excluded
  structurally, since its type is the sink's owner type, not boolean);
  otherwise the egress is *bypassable* (unguarded).

What this producer does NOT claim (E1/E2 honesty):

* no literals: a CPG scrape carries no constant values, so the budget
  parameters fall back to the lighthouse defaults (100 / 200) -- the same
  defaults ``rot.frontends.code`` falls back to, which is what makes the
  A/B IRs comparable;
* the label_flow parameter is canonicalized to the lighthouse state
  variable name (``holding_private`` -- the lowered IR fixes that name);
  the source's own parameter name stays in the provenance;
* out-of-pattern input yields ``out_of_scope=True`` with a reason, never a
  silent UNKNOWN candidate.

Narrow waist: imports ``rot.ir`` + ``rot.frontends.*`` + stdlib only.
Pure stdlib, Python 3.6 compatible (no f-strings / dataclasses).
"""

import os

import rot.ir as ir
from rot.frontends.code import (Candidate, PATTERN_BUDGET, PATTERN_LABEL_FLOW)
from rot.frontends.cpg_model import (CpgModel, EDGE_ARGUMENT, EDGE_CALL,
                                     EDGE_REACHING_DEF)
from rot.frontends.cone import cone_of_influence

__all__ = ["extract_cpg"]

# P1 vocabulary (shared with rot.frontends.code; the CPG side applies it to
# *fields* -- the conservative classifier: name classification + structural
# detection, CPG-1 status).
_INFLIGHT_NAMES = ("inflight", "in_flight", "pending", "open", "inprocess",
                   "in_process", "unresolved")
_SETTLED_NAMES = ("settled", "completed", "spent", "used", "consumed")

# Lighthouse canonicals (see the module docstring): the lowered IR fixes
# these names / defaults, so both producers must agree on them.
_LABEL_CANONICAL = "holding_private"
_DEFAULT_AMOUNT = 100
_DEFAULT_CAP = 200

_BOOL_TYPES = ("boolean", "bool", "java.lang.boolean")

_DATAFLOW = (EDGE_REACHING_DEF, EDGE_ARGUMENT)


# ---------------------------------------------------------------------------
# structural queries (over CpgModel)
# ---------------------------------------------------------------------------
def _method_by_fullname(model, full_name):
    for m in model.methods:
        if m.full_name == full_name:
            return m
    return None


def _inputs_into(model, m, local_name):
    """Input names (fields or parameters of ``m``) flowing into a local.

    The structural "the sum is over": the REACHING_DEF / ARGUMENT sources of
    the local's slot, restricted to names the method reads (fields) or
    declares (parameters).  Locals defining themselves are not inputs.
    """
    prefix = m.full_name + "#"
    args = set(m.args)
    read_fields = set(m.read_fields)
    names = set()
    for e in model.edges:
        if e.edge_type not in _DATAFLOW or e.dst != prefix + local_name:
            continue
        if e.src.startswith(prefix):
            name = e.src[len(prefix):]
            if name in args:
                names.add(name)
        else:
            name = e.src.rsplit(".", 1)[-1]
            if name in read_fields:
                names.add(name)
    return names


def _ret_bool(m):
    return m.ret_type is not None and m.ret_type.lower() in _BOOL_TYPES


def _cap_and_sum(model, m):
    """The decision method's ``(local, cap, sum_fields)``, or ``None``.

    A local with >= 2 distinct inputs (a combination of quantities) and
    exactly one read candidate (field / parameter) that does NOT flow into
    it (the cap); ``sum_fields`` = the read fields the sum is over.
    """
    args = set(m.args)
    read_fields = set(m.read_fields)
    candidates = read_fields | args
    for local in [d for d in m.defs if d not in args]:
        inputs = _inputs_into(model, m, local)
        if len(inputs) < 2:
            continue
        cap = sorted(c for c in candidates if c not in inputs)
        if len(cap) != 1:
            continue
        sum_fields = sorted(f for f in read_fields if f in inputs)
        return local, cap[0], sum_fields
    return None


def _budget_split(sum_fields):
    """enforced / bypassable from which fields the sum is over (the
    detect_apply_mode idea, generalized: the split is read from the field
    set, not the method's name).  Neither vocabulary -> ``None`` (E2)."""
    s = set(sum_fields)
    if s & set(_INFLIGHT_NAMES):
        return True
    if s & set(_SETTLED_NAMES):
        return False
    return None


def _detect_budget(model, method=None):
    """The first budget decision: ``(m, local, cap, sum_fields, enforced)``,
    or ``None`` (out-of-pattern -- the caller reports E2)."""
    for m in model.methods:
        if method is not None and m.full_name != method:
            continue
        if not _ret_bool(m) or m.written_fields or m.calls:
            continue
        found = _cap_and_sum(model, m)
        if found is None:
            continue
        local, cap, sum_fields = found
        enforced = _budget_split(sum_fields)
        if enforced is None:
            continue
        return m, local, cap, sum_fields, enforced
    return None


def _caller_of(model, sink_method):
    """The method that calls the egress (CALL edge), else the owner of the
    last dataflow edge into the sink's parameter slot."""
    for e in model.edges:
        if e.edge_type == EDGE_CALL and e.dst == sink_method.full_name:
            m = _method_by_fullname(model, e.src)
            if m is not None:
                return m
    prefix = sink_method.full_name + "#"
    for e in model.edges:
        if (e.edge_type in _DATAFLOW and e.dst.startswith(prefix)
                and not e.src.startswith(prefix)):
            m = _method_by_fullname(model, e.src.split("#", 1)[0])
            if m is not None:
                return m
    return None


def _egress_guard(model, caller):
    """The mutable boolean gate the caller reads (name-free, type-based).

    A guard = a boolean-typed field the caller reads and that some *other*
    method writes (a mutable gate).  The egress receiver is excluded
    structurally: its type is the sink's owner type, not boolean.  Returns
    the gate's field name, or ``None`` (unguarded egress -> bypassable).
    """
    for name in caller.read_fields:
        field = model.field(name)
        if field is None or field.type_name is None:
            continue
        if field.type_name.lower() not in _BOOL_TYPES:
            continue
        for m in model.methods:
            if name in m.written_fields and m.full_name != caller.full_name:
                return name
    return None


def _detect_label_flow(model, method=None):
    """The first label/flow control: ``(caller, sink_method, src, path)``,
    or ``None`` (out-of-pattern -- the caller reports E2)."""
    for sink in model.taint_sinks:
        if sink.kind != "call":
            continue
        sink_method = _method_by_fullname(model, sink.node_id)
        if sink_method is None:
            continue
        caller = _caller_of(model, sink_method)
        if caller is None:
            continue
        if method is not None and caller.full_name != method:
            continue
        for src in model.taint_sources:
            if src.kind not in ("parameter", "field"):
                continue
            path = model.taint_path(src.node_id, sink.node_id)
            if path is not None:
                return caller, sink_method, src, path
    return None



# ---------------------------------------------------------------------------
# provenance (E4: scope to the function -- method fullName + line range +
# the property-directed slice, per the CPG integration plan)
# ---------------------------------------------------------------------------
def _cone_dict(model, roots):
    """The property-directed slice (the cone of influence) of the control,
    as a plain dict for provenance; ``None`` on query failure."""
    try:
        return cone_of_influence(model, list(roots)).to_dict()
    except Exception:
        return None


def _filename(model):
    src = (model.meta or {}).get("source", "")
    return os.path.basename(src) if src else ""


def _base_provenance(model, m):
    return {
        "function": m.name,
        "fullName": m.full_name,
        "start_line": m.line,
        "end_line": m.end_line,
        "filename": _filename(model),
        "source": "rot.frontends.cpg",
    }


# ---------------------------------------------------------------------------
# canonical pinned properties (lighthouse shapes; the A/B gate pins the
# equality with rot.frontends.code's canonicals)
# ---------------------------------------------------------------------------
def _budget_pinned_property(amount, cap):
    """completed + inflight * amount <= cap (lighthouse SpendCap)."""
    return ir.BinOp("<=",
                    ir.BinOp("+", ir.V("completed"),
                             ir.BinOp("*", ir.V("inflight"), ir.C(amount))),
                    ir.C(cap))


def _label_flow_pinned_property():
    """NOT exfiltrated (lighthouse NoExfiltration)."""
    return ir.Not(ir.V("exfiltrated"))


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------
def extract_cpg(model, shape=None, method=None):
    """Extract the first P1 control in ``model`` into a :class:`Candidate`.

    ``shape``: ``"budget"`` | ``"label_flow"`` | ``None`` (try budget, then
    label_flow -- deterministic).  ``method``: an optional method fullName
    anchor (the decision method / the egress caller).  Out-of-pattern input
    yields ``out_of_scope=True`` with a reason (E2: never a silent UNKNOWN).
    """
    if not isinstance(model, CpgModel):
        raise TypeError("extract_cpg expects a CpgModel, got %r"
                        % type(model).__name__)
    if shape is not None and shape not in (PATTERN_BUDGET, PATTERN_LABEL_FLOW):
        raise ValueError("unknown P1 shape: %r" % (shape,))
    errors = model.validate()
    if errors:
        raise ValueError("invalid CpgModel: %s" % "; ".join(errors))

    reasons = []
    if shape in (None, PATTERN_BUDGET):
        found = _detect_budget(model, method)
        if found is not None:
            m, local, cap, sum_fields, enforced = found
            amount, cap_value = _DEFAULT_AMOUNT, _DEFAULT_CAP
            provenance = _base_provenance(model, m)
            provenance.update({
                "sum_local": local,
                "cap": cap,
                "sum_over": sum_fields,
                "split_reason": ("sum charges in-flight"
                                 if enforced else "sum is settled-only"),
                "cone": _cone_dict(model, [m.full_name]),
            })
            return Candidate(
                pattern=PATTERN_BUDGET,
                enforced=enforced,
                params={"amount": amount, "cap": cap_value},
                provenance=provenance,
                pinned_property=_budget_pinned_property(amount, cap_value),
                candidate=True,
                out_of_scope=False,
                reason=("budget control (lighthouse SpendCap) from CPG "
                        "structure: %s"
                        % ("enforced" if enforced else "bypassable")),
            )
        reasons.append("budget: no decision method (boolean return, no "
                       "writes, no calls) combining >= 2 inputs against a "
                       "cap, or an ambiguous sum field set")
    if shape in (None, PATTERN_LABEL_FLOW):
        found = _detect_label_flow(model, method)
        if found is not None:
            caller, sink_method, src, path = found
            guard = _egress_guard(model, caller)
            enforced = guard is not None
            provenance = _base_provenance(model, caller)
            provenance.update({
                "sink": sink_method.full_name,
                "private_source": src.node_id,
                "source_reason": src.reason,
                "taint_path": list(path),
                "guard": guard,
                "cone": _cone_dict(model, [caller.full_name,
                                           sink_method.full_name]),
            })
            return Candidate(
                pattern=PATTERN_LABEL_FLOW,
                enforced=enforced,
                params={"label": _LABEL_CANONICAL},
                provenance=provenance,
                pinned_property=_label_flow_pinned_property(),
                candidate=True,
                out_of_scope=False,
                reason=("label/flow control (lighthouse NoExfiltration) "
                        "from CPG structure: egress %s"
                        % ("guarded by %r" % guard if guard else "unguarded")),
            )
        reasons.append("label_flow: no classified private source with a "
                       "taint path to a classified egress sink")
    return Candidate.out_of_scope_candidate(
        "no P1 control in the CPG: " + "; ".join(reasons))

