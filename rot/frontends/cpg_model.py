# -*- coding: utf-8 -*-
"""cpg_model.py -- language-agnostic CPG data model (the front-end's view).

This is the *parsed* shape of what a CPG scrape yields (today: a Joern/Java
CPG, tomorrow: any CPG tool).  It is deliberately small and serializable:
front-ends consume it, never the raw CPG storage.

  CpgType:      a declared class/interface/enum (name, fullName, owner,
                lines, the supertypes it inherits/implements).
  CpgField:     a declared field (name, fullName, declared type, owner type).
  CpgMethod:    a method (name, fullName, owner type, line range, the
                *names* of methods it calls, and the field names it reads /
                writes -- the read/write split is what lets the IR builder
                see e.g. that the buggy participant applies its own vote,
                not the decision -- plus its dataflow half (CPG-1):
                ``defs``, the names it defines (parameters, locals, written
                fields), and ``args``, its parameter names in declaration
                order).
  CpgEdge:      a typed dataflow/call edge between two compact node ids
                (REACHING_DEF / ARGUMENT / FLOW / CALL).
  CpgTaintNode: a classified taint source or sink (a conservative
                classifier, not full taint-tracking).
  CpgModel:     the whole scrape: meta + types + fields + methods + typed
                ``edges`` + ``taint_sources`` / ``taint_sinks``, with
                from_dict/to_dict and JSON round-trip, plus query helpers --
                including ``taint_path(src, sink)``, the deterministic
                private->sink query over the dataflow edges (the
                "taintPath(G, P)" of the CPG integration plan, CPG-1).

Pure stdlib, Python 3.6 compatible (no f-strings / dataclasses).
"""

from collections import deque
import json
import os


# ---------------------------------------------------------------------------
# node records
# ---------------------------------------------------------------------------
class CpgType(object):
    """A declared type (class / interface / enum)."""

    def __init__(self, name, full_name, owner="", line=0, end_line=0,
                 inherits=None, constants=None, constant=None):
        self.name = name
        self.full_name = full_name
        self.owner = owner
        self.line = line
        self.end_line = end_line
        self.inherits = list(inherits or [])
        self.constants = list(constants or [])
        # The valueMap ``constant`` key (§2.4, D.3): the node's constant value
        # when the type itself is a constant holder (null otherwise).  The
        # ``constants`` list above is the *member* list (the enum values --
        # the state-space domain Q); ``constant`` is this node's own value.
        self.constant = constant

    def to_dict(self):
        d = {
            "name": self.name,
            "fullName": self.full_name,
            "owner": self.owner,
            "lineNumber": self.line,
            "endLineNumber": self.end_line,
            "inherits": list(self.inherits),
            "constants": list(self.constants),
        }
        if self.constant is not None:
            d["constant"] = self.constant
        return d

    @staticmethod
    def from_dict(d):
        return CpgType(
            name=d.get("name", ""),
            full_name=d.get("fullName", ""),
            owner=d.get("owner", ""),
            line=int(d.get("lineNumber") or 0),
            end_line=int(d.get("endLineNumber") or 0),
            inherits=list(d.get("inherits") or []),
            constants=list(d.get("constants") or []),
            constant=d.get("constant"),
        )

    def __repr__(self):
        return "CpgType(%s)" % self.full_name


class CpgField(object):
    """A declared field with its declared type and owning type.

    ``constant`` (the valueMap ``constant`` key, §2.4 D.3): the field's
    constant value when it is never reassigned (a constant node in the
    general state space, §2.6); ``None`` for a mutable field.
    """

    def __init__(self, name, full_name, type_name="", owner="", constant=None):
        self.name = name
        self.full_name = full_name
        self.type_name = type_name
        self.owner = owner
        self.constant = constant

    def to_dict(self):
        d = {
            "name": self.name,
            "fullName": self.full_name,
            "type": self.type_name,
            "owner": self.owner,
        }
        if self.constant is not None:
            d["constant"] = self.constant
        return d

    @staticmethod
    def from_dict(d):
        return CpgField(
            name=d.get("name", ""),
            full_name=d.get("fullName", ""),
            type_name=d.get("type", ""),
            owner=d.get("owner", ""),
            constant=d.get("constant"),
        )

    def __repr__(self):
        return "CpgField(%s)" % self.full_name


# ---------------------------------------------------------------------------
# dataflow records (CPG-1: the dataflow half)
# ---------------------------------------------------------------------------
# Typed edge kinds.  REACHING_DEF / ARGUMENT are the CPG's stable dataflow
# edges (def-use and argument passing); FLOW is the generic alias the plan
# uses for any other dataflow edge; CALL is control flow (kept out of the
# default taint_path search; available via include_calls=True).
#
# The control half (joern-primary-ab-plan §2.4, D) -- the edges FSM extraction
# needs beyond dataflow (taint_path keeps searching only the dataflow kinds):
#   * CDG:       control dependence (the CPG's CDG pass): src controls dst --
#                a branch block -> the value node it gates (the write in its
#                body).  The transition detector's control half (Q4).
#   * DOMINATE:  dominance (CfgDominator): src dominates dst -- the loop
#                header -> its body.  Used for the loop's exit condition.
#   * CONTAINS:  structural containment: container -> contained -- method ->
#                loop -> branch.  "Inside the loop" is a CONTAINS chain.
EDGE_REACHING_DEF = "REACHING_DEF"
EDGE_ARGUMENT = "ARGUMENT"
EDGE_FLOW = "FLOW"
EDGE_CALL = "CALL"
EDGE_CDG = "CDG"
EDGE_DOMINATE = "DOMINATE"
EDGE_CONTAINS = "CONTAINS"
EDGE_KINDS = (EDGE_REACHING_DEF, EDGE_ARGUMENT, EDGE_FLOW, EDGE_CALL,
              EDGE_CDG, EDGE_DOMINATE, EDGE_CONTAINS)

# The kinds taint_path searches by default: dataflow only (the plan's
# "REACHING_DEF/FLOW path from a private source to an unapproved sink").
DATAFLOW_EDGE_KINDS = (EDGE_REACHING_DEF, EDGE_ARGUMENT, EDGE_FLOW)


class CpgEdge(object):
    """A typed edge between two compact CPG node ids.

    Node ids are language-agnostic (the scrape maps CPG nodes onto them):
      * a method:      its fullName            (com.acme.Connector.report)
      * a slot:        fullName + "#" + name   (a parameter or a local def)
      * a field:       the field's fullName    (com.acme.Connector.cap)
      * a block:       owner + "#" + tag       (a branch / a loop, §2.4 B)
    REACHING_DEF / ARGUMENT / FLOW are the dataflow half (CPG-1); CDG /
    DOMINATE / CONTAINS are the control half (joern-primary-ab-plan §2.4 D)
    the FSM extractor consumes.
    """

    def __init__(self, edge_type, src, dst, line=0, note=""):
        self.edge_type = edge_type
        self.src = src
        self.dst = dst
        self.line = int(line or 0)
        self.note = note or ""

    def to_dict(self):
        return {
            "type": self.edge_type,
            "from": self.src,
            "to": self.dst,
            "line": self.line,
            "note": self.note,
        }

    @staticmethod
    def from_dict(d):
        return CpgEdge(
            edge_type=d.get("type", ""),
            src=d.get("from", ""),
            dst=d.get("to", ""),
            line=d.get("line", 0),
            note=d.get("note", ""),
        )

    def __repr__(self):
        return "CpgEdge(%s %s -> %s)" % (self.edge_type, self.src, self.dst)


class CpgTaintNode(object):
    """A classified taint source or sink (CPG-1).

    Conservative by design: a name-based classifier, not full taint-tracking
    (over-approximate on purpose -- never miss a path).  ``node_id`` is the
    compact node id in the dataflow graph (a parameter slot for a source, an
    egress method for a sink); ``owner`` is the method the classification was
    made in (the declaring method / the call site); ``reason`` records the
    classifier's basis (e.g. ``private-name:ssn``, ``egress-name:send``) so
    the set stays auditable.
    """

    def __init__(self, node_id, kind, name="", owner="", reason="", line=0):
        self.node_id = node_id
        self.kind = kind        # "parameter" | "field" | "call" | "return"
        self.name = name or ""
        self.owner = owner or ""
        self.reason = reason or ""
        self.line = int(line or 0)

    def to_dict(self):
        return {
            "id": self.node_id,
            "kind": self.kind,
            "name": self.name,
            "owner": self.owner,
            "reason": self.reason,
            "line": self.line,
        }

    @staticmethod
    def from_dict(d):
        return CpgTaintNode(
            node_id=d.get("id", ""),
            kind=d.get("kind", ""),
            name=d.get("name", ""),
            owner=d.get("owner", ""),
            reason=d.get("reason", ""),
            line=d.get("line", 0),
        )

    def __repr__(self):
        return "CpgTaintNode(%s %s)" % (self.kind, self.node_id)


# ---------------------------------------------------------------------------
# control records (the control half -- joern-primary-ab-plan §2.4)
# ---------------------------------------------------------------------------
# These carry the CPG structure the dataflow half (CPG-1) does not: the
# filesystem + namespace provenance (FILE / NAMESPACE_BLOCK), the method
# parameters (METHOD_PARAMETER_IN/OUT -- the input alphabet Σ, Q3), the locals
# (LOCAL -- the FSM state-variable candidates, Q2), and the blocks
# (BLOCK / CONTROL_STRUCTURE -- the loop, Q1, and the branches that gate the
# state writes, Q4).  rot/fsmextract.py consumes them; old artifacts simply
# carry empty lists for all of them (the records are additive).
class CpgFile(object):
    """A FILE node (spec §2.4, B): the filesystem half (provenance).

    ``name`` is the base name (``Coordinator.java``); ``full_name`` the
    scrape-relative path; ``namespace`` the enclosing NAMESPACE_BLOCK name.
    """

    def __init__(self, name, full_name="", namespace="", owner="",
                 line=0, end_line=0):
        self.name = name
        self.full_name = full_name
        self.namespace = namespace or ""
        self.owner = owner or ""
        self.line = int(line or 0)
        self.end_line = int(end_line or 0)

    def to_dict(self):
        return {
            "name": self.name,
            "fullName": self.full_name,
            "namespace": self.namespace,
            "owner": self.owner,
            "lineNumber": self.line,
            "endLineNumber": self.end_line,
        }

    @staticmethod
    def from_dict(d):
        return CpgFile(
            name=d.get("name", ""),
            full_name=d.get("fullName", ""),
            namespace=d.get("namespace", ""),
            owner=d.get("owner", ""),
            line=int(d.get("lineNumber") or 0),
            end_line=int(d.get("endLineNumber") or 0),
        )

    def __repr__(self):
        return "CpgFile(%s)" % (self.full_name or self.name)


class CpgNamespace(object):
    """A NAMESPACE_BLOCK node (spec §2.4, B).

    One namespace is one module = one factor-graph component (the GSSM
    "distributed" half, §2.6): the product of the local factor graphs of the
    types it contains, joined by the channel factors.
    """

    def __init__(self, name, full_name, owner="", line=0, end_line=0):
        self.name = name
        self.full_name = full_name
        self.owner = owner or ""
        self.line = int(line or 0)
        self.end_line = int(end_line or 0)

    def to_dict(self):
        return {
            "name": self.name,
            "fullName": self.full_name,
            "owner": self.owner,
            "lineNumber": self.line,
            "endLineNumber": self.end_line,
        }

    @staticmethod
    def from_dict(d):
        return CpgNamespace(
            name=d.get("name", ""),
            full_name=d.get("fullName", ""),
            owner=d.get("owner", ""),
            line=int(d.get("lineNumber") or 0),
            end_line=int(d.get("endLineNumber") or 0),
        )

    def __repr__(self):
        return "CpgNamespace(%s)" % self.full_name


class CpgParam(object):
    """A METHOD_PARAMETER_IN / METHOD_PARAMETER_OUT node (spec §2.4, A).

    The *input alphabet Σ* candidates (Q3): the direction-IN parameters of the
    FSM's owning method are the alphabet's members, and the ones a branch's
    condition reads (a REACHING_DEF into the branch block) are the channels
    the transition guards on.  ``constant`` is the valueMap ``constant`` key
    (a literal default); ``is_external`` / ``is_implicit`` feed the
    false-positive guard (Q-FP).
    """

    DIRECTION_IN = "IN"
    DIRECTION_OUT = "OUT"

    def __init__(self, name, full_name, type_name="", owner="",
                 argument_index=0, direction="IN", line=0, end_line=0,
                 is_external=False, is_implicit=False, constant=None,
                 code=""):
        self.name = name
        self.full_name = full_name
        self.type_name = type_name
        self.owner = owner or ""
        self.argument_index = int(argument_index or 0)
        self.direction = (direction or self.DIRECTION_IN).upper()
        self.line = int(line or 0)
        self.end_line = int(end_line or 0)
        self.is_external = bool(is_external)
        self.is_implicit = bool(is_implicit)
        self.constant = constant
        self.code = code or ""

    @property
    def is_input(self):
        """True iff this is a METHOD_PARAMETER_IN (an alphabet member)."""
        return self.direction == self.DIRECTION_IN

    def to_dict(self):
        return {
            "name": self.name,
            "fullName": self.full_name,
            "type": self.type_name,
            "owner": self.owner,
            "argumentIndex": self.argument_index,
            "direction": self.direction,
            "lineNumber": self.line,
            "endLineNumber": self.end_line,
            "isExternal": self.is_external,
            "isImplicit": self.is_implicit,
            "constant": self.constant,
            "code": self.code,
        }

    @staticmethod
    def from_dict(d):
        return CpgParam(
            name=d.get("name", ""),
            full_name=d.get("fullName", ""),
            type_name=d.get("type", ""),
            owner=d.get("owner", ""),
            argument_index=int(d.get("argumentIndex") or 0),
            direction=d.get("direction", "IN"),
            line=int(d.get("lineNumber") or 0),
            end_line=int(d.get("endLineNumber") or 0),
            is_external=bool(d.get("isExternal", False)),
            is_implicit=bool(d.get("isImplicit", False)),
            constant=d.get("constant"),
            code=d.get("code", ""),
        )

    def __repr__(self):
        return "CpgParam(%s %s)" % (self.direction, self.full_name)


class CpgLocal(object):
    """A LOCAL node (spec §2.4, B) -- an FSM state-variable candidate (Q2).

    ``full_name`` is the slot id (``Method#name``) the dataflow edges use;
    ``type_name`` resolves against the declared types for the bounded
    discrete domain (the Q2a test); ``constant`` is the valueMap
    ``constant`` key (a literal initializer / never-reassigned value).
    """

    def __init__(self, name, full_name, type_name="", owner="", line=0,
                 end_line=0, constant=None, code=""):
        self.name = name
        self.full_name = full_name
        self.type_name = type_name
        self.owner = owner or ""
        self.line = int(line or 0)
        self.end_line = int(end_line or 0)
        self.constant = constant
        self.code = code or ""

    def to_dict(self):
        return {
            "name": self.name,
            "fullName": self.full_name,
            "type": self.type_name,
            "owner": self.owner,
            "lineNumber": self.line,
            "endLineNumber": self.end_line,
            "constant": self.constant,
            "code": self.code,
        }

    @staticmethod
    def from_dict(d):
        return CpgLocal(
            name=d.get("name", ""),
            full_name=d.get("fullName", ""),
            type_name=d.get("type", ""),
            owner=d.get("owner", ""),
            line=int(d.get("lineNumber") or 0),
            end_line=int(d.get("endLineNumber") or 0),
            constant=d.get("constant"),
            code=d.get("code", ""),
        )

    def __repr__(self):
        return "CpgLocal(%s)" % self.full_name


class CpgBlock(object):
    """A BLOCK / CONTROL_STRUCTURE node (spec §2.4, B).

    The control structure the FSM extractor needs: the *loop* (a
    CONTROL_STRUCTURE whose ``cs_type`` is a loop kind -- the Q1 trip-count
    filter's target) and the *branches* (IF nodes) that guard the state
    writes (the Q4 transition sites).  ``full_name`` is the block id the
    CDG / DOMINATE / CONTAINS edges use; ``code`` is the valueMap ``code``
    snippet (the construct's source text -- it is what lets the extractor
    tell ``while (s != c)`` from ``while (s == c)`` when deriving F).
    """

    KIND_BLOCK = "BLOCK"
    KIND_CONTROL_STRUCTURE = "CONTROL_STRUCTURE"
    #: The control-structure types that denote a loop (the trip-count
    #: filter's candidates).
    LOOP_TYPES = ("WHILE", "DO", "FOR", "LOOP")

    def __init__(self, kind, name="", full_name="", owner="", line=0,
                 end_line=0, cs_type="", code=""):
        self.kind = (kind or self.KIND_BLOCK).upper()
        self.name = name or ""
        self.full_name = full_name
        self.owner = owner or ""
        self.line = int(line or 0)
        self.end_line = int(end_line or 0)
        self.cs_type = (cs_type or "").upper()
        self.code = code or ""

    @property
    def is_loop(self):
        """True iff this is a CONTROL_STRUCTURE loop (WHILE / DO / FOR)."""
        return (self.kind == self.KIND_CONTROL_STRUCTURE
                and self.cs_type in self.LOOP_TYPES)

    @property
    def is_branch(self):
        """True iff this is an IF branch (a transition-site candidate)."""
        return (self.kind == self.KIND_CONTROL_STRUCTURE
                and self.cs_type == "IF")

    def to_dict(self):
        d = {
            "kind": self.kind,
            "name": self.name,
            "fullName": self.full_name,
            "owner": self.owner,
            "lineNumber": self.line,
            "endLineNumber": self.end_line,
        }
        if self.cs_type:
            d["csType"] = self.cs_type
        if self.code:
            d["code"] = self.code
        return d

    @staticmethod
    def from_dict(d):
        return CpgBlock(
            kind=d.get("kind", "BLOCK"),
            name=d.get("name", ""),
            full_name=d.get("fullName", ""),
            owner=d.get("owner", ""),
            line=int(d.get("lineNumber") or 0),
            end_line=int(d.get("endLineNumber") or 0),
            cs_type=d.get("csType", ""),
            code=d.get("code", ""),
        )

    def __repr__(self):
        return "CpgBlock(%s %s)" % (self.kind, self.full_name)


class CpgCall(object):
    """A CALL node (spec §2.4, B): a call site with its dispatch metadata.

    ``callee`` is the called method's fullName; ``src`` the caller (the
    method fullName, as in the CALL edges).  ``dispatch_type`` (the valueMap
    ``dispatchType``) and ``is_external`` are the false-positive guard's
    inputs (Q-FP): a "state variable" written only by an external / virtual-
    dispatch call is a function pointer, not a state (one of the paper's two
    FPs).
    """

    def __init__(self, callee, src="", line=0, dispatch_type="",
                 is_external=False, is_implicit=False, code=""):
        self.callee = callee
        self.src = src or ""
        self.line = int(line or 0)
        self.dispatch_type = dispatch_type or ""
        self.is_external = bool(is_external)
        self.is_implicit = bool(is_implicit)
        self.code = code or ""

    def to_dict(self):
        return {
            "callee": self.callee,
            "src": self.src,
            "lineNumber": self.line,
            "dispatchType": self.dispatch_type,
            "isExternal": self.is_external,
            "isImplicit": self.is_implicit,
            "code": self.code,
        }

    @staticmethod
    def from_dict(d):
        return CpgCall(
            callee=d.get("callee", ""),
            src=d.get("src", ""),
            line=int(d.get("lineNumber") or 0),
            dispatch_type=d.get("dispatchType", ""),
            is_external=bool(d.get("isExternal", False)),
            is_implicit=bool(d.get("isImplicit", False)),
            code=d.get("code", ""),
        )

    def __repr__(self):
        return "CpgCall(%s -> %s)" % (self.src, self.callee)


class CpgMethod(object):
    """A method with call edges, field read/write edges, and its dataflow
    half (CPG-1).

    ``calls`` holds the *names* of the methods called (as reported by the CPG
    call nodes); ``read_fields`` / ``written_fields`` hold the *names* of the
    fields this method reads from / writes to.  ``defs`` holds every name the
    method *defines* (its parameters, local variables, and the fields it
    writes -- the def-use side, CPG's REACHING_DEF definitions); ``args``
    holds its parameter names in declaration order (the ARGUMENT slots).
    Keeping names (not fullNames) matches what the CPG reports on call sites
    and keeps the model compact; callers disambiguate by owner.
    """

    def __init__(self, name, full_name, owner="", line=0, end_line=0,
                 calls=None, read_fields=None, written_fields=None,
                 defs=None, args=None, ret_type=None, is_external=False,
                 is_implicit=False):
        self.name = name
        self.full_name = full_name
        self.owner = owner
        self.line = line
        self.end_line = end_line
        self.calls = list(calls or [])
        self.read_fields = list(read_fields or [])
        self.written_fields = list(written_fields or [])
        self.defs = list(defs or [])
        self.args = list(args or [])
        # CPG-2: the return type ("boolean" / "int" / ...; None when the
        # artifact predates the field).  Shape recognition needs this (a
        # *decision* method returns a boolean); a model without it can only
        # report OUT_OF_SCOPE for the shapes that require it (E2).
        self.ret_type = ret_type
        # The false-positive guard's inputs (§2.4 A / §2.5 Q-FP): a method
        # marked a stub (isExternal / isImplicit) cannot own a real FSM state
        # variable -- the paper's two FPs are excluded via these flags.
        self.is_external = bool(is_external)
        self.is_implicit = bool(is_implicit)

    def to_dict(self):
        d = {
            "name": self.name,
            "fullName": self.full_name,
            "owner": self.owner,
            "lineNumber": self.line,
            "endLineNumber": self.end_line,
            "calls": list(self.calls),
            "readFields": list(self.read_fields),
            "writtenFields": list(self.written_fields),
            "defs": list(self.defs),
            "args": list(self.args),
        }
        if self.ret_type is not None:
            d["retType"] = self.ret_type
        if self.is_external:
            d["isExternal"] = True
        if self.is_implicit:
            d["isImplicit"] = True
        return d

    @staticmethod
    def from_dict(d):
        return CpgMethod(
            name=d.get("name", ""),
            full_name=d.get("fullName", ""),
            owner=d.get("owner", ""),
            line=int(d.get("lineNumber") or 0),
            end_line=int(d.get("endLineNumber") or 0),
            calls=list(d.get("calls") or []),
            read_fields=list(d.get("readFields") or []),
            written_fields=list(d.get("writtenFields") or []),
            defs=list(d.get("defs") or []),
            args=list(d.get("args") or []),
            ret_type=d.get("retType"),
            is_external=bool(d.get("isExternal", False)),
            is_implicit=bool(d.get("isImplicit", False)),
        )

# ---------------------------------------------------------------------------
# the whole model
# ---------------------------------------------------------------------------
class CpgModel(object):
    """A complete CPG scrape: meta + types + fields + methods + the
    dataflow half (CPG-1): typed ``edges`` and the conservative
    ``taint_sources`` / ``taint_sinks`` sets.

    Plus the *control half* (joern-primary-ab-plan §2.4, additive -- old
    artifacts carry empty lists for all of these): ``files`` /
    ``namespaces`` (filesystem + namespace provenance), ``params``
    (METHOD_PARAMETER_IN/OUT -- the input alphabet Sigma), ``locals_``
    (LOCAL -- the FSM state-variable candidates), ``blocks``
    (BLOCK / CONTROL_STRUCTURE -- the loop + the branches), ``calls``
    (CALL -- the dispatch metadata), and the CDG / DOMINATE / CONTAINS
    edges inside ``edges``.
    """

    def __init__(self, meta=None, types=None, fields=None, methods=None,
                 edges=None, taint_sources=None, taint_sinks=None,
                 files=None, namespaces=None, params=None, locals_=None,
                 blocks=None, calls=None):
        self.meta = dict(meta or {})
        self.types = list(types or [])
        self.fields = list(fields or [])
        self.methods = list(methods or [])
        self.edges = list(edges or [])
        self.taint_sources = list(taint_sources or [])
        self.taint_sinks = list(taint_sinks or [])
        # The control half (§2.4): additive collections, empty by default so
        # every pre-§2.4 artifact (old fixtures) stays valid.
        self.files = list(files or [])
        self.namespaces = list(namespaces or [])
        self.params = list(params or [])
        self.locals_ = list(locals_ or [])
        self.blocks = list(blocks or [])
        self.calls = list(calls or [])

    # -- serialization ------------------------------------------------------
    def to_dict(self):
        return {
            "meta": dict(self.meta),
            "types": [t.to_dict() for t in self.types],
            "fields": [f.to_dict() for f in self.fields],
            "methods": [m.to_dict() for m in self.methods],
            "edges": [e.to_dict() for e in self.edges],
            "taint_sources": [t.to_dict() for t in self.taint_sources],
            "taint_sinks": [t.to_dict() for t in self.taint_sinks],
            # the control half (§2.4): always present (empty on old artifacts)
            "files": [f.to_dict() for f in self.files],
            "namespaces": [n.to_dict() for n in self.namespaces],
            "params": [p.to_dict() for p in self.params],
            "locals": [l.to_dict() for l in self.locals_],
            "blocks": [b.to_dict() for b in self.blocks],
            "calls": [c.to_dict() for c in self.calls],
        }

    @staticmethod
    def from_dict(d):
        return CpgModel(
            meta=dict(d.get("meta") or {}),
            types=[CpgType.from_dict(t) for t in d.get("types") or []],
            fields=[CpgField.from_dict(f) for f in d.get("fields") or []],
            methods=[CpgMethod.from_dict(m) for m in d.get("methods") or []],
            edges=[CpgEdge.from_dict(e) for e in d.get("edges") or []],
            taint_sources=[CpgTaintNode.from_dict(t)
                           for t in d.get("taint_sources") or []],
            taint_sinks=[CpgTaintNode.from_dict(t)
                         for t in d.get("taint_sinks") or []],
            files=[CpgFile.from_dict(f) for f in d.get("files") or []],
            namespaces=[CpgNamespace.from_dict(n)
                        for n in d.get("namespaces") or []],
            params=[CpgParam.from_dict(p) for p in d.get("params") or []],
            locals_=[CpgLocal.from_dict(l) for l in d.get("locals") or []],
            blocks=[CpgBlock.from_dict(b) for b in d.get("blocks") or []],
            calls=[CpgCall.from_dict(c) for c in d.get("calls") or []],
        )

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @staticmethod
    def from_json(text):
        return CpgModel.from_dict(json.loads(text))

    @staticmethod
    def from_file(path):
        with open(path, "r") as f:
            return CpgModel.from_json(f.read())

    def to_file(self, path):
        d = os.path.dirname(os.path.abspath(path))
        if d and not os.path.isdir(d):
            os.makedirs(d)
        with open(path, "w") as f:
            f.write(self.to_json())
            f.write("\n")

    # -- validation ---------------------------------------------------------
    def validate(self):
        """Return the list of well-formedness errors (empty list == valid)."""
        errors = []
        if not self.types:
            errors.append("CpgModel has no types")
        for t in self.types:
            if not t.name:
                errors.append("type with empty name")
            if not t.full_name:
                errors.append("type with empty fullName: %s" % t.name)
        for f in self.fields:
            if not f.full_name:
                errors.append("field with empty fullName: %s" % f.name)
        seen = set()
        for m in self.methods:
            if not m.full_name:
                errors.append("method with empty fullName: %s" % m.name)
            if m.full_name in seen:
                errors.append("duplicate method fullName: %s" % m.full_name)
            seen.add(m.full_name)
        for e in self.edges:
            if e.edge_type not in EDGE_KINDS:
                errors.append("edge with unknown kind %r: %s -> %s"
                              % (e.edge_type, e.src, e.dst))
            elif not e.src or not e.dst:
                errors.append("edge with empty endpoint: %r -> %r"
                              % (e.src, e.dst))
        for t in list(self.taint_sources) + list(self.taint_sinks):
            if not t.node_id:
                errors.append("taint node with empty id (kind=%r)" % (t.kind,))
        # the control half (§2.4): light well-formedness, additive
        for f in self.files:
            if not f.name:
                errors.append("file with empty name")
        for n in self.namespaces:
            if not n.full_name:
                errors.append("namespace with empty fullName: %s" % n.name)
        for p in self.params:
            if not p.full_name:
                errors.append("param with empty fullName: %s" % p.name)
        for l in self.locals_:
            if not l.full_name:
                errors.append("local with empty fullName: %s" % l.name)
        for b in self.blocks:
            if not b.full_name:
                errors.append("block with empty fullName: %s" % b.name)
        for c in self.calls:
            if not c.callee:
                errors.append("call with empty callee (src=%r)" % c.src)
        return errors

    # -- queries ------------------------------------------------------------
    def type_names(self):
        return set(t.name for t in self.types)

    def has_type(self, name):
        return name in self.type_names()

    def types_named(self, name):
        return [t for t in self.types if t.name == name]

    def field(self, name):
        for f in self.fields:
            if f.name == name:
                return f
        return None

    def fields_named(self, name):
        return [f for f in self.fields if f.name == name]

    def fields_of(self, owner):
        """Fields whose owner type is ``owner`` (exact name match)."""
        return [f for f in self.fields if f.owner == owner]

    def has_field(self, name, owner=None):
        if owner is None:
            return self.field(name) is not None
        return any(f.name == name and f.owner == owner for f in self.fields)

    def methods_of(self, owner):
        return [m for m in self.methods if m.owner == owner]

    def methods_named(self, name):
        return [m for m in self.methods if m.name == name]

    def method(self, full_name):
        for m in self.methods:
            if m.full_name == full_name:
                return m
        return None

    def has_method(self, full_name):
        return self.method(full_name) is not None

    def method_names(self):
        return set(m.name for m in self.methods)

    def callers_of(self, name_or_full_name):
        """Methods that call the method with this name or fullName."""
        target_names = set()
        target_ids = set()
        for m in self.methods:
            if m.name == name_or_full_name or m.full_name == name_or_full_name:
                target_names.add(m.name)
                target_ids.add(id(m))
        out = []
        for m in self.methods:
            if id(m) in target_ids:
                continue
            if any(c in target_names for c in m.calls):
                out.append(m)
        return out

    def writers_of(self, field_name):
        return [m for m in self.methods if field_name in m.written_fields]

    def readers_of(self, field_name):
        return [m for m in self.methods if field_name in m.read_fields]

    # -- dataflow (CPG-1) ---------------------------------------------------
    def edges_of(self, kind):
        """All edges of one typed kind (e.g. ``EDGE_ARGUMENT``)."""
        return [e for e in self.edges if e.edge_type == kind]

    def dataflow_edges(self):
        """The dataflow edges (REACHING_DEF / ARGUMENT / FLOW)."""
        return [e for e in self.edges if e.edge_type in DATAFLOW_EDGE_KINDS]

    # -- control half (joern-primary-ab-plan §2.4) ---------------------------
    def params_of(self, owner):
        """All METHOD_PARAMETER nodes of ``owner`` (IN and OUT)."""
        return [p for p in self.params if p.owner == owner]

    def input_params(self, owner):
        """The direction-IN parameters of ``owner`` (the alphabet Σ)."""
        return [p for p in self.params_of(owner) if p.is_input]

    def param(self, full_name):
        for p in self.params:
            if p.full_name == full_name:
                return p
        return None

    def locals_of(self, owner):
        """The LOCAL nodes of ``owner`` (the state-variable candidates)."""
        return [l for l in self.locals_ if l.owner == owner]

    def local(self, full_name):
        for l in self.locals_:
            if l.full_name == full_name:
                return l
        return None

    def blocks_of(self, owner):
        """The BLOCK / CONTROL_STRUCTURE nodes of ``owner``."""
        return [b for b in self.blocks if b.owner == owner]

    def loop_blocks(self, owner=None):
        """The loop CONTROL_STRUCTUREs (optionally scoped to ``owner``)."""
        out = [b for b in self.blocks if b.is_loop]
        if owner is not None:
            out = [b for b in out if b.owner == owner]
        return out

    def branch_blocks(self, owner=None):
        """The IF branch CONTROL_STRUCTUREs (optionally scoped)."""
        out = [b for b in self.blocks if b.is_branch]
        if owner is not None:
            out = [b for b in out if b.owner == owner]
        return out

    def block(self, full_name):
        for b in self.blocks:
            if b.full_name == full_name:
                return b
        return None

    def calls_of(self, src):
        """CALL nodes whose caller is ``src`` (a method fullName)."""
        return [c for c in self.calls if c.src == src]

    def calls_to(self, callee):
        """CALL nodes whose callee is ``callee`` (a method fullName)."""
        return [c for c in self.calls if c.callee == callee]

    def reads_of(self, node_id):
        """Dataflow edges flowing INTO ``node_id`` (REACHING_DEF/ARGUMENT/FLOW).

        ``src`` is the def the node reads: the branch's condition inputs
        (constants / state variable / input channels) and the loop's exit
        test inputs are exactly these edges.
        """
        return [e for e in self.dataflow_edges() if e.dst == node_id]

    def writes_of(self, node_id):
        """Dataflow edges flowing OUT of ``node_id`` (its defs' uses)."""
        return [e for e in self.dataflow_edges() if e.src == node_id]

    def cdg_dependents(self, node_id):
        """The value nodes control-dependent on ``node_id`` (CDG out-edges).

        For a branch block, this is the set of writes its body performs --
        the control half of the transition detector (Q4).
        """
        return [e for e in self.edges if e.edge_type == EDGE_CDG
                and e.src == node_id]

    def contained_in(self, node_id, container_id):
        """True iff ``node_id`` is structurally inside ``container_id``.

        A transitive CONTAINS chain: method -> loop -> branch (or the same
        node).  This is the "inside the loop" test the trip-count filter
        (Q1) and the s0/F separation (Q5) rely on.
        """
        if node_id == container_id:
            return True
        adj = {}
        for e in self.edges:
            if e.edge_type == EDGE_CONTAINS:
                adj.setdefault(e.src, set()).add(e.dst)
        seen = set()
        queue = [container_id]
        while queue:
            cur = queue.pop()
            for nxt in adj.get(cur, ()):
                if nxt == node_id:
                    return True
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)
        return False

    def taint_source_ids(self):
        """Sorted node ids of the classified taint sources."""
        return sorted(set(t.node_id for t in self.taint_sources if t.node_id))

    def taint_sink_ids(self):
        """Sorted node ids of the classified taint sinks."""
        return sorted(set(t.node_id for t in self.taint_sinks if t.node_id))

    def is_taint_source(self, node_id):
        return node_id in set(t.node_id for t in self.taint_sources)

    def is_taint_sink(self, node_id):
        return node_id in set(t.node_id for t in self.taint_sinks)

    def _slot_nodes(self):
        """Every slot id (``method#name``) the model knows: the slot
        endpoints of the edges plus the defs/args of every method."""
        slots = set()
        for e in self.edges:
            for node in (e.src, e.dst):
                if node and "#" in node:
                    slots.add(node)
        for m in self.methods:
            if not m.full_name:
                continue
            for name in list(m.defs) + list(m.args):
                if name:
                    slots.add(m.full_name + "#" + name)
        return slots

    def taint_path(self, src, sink, include_calls=False):
        """A deterministic path from taint node ``src`` to taint node
        ``sink`` over the dataflow edges.

        This is the "taintPath(G, P)" query of the CPG integration plan:
        a path over the REACHING_DEF / ARGUMENT / FLOW edges (plus CALL
        edges only when ``include_calls`` -- the over-approximate
        variant).  Returns the first path found by a sorted BFS, i.e. the
        shortest path under a deterministic tie-break, as a list of node
        ids ``[src, ..., sink]``; ``None`` when the sink is unreachable.

        A method node counts as reached when the method itself *or any of
        its parameter / local slots* is reached (a tainted slot taints its
        owning method), so a sink named after an egress method (e.g.
        ``com.acme.AuditLog.send``) is found through its parameter slot.
        """
        if not src or not sink:
            return None
        if src == sink:
            return [src]
        kinds = set(DATAFLOW_EDGE_KINDS)
        if include_calls:
            kinds.add(EDGE_CALL)
        adj = {}
        for e in self.edges:
            if e.edge_type not in kinds or not e.src or not e.dst:
                continue
            adj.setdefault(e.src, set()).add(e.dst)
        for slot in self._slot_nodes():          # slot -> method projection
            method = slot.split("#", 1)[0]
            if method:
                adj.setdefault(slot, set()).add(method)
        prev = dict([(src, None)])
        queue = deque([src])
        while queue:
            cur = queue.popleft()
            if cur == sink:
                break
            for nxt in sorted(adj.get(cur, ())):
                if nxt not in prev:
                    prev[nxt] = cur
                    queue.append(nxt)
        if sink not in prev:
            return None
        path = []
        cur = sink
        while cur is not None:
            path.append(cur)
            cur = prev[cur]
        path.reverse()
        return path

    def taint_paths(self, include_calls=False):
        """Every ``(source, sink, path)`` pair where a classified taint
        source reaches a classified taint sink -- the full "taintPath(G)"
        set.  Sorted by (source, sink) for determinism."""
        out = []
        for s in self.taint_source_ids():
            for k in self.taint_sink_ids():
                p = self.taint_path(s, k, include_calls=include_calls)
                if p is not None:
                    out.append((s, k, p))
        out.sort(key=lambda pair: (pair[0], pair[1]))
        return out

    def __repr__(self):
        return ("CpgModel(types=%d fields=%d methods=%d edges=%d "
                "sources=%d sinks=%d src=%s)" % (
                    len(self.types), len(self.fields), len(self.methods),
                    len(self.edges), len(self.taint_sources),
                    len(self.taint_sinks), self.meta.get("source", "?")))


__all__ = [
    "CpgType", "CpgField", "CpgMethod", "CpgEdge", "CpgTaintNode", "CpgModel",
    # the control half (joern-primary-ab-plan §2.4)
    "CpgFile", "CpgNamespace", "CpgParam", "CpgLocal", "CpgBlock", "CpgCall",
    "EDGE_REACHING_DEF", "EDGE_ARGUMENT", "EDGE_FLOW", "EDGE_CALL",
    "EDGE_CDG", "EDGE_DOMINATE", "EDGE_CONTAINS",
    "EDGE_KINDS", "DATAFLOW_EDGE_KINDS",
]
