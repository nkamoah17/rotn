# -*- coding: utf-8 -*-
"""cone.py -- cone of influence over a CPG (front-end side).

Given a set of *root* symbols (method names / fullNames / field names), the
cone of influence is the minimal sub-graph of the CPG that can affect them:

  * forward closure: every method reachable by calls from a root method;
  * backward closure: every caller of a root method (so we keep the entry
    points that can reach a bug, not just the bug site);
  * field closure: fields read or written by any method in the cone.

This is what lets the IR builder emit *only* the slice of the program that
matters for the pinned property, instead of the whole CPG -- the CPG
analogue of property-directed variable selection.  Pure Python over
``cpg_model.CpgModel``; no Joern, fully unit-testable.
"""


class ConeResult(object):
    """The computed cone: the methods/fields/types in scope.

    ``roots`` are the symbols the cone was anchored on; ``methods`` /
    ``fields`` / ``types`` are the fullNames/names pulled in by the closure.
    """

    def __init__(self, roots, methods, fields, types):
        self.roots = sorted(roots)
        self.methods = sorted(methods)
        self.fields = sorted(fields)
        self.types = sorted(types)

    def to_dict(self):
        return {
            "roots": list(self.roots),
            "methods": list(self.methods),
            "fields": list(self.fields),
            "types": list(self.types),
        }

    def __repr__(self):
        return ("Cone(roots=%d methods=%d fields=%d types=%d)" % (
            len(self.roots), len(self.methods), len(self.fields),
            len(self.types)))


def _method_by_name(model, name):
    """Methods whose short name matches (may be several across types)."""
    return model.methods_named(name)


def cone_of_influence(model, roots, max_depth=None):
    """Compute the cone of influence of ``roots`` in ``model``.

    ``roots`` may mix method names, method fullNames, and field names.
    ``max_depth`` bounds the call-graph BFS distance from a method root
    (None = unbounded).  Returns a ``ConeResult``.
    """
    if model is None:
        raise ValueError("cone_of_influence: model is None")
    roots = list(roots)
    if not roots:
        raise ValueError("cone_of_influence: roots must be non-empty")

    # Identify root methods (by name or fullName) and root fields.
    root_methods = set()
    root_fields = set()
    for r in roots:
        by_full = model.method(r)
        if by_full is not None:
            root_methods.add(by_full.full_name)
        for m in model.methods_named(r):
            root_methods.add(m.full_name)
        for f in model.fields_named(r):
            root_fields.add(f.name)
    if not root_methods and not root_fields:
        raise ValueError(
            "cone_of_influence: no root matched a method or field: %s" % roots)

    # BFS over the call graph from root methods, forward + backward.
    in_cone = set()          # fullNames of methods in the cone
    depth = dict((m, 0) for m in root_methods)

    def add(mfn, d):
        if mfn not in depth or d < depth[mfn]:
            depth[mfn] = d
            in_cone.add(mfn)

    frontier = list(root_methods)
    while frontier:
        cur = frontier.pop()
        cur_depth = depth[cur]
        if max_depth is not None and cur_depth >= max_depth:
            continue
        cur_method = model.method(cur)
        if cur_method is None:
            continue
        nd = cur_depth + 1
        # forward: methods this method calls
        for name in cur_method.calls:
            for m in _method_by_name(model, name):
                if m.full_name not in in_cone:
                    add(m.full_name, nd)
                    frontier.append(m.full_name)
        # backward: callers of this method (unbounded -- entry points matter)
        for c in model.callers_of(cur):
            if c.full_name not in in_cone:
                add(c.full_name, nd)
                frontier.append(c.full_name)

    # Field closure: fields touched by any method in the cone (and root fields).
    fields = set(root_fields)
    for mfn in in_cone:
        m = model.method(mfn)
        if m is None:
            continue
        fields.update(m.read_fields)
        fields.update(m.written_fields)

    # Type closure: owners of the methods/fields in scope.
    types = set()
    for mfn in in_cone:
        m = model.method(mfn)
        if m is not None and m.owner:
            types.add(m.owner)
    for fname in fields:
        for f in model.fields_named(fname):
            if f.owner:
                types.add(f.owner)

    return ConeResult(
        roots=roots,
        methods=in_cone,
        fields=fields,
        types=types,
    )


__all__ = ["ConeResult", "cone_of_influence"]
