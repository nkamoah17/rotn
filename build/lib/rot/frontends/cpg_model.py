# -*- coding: utf-8 -*-
"""cpg_model.py -- language-agnostic CPG data model (the front-end's view).

This is the *parsed* shape of what a CPG scrape yields (today: a Joern/Java
CPG, tomorrow: any CPG tool).  It is deliberately small and serializable:
front-ends consume it, never the raw CPG storage.

  CpgType:   a declared class/interface/enum (name, fullName, owner, lines,
             the supertypes it inherits/implements).
  CpgField:  a declared field (name, fullName, declared type, owner type).
  CpgMethod: a method (name, fullName, owner type, line range, the *names*
             of methods it calls, and the field names it reads / writes --
             the read/write split is what lets the IR builder see e.g. that
             the buggy participant applies its own vote, not the decision).
  CpgModel:  the whole scrape: meta + types + fields + methods, with
             from_dict/to_dict and JSON round-trip, plus query helpers.

Pure stdlib, Python 3.6 compatible (no f-strings / dataclasses).
"""

import json
import os


# ---------------------------------------------------------------------------
# node records
# ---------------------------------------------------------------------------
class CpgType(object):
    """A declared type (class / interface / enum)."""

    def __init__(self, name, full_name, owner="", line=0, end_line=0,
                 inherits=None, constants=None):
        self.name = name
        self.full_name = full_name
        self.owner = owner
        self.line = line
        self.end_line = end_line
        self.inherits = list(inherits or [])
        self.constants = list(constants or [])

    def to_dict(self):
        return {
            "name": self.name,
            "fullName": self.full_name,
            "owner": self.owner,
            "lineNumber": self.line,
            "endLineNumber": self.end_line,
            "inherits": list(self.inherits),
            "constants": list(self.constants),
        }

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
        )

    def __repr__(self):
        return "CpgType(%s)" % self.full_name


class CpgField(object):
    """A declared field with its declared type and owning type."""

    def __init__(self, name, full_name, type_name="", owner=""):
        self.name = name
        self.full_name = full_name
        self.type_name = type_name
        self.owner = owner

    def to_dict(self):
        return {
            "name": self.name,
            "fullName": self.full_name,
            "type": self.type_name,
            "owner": self.owner,
        }

    @staticmethod
    def from_dict(d):
        return CpgField(
            name=d.get("name", ""),
            full_name=d.get("fullName", ""),
            type_name=d.get("type", ""),
            owner=d.get("owner", ""),
        )

    def __repr__(self):
        return "CpgField(%s)" % self.full_name


class CpgMethod(object):
    """A method with call edges and field read/write edges.

    ``calls`` holds the *names* of the methods called (as reported by the CPG
    call nodes); ``read_fields`` / ``written_fields`` hold the *names* of the
    fields this method reads from / writes to.  Keeping names (not fullNames)
    matches what the CPG reports on call sites and keeps the model compact;
    callers disambiguate by owner.
    """

    def __init__(self, name, full_name, owner="", line=0, end_line=0,
                 calls=None, read_fields=None, written_fields=None):
        self.name = name
        self.full_name = full_name
        self.owner = owner
        self.line = line
        self.end_line = end_line
        self.calls = list(calls or [])
        self.read_fields = list(read_fields or [])
        self.written_fields = list(written_fields or [])

    def to_dict(self):
        return {
            "name": self.name,
            "fullName": self.full_name,
            "owner": self.owner,
            "lineNumber": self.line,
            "endLineNumber": self.end_line,
            "calls": list(self.calls),
            "readFields": list(self.read_fields),
            "writtenFields": list(self.written_fields),
        }

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
        )

# ---------------------------------------------------------------------------
# the whole model
# ---------------------------------------------------------------------------
class CpgModel(object):
    """A complete CPG scrape: meta + types + fields + methods."""

    def __init__(self, meta=None, types=None, fields=None, methods=None):
        self.meta = dict(meta or {})
        self.types = list(types or [])
        self.fields = list(fields or [])
        self.methods = list(methods or [])

    # -- serialization ------------------------------------------------------
    def to_dict(self):
        return {
            "meta": dict(self.meta),
            "types": [t.to_dict() for t in self.types],
            "fields": [f.to_dict() for f in self.fields],
            "methods": [m.to_dict() for m in self.methods],
        }

    @staticmethod
    def from_dict(d):
        return CpgModel(
            meta=dict(d.get("meta") or {}),
            types=[CpgType.from_dict(t) for t in d.get("types") or []],
            fields=[CpgField.from_dict(f) for f in d.get("fields") or []],
            methods=[CpgMethod.from_dict(m) for m in d.get("methods") or []],
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

    def __repr__(self):
        return ("CpgModel(types=%d fields=%d methods=%d src=%s)" % (
            len(self.types), len(self.fields), len(self.methods),
            self.meta.get("source", "?")))


__all__ = ["CpgType", "CpgField", "CpgMethod", "CpgModel"]
