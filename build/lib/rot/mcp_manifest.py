# -*- coding: utf-8 -*-
"""MCP Manifest v1 -- a superset of the MCP ``tools/list`` result.

This is the *ingestion* half of the MCP adoption surface (Phase B, B1).
An MCP manifest is a JSON document describing an MCP server's tool catalog
in the shape defined by the Model Context Protocol (spec ``2025-06-18``),
*plus* the Caravel policy/compliance fields that let :mod:`rot.mcp_adapter`
run structural checks (field permission, tenant isolation) without a
runtime.

A manifest is a **superset** of the MCP ``tools/list`` result:

* the ``tools`` array is exactly the MCP ``result.tools[]`` shape -- each
  tool carries ``name`` (required) and the optional ``title``,
  ``description``, ``inputSchema``, ``outputSchema`` and ``annotations``
  (``readOnlyHint`` / ``destructiveHint`` / ``idempotentHint`` /
  ``openWorldHint``);
* the Caravel additions are ``tenant_scope`` (which tenant a tool acts on),
  ``read_fields`` / ``write_fields`` (the data fields it reads/writes), and
  the top-level ``allowed_write_fields`` (the tenant's write-permission set).

The manifest is *policy-bearing*: it is the single document that names the
action universe (``tools[].name``) and the compliance constraints, so
``rot check --manifest mcp.json`` needs no separate policy file.

Pure stdlib (Python 3.6 compatible).  See ``docs/manifest-format.md`` for
the full schema reference.
"""

import json

__all__ = [
    "MANIFEST_SCHEMA",
    "McpManifestError",
    "McpTool",
    "McpManifest",
    "parse_manifest",
    "parse_manifest_file",
]

# The manifest schema tag (the "manifest" field value).
MANIFEST_SCHEMA = "caravel.mcp-manifest/v1"

# The MCP annotation keys (spec 2025-06-18) and their boolean hint values.
_ANNOTATION_KEYS = (
    "readOnlyHint",
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
)

# The Caravel per-tool compliance keys.
_TOOL_CARAVEL_KEYS = ("tenant_scope", "read_fields", "write_fields")

# Top-level keys that are always present (required) in a manifest.
_TOP_REQUIRED = ("manifest", "tools")


class McpManifestError(ValueError):
    """Raised when a manifest document is malformed or fails validation.

    The message is stable and human-readable so it can be surfaced directly
    by the CLI (``rot check --manifest``) and by tests.
    """


# ---------------------------------------------------------------------------
# low-level validators (pure, deterministic)
# ---------------------------------------------------------------------------

def _is_nonempty_str(v):
    return isinstance(v, str) and v != ""


def _is_str_list(v):
    """True if ``v`` is a list of non-empty strings."""
    return (isinstance(v, list)
            and all(isinstance(x, str) and x for x in v))


def _check_tool_annotations(annotations, where):
    """Validate the MCP ``annotations`` object (all values booleans)."""
    if annotations is None:
        return None
    if not isinstance(annotations, dict):
        raise McpManifestError(
            "%s: 'annotations' must be an object" % where)
    for key, val in annotations.items():
        if key not in _ANNOTATION_KEYS:
            raise McpManifestError(
                "%s: unknown annotation %r (expected one of %s)"
                % (where, key, ", ".join(_ANNOTATION_KEYS)))
        if not isinstance(val, bool):
            raise McpManifestError(
                "%s: annotation %r must be a boolean" % (where, key))
    return dict(annotations)


def _check_input_schema(schema, where):
    """Validate the MCP ``inputSchema`` / ``outputSchema`` (JSON Schema).

    We enforce the *shape* Caravel relies on (a JSON Schema object) without
    pulling in a full JSON-Schema validator (zero deps).  The minimum
    contract: a JSON object; if it declares ``type`` it must be ``"object"``
    (tool inputs are object-valued); ``properties`` (if present) is a mapping
    of name -> schema; ``required`` (if present) is a list of names.
    """
    if schema is None:
        return None
    if not isinstance(schema, dict):
        raise McpManifestError(
            "%s: 'inputSchema' must be a JSON Schema object" % where)
    if "type" in schema and schema["type"] != "object":
        raise McpManifestError(
            "%s: 'inputSchema.type' must be 'object' (got %r)"
            % (where, schema["type"]))
    if "properties" in schema:
        props = schema["properties"]
        if not isinstance(props, dict):
            raise McpManifestError(
                "%s: 'inputSchema.properties' must be an object" % where)
        for pname, pschema in props.items():
            if not _is_nonempty_str(pname):
                raise McpManifestError(
                    "%s: 'inputSchema.properties' keys must be non-empty "
                    "strings" % where)
            if not isinstance(pschema, dict):
                raise McpManifestError(
                    "%s: 'inputSchema.properties[%r]' must be a JSON Schema "
                    "object" % (where, pname))
    if "required" in schema:
        req = schema["required"]
        if not _is_str_list(req):
            raise McpManifestError(
                "%s: 'inputSchema.required' must be a list of field names"
                % where)
    return dict(schema)


def _check_field_list(v, key, where):
    """Validate a Caravel ``read_fields`` / ``write_fields`` list."""
    if v is None:
        return None
    if not _is_str_list(v):
        raise McpManifestError(
            "%s: %r must be a list of non-empty field-name strings"
            % (where, key))
    return list(v)


def _check_tenant_scope(v, where):
    """Validate a Caravel ``tenant_scope`` value."""
    if v is None:
        return None
    if not _is_nonempty_str(v):
        raise McpManifestError(
            "%s: 'tenant_scope' must be a non-empty string" % where)
    return v


class McpTool(object):
    """One entry of the manifest ``tools`` array.

    This is a *superset* of the MCP ``tools/list`` tool object: the MCP
    fields (``name``, ``title``, ``description``, ``inputSchema``,
    ``outputSchema``, ``annotations``) plus the Caravel compliance fields
    (``tenant_scope``, ``read_fields``, ``write_fields``).

    Attributes
    ----------
    name : str
        The tool name (required by MCP; must be unique within the manifest).
    title : str or None
        Human-readable title (optional, MCP).
    description : str or None
        Human-readable description (optional, MCP).
    input_schema : dict or None
        The JSON Schema for the tool's input (optional, MCP).
    output_schema : dict or None
        The JSON Schema for the tool's output (optional, MCP).
    annotations : dict or None
        The MCP hint annotations (optional, MCP).
    tenant_scope : str or None
        Caravel: which tenant this tool acts on (defaults to the manifest's
        top-level ``tenant_scope`` when omitted).
    read_fields : list[str]
        Caravel: the data fields the tool reads (default ``[]``).
    write_fields : list[str]
        Caravel: the data fields the tool writes (default ``[]``).
    """

    def __init__(self, name, title=None, description=None, input_schema=None,
                 output_schema=None, annotations=None, tenant_scope=None,
                 read_fields=None, write_fields=None):
        self.name = name
        self.title = title
        self.description = description
        self.input_schema = input_schema
        self.output_schema = output_schema
        self.annotations = annotations
        self.tenant_scope = tenant_scope
        self.read_fields = list(read_fields or [])
        self.write_fields = list(write_fields or [])

    # -- construction --------------------------------------------------------
    @classmethod
    def from_dict(cls, d, where="tool"):
        """Build an :class:`McpTool` from a raw ``tools[]`` object.

        Raises
        ------
        McpManifestError
            If the object is not a well-formed manifest tool.
        """
        if not isinstance(d, dict):
            raise McpManifestError(
                "%s: each tool must be a JSON object" % where)
        name = d.get("name")
        if not _is_nonempty_str(name):
            raise McpManifestError(
                "%s: 'name' is required and must be a non-empty string"
                % where)

        # MCP optional fields.
        title = d.get("title")
        if title is not None and not _is_nonempty_str(title):
            raise McpManifestError(
                "%s: 'title' must be a non-empty string when present" % where)
        description = d.get("description")
        if description is not None and not _is_nonempty_str(description):
            raise McpManifestError(
                "%s: 'description' must be a non-empty string when present"
                % where)
        input_schema = _check_input_schema(d.get("inputSchema"), where)
        output_schema = _check_input_schema(d.get("outputSchema"), where)
        annotations = _check_tool_annotations(d.get("annotations"), where)

        # Caravel compliance fields.
        tenant_scope = _check_tenant_scope(d.get("tenant_scope"), where)
        read_fields = _check_field_list(d.get("read_fields"),
                                       "read_fields", where)
        write_fields = _check_field_list(d.get("write_fields"),
                                        "write_fields", where)

        # Reject unknown keys (strict: a typo should not silently pass).
        known = {"name", "title", "description", "inputSchema",
                 "outputSchema", "annotations", "tenant_scope",
                 "read_fields", "write_fields"}
        extra = sorted(set(d) - known)
        if extra:
            raise McpManifestError(
                "%s: unknown tool key(s) %s" % (where, ", ".join(extra)))

        return cls(
            name=name,
            title=title,
            description=description,
            input_schema=input_schema,
            output_schema=output_schema,
            annotations=annotations,
            tenant_scope=tenant_scope,
            read_fields=read_fields,
            write_fields=write_fields,
        )

    # -- serialisation -------------------------------------------------------
    def to_dict(self):
        """A stable, JSON-serialisable dict (MCP + Caravel fields)."""
        d = {"name": self.name}
        if self.title is not None:
            d["title"] = self.title
        if self.description is not None:
            d["description"] = self.description
        if self.input_schema is not None:
            d["inputSchema"] = self.input_schema
        if self.output_schema is not None:
            d["outputSchema"] = self.output_schema
        if self.annotations is not None:
            d["annotations"] = self.annotations
        if self.tenant_scope is not None:
            d["tenant_scope"] = self.tenant_scope
        if self.read_fields:
            d["read_fields"] = list(self.read_fields)
        if self.write_fields:
            d["write_fields"] = list(self.write_fields)
        return d

    def __repr__(self):
        return ("McpTool(name=%r, read_fields=%r, write_fields=%r)"
                % (self.name, self.read_fields, self.write_fields))


class McpManifest(object):
    """A validated MCP Manifest v1 document.

    Attributes
    ----------
    manifest : str
        The schema tag (always :data:`MANIFEST_SCHEMA`).
    server : str or None
        The MCP server name (optional, provenance).
    version : str or None
        The server/manifest version (optional, provenance).
    tenant_scope : str or None
        The default tenant scope (Caravel). A tool that omits its own
        ``tenant_scope`` inherits this value.
    allowed_write_fields : list[str]
        The tenant's write-permission set (Caravel). A tool whose
        ``write_fields`` is not a subset of this set is *overly permissive*
        (field permission).
    tools : list[McpTool]
        The tool catalog (the MCP ``tools/list`` ``result.tools[]``).
    """

    def __init__(self, manifest, server=None, version=None,
                 tenant_scope=None, allowed_write_fields=None, tools=None):
        self.manifest = manifest
        self.server = server
        self.version = version
        self.tenant_scope = tenant_scope
        self.allowed_write_fields = list(allowed_write_fields or [])
        self.tools = list(tools or [])

    # -- construction --------------------------------------------------------
    @classmethod
    def from_dict(cls, d):
        """Build a :class:`McpManifest` from a raw manifest dict.

        Performs full validation and raises :class:`McpManifestError` on the
        first structural problem (with a stable, human-readable message).

        Raises
        ------
        McpManifestError
            If the document is not a well-formed MCP Manifest v1.
        """
        if not isinstance(d, dict):
            raise McpManifestError(
                "manifest must be a JSON object")

        # Required top-level keys.
        for key in _TOP_REQUIRED:
            if key not in d:
                raise McpManifestError(
                    "manifest missing required key %r" % key)

        schema = d["manifest"]
        if schema != MANIFEST_SCHEMA:
            raise McpManifestError(
                "unsupported manifest schema %r (expected %r)"
                % (schema, MANIFEST_SCHEMA))

        # Optional provenance.
        server = d.get("server")
        if server is not None and not _is_nonempty_str(server):
            raise McpManifestError(
                "'server' must be a non-empty string when present")
        version = d.get("version")
        if version is not None and not _is_nonempty_str(version):
            raise McpManifestError(
                "'version' must be a non-empty string when present")

        # Caravel top-level compliance fields.
        tenant_scope = _check_tenant_scope(d.get("tenant_scope"), "manifest")
        allowed_write_fields = _check_field_list(
            d.get("allowed_write_fields"), "allowed_write_fields", "manifest")

        # Reject unknown top-level keys (strict).
        known = {"manifest", "server", "version", "tenant_scope",
                 "allowed_write_fields", "tools"}
        extra = sorted(set(d) - known)
        if extra:
            raise McpManifestError(
                "manifest: unknown key(s) %s" % ", ".join(extra))

        # The tool catalog.
        raw_tools = d["tools"]
        if not isinstance(raw_tools, list):
            raise McpManifestError("manifest: 'tools' must be an array")
        tools = []
        seen = set()
        for i, raw in enumerate(raw_tools):
            where = "tools[%d]" % i
            tool = McpTool.from_dict(raw, where=where)
            if tool.name in seen:
                raise McpManifestError(
                    "tools[%d]: duplicate tool name %r" % (i, tool.name))
            seen.add(tool.name)
            tools.append(tool)

        return cls(
            manifest=schema,
            server=server,
            version=version,
            tenant_scope=tenant_scope,
            allowed_write_fields=allowed_write_fields,
            tools=tools,
        )

    # -- convenience ---------------------------------------------------------
    def tool_names(self):
        """The action universe: the sorted set of ``tools[].name``."""
        return sorted(t.name for t in self.tools)

    def get_tool(self, name):
        """Return the :class:`McpTool` called ``name`` (or ``None``)."""
        for t in self.tools:
            if t.name == name:
                return t
        return None

    def effective_tenant_scope(self, tool):
        """A tool's tenant scope, falling back to the manifest default."""
        return tool.tenant_scope if tool.tenant_scope is not None \
            else self.tenant_scope

    # -- serialisation -------------------------------------------------------
    def to_dict(self):
        """A stable, JSON-serialisable dict (round-trips through
        :meth:`from_dict`)."""
        d = {"manifest": self.manifest}
        if self.server is not None:
            d["server"] = self.server
        if self.version is not None:
            d["version"] = self.version
        if self.tenant_scope is not None:
            d["tenant_scope"] = self.tenant_scope
        if self.allowed_write_fields:
            d["allowed_write_fields"] = list(self.allowed_write_fields)
        d["tools"] = [t.to_dict() for t in self.tools]
        return d

    def __repr__(self):
        return ("McpManifest(server=%r, tenant_scope=%r, tools=%r)"
                % (self.server, self.tenant_scope,
                   [t.name for t in self.tools]))


def parse_manifest(doc):
    """Parse and validate a manifest *dict* into a :class:`McpManifest`.

    This is the in-memory entry point (the CLI and tests call it with an
    already-decoded JSON object).  See :meth:`McpManifest.from_dict` for the
    validation contract.

    Parameters
    ----------
    doc : dict
        A decoded manifest document.

    Returns
    -------
    McpManifest
        A validated manifest.

    Raises
    ------
    McpManifestError
        If the document is not a well-formed MCP Manifest v1.
    """
    return McpManifest.from_dict(doc)


def parse_manifest_file(path):
    """Read, parse and validate a manifest file.

    Parameters
    ----------
    path : str
        Path to a JSON manifest file.

    Returns
    -------
    McpManifest
        A validated manifest.

    Raises
    ------
    McpManifestError
        If the file is missing, is not valid JSON, or does not validate as
        an MCP Manifest v1.
    """
    try:
        with open(path, "r") as fh:
            doc = json.load(fh)
    except (IOError, OSError) as exc:
        raise McpManifestError("could not read manifest file %r: %s"
                               % (path, exc))
    except ValueError as exc:  # json.JSONDecodeError subclasses ValueError
        raise McpManifestError("malformed JSON in manifest file %r: %s"
                               % (path, exc))
    return parse_manifest(doc)