# MCP Manifest v1

> **Schema tag:** `caravel.mcp-manifest/v1` · **Module:** `rot/mcp_manifest.py`
> **Status:** shipped (Phase B, B1)

An **MCP Manifest** is a single JSON document that describes an MCP server's
tool catalog in the shape defined by the Model Context Protocol
(specification `2025-06-18`), *plus* the Caravel policy/compliance fields that
let `rot check --manifest` run structural checks (field permission, tenant
isolation) without a runtime.

A manifest is a **superset** of the MCP `tools/list` result:

* the `tools` array is exactly the MCP `result.tools[]` shape — each tool
  carries `name` (required) and the optional `title`, `description`,
  `inputSchema`, `outputSchema`, and `annotations`;
* the Caravel additions are `tenant_scope` (which tenant a tool acts on),
  `read_fields` / `write_fields` (the data fields it reads/writes), and the
  top-level `allowed_write_fields` (the tenant's write-permission set).

The manifest is **policy-bearing**: it is the single document that names the
action universe (`tools[].name`) and the compliance constraints, so
`rot check --manifest mcp.json` needs no separate policy file.

---

## 1. Top-level shape

| key | type | required | meaning |
|-----|------|----------|---------|
| `manifest` | string | **yes** | Must be exactly `caravel.mcp-manifest/v1`. |
| `server` | string | no | The MCP server name (provenance). |
| `version` | string | no | The server/manifest version (provenance). |
| `tenant_scope` | string | no | Default tenant scope. A tool that omits its own `tenant_scope` inherits this. |
| `allowed_write_fields` | list[string] | no | The tenant's write-permission set. A tool whose `write_fields` is not a subset of this set is **Overly Permissive** (field permission). |
| `tools` | list[object] | **yes** | The tool catalog (the MCP `tools/list` `result.tools[]`). |

Unknown top-level keys are rejected (strict — a typo should not silently pass).

---

## 2. Tool object

Each `tools[]` entry is a **superset** of the MCP tool object.

### MCP fields (spec `2025-06-18`)

| key | type | required | meaning |
|-----|------|----------|---------|
| `name` | string | **yes** | The tool name. Must be unique within the manifest. |
| `title` | string | no | Human-readable title. |
| `description` | string | no | Human-readable description. |
| `inputSchema` | object | no | JSON Schema for the tool's input (must be `type: "object"`). |
| `outputSchema` | object | no | JSON Schema for the tool's output (must be `type: "object"`). |
| `annotations` | object | no | MCP hint annotations (see below). |

### Caravel compliance fields

| key | type | required | meaning |
|-----|------|----------|---------|
| `tenant_scope` | string | no | Which tenant this tool acts on (defaults to the manifest's `tenant_scope`). |
| `read_fields` | list[string] | no | The data fields the tool reads (default `[]`). |
| `write_fields` | list[string] | no | The data fields the tool writes (default `[]`). |

Unknown tool keys are rejected.

### `annotations` object

All values are booleans. Only these keys are accepted:

| key | meaning |
|-----|---------|
| `readOnlyHint` | `true` if the tool does not modify its environment. |
| `destructiveHint` | `true` if the tool performs a destructive update. |
| `idempotentHint` | `true` if repeated calls have no additional effect. |
| `openWorldHint` | `true` if the tool interacts with entities outside the system. |


---

## 3. `inputSchema` / `outputSchema`

Caravel enforces the *shape* it relies on without pulling in a full
JSON-Schema validator (zero deps):

* it is a JSON object;
* if it declares `type`, it must be `"object"` (tool inputs/outputs are
  object-valued);
* `properties` (if present) is a mapping of non-empty name → JSON Schema
  object;
* `required` (if present) is a list of field names.

---

## 4. Example

```jsonc
{
  "manifest": "caravel.mcp-manifest/v1",
  "server": "caravel-agent-tools",
  "version": "1.0.0",
  "tenant_scope": "tenant:acme",              // default, overridable per tool
  "allowed_write_fields": ["account.balance"],// the tenant's write set
  "tools": [
    {
      "name": "update_balance",                // required (MCP)
      "title": "Update account balance",       // optional (MCP)
      "description": "Adjust a tenant's balance", // optional (MCP)
      "inputSchema": {                         // MCP
        "type": "object",
        "properties": { "amount": { "type": "number" } },
        "required": ["amount"]
      },
      "annotations": {                         // MCP
        "readOnlyHint": false,
        "destructiveHint": true,
        "idempotentHint": false,
        "openWorldHint": true
      },
      "tenant_scope": "tenant:acme",           // Caravel: which tenant it acts on
      "read_fields":  ["account.balance"],     // Caravel: fields it reads
      "write_fields": ["account.balance"]      // Caravel: fields it writes
    }
  ]
}
```

---

## 5. Validation contract

`rot.mcp_manifest.parse_manifest(doc)` (and `parse_manifest_file(path)`)
performs full validation and raises `McpManifestError` on the first structural
problem, with a stable, human-readable message. Checks include:

* the `manifest` tag is exactly `caravel.mcp-manifest/v1`;
* required keys are present (`manifest`, `tools`); each `tools[]` has a
  non-empty `name`; tool names are unique;
* `annotations` values are booleans and only known keys are used;
* `inputSchema` / `outputSchema` are JSON Schema objects (`type: "object"`);
* `read_fields` / `write_fields` / `allowed_write_fields` are lists of
  non-empty strings;
* unknown keys (top-level and per-tool) are rejected.

Parsing is **pure and deterministic**: the same document always yields the
same `McpManifest`, and `parse_manifest(m.to_dict())` round-trips.

---

## 6. How it feeds `rot check --manifest`

`rot check --manifest mcp.json` (Phase B, B2) does **not** re-derive a policy
from the manifest. Instead it:

1. maps `tools[].name` → the allowed action universe (the dogwood
   `AgentStep` model, `rot.ir.AdversarialPolicy`);
2. runs the **field/tenant structural checks** in `rot.mcp_adapter`:
   * `write_fields ⊄ allowed_write_fields` → **Overly Permissive**
     (field permission);
   * `read_fields` outside `tenant_scope` (cross-tenant) → **Overly
     Permissive** (tenant isolation);
3. emits the Cedar-AR findings report and the gate exit code
   (`0` PASS / `1` BLOCK / `2` OUT_OF_SCOPE / `3` error).

The manifest is the *ingestion* surface; `rot.mcp_adapter` is the *finding*
surface. Neither imports the other's internals — both sit above the narrow
waist (`rot.ir`) and below the CLI (`rot/__main__.py`).