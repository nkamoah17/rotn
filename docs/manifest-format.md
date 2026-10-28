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

1. maps `tools[].name` → the action universe (the agent's tool catalog);
2. runs the **field/tenant structural checks** in `rot.mcp_adapter`:
   * `write_fields ⊄ allowed_write_fields` → **Overly Permissive**
     (field permission);
   * `read_fields` outside `tenant_scope` (cross-tenant) → **Overly
     Permissive** (tenant isolation);
3. runs the **behavioral (temporal) audit** in `rot.mcp_behavioral` (B2.5,
   closes gap G8): the manifest's safety property is *model-checked* over
   the adversarial agent's tool-call **sequences** (see §7);
4. emits the Cedar-AR findings report (structural + behavioral) and the
   gate exit code (`0` PASS / `1` BLOCK / `2` OUT_OF_SCOPE / `3` error).

The manifest is the *ingestion* surface; `rot.mcp_adapter` is the *finding*
surface; `rot.mcp_behavioral` is the *proof* surface. None imports the
other's internals — all sit above the narrow waist (`rot.ir`,
`rot.agent_harness`) and below the CLI (`rot/__main__.py`).

---

## 7. The behavioral (temporal) audit — G8

The structural checks above are a *declaration* check: they inspect the
fields each tool **declares**. Gap G8 (the audit's own words) flagged
exactly this — Product 4's claim, *"no user's agent can read another
user's data through this connector,"* is a *declaration* check, not a
*behavioral* proof. There was no temporal/concurrency verification of tool
use, and no adversarial agent calling the MCP tools in sequence.

`rot.mcp_behavioral` closes that by turning the manifest into an instance
of the general **adversarial agent + policy harness** model
(`rot.agent_harness`, the G1 generalization) and *model-checking* the
safety property over the reachable state space of tool-call sequences:

* **the agent** is a nondeterministic actor that may attempt *any* tool in
  the catalog, in *any order*, *repeatedly* (the thesis's "a fully
  compromised model");
* **the harness** (the thing under test) is the manifest's declared
  configuration — the exposed tools and their declared data access;
* **the property** is the guarantee proven to hold in *every* reachable
  state: the agent never reads another tenant's data and never writes
  outside the allowed write set.

The state tracks the *cumulative* data the agent has touched (four
precise boolean latches: `read_foreign`, `wrote_unapproved`,
`holding_private`, `used_outbound`), so the model is genuinely
*temporal*: a violation is a reachable state produced only by a
*sequence* of tool calls.

### The lethal-trifecta risk (flagged, not gated)

One property the declaration check cannot see at all is the
**exfiltration** configuration — the thesis's "lethal trifecta": the
agent reads the tenant's own private data (an *in-scope*,
structurally-clean read) **and** reaches an outbound (`openWorldHint`)
channel. Each tool is individually in-scope (the structural check PASSES),
but the *sequence* read-then-exfiltrate is the risk. The behavioral audit
**proves** the two hard guarantees and **reports** the trifecta as a
*risk warning* (`behavioral.trifecta_risk: true`) — it is never a
gate-affecting finding, matching the thesis's "flag this combination."

### Verdicts (bounded, fail-closed, like the rest of the engine)

| status | meaning |
|--------|---------|
| `proven` | the whole reachable state space was explored and the property holds in every state (a proof over the bounded model); |
| `violated` | a reachable state violates the property; the **witness** is that state *and* the tool-call **attack path** that reaches it; |
| `unknown` | the state budget was exhausted before the space drained — an honest `OUT_OF_SCOPE`, never read as proven. |

The audit is a **pure function** of the manifest + budget, so it is
deterministic, JSON-serialisable, and hashable. It is tier-gated exactly
like the rest of the engine: the manifest's tenant-scope count must be
within the tier's `max_tenant_scopes`, and the model-check respects the
tier's `max_states` (a truncated search is an honest `unknown`).

The verdict is attached to the findings report (`report.behavioral`)
and rendered in the narrative; a behavioral **violation blocks** even if
the structural check missed it (a safety net), and a behavioral
`unknown` is reported as `OUT_OF_SCOPE`.

See `tests/test_mcp_behavioral.py` for the worked cases (proven /
violated / trifecta / budget-exhausted) and the examples:

```bash
# Hard guarantees proven + the trifecta *risk* flagged (a warning).
rot check --manifest examples/mcp-manifest-good.json --tier free

# A cross-tenant read + an unapproved write, proven as a *sequence* with
# the attack path attached (the paid tier lifts the tenant-scope cap).
rot check --manifest examples/mcp-manifest-bad.json --tier paid
```
