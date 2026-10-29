# -*- coding: utf-8 -*-
"""rot.runtime -- the Product 2 runtime "coach" plane (Phase B).

Where the rest of ROTN is the *offline* plane -- verify a policy, emit a
hashable trace, coach the agent back in bounds *with a proof* -- this package
is the *runtime* plane: the same deterministic core deciding, **live**, on
every tool call an agent makes, and refusing with the exact same auditable
shape the offline coach produces.

The architectural promise (the narrow waist holds at runtime, not just offline)
is that **no new proof engine is added**.  Every decision is the evaluation of
a ``ProtocolIR`` decision-action guard (the spec) against the current state,
with the ``to_proceed`` enabling condition computed by :mod:`rot.to_proceed`
-- the *same* predicate the offline engine discharged.  The runtime only
*re-applies* the proven guard; it never re-derives it.

Modules (the B1..B6 plane):

  * :mod:`rot.runtime.core`       -- ``RuntimeGuard``: the deterministic
                                      allow/deny core (B1).
  * :mod:`rot.runtime.refusal`    -- the refusal JSON schema + deterministic,
                                      hashable serialization (B2).
  * :mod:`rot.runtime.rules`      -- the concrete rules (the spend-cap rule
                                      first): a ``ProtocolIR`` + the canonical
                                      ``why`` / ``to_proceed`` strings.
  * :mod:`rot.runtime.langchain`  -- the LangChain adapter: a tool-callback /
                                      ``Runnable`` wrapper (B3, first).
  * :mod:`rot.runtime.mcp`        -- the MCP ``tools/call`` interceptor (B4,
                                      second); the manifest is a first-class
                                      input.
  * :mod:`rot.runtime.ledger`     -- the append-only decision ledger (B5).
  * :mod:`rot.runtime.aggregate`  -- ``rot coach --aggregate``: which prompts /
                                      tool-descriptions cause blocks, which
                                      rules block legitimate work, and a
                                      re-proof that any relaxation stays safe.

The core (:mod:`rot.runtime.core` + :mod:`rot.runtime.refusal`) is **pure
stdlib** and Python 3.6 compatible -- it imports no framework.  The adapters
(:mod:`rot.runtime.langchain`, :mod:`rot.runtime.mcp`) lazy-import their
framework so the package stays importable (and the core stays testable)
without LangChain / an MCP runtime installed.

See ``docs/runtime.md`` for the design and the spend-cap runtime example.
"""

from .refusal import (
    SCHEMA as REFUSAL_SCHEMA,
    Refusal,
    refusal_hash,
    canonical_json,
)
from .core import RuntimeGuard, Decision, Rule, ALLOWED, BLOCKED
from .rules import spendcap_rule, exfiltration_rule, get_rule, RULES
from .ledger import (
    SCHEMA as LEDGER_SCHEMA,
    GENESIS_HASH,
    LedgerError,
    ChainBreak,
    LedgerEntry,
    DecisionLedger,
)
from .aggregate import (
    SCHEMA as AGGREGATE_SCHEMA,
    SAFE,
    UNSAFE,
    UNVERIFIED,
    NOT_APPLICABLE,
    AggregateResult,
    aggregate_ledger,
)
from .mcp import (
    JSONRPC,
    MCP_SCHEMA,
    McpError,
    McpGateway,
    intercept_tools_call,
    build_http_server,
)
from .langchain import (
    LangChainNotInstalled,
    GuardRunner,
    langchain_runnable,
    langchain_tool_callback,
    guarded_tool,
)

__all__ = [
    # B2 refusal
    "REFUSAL_SCHEMA",
    "Refusal",
    "refusal_hash",
    "canonical_json",
    # B1 core
    "RuntimeGuard",
    "Decision",
    "Rule",
    "ALLOWED",
    "BLOCKED",
    # B3 rules
    "spendcap_rule",
    "exfiltration_rule",
    "get_rule",
    "RULES",
    # B4 adapters
    "LangChainNotInstalled",
    "GuardRunner",
    "langchain_runnable",
    "langchain_tool_callback",
    "guarded_tool",
    "JSONRPC",
    "MCP_SCHEMA",
    "McpError",
    "McpGateway",
    "intercept_tools_call",
    "build_http_server",
    # B5 ledger + aggregate
    "LEDGER_SCHEMA",
    "GENESIS_HASH",
    "LedgerError",
    "ChainBreak",
    "LedgerEntry",
    "DecisionLedger",
    "AGGREGATE_SCHEMA",
    "SAFE",
    "UNSAFE",
    "UNVERIFIED",
    "NOT_APPLICABLE",
    "AggregateResult",
    "aggregate_ledger",
]
