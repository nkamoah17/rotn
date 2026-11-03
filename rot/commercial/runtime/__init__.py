# -*- coding: utf-8 -*-
"""rot.commercial.runtime -- the Product 2 runtime **service** plane.

The deterministic *decision* core -- :class:`~rot.runtime.core.RuntimeGuard`,
the canonical rules, the hashable refusal shape, and the append-only ledger --
stays in the **core** (:mod:`rot.runtime`, Apache-2.0).  This package is the
*service* half that wraps that core for the agent frameworks and the fleet:

  * :mod:`rot.commercial.runtime.langchain` -- the LangChain adapter (B3);
  * :mod:`rot.commercial.runtime.mcp`       -- the MCP ``tools/call`` gateway
                                               (B4, ``rot runtime serve``);
  * :mod:`rot.commercial.runtime.aggregate` -- ``rot coach --aggregate``:
                                               fleet near-miss learning (B5).

All three import the core via absolute :mod:`rot.runtime` paths, so the
dependency is one-directional (commercial -> core) and the core stays importable
with this package absent.  Requires the ``rotn-commercial`` distribution.
"""

from rot.commercial.runtime import langchain  # noqa: E402,F401
from rot.commercial.runtime import mcp  # noqa: E402,F401
from rot.commercial.runtime import aggregate  # noqa: E402,F401

__all__ = ["langchain", "mcp", "aggregate"]
