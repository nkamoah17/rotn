# -*- coding: utf-8 -*-
"""rot.commercial -- the ROTN **commercial** layer (SSPL-1.0 / commercial).

This is the "thick" commercial layer -- **source-available** in this repo
(the code is here to read and use), licensed separately under SSPL-1.0:

  * :mod:`rot.commercial.runtime`  -- the Product 2 runtime coach **as a
    service**: the LangChain adapter, the MCP ``tools/call`` gateway
    (``rot runtime serve``), and the fleet near-miss aggregate
    (``rot coach --aggregate``);
  * :mod:`rot.commercial.mcp_behavioral` -- the G8 **behavioral** (temporal)
    audit of an MCP manifest (the "declaration check -> behavioral proof"
    upgrade);
  * :mod:`rot.commercial.trifecta_risk` -- the Lethal-Trifecta risk surface +
    checkable property (risk forecasting).

Licensing
---------
The **core** (:mod:`rot` -- the bounded engine, the spend-cap policy class,
the deterministic counterexample, the tests, the one-pager generator, and the
CI gate) is **Apache-2.0**.  This layer is **source-available** in the repo
and licensed **separately** under SSPL-1.0 / commercial terms (see
``rot/commercial/LICENSE`` and ``docs/licensing.md``): free to read, use, and
self-host, but a hosted clone must open-source its entire stack or buy a
license.

:mod:`rot.commercial` ships as the ``rotn-commercial`` distribution (which
depends on the ``rotn`` core).  The core is fully importable and runnable
**without** this package -- ``rot demo`` never touches it.
"""
