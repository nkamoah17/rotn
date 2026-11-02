# -*- coding: utf-8 -*-
"""rot.commercial -- the ROTN **paid** layer (SSPL / commercial license).

This is the "thick" open-core paid layer -- the value that is closed:

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
CI gate) is **Apache-2.0**.  This layer is licensed **separately** under SSPL
/ commercial terms (see ``rot/commercial/LICENSE`` and ``docs/licensing.md``)
so that a hosted clone of the paid layer must open-source its entire stack or
buy a license.

:mod:`rot.commercial` requires the ``rotn-commercial`` distribution (which
depends on the ``rotn`` core).  The core is fully importable and runnable
**without** this package -- the free ``rot demo`` never touches it.
"""
