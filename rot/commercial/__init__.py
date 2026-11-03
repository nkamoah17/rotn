# -*- coding: utf-8 -*-
"""rot.commercial -- the ROTN **commercial** layer (Apache-2.0).

This is the "thick" commercial layer -- the service plane that wraps the
Apache-2.0 core:

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
All local code in this repo is **Apache-2.0** (the core and this layer).
The paid product is the **hosted service** (the cloud version of
``rot runtime serve`` + the signed attestations), which is NOT in this repo.
There is no free/paid budget split and no local license gate.

:mod:`rot.commercial` ships as the ``rotn-commercial`` distribution (which
depends on the ``rotn`` core).  The core is fully importable and runnable
**without** this package -- ``rot demo`` never touches it.
"""
