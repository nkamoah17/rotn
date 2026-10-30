# CPG fixtures (CPG-1)

Offline CPG artifacts for the CPG + TLA+ integration (CPG-1,
`docs/cpg-integration-plan.md`): the committed dataflow half.

- `connector.java` -- a small Java spend-cap + exfiltration connector: the
  budget control `canSpend` (in-flight aware, so a parallel burst cannot
  overshoot the cap) plus the private->sink exfiltration path
  `report -> mask -> AuditLog.send`.  Provenance: the JSON below is a
  scrape of this file; every node id and line number in the fixture refers
  to it.
- `connector.cpg.json` -- the CPG model (the `rot.frontends.cpg_model`
  shape) with the dataflow half populated: per-method `defs` / `args`, the
  typed `edges` (REACHING_DEF / ARGUMENT / CALL), and the conservative
  `taint_sources` / `taint_sinks` sets.

The live path is `rot.frontends.joern.scrape_model` (Joern + this tree's
`scrape.sc`); this artifact exists so the whole chain is testable
**offline** (no Java / no Joern), exactly like the TLC artifacts.