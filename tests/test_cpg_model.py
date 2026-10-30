# -*- coding: utf-8 -*-
"""CPG-1 -- the dataflow half of the CPG model (rot.frontends.cpg_model):
round-trip of the new fields (defs/args, typed edges, taint sets), the
``taint_path`` private->sink query over the committed fixture, graceful
degradation of ``load_cpg_or_none``, and the offline import chain for the
CPG-2 integration (joern -> cpg_reader -> IR builder).

Runs offline: no Java, no Joern (the fixture is a committed artifact, like
the TLC artifacts).  ``python tests/test_cpg_model.py`` or pytest.
"""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from rot.frontends import cpg_reader
from rot.frontends.cpg_model import (
    CpgEdge, CpgField, CpgMethod, CpgModel, CpgTaintNode, CpgType,
    EDGE_ARGUMENT, EDGE_CALL, EDGE_REACHING_DEF,
)

FIXTURE = os.path.join(ROOT, "tests", "fixtures", "cpg", "connector.cpg.json")
JAVA = os.path.join(ROOT, "tests", "fixtures", "cpg", "connector.java")
CONN = "com.acme.guard.Connector"
AUDIT = "com.acme.guard.AuditLog"
SRC_SSN = CONN + ".report#ssn"          # classified taint source
SINK_SEND = AUDIT + ".send"             # classified egress sink (a method)
SRC_AMOUNT = CONN + ".canSpend#amount"  # a source that must NOT reach SINK_SEND


def _roundtrip_model():
    model = CpgModel(
        meta={"source": "x"},
        types=[CpgType("T", "a.T", owner="a", line=1, end_line=9,
                       inherits=["a.Base"])],
        fields=[CpgField("f", "a.T.f", type_name="int", owner="a.T")],
        methods=[CpgMethod("m", "a.T.m", owner="a.T", line=2, end_line=4,
                           calls=["a.T.n"], read_fields=["f"],
                           written_fields=["f"], defs=["f", "x"], args=["x"])],
        edges=[CpgEdge(EDGE_REACHING_DEF, "a.T.m#x", "a.T.n#x", line=3,
                       note="pass"),
               CpgEdge(EDGE_ARGUMENT, "a.T.m#x", "a.T.n#x", line=3),
               CpgEdge(EDGE_CALL, "a.T.m", "a.T.n", line=3)],
        taint_sources=[CpgTaintNode("a.T.m#x", "parameter", name="x",
                                    owner="a.T.m", reason="private-name:x",
                                    line=2)],
        taint_sinks=[CpgTaintNode("a.T.n", "call", name="n", owner="a.T.m",
                                  reason="egress-name:send", line=3)],
    )
    assert not model.validate(), model.validate()
    d = model.to_dict()
    m2 = CpgModel.from_dict(d)
    assert m2.to_dict() == d, "JSON round-trip changed the model"
    return model


def test_roundtrip_new_fields():
    m = _roundtrip_model()
    assert m.edges and m.taint_sources and m.taint_sinks
    assert m.edges_of(EDGE_CALL)[0].src == "a.T.m"
    assert len(m.dataflow_edges()) == 2
    assert m.is_taint_source("a.T.m#x") and not m.is_taint_source("a.T.m")
    assert m.is_taint_sink("a.T.n")
    # taint_path over dataflow edges (not via CALL): source -> sink method,
    # via the parameter slot, then the slot -> owning-method projection.
    path = m.taint_path("a.T.m#x", "a.T.n")
    assert path == ["a.T.m#x", "a.T.n#x", "a.T.n"]
    # the full taintPath(G) set
    pairs = m.taint_paths()
    assert len(pairs) == 1 and pairs[0][0] == "a.T.m#x" and pairs[0][1] == "a.T.n"


def test_taint_path_negative_and_trivial():
    m = _roundtrip_model()
    assert m.taint_path("a.T.n#x", "a.T.m#x") is None
    assert m.taint_path("", "a.T.n") is None
    assert m.taint_path("a.T.m#x", "a.T.m#x") == ["a.T.m#x"]


def test_backwards_compat_old_json():
    d = {
        "meta": {"source": "old"},
        "types": [{"name": "T", "fullName": "a.T"}],
        "fields": [{"name": "f", "fullName": "a.T.f", "type": "int"}],
        "methods": [{"name": "m", "fullName": "a.T.m", "owner": "a.T",
                     "calls": [], "readFields": [], "writtenFields": []}],
    }
    m = CpgModel.from_dict(d)
    assert m.edges == [] and m.taint_sources == [] and m.taint_sinks == []
    assert [x for x in m.methods[0].defs] == []
    assert m.methods[0].args == []
    assert m.taint_path("a.T.m", "a.T.f") is None
    assert m.validate() == []


def test_fixture_loads_and_taint_path_found():
    m = cpg_reader.load_cpg_or_none(FIXTURE)
    assert m is not None, "the committed CPG fixture must load"
    assert not m.validate()
    assert m.taint_source_ids(), "fixture must classify at least one source"
    assert SINK_SEND in m.taint_sink_ids()
    assert m.is_taint_source(SRC_SSN)
    path = m.taint_path(SRC_SSN, SINK_SEND)
    assert path is not None, "taint_path must find the private->sink edge"
    assert path[0] == SRC_SSN and path[-1] == SINK_SEND
    assert len(path) >= 3
    # deterministic: same query, same path
    assert m.taint_path(SRC_SSN, SINK_SEND) == path
    # negative: an unrelated source must not reach the sink
    assert SRC_AMOUNT in m.taint_source_ids()
    assert m.taint_path(SRC_AMOUNT, SINK_SEND) is None
    # the spend-cap control is present in the fixture (the budget side)
    can = [x for x in m.methods if x.name == "canSpend"]
    assert can and can[0].read_fields and "cap" in can[0].read_fields
    assert "amount" in can[0].args and "projected" in can[0].defs


def test_load_degrades_gracefully():
    d = tempfile.mkdtemp(prefix="rotn_cpg_test_")
    p = os.path.join(d, "broken.cpg.json")
    with open(p, "w") as fh:
        fh.write("{ not json")
    assert cpg_reader.load_cpg_or_none(p) is None
    p2 = os.path.join(d, "missing.cpg.json")
    assert cpg_reader.load_cpg_or_none(p2) is None
    # an old-shape JSON (no dataflow half) still loads
    p3 = os.path.join(d, "old.cpg.json")
    with open(p3, "w") as fh:
        json.dump({"meta": {"source": "old"},
                   "types": [{"name": "T", "fullName": "a.T"}],
                   "fields": [], "methods": []}, fh)
    m = cpg_reader.load_cpg_or_none(p3)
    assert m is not None and m.edges == [] and m.taint_sources == []


def test_offline_chain_and_scrape_contract():
    # CPG-2 chain surface: joern driver + reader + model all import offline.
    from rot.frontends import joern, cpg_reader as cr, cpg_model as cm
    assert cr.load_cpg_or_none is not None
    assert hasattr(joern, "scrape_model")
    assert hasattr(cm.CpgModel, "taint_path") and hasattr(cm.CpgModel, "taint_paths")
    # scrape contract: the scrape still emits the core sections and now the
    # dataflow half; the success marker is unchanged.
    sc = os.path.join(ROOT, "rot", "frontends", "java", "scrape.sc")
    with open(sc, encoding="utf-8") as fh:
        src = fh.read()
    for token in ("ROTN-SCRAPE-OK", "types", "fields", "methods", "edges",
                  "taint_sources", "taint_sinks", "defs", "args",
                  "REACHING_DEF", "ARGUMENT", "CALL", "knownMethods"):
        assert token in src, "scrape.sc lost a contract token: %s" % token
    # the fixture source is present (provenance)
    assert os.path.isfile(JAVA)


def main():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print("PASS", fn.__name__)
    print("test_cpg_model: all %d passed" % len(fns))


if __name__ == "__main__":
    main()