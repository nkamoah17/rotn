# -*- coding: utf-8 -*-
"""``python -m rot.frontends.java`` -- Java front-end CLI.

Usage::

    python -m rot.frontends.java <java_dir> --participants N [--buggy]
                                  [--dump-cpg] [--validate]

  * default        -- build the ProtocolIR from the Java sources under
                      ``<java_dir>`` and print its JSON (``ir.to_dict()``)
                      to stdout.
  * ``--dump-cpg`` -- print the IR as a ``rot/cpg_reader``-schema CpgGraph
                      document instead (the ``_joern_test`` fixture shape).
  * ``--validate`` -- build the IR, run ``ir.validate()`` (raises on
                      inconsistency) and exit 0; exit 1 on any failure.
                      Can be combined with the other modes (validate first,
                      then emit).

Only ``rot.frontends.java`` + ``rot.ir`` are used (narrow-waist contract);
the CPG document rendering is inlined here so no downstream engine module is
imported.  Python 3.6 compatible.
"""

import argparse
import json
import sys

from . import ir_builder


def to_cpg_document(ir):
    """Render ``ir`` as a ``rot/cpg_reader``-schema CpgGraph document.

    Same shape as ``_joern_test/cpg_bridge.build_document`` (one function
    whose ``branches`` are the IR actions; guard/effect expressions use the
    canonical ``Expr.to_dict`` so ``rot.cpg_reader.build_ir`` maps them
    losslessly back through ``Expr.from_dict``).  Inlined here -- the
    narrow-waist rule forbids importing ``rot.cpg_reader`` from this
    package.
    """
    variables = [
        {"name": v.name,
         "domain": {"kind": "enum", "values": list(v.domain.values)},
         "mode": v.mode, "owner": v.owner, "desc": v.desc}
        for v in ir.variables
    ]
    branches = [
        {"id": a.name,
         "owner": a.owner,
         "guard": a.guard.to_dict(),
         "effects": [{"var": e.var, "expr": e.expr.to_dict()}
                     for e in a.effects],
         "initial": bool(getattr(a, "is_initial", False)),
         "source": ir.source_path or ""}
        for a in ir.actions
    ]
    functions = [{"name": ir.metadata.get("protocol", "twopc"),
                  "calls": [], "branches": branches}]
    return {
        "module": ir.name,
        "language": ir.metadata.get("language", "java"),
        "source_file": ir.source_path or "",
        "description": ir.metadata.get("description", ""),
        "variables": variables,
        "functions": functions,
        "messages": [],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="rot.frontends.java",
        description="Java -> rot.ir.ProtocolIR front-end (2PC).")
    parser.add_argument("source_dir",
                        help="directory containing the .java sources")
    parser.add_argument("-n", "--participants", type=int, default=3,
                        help="number of participants to linearise (default 3)")
    parser.add_argument("--buggy", action="store_true",
                        help="force the BUGGY apply mode (participants "
                             "re-derive their decision from their own vote)")
    parser.add_argument("--dump-cpg", action="store_true",
                        help="emit a CpgGraph document (rot/cpg_reader "
                             "schema) instead of the IR JSON")
    parser.add_argument("--validate", action="store_true",
                        help="run ir.validate() before emitting (exit 0/1)")
    args = parser.parse_args(argv)

    try:
        buggy = True if args.buggy else None  # None: detect from sources
        ir = ir_builder.build_ir(args.source_dir,
                                 protocol=ir_builder.PROTOCOL_TWOPC,
                                 n=args.participants, buggy=buggy)
        if args.validate:
            ir.validate()
    except Exception as exc:  # noqa: BLE001 -- CLI boundary: report + exit 1
        sys.stderr.write("rot.frontends.java: %s\n" % (exc,))
        return 1

    if args.dump_cpg:
        print(json.dumps(to_cpg_document(ir), indent=2))
    else:
        print(json.dumps(ir.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())