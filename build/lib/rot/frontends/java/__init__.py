# -*- coding: utf-8 -*-
"""rot.frontends.java -- Java front-end: ``.java`` sources -> ``rot.ir.ProtocolIR``.

Public entry point (narrow-waist contract, see ``rot/frontends/__init__.py``)::

    build_ir(source_dir, protocol, n, buggy) -> ProtocolIR
"""

from .ir_builder import (PROTOCOL_TWOPC, agreement_property, build_ir,
                         detect_apply_mode, find_field_lines, method_span,
                         recover_enums, read_java_files, strip_comments)

__all__ = [
    "PROTOCOL_TWOPC",
    "agreement_property", "build_ir",
    "detect_apply_mode", "find_field_lines", "method_span",
    "recover_enums", "read_java_files", "strip_comments",
]