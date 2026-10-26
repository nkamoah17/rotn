# -*- coding: utf-8 -*-
"""
cpg_reader.py -- load and validate pre-computed CPG JSON artifacts.

``rot.frontends.joern.scrape.sc`` runs a *live* Joern scrape (needs the Java
+ Joern toolchain).  When a CPG has already been produced -- e.g. the scrape
was run once and the JSON committed as ``<name>.cpg.json`` -- this module
loads it with no Java dependency and validates it, so downstream consumers
(``cone_of_influence``) can rely on a well-formed ``CpgModel``::

    from rot.frontends import cpg_reader, cone
    cpg  = cpg_reader.load_cpg("examples/twopc/twopc.cpg.json")
    cone.cone_of_influence(cpg, "Participant.vote")

Narrow waist: stdlib + ``rot.frontends.cpg_model`` only.
"""

import os
import sys

from rot.frontends.cpg_model import CpgModel


class CpgReadError(Exception):
    """Raised when a CPG artifact is missing, unparseable, or malformed."""


def load_cpg(path):
    """Load the CPG JSON artifact at ``path`` and validate it.

    Returns a ``cpg_model.CpgModel``.  Raises :class:`CpgReadError` if the
    file does not exist, is not valid JSON, or fails the model's
    well-formedness check (``CpgModel.validate``).
    """
    if not os.path.isfile(path):
        raise CpgReadError("CPG artifact not found: %s" % path)
    try:
        model = CpgModel.from_file(path)
    except (IOError, OSError, ValueError) as exc:
        raise CpgReadError("cannot parse CPG artifact %s: %s" % (path, exc))
    errors = model.validate()
    if errors:
        raise CpgReadError("CPG artifact %s is malformed: %s"
                           % (path, "; ".join(errors)))
    return model


def load_cpg_or_none(path):
    """Like :func:`load_cpg`, but returns ``None`` (warning on stderr) instead
    of raising -- for optional, CPG-enhanced paths that must degrade
    gracefully when the artifact is absent."""
    try:
        return load_cpg(path)
    except CpgReadError as exc:
        sys.stderr.write("cpg_reader: %s\n" % exc)
        return None


__all__ = ["CpgReadError", "load_cpg", "load_cpg_or_none"]