# -*- coding: utf-8 -*-
"""incremental.py -- delta IR construction + incremental TLA+ translation.

Given an existing ``ProtocolIR`` and an :class:`rot.impact.ImpactSet`, this
module produces a *delta* IR (only the impacted transition actions, with the
same state schema) and emits it as a focused TLA+ spec -- the TLA+ fragment
that changed, not the whole protocol. The result is small enough that
TLC/Apalache can re-check it quickly after a change.

This is the "incremental translation" companion to :mod:`rot.impact`:
impact answers *what* changed and *what else is affected*; incremental
answers *how to re-verify only the affected slice*.

Pure stdlib, Python 3.6 compatible.
"""

from .ir import ProtocolIR
from .impact import compute_impact

__all__ = ["build_delta_ir", "emit_delta_spec"]


def build_delta_ir(ir, impact_set):
    """Filter ``ir`` to only the impacted transition actions.

    Returns a new :class:`rot.ir.ProtocolIR` that keeps the *same state schema*
    (all variables, init, pinned property) but only the init action plus the
    transition actions named in ``impact_set.impacted_actions``. This is the
    delta IR: the slice of the protocol the change can reach.

    The original ``ir`` is not mutated.
    """
    impacted = set(impact_set.impacted_actions)
    delta_actions = [
        a for a in ir.actions
        if a.is_initial or a.name in impacted
    ]
    return ProtocolIR(
        name=ir.name + "_delta",
        variables=list(ir.variables),
        actions=delta_actions,
        init=ir.init,
        pinned_property=ir.pinned_property,
        assumptions=list(ir.assumptions),
        source_path=ir.source_path,
        metadata=dict(
            ir.metadata,
            delta=True,
            changed_actions=list(impact_set.changed_actions),
            impacted_actions=list(impact_set.impacted_actions),
        ),
    )


def emit_delta_spec(ir, impact_set=None, changed_actions=None,
                    invariant_name="", invariant_expr=None,
                    out_dir=None, module_name=None):
    """Incremental translation: build the delta IR and emit a focused TLA+ spec.

    Parameters
    ----------
    ir:
        The full :class:`rot.ir.ProtocolIR`.
    impact_set:
        A precomputed :class:`rot.impact.ImpactSet`. If ``None`` and
        ``changed_actions`` is given, one is computed on the fly.
    changed_actions:
        Action names that changed (used only when ``impact_set`` is ``None``).
    invariant_name, invariant_expr:
        The property to check the delta spec against.
    out_dir:
        If given, the ``.tla``/``.cfg`` are written there.
    module_name:
        Optional TLA+ module name (defaults to a derived identifier).

    Returns a dict with keys ``tla_source``, ``op_name``, ``tla_path``,
    ``cfg_path``, ``delta_ir``.
    """
    if impact_set is None:
        if not changed_actions:
            raise ValueError(
                "emit_delta_spec needs an impact_set or changed_actions")
        # Fold the invariant to check into an Invariant so it participates in
        # the affected-invariants computation (and thus the delta schema).
        inv_list = []
        if invariant_expr is not None:
            from .invariants import Invariant as _Inv
            inv_list = [_Inv(invariant_name or "property", "",
                             invariant_expr, "safety")]
        impact_set = compute_impact(ir, changed_actions, invariants=inv_list)

    delta_ir = build_delta_ir(ir, impact_set)

    from .emitter import emit_delta
    tla_source, op_name, emitter = emit_delta(
        delta_ir, invariant_name, invariant_expr, module_name=module_name)

    tla_path = cfg_path = None
    if out_dir:
        import os
        if not os.path.isdir(out_dir):
            os.makedirs(out_dir)
        base = emitter.module_name
        tla_path, cfg_path, _ = emitter.write(
            out_dir, invariant_name, invariant_expr, base=base)

    return {
        "tla_source": tla_source,
        "op_name": op_name,
        "tla_path": tla_path,
        "cfg_path": cfg_path,
        "delta_ir": delta_ir,
        "impact_set": impact_set,
    }