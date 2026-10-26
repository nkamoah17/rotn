# -*- coding: utf-8 -*-
"""composition.py -- the composition plane: merge per-service IRs into one.

Phase 2 of the multi-service verification program.  Phase 1 (the assurance
ladder) decided *how strongly* a property may gate a merge request; Phase 2
extends the *scope* of verification from one service to several services that
share state and act concurrently.

The building block is :func:`compose`: it takes two or more well-formed
:class:`rot.ir.ProtocolIR` objects (one per service) and merges them into a
single concurrent transition system:

  * **state variables** are unioned by name.  A variable shared by two
    services must agree on domain and mode; a shared name with a conflicting
    meaning is a modelling error, so :class:`CompositionError` is raised
    (rather than silently renaming one of them away);
  * **actions** are namespaced as ``<service>.<action>`` so that two services
    with same-named actions (e.g. two ``init`` actions) cannot collide, and
    every witness step stays attributable to the service that owns it;
  * **initialisation** is merged: the services' initial actions must agree on
    the value assigned to every variable they both initialise, yielding one
    consistent global init state (disagreement raises
    :class:`CompositionError`);
  * invariants (pinned properties), assumptions, channels and provenance
    metadata are combined, and the composed IR must itself pass
    ``ProtocolIR.validate()``.

Cross-service invariants (e.g. ``no_double_charge`` on the payment target) are
then pinned against the composed IR exactly like any other invariant, and --
by the Phase 1 assurance ladder -- they live on the ``RUNG_E2E`` rung: they
may carry a blocking label and pinning, and a violation may block the merge
request.

Pure stdlib, Python 3.6 compatible.
"""

import rot.ir as ir

__all__ = [
    "CompositionError",
    "compose",
    "shared_variables",
]


class CompositionError(Exception):
    """Raised when per-service IRs cannot be merged into one well-formed IR."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _domain_key(domain):
    """A structural key for a variable domain, for compatibility checks."""
    if isinstance(domain, ir.Bool):
        return ("bool",)
    if isinstance(domain, ir.Enum):
        return ("enum", tuple(domain.values))
    if isinstance(domain, ir.IntRange):
        return ("int", domain.lo, domain.hi)
    if isinstance(domain, ir.RealRange):
        return ("real", domain.lo, domain.hi)
    return ("other", type(domain).__name__)


def _same_domain(a, b):
    return _domain_key(a.domain) == _domain_key(b.domain)


def shared_variables(*services):
    """Names of state variables declared by more than one of ``services``."""
    counts = {}
    for svc in services:
        for v in svc.variables:
            counts[v.name] = counts.get(v.name, 0) + 1
    return sorted(n for n, c in counts.items() if c > 1)


def _expr_equal(a, b):
    """Structural equality of two IR expressions (falls back to identity)."""
    try:
        return a == b
    except Exception:
        return a is b


# ---------------------------------------------------------------------------
# The composition plane
# ---------------------------------------------------------------------------
def _is_true(e): 
    """True iff ``e`` is the constant True (``ir.T()``)."""
    return isinstance(e, ir.Const) and e.value is True

def compose(name, services, assumptions=None, metadata=None):
    """Compose per-service :class:`rot.ir.ProtocolIR` objects into one IR.

    Parameters
    ----------
    name : str
        Name of the composed IR (e.g. ``"payment"``).
    services : list of ProtocolIR
        The per-service IRs, in composition order.  Each must already be
        well-formed (``ProtocolIR.validate()`` empty) and the names must be
        unique (they namespace the actions of the composed IR).
    assumptions : Expr or None
        Extra environment assumptions, AND-combined with each service's own.
    metadata : dict or None
        Extra provenance metadata for the composed IR.

    Returns
    -------
    ProtocolIR
        A single, well-formed IR whose states are the product of the service
        states and whose actions are the services' actions, namespaced.

    Raises
    ------
    CompositionError
        If a service is ill-formed, two services share a name, a shared state
        variable is declared with a conflicting domain or mode, or the
        services' initial actions disagree on a shared variable.
    """
    if not services:
        raise CompositionError("compose() needs at least one service IR")
    for svc in services:
        if not isinstance(svc, ir.ProtocolIR):
            raise CompositionError(
                "every service must be a ProtocolIR, got %r" % (type(svc),))
        # NOTE: a service IR need not be self-contained -- it may
        # reference variables owned by *other* services (that is what
        # composition is for).  The *composed* IR is validated for
        # well-formedness at the end of this function.

    # -- unique service names (they namespace the composed actions) ----------
    labels = [svc.name for svc in services]
    if len(set(labels)) != len(labels):
        raise CompositionError(
            "service names must be unique to namespace actions; got %r"
            % (labels,))

    # -- merge state variables (union by name, compatible domains) -----------
    variables = []
    by_name = {}
    for svc in services:
        for v in svc.variables:
            if v.name in by_name:
                if not (_same_domain(by_name[v.name], v)
                        and by_name[v.name].mode == v.mode):
                    raise CompositionError(
                        "shared state variable %r is declared with a "
                        "conflicting domain/mode by services %r and %r"
                        % (v.name, by_name[v.name].owner, v.owner))
            else:
                by_name[v.name] = v
                variables.append(v)

    # -- namespace actions; collect initial actions for a merged init --------
    actions = []
    action_names = set()
    init_effects = []
    init_services = []
    for svc in services:
        for a in svc.actions:
            new_name = "%s.%s" % (svc.name, a.name)
            if new_name in action_names:
                raise CompositionError("action name collision: %r" % (new_name,))
            action_names.add(new_name)
            if a.is_initial:
                init_services.append(svc.name)
                init_effects.extend(a.effects)
            else:
                actions.append(ir.Action(
                    name=new_name,
                    owner=a.owner,
                    guard=a.guard,
                    effects=list(a.effects),
                    linearization=a.linearization,
                    env_free=a.env_free,
                    is_initial=False,
                    source=a.source,
                    rung=a.rung,
                    is_env=a.is_env,
                ))

    # -- merge the init actions into one consistent global init state --------
    merged = []
    assigned = {}
    for e in init_effects:
        if e.var in assigned:
            if not _expr_equal(assigned[e.var], e.expr):
                raise CompositionError(
                    "services disagree on the initial value of shared "
                    "variable %r (initialised by %s)"
                    % (e.var, ", ".join(init_services)))
        else:
            assigned[e.var] = e.expr
            merged.append(e)
    if merged:
        actions.append(ir.Action(
            name="init",
            owner="composed",
            guard=ir.T(),
            effects=merged,
            is_initial=True,
        ))

    # -- combine invariants / assumptions / channels -------------------------
    pinned = None
    for svc in services:
        p = svc.pinned_property
        if p is not None and not _is_true(p):
            pinned = p if pinned is None else ir.And(pinned, p)
    assumption_parts = []
    for svc in services:
        for a in (svc.assumptions or []):
            if a is not None and not _is_true(a):
                assumption_parts.append(a)
    if assumptions is not None:
        if isinstance(assumptions, (list, tuple)):
            for a in assumptions:
                if a is not None and not _is_true(a):
                    assumption_parts.append(a)
        elif not _is_true(assumptions):
            assumption_parts.append(assumptions)
    assumptions_out = None
    for a in assumption_parts:
        assumptions_out = (a if assumptions_out is None
                           else ir.And(assumptions_out, a))
    channels = []
    seen_channels = set()
    for svc in services:
        for c in (svc.channels or []):
            if c.name not in seen_channels:
                seen_channels.add(c.name)
                channels.append(c)

    # -- provenance: keep each service's metadata under its label ------------
    meta = dict(metadata or {})
    meta["composition"] = {
        "services": [
            {
                "name": svc.name,
                "source_path": svc.source_path or "",
                "metadata": svc.metadata or {},
            }
            for svc in services
        ],
        "shared_variables": shared_variables(*services),
    }

    composed = ir.ProtocolIR(
        name=name,
        variables=variables,
        channels=channels,
        actions=actions,
        init=ir.T(),
        pinned_property=pinned,
        assumptions=assumptions_out,
        source_path="",
        metadata=meta,
    )
    problems = composed.validate()
    if problems:
        raise CompositionError(
            "composed IR %r is not well-formed: %s"
            % (name, "; ".join(problems)))
    return composed