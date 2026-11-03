# -*- coding: utf-8 -*-
"""license.py -- DepthBudget (full-strength) + optional depth bound.

ROTN is **full-strength for everyone**: there is no paid/free budget split and
no local license gate. The depth budget (``max_states``, ``max_horizon``,
``max_tools``, ``max_tenant_scopes``) is always the generous
:data:`FREE_LIMITS`; a bounded search that exceeds them is reported as an
honest ``UNKNOWN``, never silently truncated.

The module also supports an optional user-set ``depth`` bound (a ``max_states``
cap that may only *lower* the budget) -- a self-limiting cap, not a
monetization gate. The paid product is the hosted service + signed
attestations, not a budget privilege (see ``docs/licensing.md``).

* :class:`DepthBudget` -- the resolved depth budget.
* :func:`resolve_budget` -- full-strength by default; honors an optional
  ``depth`` bound (may only lower the budget).
* Tests -- see ``tests/test_license.py``.

Pure stdlib.
"""

__all__ = [
    "LIMIT_KEYS", "FREE_LIMITS",
    "DepthBudget", "resolve_budget",
]

#: The depth-limit keys (stable order).
LIMIT_KEYS = ("max_states", "max_horizon", "max_tools", "max_tenant_scopes")

#: The depth limits. ROTN is full-strength for everyone: this is the default
#: (and only) budget, so there is no paid/free split. A bounded search that
#: exceeds them is reported as an honest ``UNKNOWN``, never silently truncated.
FREE_LIMITS = {
    "max_states": 1000000,
    "max_horizon": 12,
    "max_tools": 100,
    "max_tenant_scopes": 10,
}


class DepthBudget(object):
    """The resolved depth budget (the full-strength default + optional bound).

    The budget caps the bounded search: a search that exceeds it is reported
    as an honest ``UNKNOWN`` (the existing budget-exhaustion behavior) -- so
    no new engine logic is required.

    A user may set a *tighter* bound (a self-limiting cap, not a
    monetization gate); the bound may only **lower** the budget, never raise
    it.

    Attributes
    ----------
    max_states : int
        The state budget for the model finder / symbolic engine.
    max_horizon : int
        The bounded-liveness horizon (max steps).
    max_tools : int
        The maximum tool-catalog size for the structural audit (out-of-scope
        beyond this is reported as ``UNKNOWN``).
    max_tenant_scopes : int
        The maximum tenant-scope count for the manifest audit (out-of-scope
        beyond this is reported as ``UNKNOWN``).
    source : str
        Where the budget came from: ``"free"`` (the full-strength defaults) or
        a user-set bound label.
    """

    __slots__ = ("max_states", "max_horizon", "max_tools",
                 "max_tenant_scopes", "source")

    def __init__(self, max_states, max_horizon, max_tools,
                 max_tenant_scopes, source):
        self.max_states = int(max_states)
        self.max_horizon = int(max_horizon)
        self.max_tools = int(max_tools)
        self.max_tenant_scopes = int(max_tenant_scopes)
        self.source = source

    @classmethod
    def from_limits(cls, limits, source):
        return cls(
            max_states=limits["max_states"],
            max_horizon=limits["max_horizon"],
            max_tools=limits["max_tools"],
            max_tenant_scopes=limits["max_tenant_scopes"],
            source=source,
        )

    @classmethod
    def free(cls):
        """The full-strength default budget (everyone gets this)."""
        return cls.from_limits(FREE_LIMITS, "free")

    def to_dict(self):
        return {
            "max_states": self.max_states,
            "max_horizon": self.max_horizon,
            "max_tools": self.max_tools,
            "max_tenant_scopes": self.max_tenant_scopes,
            "source": self.source,
        }

    def __repr__(self):
        return ("DepthBudget(max_states=%d, max_horizon=%d, max_tools=%d, "
                "max_tenant_scopes=%d, source=%r)"
                % (self.max_states, self.max_horizon, self.max_tools,
                   self.max_tenant_scopes, self.source))


def resolve_budget(depth=None):
    """Compute the effective :class:`DepthBudget`.

    ROTN is **full-strength for everyone**: the default budget is always the
    generous :data:`FREE_LIMITS`. There is no paid/free split and no tier
    privilege -- the paid product is the hosted service + signed attestations,
    not a budget privilege.

    Parameters
    ----------
    depth : int or None
        An optional user-set ``max_states`` bound (may only lower the budget).

    Returns
    -------
    DepthBudget
    """
    base = dict(FREE_LIMITS)
    source = "free"
    if depth is not None:
        base["max_states"] = min(int(base["max_states"]), int(depth))
        source = "depth-bound"
    return DepthBudget.from_limits(base, source)