# -*- coding: utf-8 -*-
"""license.py -- Caravel tier gating: license model + DepthBudget (Phase D).

This module implements **Phase D (tier gating)** of the ``caravel/rot-verify``
productization plan. It adds *no engine logic*: tiering is "cap the
bounded-search budget," which plugs directly into the existing
``UNKNOWN``-on-budget-exhaustion behavior of the three engines.

* **D1. License model** -- a zero-dependency, stdlib-only (``hmac`` +
  ``hashlib``) HMAC-SHA256 signed license (schema ``caravel.license/v1``).
* **D2. DepthBudget** -- the resolved depth budget
  (``max_states``, ``max_horizon``, ``max_tools``, ``max_tenant_scopes``)
  computed from *license -> action input -> free defaults*.
* **D3. GitHub-Action input** -- ``tier`` + ``depth`` inputs; when
  ``tier: free`` the action caps ``depth`` to the free maximum.
* **D4. Tests** -- see ``tests/test_license.py``.

The license is **fail-closed**: a tampered (bad HMAC), expired, or malformed
license is *rejected* (``LicenseError``), never silently downgraded.

Pure stdlib, Python 3.6 compatible.
"""

import datetime
import hashlib
import hmac
import json
import os

__all__ = [
    "SCHEMA", "TIERS", "LIMIT_KEYS", "FREE_LIMITS", "PAID_LIMITS",
    "DEFAULT_KEY", "HMAC_PREFIX", "KEY_ENV",
    "LicenseError", "License", "DepthBudget",
    "canonical_body", "sign", "verify_signature",
    "make_license", "load_license", "check_license",
    "resolve_budget", "key_from_env",
]

#: The license schema identifier (stable, versioned).
SCHEMA = "caravel.license/v1"

#: The supported tiers.
TIERS = ("free", "paid")

#: The depth-limit keys (stable order).
LIMIT_KEYS = ("max_states", "max_horizon", "max_tools", "max_tenant_scopes")

#: The free-tier depth limits (D2). Fail-closed defaults: a bounded search
#: that exceeds them is reported as ``UNKNOWN``.
FREE_LIMITS = {
    "max_states": 1000,
    "max_horizon": 4,
    "max_tools": 5,
    "max_tenant_scopes": 1,
}

#: The paid-tier depth limits (generous defaults for the action-input path).
PAID_LIMITS = {
    "max_states": 1000000,
    "max_horizon": 12,
    "max_tools": 100,
    "max_tenant_scopes": 10,
}

#: The demo Caravel key. In production this is a *secret* held by the Caravel
#: backend; for the zero-deps demo it is a well-known placeholder, overridable
#: via the ``CARAVEL_LICENSE_KEY`` environment variable or the ``--key`` CLI
#: option. Never ship a real key in source.
DEFAULT_KEY = "caravel-demo-key-v1"

#: The HMAC field prefix (identifies the algorithm).
HMAC_PREFIX = "hmac-sha256:"

#: Environment variable that overrides the demo key.
KEY_ENV = "CARAVEL_LICENSE_KEY"


class LicenseError(ValueError):
    """A license is missing, malformed, tampered, or expired (fail-closed)."""


def key_from_env():
    """The Caravel key: ``$CARAVEL_LICENSE_KEY`` if set, else the demo key."""
    return os.environ.get(KEY_ENV) or DEFAULT_KEY


# ---------------------------------------------------------------------------
# Signing / verification (D1)
# ---------------------------------------------------------------------------

def _json_default(obj):
    """Fallback serializer (stable ``to_dict()`` then ``repr``)."""
    to_dict = getattr(obj, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    return repr(obj)


def canonical_body(license_dict):
    """The canonical JSON of the license body (everything except ``hmac``).

    Serialized with sorted keys and compact separators so the byte string is
    stable across runs (deterministic). This is the exact byte string the
    HMAC is computed over.
    """
    if not isinstance(license_dict, dict):
        raise LicenseError("license must be a JSON object")
    body = {k: v for k, v in license_dict.items() if k != "hmac"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      default=_json_default)


def _as_bytes_key(key):
    if isinstance(key, bytes):
        return key
    if isinstance(key, str):
        return key.encode("utf-8")
    raise LicenseError("key must be a str or bytes")


def sign(license_dict, key=None):
    """Compute the ``hmac`` field for a license body under ``key``.

    Returns the ``hmac-sha256:<hex>`` string (the value stored in the
    license's ``hmac`` field).
    """
    key = key if key is not None else key_from_env()
    key_bytes = _as_bytes_key(key)
    body = canonical_body(license_dict).encode("utf-8")
    digest = hmac.new(key_bytes, body, hashlib.sha256).hexdigest()
    return HMAC_PREFIX + digest


def verify_signature(license_dict, key=None):
    """True iff the license's ``hmac`` field matches a fresh signature.

    Uses :func:`hmac.compare_digest` (constant-time) so a forged HMAC is
    rejected without a timing oracle.
    """
    key = key if key is not None else key_from_env()
    try:
        expected = sign(license_dict, key)
    except LicenseError:
        return False
    actual = license_dict.get("hmac") if isinstance(license_dict, dict) else None
    if not isinstance(actual, str):
        return False
    return hmac.compare_digest(expected, actual)


# ---------------------------------------------------------------------------
# Date / limits validation helpers
# ---------------------------------------------------------------------------

def _parse_date(value, field):
    """Parse an ISO-8601 ``YYYY-MM-DD`` date, raising ``LicenseError``."""
    if not isinstance(value, str):
        raise LicenseError("%s must be an ISO-8601 date string" % field)
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        raise LicenseError("%s is not a valid ISO-8601 date: %r" % (field, value))


def _validate_limits(limits):
    """Raise ``LicenseError`` unless ``limits`` is a well-formed limits dict."""
    if not isinstance(limits, dict):
        raise LicenseError("limits must be a JSON object")
    for k in LIMIT_KEYS:
        v = limits.get(k)
        if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
            raise LicenseError("limits.%s must be a positive integer" % k)


# ---------------------------------------------------------------------------
# License model (D1)
# ---------------------------------------------------------------------------

class License(object):
    """A validated Caravel license (D1).

    Attributes
    ----------
    schema : str
        The schema identifier (``caravel.license/v1``).
    org : str
        The licensed organization.
    tier : str
        The tier (``free`` or ``paid``).
    limits : dict
        The depth limits (the four :data:`LIMIT_KEYS`).
    issued : datetime.date
        The issue date.
    expiry : datetime.date
        The expiry date (inclusive -- a license is valid on its expiry day).
    hmac_value : str
        The ``hmac`` field (``hmac-sha256:<hex>``).
    """

    __slots__ = ("schema", "org", "tier", "limits", "issued", "expiry",
                 "hmac_value")

    def __init__(self, schema, org, tier, limits, issued, expiry, hmac_value):
        self.schema = schema
        self.org = org
        self.tier = tier
        self.limits = dict(limits)
        self.issued = issued
        self.expiry = expiry
        self.hmac_value = hmac_value

    @classmethod
    def from_dict(cls, d):
        """Build a :class:`License` from a license JSON object (unvalidated)."""
        if not isinstance(d, dict):
            raise LicenseError("license must be a JSON object")
        return cls(
            schema=d.get("schema"),
            org=d.get("org"),
            tier=d.get("tier"),
            limits=d.get("limits") or {},
            issued=d.get("issued"),
            expiry=d.get("expiry"),
            hmac_value=d.get("hmac"),
        )

    def to_dict(self):
        """The license as a JSON-serializable dict (dates as ISO strings)."""
        out = {
            "schema": self.schema,
            "org": self.org,
            "tier": self.tier,
            "limits": dict(self.limits),
            "hmac": self.hmac_value,
        }
        if self.issued is not None:
            out["issued"] = self.issued.isoformat() \
                if isinstance(self.issued, datetime.date) else self.issued
        if self.expiry is not None:
            out["expiry"] = self.expiry.isoformat() \
                if isinstance(self.expiry, datetime.date) else self.expiry
        return out

    def is_expired(self, now=None):
        """True iff the license is strictly past its expiry (inclusive).

        ``expiry`` may be stored as an ISO-8601 string (as produced by
        :meth:`from_dict` on a JSON body) or as a :class:`datetime.date`;
        both are handled. A missing or unparseable expiry is treated as
        expired (fail-closed).
        """
        now = now or datetime.date.today()
        expiry = self.expiry
        if isinstance(expiry, str):
            try:
                expiry = datetime.datetime.strptime(expiry, "%Y-%m-%d").date()
            except ValueError:
                return True  # fail-closed: unparseable expiry is expired
        if not isinstance(expiry, datetime.date):
            return True  # fail-closed: no valid expiry
        return now > expiry

    def __repr__(self):
        return ("License(org=%r, tier=%r, issued=%r, expiry=%r)"
                % (self.org, self.tier, self.issued, self.expiry))


# ---------------------------------------------------------------------------
# Issuing / loading / checking (D1)
# ---------------------------------------------------------------------------

def make_license(org, tier, limits=None, issued=None, expiry=None, key=None):
    """Issue a signed license dict (for testing / the Caravel backend).

    Parameters
    ----------
    org : str
        The licensed organization.
    tier : str
        The tier (``free`` or ``paid``).
    limits : dict, optional
        The depth limits (defaults to the tier's limits).
    issued : str, optional
        The issue date (ISO-8601; defaults to today).
    expiry : str, optional
        The expiry date (ISO-8601; defaults to one year from today).
    key : str or bytes, optional
        The Caravel key (defaults to :func:`key_from_env`).

    Returns
    -------
    dict
        The signed license (with the ``hmac`` field).
    """
    key = key if key is not None else key_from_env()
    if tier not in TIERS:
        raise LicenseError("unknown tier %r (expected one of %r)"
                           % (tier, list(TIERS)))
    if limits is None:
        limits = dict(FREE_LIMITS if tier == "free" else PAID_LIMITS)
    else:
        _validate_limits(limits)
        limits = {k: int(limits[k]) for k in LIMIT_KEYS}
    today = datetime.date.today()
    issued = issued or today.isoformat()
    if expiry is None:
        try:
            expiry = today.replace(year=today.year + 1).isoformat()
        except ValueError:  # Feb 29 -> Feb 28
            expiry = today.replace(year=today.year + 1, day=28).isoformat()
    body = {
        "schema": SCHEMA,
        "org": org,
        "tier": tier,
        "limits": limits,
        "issued": issued,
        "expiry": expiry,
    }
    body["hmac"] = sign(body, key)
    return body


def check_license(license_dict, key=None, now=None):
    """Validate a license dict (schema, tier, limits, signature, expiry).

    Returns a tuple ``(ok, note)`` where ``ok`` is a bool and ``note`` is a
    human-readable reason (empty when ``ok`` is True). This is the pure
    validation used by ``rot license --verify`` and by :func:`load_license`.

    Parameters
    ----------
    license_dict : dict
        The license JSON object.
    key : str or bytes, optional
        The Caravel key (defaults to :func:`key_from_env`).
    now : datetime.date, optional
        The reference date for the expiry check (defaults to today). Pass a
        fixed date for deterministic tests.
    """
    key = key if key is not None else key_from_env()
    if not isinstance(license_dict, dict):
        return False, "license must be a JSON object"
    if license_dict.get("schema") != SCHEMA:
        return False, "unsupported schema %r (expected %r)" % (
            license_dict.get("schema"), SCHEMA)
    tier = license_dict.get("tier")
    if tier not in TIERS:
        return False, "unknown tier %r (expected one of %r)" % (tier, list(TIERS))
    try:
        _validate_limits(license_dict.get("limits"))
    except LicenseError as exc:
        return False, str(exc)
    try:
        issued = _parse_date(license_dict.get("issued"), "issued")
        expiry = _parse_date(license_dict.get("expiry"), "expiry")
    except LicenseError as exc:
        return False, str(exc)
    if issued > expiry:
        return False, "issued date %s is after expiry %s" % (issued, expiry)
    # Signature (fail-closed): a tampered body or wrong key is rejected.
    if not verify_signature(license_dict, key):
        return False, "HMAC verification failed (tampered or wrong key)"
    # Expiry (fail-closed): a past-expiry license is rejected.
    now = now or datetime.date.today()
    if now > expiry:
        return False, "license expired on %s" % expiry.isoformat()
    return True, ""


def load_license(path, key=None, now=None):
    """Read and validate a license file (fail-closed).

    Returns a :class:`License` on success; raises :class:`LicenseError` if
    the file is missing, malformed, tampered, or expired.
    """
    key = key if key is not None else key_from_env()
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
    except (IOError, OSError) as exc:
        raise LicenseError("could not read license %r: %s" % (path, exc))
    except ValueError as exc:  # json.JSONDecodeError subclasses ValueError
        raise LicenseError("malformed JSON in license %r: %s" % (path, exc))
    ok, note = check_license(data, key=key, now=now)
    if not ok:
        raise LicenseError("invalid license %r: %s" % (path, note))
    return License.from_dict(data)


# ---------------------------------------------------------------------------
# DepthBudget (D2) + resolution (D2/D3)
# ---------------------------------------------------------------------------

class DepthBudget(object):
    """The resolved depth budget (D2), threaded into the three engines.

    Tiering is "cap the bounded-search budget": ``max_states`` and
    ``max_horizon`` are the budgets the engines already honor, and a bounded
    search that exceeds them is reported as ``UNKNOWN`` (the existing
    budget-exhaustion behavior) -- so no new engine logic is required.

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
        Where the budget came from: ``"license"``, ``"action"``, or ``"free"``.
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
        """The free-tier budget (the fail-closed defaults)."""
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


def resolve_budget(license=None, tier=None, depth=None):
    """Compute the effective :class:`DepthBudget` (D2/D3).

    Resolution order: **license -> action input -> free defaults**.

    Parameters
    ----------
    license : rot.license.License or None
        A validated license (highest authority). When given, its limits are
        used verbatim.
    tier : str or None
        The GitHub-Action tier input (``free`` or ``paid``). Used when no
        license is present.
    depth : int or None
        The GitHub-Action ``depth`` input (a ``max_states`` override). When
        ``tier`` is ``free`` it is capped to the free maximum; when ``tier``
        is ``paid`` it is used as-is.

    Returns
    -------
    DepthBudget
    """
    # 1. License (highest authority).
    if license is not None:
        return DepthBudget.from_limits(license.limits, "license")
    # 2. Action input (tier + depth).
    if tier in TIERS:
        base = dict(FREE_LIMITS if tier == "free" else PAID_LIMITS)
        if depth is not None:
            base["max_states"] = int(depth)
        if tier == "free":
            # D3: the action caps depth to the free max when tier: free.
            base["max_states"] = min(base["max_states"],
                                    FREE_LIMITS["max_states"])
        return DepthBudget.from_limits(base, "action")
    # 3. Free defaults.
    return DepthBudget.free()