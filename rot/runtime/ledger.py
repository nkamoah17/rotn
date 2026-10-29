# -*- coding: utf-8 -*-
"""ledger.py -- the append-only decision ledger (B5).

Every :class:`~rot.runtime.core.RuntimeGuard` decision -- allow **or** deny --
is appended to the ledger as a deterministic, hash-chained entry.  The ledger
is the *auditable record* of the runtime plane: it is what
:mod:`rot.runtime.aggregate` (``rot coach --aggregate``) reads to surface
which prompts / tool-descriptions cause blocks, which rules block legitimate
work, and the re-proof that any relaxation stays safe.

Design contract
---------------

  * **Append-only.**  Entries are never modified or deleted; the ledger grows
    at the end.  ``record`` returns the entry it appended.
  * **Hash-chained (tamper-evident).**  Entry ``N`` carries the entry hash of
    entry ``N - 1`` (the first entry carries :data:`GENESIS_HASH`).  A reader
    can re-walk the chain (:meth:`DecisionLedger.verify`) and detect any
    insertion, deletion, or edit -- the same auditable discipline as the RTF
    trace and the coaching artifact.
  * **Deterministic.**  No timestamps, no random IDs: the ledger is a pure
    function of the decisions recorded.  Two ledgers with the same decisions,
    in the same order, serialize to the same bytes and hash to the same value.
  * **Self-contained.**  Each entry embeds the full refusal (with its own
    hash), so a reader can re-run the guard on the recorded state and confirm
    the decision byte-for-byte -- no proof engine needed.

Two ``record`` forms (both adapters use the first)::

    ledger.record(name, args, state, decision)   # the adapter form
    ledger.record(decision, context=None)        # the convenience form

Serialization: JSON (``to_json`` / ``from_dict``) and JSONL (``to_jsonl`` /
``from_jsonl`` -- one canonical line per entry; the native on-disk form).

Pure stdlib, Python 3.6 compatible (no f-strings).
"""

from __future__ import print_function

import json

import rot
from .refusal import Refusal, canonical_json, refusal_hash
from .core import Decision

__all__ = [
    "SCHEMA",
    "GENESIS_HASH",
    "LedgerError",
    "ChainBreak",
    "LedgerEntry",
    "DecisionLedger",
]

#: The ledger schema tag (stable; bump on breaking changes to the shape).
SCHEMA = "caravel.ledger/v1"

#: The prev_hash of the first entry (the empty chain).
GENESIS_HASH = "0" * 64


class LedgerError(ValueError):
    """A ledger (or entry) is malformed or fails validation (fail-closed)."""


class ChainBreak(LedgerError):
    """The hash chain is broken at entry ``seq`` (expected != actual).

    Raised by :meth:`DecisionLedger.verify` when an entry's ``prev_hash``
    does not equal the preceding entry's hash -- i.e. the ledger was
    inserted into, edited, or truncated.
    """

    def __init__(self, seq, expected, actual):
        super(ChainBreak, self).__init__(
            "chain break at seq %d: prev_hash %s != %s"
            % (seq, expected, actual))
        self.seq = seq
        self.expected = expected
        self.actual = actual


def _refusal_dict(refusal):
    """Normalize a refusal (a :class:`Refusal` or its dict form) to a dict."""
    if isinstance(refusal, Refusal):
        return refusal.to_dict()
    if isinstance(refusal, dict):
        if "hash" not in refusal:
            raise LedgerError(
                "a raw refusal dict must carry its 'hash' (the refusal is "
                "hashable; a hashless dict is not auditable)")
        return dict(refusal)
    raise LedgerError(
        "a ledger entry must carry a Refusal or its dict form (got %r)"
        % type(refusal).__name__)


class LedgerEntry(object):
    """One append-only, hash-chained ledger entry.

    The entry body is ``{seq, prev_hash, refusal, context}`` and the entry
    hash is :func:`rot.runtime.refusal.refusal_hash` of that body -- the *same*
    canonicaliser the refusals and the RTF trace use, so the whole plane
    shares one hash discipline.  The stored ``hash`` field is checked on load
    (a mismatch is a corrupt entry, fail-closed).
    """

    def __init__(self, seq, prev_hash, refusal, context=None):
        self.seq = int(seq)
        self.prev_hash = prev_hash
        self.refusal = _refusal_dict(refusal)
        self.context = dict(context or {})
        self.entry_hash = refusal_hash(self._body())

    # -- body / hash ---------------------------------------------------------
    def _body(self):
        """The hashable body (no stored ``hash`` field)."""
        return {
            "seq": self.seq,
            "prev_hash": self.prev_hash,
            "refusal": self.refusal,
            "context": self.context,
        }

    def to_dict(self):
        """The entry body plus the top-level ``hash``."""
        d = self._body()
        d["hash"] = self.entry_hash
        return d

    @classmethod
    def from_dict(cls, d):
        """Rebuild (and re-hash) an entry from its dict form.

        Raises
        ------
        LedgerError
            If a field is missing or the stored ``hash`` does not match the
            recomputed one (a corrupt / edited entry -- fail-closed).
        """
        if not isinstance(d, dict):
            raise LedgerError("a ledger entry must be a JSON object")
        seq = d.get("seq")
        if not isinstance(seq, int):
            raise LedgerError("entry missing integer 'seq'")
        prev = d.get("prev_hash")
        if not isinstance(prev, str) or not prev:
            raise LedgerError("entry missing 'prev_hash'")
        if not isinstance(d.get("refusal"), dict):
            raise LedgerError("entry missing 'refusal'")
        context = d.get("context") or {}
        if not isinstance(context, dict):
            raise LedgerError("entry 'context' must be an object")
        entry = cls(seq, prev, d["refusal"], context)
        stored = d.get("hash")
        if stored is not None and stored != entry.entry_hash:
            raise LedgerError(
                "entry at seq %d is corrupt (stored hash %s != recomputed %s)"
                % (seq, stored, entry.entry_hash))
        return entry

    def to_jsonl(self):
        """The entry as one canonical JSON line (the native on-disk form)."""
        return canonical_json(self.to_dict())

    def __repr__(self):
        return "LedgerEntry(seq=%d, blocked=%s, rule=%r)" % (
            self.seq, self.refusal.get("blocked"), self.refusal.get("rule"))



class DecisionLedger(object):
    """The append-only, hash-chained decision ledger.

    Parameters
    ----------
    entries : list of LedgerEntry, optional
        Pre-existing entries (used by the loaders).  New entries are always
        appended at the end.
    """

    def __init__(self, entries=None):
        self._entries = list(entries or [])

    # -- append --------------------------------------------------------------
    def record(self, first, second=None, third=None, fourth=None,
               context=None):
        """Append one decision and return the new entry.

        Two forms (dispatched on the first argument's type):

        * ``record(name, args, state, decision)`` -- the **adapter form**
          (both :mod:`rot.runtime.langchain` and :mod:`rot.runtime.mcp`
          record this way, so the ledger is uniform across frameworks);
        * ``record(decision, context=None)`` -- the **convenience form**
          (``decision`` is a :class:`~rot.runtime.core.Decision` or a
          :class:`~rot.runtime.refusal.Refusal`).
        """
        if isinstance(first, (Decision, Refusal)):
            decision = first
            ctx = second if isinstance(second, dict) else {}
            if context:
                ctx = dict(ctx)
                ctx.update(context)
        else:
            name, args, state, decision = first, second, third, fourth
            if not isinstance(decision, (Decision, Refusal)):
                raise LedgerError(
                    "record expects (name, args, state, decision) or "
                    "(decision, context); got first=%r" % (first,))
            ctx = {"tool": name, "args": dict(args or {})}
            if state is not None:
                ctx["state"] = dict(state)
            if context:
                ctx.update(context)
        return self._append(decision, ctx)

    def _append(self, decision, context):
        """Append one entry (the hash chain step)."""
        refusal = (decision.refusal if isinstance(decision, Decision)
                   else decision)
        prev = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
        entry = LedgerEntry(len(self._entries), prev, refusal, context)
        self._entries.append(entry)
        return entry

    # -- read ----------------------------------------------------------------
    def __len__(self):
        return len(self._entries)

    def __iter__(self):
        return iter(self._entries)

    def __getitem__(self, i):
        return self._entries[i]

    def entries(self):
        """A copy of the entry list."""
        return list(self._entries)

    def last_entry_hash(self):
        """The last entry's hash (the chain head; genesis when empty)."""
        return self._entries[-1].entry_hash if self._entries else GENESIS_HASH

    def verify(self):
        """Verify the hash chain and every entry hash.

        Returns ``True`` when the ledger is intact; raises
        :class:`ChainBreak` (a broken link) or :class:`LedgerError` (a corrupt
        entry) otherwise -- fail-closed: an unverifiable ledger is never read
        as clean.
        """
        prev = GENESIS_HASH
        for entry in self._entries:
            if entry.prev_hash != prev:
                raise ChainBreak(entry.seq, prev, entry.prev_hash)
            if refusal_hash(entry._body()) != entry.entry_hash:
                raise LedgerError(
                    "entry at seq %d is corrupt (hash mismatch)" % entry.seq)
            prev = entry.entry_hash
        return True



    # -- serialization ---------------------------------------------------------
    def to_dict(self):
        """The ledger as a deterministic dict (schema + entries + chain head)."""
        return {
            "schema": SCHEMA,
            "rot_version": rot.__version__,
            "entries": [e.to_dict() for e in self._entries],
            "last_entry_hash": self.last_entry_hash(),
        }

    def to_json(self, indent=2):
        """Deterministic JSON (sorted keys, stable separators)."""
        return canonical_json(self.to_dict(), indent=indent)

    def to_jsonl(self):
        """The ledger as JSONL (one canonical line per entry)."""
        return "\n".join(e.to_jsonl() for e in self._entries)

    @classmethod
    def from_dict(cls, d):
        """Load (and verify) a ledger from its dict form (fail-closed)."""
        if not isinstance(d, dict):
            raise LedgerError("a ledger must be a JSON object")
        if d.get("schema") not in (None, SCHEMA):
            raise LedgerError("unknown ledger schema %r" % d.get("schema"))
        entries = d.get("entries")
        if not isinstance(entries, list):
            raise LedgerError("a ledger must carry an 'entries' array")
        ledger = cls([LedgerEntry.from_dict(e) for e in entries])
        ledger.verify()
        return ledger

    @classmethod
    def from_jsonl(cls, text):
        """Load (and verify) a ledger from JSONL text (fail-closed)."""
        entries = []
        for i, line in enumerate(text.splitlines()):
            if not line.strip():
                continue
            try:
                d = json.loads(line)
            except ValueError as exc:
                raise LedgerError(
                    "ledger line %d is not valid JSON: %s" % (i, exc))
            entries.append(LedgerEntry.from_dict(d))
        ledger = cls(entries)
        ledger.verify()
        return ledger

    @classmethod
    def from_file(cls, path):
        """Load a ledger from ``path`` (JSON object, JSON array, or JSONL).

        Detection: the file is parsed as a single JSON document first; if it
        is a JSON object it is the ledger form (``from_dict``), if it is a
        JSON array a bare list of entries (still verified), and if it is not
        a single JSON document it is JSONL (one entry per line).

        Raises
        ------
        LedgerError
            If the file is malformed, the chain is broken, or an entry is
            corrupt (fail-closed).
        """
        with open(path, "r") as fh:
            text = fh.read()
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            return cls.from_dict(parsed)
        if isinstance(parsed, list):
            ledger = cls([LedgerEntry.from_dict(e) for e in parsed])
            ledger.verify()
            return ledger
        return cls.from_jsonl(text)

    def export_jsonl(self, path):
        """Write the ledger to ``path`` as JSONL (one line per entry)."""
        with open(path, "w") as fh:
            fh.write(self.to_jsonl() + "\n")
        return path

    def __repr__(self):
        return "DecisionLedger(entries=%d, last=%s...)" % (
            len(self._entries), self.last_entry_hash()[:12])