# -*- coding: utf-8 -*-
"""llm_baseline.py -- OPTIONAL, NON-SOUND LLM baseline for the ROTN pipeline.

Why this exists
---------------
The formal pipeline (symbolic engine, and later Apalache/TLC) gives *sound*
verdicts: ``PROVEN`` / ``DISPROVEN`` with a model or a concrete counterexample.
This module is deliberately a different, *weaker* tool: it asks an LLM to
inspect the TLA+ specification and to (a) name the interesting invariants,
(b) produce candidate counterexample traces, and (c) explain a result in
plain English. It is a human-facing "baseline" for reading and reasoning about
the protocol -- useful for spotting the *shape* of a bug and for pedagogy, but
it has NO soundness guarantee and can hallucinate.

Soundness contract (IMPORTANT)
------------------------------
  * This module NEVER changes the formal verdict. The pipeline's verdict and
    exit code are computed solely from the engine results.
  * It is strictly OPT-IN: nothing here runs unless ``Config.llm_enabled``
    (or ``--llm-baseline``) is set. By default the pipeline is fully offline.
  * It NEVER fabricates a counterexample. If the LLM cannot supply a concrete
    trace, we emit ``None`` and say so. The only "counterexample" the verdict
    logic ever trusts is one produced by the real engine.
  * It degrades gracefully: missing API key, unreachable endpoint, or a
    malformed response all yield a ``skipped``/``unavailable`` report instead
    of an exception that would break the run.

Design
------
  * Pure stdlib HTTP (``urllib``) -- no new dependency, works on Python 3.6.
  * The concrete transport is swappable: :class:`OpenAICompatibleClient`
    implements the OpenAI-style ``/chat/completions`` REST API, which is what
    OpenAI, Azure OpenAI, and many local servers (Ollama, vLLM, llama.cpp,
    LM Studio, ...) expose. The parser and baseline driver only depend on the
    tiny :class:`LLMRequest` / client protocol, so they are unit-testable with
    a fake client and never touch the network.

  * The prompt asks the model to answer in STRICT JSON, then
    :func:`parse_model_response` defensively extracts and validates that JSON
    (stripping code fences, tolerating surrounding prose). If the model returns
    garbage, we get ``None`` fields -- never a crash.

This keeps the LLM baseline useful and *honest*: it is clearly labelled as a
non-sound baseline and is quarantined from the sound formal verdict.
"""

from __future__ import print_function

import json
import re

# JSON response schema we ask the model for.
_LLM_INSTRUCT = (
    "You are a careful protocol-verification assistant. You are given a TLA+"
    " specification and a set of invariants under study. Answer ONLY with a "
    "single JSON object (no prose, no markdown) of this shape:\n"
    "{\n"
    '  "interesting_invariants": ["<TLA+ predicate>", ...],\n'
    '  "likely_bug": "<one-sentence hypothesis or the string \"none\">",\n'
    '  "counterexample": <a concrete step-by-step trace as an array of objects '
    'with keys "step", "actor", "action", "state">, or null if you cannot '
    'construct a real trace>\n'
    "}\n"
    "Do NOT invent state values that contradict the spec. If you cannot build "
    "a concrete trace that actually violates an invariant, set "
    '"counterexample" to null.\n'
)


def _strip_code_fence(text):
    """Remove markdown code fences / surrounding prose, return the JSON part."""
    if not text:
        return text
    t = text.strip()
    # Strip ```json ... ``` or ``` ... ``` fences.
    m = re.search(r"```[a-zA-Z]*\s*\n?(.*?)```", t, flags=re.DOTALL)
    if m:
        t = m.group(1).strip()
    # If there is prose around a JSON object, pull the first {...} block.
    start = t.find("{")
    end = t.rfind("}")
    if start != -1 and end != -1 and end > start:
        t = t[start:end + 1]
    return t.strip()


class LLMRequest(object):
    """One logical LLM call: a prompt plus the config needed to send it.

    Kept separate from the concrete client so the baseline driver can be
    unit-tested with a fake client (no network).
    """

    def __init__(self, prompt, base_url, api_key, model, timeout=120,
                 api_key_env="OPENAI_API_KEY"):
        self.prompt = prompt
        self.base_url = base_url
        self.api_key = api_key
        self.model = model
        self.timeout = int(timeout)
        self.api_key_env = api_key_env

    def __repr__(self):
        return "LLMRequest(model=%r, prompt=%d chars)" % (
            self.model, len(self.prompt or ""))


class _LLMClient(object):
    """Abstract transport. Subclasses implement :meth:`complete`."""

    def available(self):
        """True if this client could possibly make a call (key/endpoint set)."""
        raise NotImplementedError

    def complete(self, prompt):
        """Send ``prompt`` to the model and return the raw text response."""
        raise NotImplementedError


class OpenAICompatibleClient(_LLMClient):
    """Talks the OpenAI ``/chat/completions`` REST API (works with OpenAI,
    Azure, and any OpenAI-compatible server: Ollama, vLLM, llama.cpp, ...).

    Uses only ``urllib`` (stdlib) so no third-party package is required.
    """

    def __init__(self, base_url=None, api_key=None, model="gpt-4o-mini",
                 timeout=120, api_key_env="OPENAI_API_KEY"):
        # Resolve endpoint: prefer explicit base_url, else common defaults.
        self.base_url = (base_url or _default_base_url()).rstrip("/")
        # Resolve API key: explicit value, else the named env var.
        self.api_key = api_key or _env_api_key(api_key_env)
        self.model = model or "gpt-4o-mini"
        self.timeout = int(timeout)

    def available(self):
        return bool(self.api_key) and bool(self.base_url)

    def _endpoint(self):
        # Support both ".../v1" and ".../v1/chat/completions" style base urls.
        if self.base_url.endswith("/chat/completions"):
            return self.base_url
        return self.base_url + "/chat/completions"

    def complete(self, prompt):
        import urllib.request
        import urllib.error

        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.0,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self._endpoint(), data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        if self.api_key:
            req.add_header("Authorization", "Bearer " + self.api_key)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            raise RuntimeError("LLM HTTP %s: %s" % (e.code, body[:300]))
        except Exception as e:
            raise RuntimeError("LLM request failed: %s" % (e,))
        try:
            obj = json.loads(body)
            return obj["choices"][0]["message"]["content"]
        except (KeyError, IndexError, ValueError, TypeError) as e:
            raise RuntimeError("Malformed LLM response: %s" % (e,))


def _default_base_url():
    import os
    return (os.environ.get("LLM_BASE_URL")
            or os.environ.get("OPENAI_BASE_URL")
            or "https://api.openai.com/v1")


def _env_api_key(name):
    import os
    return os.environ.get(name) or os.environ.get("LLM_API_KEY")


# --- response parsing ----------------------------------------------------------

def parse_model_response(raw_text):
    """Defensively parse an LLM response into a normalized dict.

    Returns a dict with keys ``interesting_invariants`` (list), ``likely_bug``
    (str) and ``counterexample`` (list or ``None``). Never raises: any
    malform yields the empty/None values so callers can rely on the shape.
    """
    result = {
        "interesting_invariants": [],
        "likely_bug": None,
        "counterexample": None,
    }
    if not raw_text:
        return result
    cleaned = _strip_code_fence(raw_text)
    try:
        obj = json.loads(cleaned)
    except (ValueError, TypeError):
        # Last-ditch: try to find a JSON object anywhere in the text.
        m = re.search(r"\{.*\}", raw_text, flags=re.DOTALL)
        if not m:
            return result
        try:
            obj = json.loads(m.group(0))
        except (ValueError, TypeError):
            return result
    if not isinstance(obj, dict):
        return result

    inv = obj.get("interesting_invariants")
    if isinstance(inv, list):
        result["interesting_invariants"] = [str(x) for x in inv
                                            if isinstance(x, (str, int, float))]
    elif isinstance(inv, str):
        result["interesting_invariants"] = [inv]

    bug = obj.get("likely_bug")
    if isinstance(bug, (str, int, float)):
        result["likely_bug"] = str(bug)

    ce = obj.get("counterexample")
    if isinstance(ce, list) and ce:
        # Only accept a *concrete* trace (list of step objects) as a candidate;
        # never trust a bare string as a counterexample.
        concrete = [x for x in ce if isinstance(x, dict)]
        if concrete:
            result["counterexample"] = concrete
    return result


# --- baseline driver -----------------------------------------------------------

def llm_baseline(config, spec_text, invariants, verdict, engine_result=None,
                 client=None):
    """Run the optional LLM baseline and return a self-describing report.

    ``config``        -- a ``rot.config.Config`` (provides llm_* settings).
    ``spec_text``     -- the TLA+ specification text to analyse.
    ``invariants``    -- list of invariant names/predicates under study.
    ``verdict``       -- the formal verdict string (informational only).
    ``engine_result`` -- optional engine result (informational only).
    ``client``        -- optional pre-built client (used as-is). When ``None``
                         an :class:`OpenAICompatibleClient` is constructed from
                         ``config``. Tests pass a fake client to exercise the
                         happy path without any network access.

    The returned dict ALWAYS has the keys:
        enabled, status, model, interesting_invariants, likely_bug,
        counterexample, raw, error, disclaimer
    where ``status`` is one of ``"ok" | "skipped" | "unavailable" | "error"``.

    Soundness contract: this function NEVER raises and NEVER modifies
    ``verdict``. A malformed or absent LLM answer simply yields
    ``status != "ok"`` with ``counterexample=None``.
    """
    disclaimer = ("NON-SOUND LLM baseline: informational only. This does NOT "
                  "affect the formal verdict (see 'verdict' above). LLM "
                  "answers may be wrong or hallucinated.")
    report = {
        "enabled": False,
        "status": "skipped",
        "model": None,
        "interesting_invariants": None,
        "likely_bug": None,
        "counterexample": None,
        "raw": None,
        "error": None,
        "disclaimer": disclaimer,
    }

    if not getattr(config, "llm_enabled", False):
        return report

    report["enabled"] = True
    model = getattr(config, "llm_model", None) or "gpt-4o-mini"
    report["model"] = model

    if client is None:
        client = OpenAICompatibleClient(
            base_url=getattr(config, "llm_base_url", None),
            model=model,
            timeout=getattr(config, "llm_timeout", 120),
            api_key_env=getattr(config, "llm_api_key_env", "OPENAI_API_KEY"),
        )
    if not client.available():
        report["status"] = "unavailable"
        report["error"] = ("No API key found. Set the env var "
                          "%s (and optionally LLM_BASE_URL) to enable the "
                          "baseline." % getattr(
                              config, "llm_api_key_env", "OPENAI_API_KEY"))
        return report

    # Build the prompt from the spec + invariants + (informational) verdict.
    inv_text = ", ".join(str(i) for i in invariants) if invariants else "(none)"
    prompt = (
        _LLM_INSTRUCT
        + "\n--- TLA+ specification ---\n" + (spec_text or "") + "\n"
        + "\n--- Invariants under study ---\n" + inv_text + "\n"
        + "\n--- Formal engine verdict (context only) ---\n" + str(verdict) + "\n"
        + "\nProduce the JSON object now.\n"
    )

    try:
        raw = client.complete(prompt)
    except Exception as e:  # noqa: broad on purpose -- must not break the run
        report["status"] = "error"
        report["error"] = str(e)
        return report

    report["raw"] = raw
    parsed = parse_model_response(raw)
    report["interesting_invariants"] = parsed["interesting_invariants"] or None
    report["likely_bug"] = parsed["likely_bug"]
    report["counterexample"] = parsed["counterexample"]
    report["status"] = "ok"
    return report


__all__ = [
    "LLMRequest",
    "OpenAICompatibleClient",
    "parse_model_response",
    "llm_baseline",
]
