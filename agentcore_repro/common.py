# -*- coding: utf-8 -*-
"""common.py -- shared helpers for the real-AgentCore repro (GAP 4).

Pure stdlib, Python 3.6 compatible (repo convention).  All AWS control-plane
work goes through the AWS CLI v2; the data plane (gateway invoke) goes
through the official AgentCore CLI (node), which performs SigV4 signing with
the local AWS credentials profile.  Nothing here opens a browser or touches a
console -- the whole repro is local, scripted, and re-runnable.

State
-----
A single JSON file (``out/state.json``) carries IDs/ARNs between steps so
every step is idempotent and resumable.  Step scripts read what earlier
steps wrote and append their own results.
"""

import json
import os
import random
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
OUT_DIR = os.path.join(HERE, "out")
STATE_PATH = os.path.join(OUT_DIR, "state.json")

# --------------------------------------------------------------------------
# Locating the tools
# --------------------------------------------------------------------------

def find_aws():
    """Resolve the AWS CLI v2 executable (PATH, then the standard Windows
    install location)."""
    p = shutil.which("aws")
    if p:
        return p
    if os.name == "nt":
        cand = os.path.join(
            os.environ.get("ProgramFiles", r"C:\Program Files"),
            "Amazon", "AWSCLIV2", "aws.exe")
        if os.path.exists(cand):
            return cand
    raise RuntimeError(
        "aws CLI not found on PATH or in the standard location; "
        "install AWS CLI v2 first (tools/install_awscli.ps1)")


def find_agentcore_cli():
    """Resolve the official AgentCore CLI as an executable command.

    Prefers the npm bin shim (``agentcore`` / ``agentcore.cmd``) on PATH,
    then the standard npm-global locations.  The bin shim already knows how
    to launch node, so we run it directly.
    """
    for name in ("agentcore", "agentcore.cmd", "agentcore.ps1"):
        p = shutil.which(name)
        if p:
            return [p]
    if os.name == "nt":
        appdata = os.environ.get("APPDATA", "")
        cand = os.path.join(appdata, "npm", "agentcore.cmd")
        if os.path.exists(cand):
            return [cand]
        node = shutil.which("node")
        if node:
            idx = os.path.join(appdata, "npm", "node_modules", "@aws",
                               "agentcore", "dist", "index.js")
            if os.path.exists(idx):
                return [node, idx]
    raise RuntimeError(
        "AgentCore CLI (@aws/agentcore) not found; run: npm install -g @aws/agentcore")


AWS_EXE = None      # resolved lazily (so imports never fail)
AC_CMD = None


def aws_exe():
    global AWS_EXE
    if AWS_EXE is None:
        AWS_EXE = find_aws()
    return AWS_EXE


def ac_cmd():
    global AC_CMD
    if AC_CMD is None:
        AC_CMD = find_agentcore_cli()
    return AC_CMD


# --------------------------------------------------------------------------
# Process helpers
# --------------------------------------------------------------------------

def run(cmd, timeout=600, check=True, quiet=False, env_extra=None, retries=0):
    """Run ``cmd`` (list form), capture stdout/stderr, return
    (returncode, stdout_text).  Raises RuntimeError on non-zero exit when
    ``check`` is True.

    When ``retries`` > 0, transient failures (network blips, timeouts,
    throttling, 5xx server errors) are retried with exponential backoff +
    jitter.  Permanent errors (AccessDenied, validation, not-found, ...) are
    never retried -- see ``_is_transient()``."""
    attempt = 0
    while True:
        attempt += 1
        if not quiet:
            log("$ " + " ".join(_q(a) for a in cmd[:6])
                + (" ..." if len(cmd) > 6 else ""))
        env = dict(os.environ)
        if env_extra:
            env.update(env_extra)
        timed_out = False
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env)
        try:
            out_b, err_b = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            p.kill()
            out_b, err_b = p.communicate()
        out = (out_b or b"").decode("utf-8", "replace")
        err = (err_b or b"").decode("utf-8", "replace")
        if err.strip():
            sys.stderr.write(err)
        rc = p.returncode
        if timed_out:
            errmsg = ("command timed out after %ss: %s"
                      % (timeout, " ".join(cmd[:6])))
        elif rc != 0:
            errmsg = ("command exited %d: %s\nSTDOUT: %s\nSTDERR: %s"
                      % (rc, " ".join(cmd[:6]), out[-4000:], err[-4000:]))
        else:
            errmsg = ""
        if errmsg and _maybe_retry(errmsg, attempt, retries):
            continue
        if errmsg and check:
            raise RuntimeError(errmsg)
        return rc, out


def _maybe_retry(errmsg, attempt, retries):
    """Sleep (backoff + jitter) and return True when ``errmsg`` is transient
    and a retry is still available; otherwise return False."""
    if retries <= 0 or attempt > retries or not _is_transient(errmsg):
        return False
    delay = min(30.0, float(2 ** attempt) + random.uniform(0.0, 1.5))
    log("  transient failure (attempt %d/%d); retrying in %.1fs"
        % (attempt, retries, delay))
    time.sleep(delay)
    return True


def _q(a):
    if " " in a or '"' in a:
        return '"' + a.replace('"', '\\"') + '"'
    return a


# --- transient-vs-permanent AWS error classification (for retries) --------
# Lower-cased substrings that mark a TRANSIENT failure worth retrying:
# network blips, timeouts, throttling, and 5xx server errors.
_TRANSIENT_MARKERS = (
    "could not connect to the endpoint url",
    "connection closed",
    "connection reset",
    "connection refused",
    "connection aborted",
    "connection error",
    "readtimedouterror",
    "connecttimeouterror",
    "connectiontimeout",
    "read timeout",
    "sockettimeout",
    "socket timeout",
    "throttlingexception",
    "throttlinglexception",
    "toomanyrequestsexception",
    "provisionedthroughputexceeded",
    "requesttimeout",
    "request timeout",
    "serviceunavailableexception",
    "internalservererror",
    "internalexception",
    "temporarily unavailable",
    "server disconnected",
    "remote end closed connection",
    "bad gateway",
    "gateway timeout",
    "an error occurred (500)",
    "an error occurred (502)",
    "an error occurred (503)",
    "an error occurred (504)",
    "winerror 10053",
    "winerror 10054",
    "winerror 10060",
    "command timed out",
)

# Lower-cased substrings that mark a PERMANENT failure that must NOT be
# retried (retrying would burn time and could double-apply a write).
_PERMANENT_MARKERS = (
    "accessdeniedexception",
    "unauthorizedaccess",
    "paramvalidation",
    "invalidparameter",
    "invalidrequestexception",
    "validationexception",
    "resourcenotfoundexception",
    "conflictexception",
    "invalidstateexception",
    "unknownendpoint",
    "incompleteexception",
    "unmodelexception",
)


def _is_transient(err_text):
    """True when ``err_text`` looks like a transient AWS/network failure."""
    t = (err_text or "").lower()
    if not t:
        return False
    if any(m in t for m in _PERMANENT_MARKERS):
        return False
    return any(m in t for m in _TRANSIENT_MARKERS)


def _aws_retries():
    """Default retry budget for AWS calls (override with AC_AWS_RETRIES)."""
    try:
        return max(0, int(os.environ.get("AC_AWS_RETRIES", "4")))
    except ValueError:
        return 4


def aws_json(*args, timeout=300, check=True):
    """Run ``aws <args> --output json`` and parse the JSON result."""
    rc, out = run([aws_exe()] + list(args) + ["--output", "json"],
                  timeout=timeout, check=check, retries=_aws_retries())
    out = out.strip()
    if not out:
        return {}
    try:
        return json.loads(out)
    except ValueError:
        raise RuntimeError("aws returned non-JSON (auth error?):\n" + out[:2000])


def aws_raw(*args, timeout=300, check=True):
    """Run ``aws <args>`` (no JSON) and return stdout text."""
    rc, out = run([aws_exe()] + list(args), timeout=timeout, check=check,
                  retries=_aws_retries())
    return out




def gateway_invoke_cmd(gw_id, path, method, payload, outfile,
                       session_id=None):
    """Build the official CLI command for one gateway invoke (data plane).

    Confirmed syntax (``agentcore gateway invoke --help``):
        agentcore gateway invoke --id <gw> --path <p> --method <m>
          --payload <json> --content-type application/json
          [--session-id <uuid>] [--header "Name: value"] --output-file <f>
    The CLI signs the request with SigV4 (service ``bedrock-agentcore``)
    using the local AWS credentials profile; no console, no browser.

    Two session headers are in play:
      * ``--session-id <uuid>`` sends
        ``x-amzn-bedrock-agentcore-runtime-session-id`` (the MCP runtime
        conversation session).
      * the TEMPORAL POLICY ENGINE scopes its recorded history to a
        SEPARATE header, ``x-amzn-bedrock-agentcore-policy-session-id``
        (see AgentCore temporal-policy docs).  The CLI has no dedicated
        flag for it, so we send it via ``--header`` (format ``Name: value``,
        confirmed from the CLI's ``parseGatewayInvokeHeaders``).

    Both are set to the same ``session_id`` so that concurrent fires in one
    session share a single temporal history and count against each other.
    """
    cmd = ac_cmd() + [
        "gateway", "invoke",
        "--id", gw_id,
        "--path", path,
        "--method", method,
        "--payload", payload,
        "--content-type", "application/json",
    ]
    if session_id:
        cmd += ["--session-id", session_id]
        cmd += ["--header",
                "x-amzn-bedrock-agentcore-policy-session-id: " + session_id]
    cmd += ["--output-file", outfile]
    return cmd


def gateway_invoke(gw_id, path, method, payload, outfile,
                   session_id=None, timeout=120):
    """Run one gateway invoke (sequentially) and return
    (rc, stdout, stderr, elapsed_s).  The response body is saved to
    ``outfile`` by the CLI."""
    cmd = gateway_invoke_cmd(gw_id, path, method, payload, outfile,
                             session_id)
    log("$ " + " ".join(_q(a) for a in cmd[:8]) + " ...")
    t0 = time.time()
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate(timeout=timeout)
        rc = p.returncode
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        rc = -1
        err = (err or b"") + b"\nTIMEOUT"
    return rc, out.decode("utf-8", "replace"), err.decode("utf-8", "replace"), \
        time.time() - t0


def policy_generate(gw_id, prompt, name=None, timeout=300):
    """Run AWS's own Cedar policy generator (``agentcore gateway policy
    generate --json``) for ``gw_id`` with a natural-language ``prompt``.

    Returns the parsed JSON result (dict).  The result contains
    ``policies: [{statement, findings}]`` -- a valid Cedar statement
    validated against the gateway's tool schema.  This is the ground-truth
    oracle for the Cedar action/resource names, so we don't have to guess
    the exact ``::Action::`` / ``::Gateway::`` identifiers.
    """
    cmd = ac_cmd() + [
        "gateway", "policy", "generate",
        "--gateway-id", gw_id,
        "--prompt", prompt,
        "--json",
    ]
    if name:
        cmd += ["--name", name]
    log("$ " + " ".join(_q(a) for a in cmd[:8]) + " ...")
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate(timeout=timeout)
        rc = p.returncode
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        rc = -1
    out = out.decode("utf-8", "replace")
    err = err.decode("utf-8", "replace")
    if rc != 0:
        raise RuntimeError("policy generate failed (rc=%s):\n%s\n%s"
                           % (rc, out[-2000:], err[-2000:]))
    return json.loads(out)


def extract_cedar_names(statement):
    """Extract the Cedar action name and gateway resource from a generated
    Cedar statement (first occurrences).  Returns (action, resource); either
    may be None if not present."""
    import re
    m = re.search(r'::Action::"([^"]+)"', statement or "")
    action = m.group(1) if m else None
    m = re.search(r'::Gateway::"([^"]+)"', statement or "")
    resource = m.group(1) if m else None
    return action, resource


# --------------------------------------------------------------------------
# State, logging, templates
# --------------------------------------------------------------------------

def ensure_out():
    if not os.path.isdir(OUT_DIR):
        os.makedirs(OUT_DIR)


def load_state():
    ensure_out()
    if os.path.exists(STATE_PATH):
        with open(STATE_PATH, "r") as f:
            return json.load(f)
    return {}


def save_state(patch):
    ensure_out()
    st = load_state()
    st.update(patch)
    st["updated_utc"] = now_iso()
    with open(STATE_PATH, "w") as f:
        json.dump(st, f, indent=2, sort_keys=True)
    return st


def write_json(name, obj):
    ensure_out()
    p = os.path.join(OUT_DIR, name)
    with open(p, "w") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
    return p


def write_text(name, text):
    ensure_out()
    p = os.path.join(OUT_DIR, name)
    with open(p, "w") as f:
        f.write(text)
    return p


def read_text(p):
    with open(p, "r") as f:
        return f.read()


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg))
    sys.stdout.flush()


def die(msg, code=3):
    print("\nERROR: " + msg, file=sys.stderr)
    sys.exit(code)


def render_template(text, mapping):
    """Replace ``{{KEY}}`` placeholders; leaves unknown ones intact so a
    partial render is visible in the error rather than silently wrong."""
    def sub(m):
        key = m.group(1)
        if key in mapping:
            return str(mapping[key])
        return m.group(0)
    return re.sub(r"\{\{([A-Z0-9_]+)\}\}", sub, text)


def poll(desc, fn, timeout=600, interval=5, want=None):
    """Poll ``fn()`` until it returns a value in ``want`` (a set) or timeout.
    Returns the final value."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = fn()
        if last in want:
            return last
        log("    %s: %s (waiting...)" % (desc, last))
        time.sleep(interval)
    raise RuntimeError("timeout waiting for %s (last=%s)" % (desc, last))


def region():
    r = os.environ.get("AC_REPRO_REGION", "").strip()
    if r:
        return r
    # `aws configure get region` works on current CLI v2; the older
    # `aws configure get aws region` form is rejected by some builds
    # ("Unknown options: region"). Try the working form first, then the
    # legacy form, then fall back to the default.
    for args in (("configure", "get", "region"),
                 ("configure", "get", "aws", "region")):
        try:
            v = aws_raw(*args, check=False).strip()
            if v:
                return v
        except Exception:
            pass
    return "us-east-1"


def prefix():
    """Resource name prefix (default rot-)."""
    return os.environ.get("AC_REPRO_PREFIX", "rot").strip().lower() or "rot"


def names():
    """Canonical resource names for this repro (stable + idempotent).

    AgentCore name rules DIFFER per service (confirmed via ValidationException):
      * policy engine : ^[A-Za-z][A-Za-z0-9_]*$      -> underscores OK, no hyphens
      * gateway       : ([0-9a-zA-Z][-]?){1,48}      -> hyphens OK, no underscores
    Pure-alphanumeric is valid under BOTH, so the policy name uses none.
    IAM roles / Lambda allow hyphens and keep them (already created).
    """
    p = prefix()
    return {
        "gateway": p + "-spendcap-gw",
        "gateway_role": p + "-ac-gateway-role",
        "lambda": p + "-transfer-mock",
        "lambda_role": p + "-lambda-exec",
        "policy_engine": p + "_spendcap_engine",
        "policy": p + "spendcap",
        "target": "TransferTarget",
    }