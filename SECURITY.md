# Security policy

ROTN is a security tool — it decides whether an agent's tool policy is
sound under concurrency. Two different kinds of security issues can arise
around this project, and the rules for them are different:

- **issues in ROTN itself** (this repository), and
- **issues in the vendor services it checks against** (AWS Dogwood /
  Amazon Bedrock AgentCore) — including any divergence from the
  documented semantics.

## 1. Reporting a vulnerability in ROTN

**Report privately. Do not open a public issue, pull request, or
discussion about a suspected vulnerability in this code.**

- Preferred: GitHub private vulnerability reporting —
  `nkamoah17/rotn` → *Security* → *Report a vulnerability*.
- If private reporting is not available, send a direct private message to
  the maintainer with the subject `rotn security report`.

Include, if available:

- the exact command + inputs that reproduce it (policy file,
  `--max-inflight` / depth, engine) — a minimal `.dw` / `.cedar` /
  manifest is best;
- the observed verdict and exit code, with the engine label;
- what the *correct* verdict should be, and the semantics relied on
  (e.g. the Dogwood spec section);
- the environment (OS, Python version, which optional engines were
  present).

**What counts as a security issue here** (in priority order):

1. a **soundness hole** — a path that can report `PROVEN` (or a gate
   PASS) for a policy that is actually `VIOLATED`; this inverts the
   purpose of the tool;
2. a **gate / waiver bypass** — a labeled divergence that can be turned
   into a silent PASS (the waiver rules are in `CONTRIBUTING.md`);
3. a **verdict leak from a non-sound source** — the LLM baseline or any
   optional cross-check influencing a verdict or exit code (they must
   degrade to skip / `UNKNOWN`, never decide);
4. **secret material** appearing in `agentcore_repro/` output, logs, or
   artifacts (the scripts must never read or print credentials);
5. **supply chain** — any addition of a runtime dependency (the core is
   zero-dependency by design) or a change to the packaging surface.

**Response.** Solo-maintained, best effort: acknowledgement within 72
hours where possible; a fix, or a documented reason (with a waiver where
appropriate) before the next release. We will not publicly discuss a
report in a way that discloses an unpatched issue.

**Safe harbor.** Good-faith security research on this code — including
running the `agentcore_repro/` scripts against your own AWS account —
will not be treated as wrongdoing.

## 2. Scope

**In scope** (report to this project):

- the `rot` package (engines, front-ends, lowering, oracles, CLI) and
  the `rot` console entry point;
- the `agentcore_repro/` scripts and their artifact handling;
- the release artifacts (sdist / wheel) and the CI workflows.

**Out of scope** (report to the relevant owner):

- the hosted commercial service (`rotn-commercial`: the cloud runtime
  coach, the fleet aggregate, the signed attestations) — a separate
  product with its own channel;
- the protocol-plane research repository (`nkamoah17/rotn-research`);
- upstream tools (Dogwood, Cedar, Z3, TLC, Apalache, the Rust toolchain)
  — report to those projects;
- non-security bugs, missing features, rate limits, or usage questions —
  use the normal issue tracker.

## 3. Vendor-divergence note (read this first if you touch AWS)

This project **compares** ROTN's verdicts and Dogwood's documented
semantics against the **live** Amazon Bedrock AgentCore gateway
(`agentcore_repro/`, runbook `docs/agentcore-repro.md`). To date, the
live runs have *not* reproduced the spec prediction for the corrected
policy (runs 2–3, runbook §6), and **no cause has been established**.
Nothing in this repository claims an AWS defect, and no public claim is
permitted until the process below has been followed.

If you have evidence that a live AWS service (Dogwood evaluation,
AgentCore gateway) **diverges from the documented semantics** — or
exhibits a defect — the rule is:

1. **Report it privately to the vendor first**, through AWS's
   vulnerability-reporting process
   (<https://aws.amazon.com/security/vulnerability-reporting/>).
2. **Do not publish** (issue, PR, doc, blog, video) further detail
   before that report and any coordinated statement.
3. If you have additional live-gateway evidence beyond what
   `docs/agentcore-repro.md` §6 already records, **send it to the
   maintainer privately** (the channel in §1) instead of opening a public
   issue asserting a vendor defect.

The same rule governs this project's own follow-up: if the pending
controls (`docs/agentcore-repro.md` §5, E1–E4) indicate a divergence
from the documented semantics, we will report privately to AWS before
publishing further detail.

## 4. What we never do

- No public disclosure of an unpatched ROTN vulnerability.
- No public claim of a vendor defect before the vendor's
  responsible-disclosure process.
- No waiver, exception, or "honest caveat" that turns a failing gate
  into a silent PASS — divergences are labeled (see `CONTRIBUTING.md`,
  "Waiver rules").
