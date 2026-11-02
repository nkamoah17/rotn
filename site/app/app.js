/* ROTN replay site -- core: boot, hash routing, gallery, the four-beat
 * replay arc, and the attestation view (E2/E3/E4).
 *
 * No framework, no build step, no CDN:
 *   - hash routing:   #/                    -> landing + gallery
 *                     #/replay/<id>         -> replay: RULE -> ATTACK ->
 *                                              PROOF -> COACH (the arc; the
 *                                              K-sweep and to_proceed are the
 *                                              two climaxes)
 *                     #/compare/<a>/<b>     -> side-by-side + K-sweep
 *                     #/attestation/<id>?h= -> the B3 attestation (one-pager)
 *                                              from the SAME trace data; the
 *                                              ?h=<sha256> pin in the URL is
 *                                              verified against the trace --
 *                                              the link IS the attestation
 *   - trace loading:  fetch('data/<id>.trace.json') when served over HTTP
 *                     (GitHub Pages), with the generated registry
 *                     data/traces.js (window.ROT_TRACES) as the offline
 *                     file:// fallback (where browsers block local fetch).
 *
 * The RTF v1 trace is the single data contract (see rot/trace.py); this
 * module renders it and adds no verification logic. The attestation view is
 * the JS twin of rot/attestation.py (same fields, same bounded discipline).
 */
(function () {
  "use strict";

  var ROT = (window.ROT = window.ROT || {});

  // True once the user has navigated (hashchange). Focus management is
  // skipped on the very first render so we don't steal focus from the URL
  // bar on initial page load.
  var navigated = false;

  /* ---------------- small helpers ---------------- */

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  ROT.esc = esc;

  function shortHash(h, n) {
    h = String(h || "");
    n = n || 12;
    return h.length > n ? h.slice(0, n) + "\u2026" : h;
  }

  function registry() {
    return window.ROT_TRACES || {};
  }

  /* ---------------- trace loading ---------------- */

  ROT.traceIds = function () {
    return Object.keys(registry()).sort();
  };

  ROT.loadTrace = function (id) {
    function fromRegistry() {
      return Promise.resolve(registry()[id] || null);
    }
    if (typeof fetch === "function" && location.protocol !== "file:") {
      return fetch("data/" + id + ".trace.json", { cache: "no-cache" })
        .then(function (r) {
          if (!r.ok) { throw new Error("HTTP " + r.status); }
          return r.json();
        })
        .catch(fromRegistry);
    }
    return fromRegistry();
  };

  /* ---------------- verdict model ---------------- */

  var VERDICTS = {
    proven: {
      label: "PROVEN", cls: "proven",
      desc: "Every check passed \u2014 the policy holds within the verified bounds."
    },
    violated: {
      label: "VIOLATED", cls: "violated",
      desc: "A counterexample exists \u2014 the policy is broken. The violating path is highlighted in red."
    },
    unknown: {
      label: "UNKNOWN", cls: "unknown",
      desc: "The bounded search exhausted its budget before deciding (fail-closed, honest UNKNOWN)."
    }
  };
  ROT.verdictInfo = function (v) {
    return VERDICTS[String(v == null ? "" : v).toLowerCase()] || VERDICTS.unknown;
  };

  /* ---------------- re-verify command ---------------- */

  ROT.reverifyCommand = function (id, t) {
    var src = (t && t.source && t.source.path)
      ? String(t.source.path).replace(/\\/g, "/")
      : null;
    var schema = (t && t.source && t.source.schema) || "";
    var isPolicy = /dogwood/i.test(schema);
    var flag = isPolicy ? "--policy" : "--manifest";
    var def = isPolicy ? "<policy.dw>" : "<manifest.json>";
    var k = (t && t.policy && t.policy.max_inflight != null)
      ? " --max-inflight " + t.policy.max_inflight
      : "";
    return "rot trace " + flag + " " + (src || def) + k + " --out site/data/" + id + ".trace.json";
  };

  /* ---------------- E4: the shareable, hash-pinned URL ----------------
   *
   * The link IS the attestation: it carries the trace's SHA-256 in the URL
   * (?h=<hash>), and the attestation view verifies that pin against the
   * trace data before rendering. A mismatch (tampered policy, changed engine)
   * is flagged STALE, never silently re-proven.
   */

  function pageBase() {
    if (typeof location.href === "string" && location.href) {
      return location.href.split("#")[0].split("?")[0];
    }
    return "";
  }

  ROT.shareURL = function (t, id) {
    return "#/attestation/" + id + (t && t.hash ? "?h=" + t.hash : "");
  };
  ROT.shareLink = function (t, id) {
    return pageBase() + ROT.shareURL(t, id);
  };

  /* ---------------- E3: the attestation body (B3, JS twin) ----------------
   *
   * A pure function of the trace -- the same fields rot/attestation.py
   * derives (scope, coverage conditions, out-of-scope, controls, bounded
   * caveat, version, re-verify), so the site's one-pager and the CLI's
   * agree on what an attestation contains. No verification logic.
   */

  ROT.attestationBody = function (t, id) {
    var policy = t.policy || {};
    var source = t.source || {};
    var prov = t.provenance || {};
    var compliance = t.compliance || {};
    var verdict = t.verdict;
    var policyHash = (source && source.hash) || prov.policy_hash || null;
    var nStates = prov.n_states != null ? prov.n_states : null;
    var amount = policy.amount != null ? policy.amount : null;
    var cap = policy.cap != null ? policy.cap : null;
    var maxInflight = policy.max_inflight != null ? policy.max_inflight : null;
    var buggy = !!policy.buggy;

    var scope = { property: policy.property || null, kind: policy.kind || null };
    if (amount != null) { scope.amount = amount; }
    if (cap != null) { scope.cap = cap; }
    if (maxInflight != null) { scope.max_inflight = maxInflight; }
    if (policy.server) { scope.server = policy.server; }
    if (policy.tenant_scope) { scope.tenant_scope = policy.tenant_scope; }
    scope.verdict = verdict;

    var conds = [];
    if (amount != null) { conds.push("AMOUNT = " + amount + " (per-request spend)"); }
    if (cap != null) { conds.push("CAP = " + cap + " (the spend cap)"); }
    if (maxInflight != null) {
      conds.push("bounded pool: max_inflight = " + maxInflight +
        " (the reachable state space is bounded)");
    }
    if (buggy) {
      conds.push("K >= 2 (a burst of parallel fires exposes the bug; " +
        "K = 1 masks it under settled-only accounting)");
    }
    if (nStates != null) {
      conds.push("reachable state space explored: n_states = " + nStates);
    }

    var touched = (compliance && compliance.controls_touched) || [];
    var soc2 = [], aiuc = [];
    for (var i = 0; i < touched.length; i++) {
      if (touched[i].indexOf("CC") === 0) { soc2.push(touched[i]); }
      if (touched[i].indexOf("AIUC") === 0) { aiuc.push(touched[i]); }
    }

    var rotVersion = t.rot_version || "?";
    return {
      schema: "caravel.attestation/v1",
      artifact_hierarchy: [
        { artifact: "RTF v1 trace", schema: "caravel.rtf/v1",
          role: "source of truth (hash-pinned)" },
        { artifact: "one-pager", schema: "caravel.attestation/v1",
          role: "underwriter view (a pure function of the trace)" },
        { artifact: "site", schema: "site/data",
          role: "demo view (interactive; renders the same trace data)" }
      ],
      verdict: verdict,
      source_trace: { schema: t.schema, manifest_id: t.manifest_id, hash: t.hash },
      version: {
        policy_hash: policyHash,
        engine_version: rotVersion,
        engines: t.engines || [],
        id: (policyHash ? String(policyHash).slice(0, 16) : "unknown") + "+" + rotVersion
      },
      scope: scope,
      coverage_conditions: conds,
      out_of_scope: [
        "liveness (task completion) -- this is a SAFETY property; liveness is bounded only by the horizon",
        "other invariant kinds (approval ordering, information-flow) -- not in this trace",
        "state space beyond the reachable set explored (n_states = " +
          (nStates != null ? nStates : "unknown") + ")"
      ],
      counterexample: t.counterexample || null,
      controls: { soc2: soc2, aiuc: aiuc, labels: (compliance && compliance.controls) || {} },
      bounded_caveat: (nStates != null
        ? "This is a BOUNDED proof: it holds over the reachable state space explored (n_states = " +
          nStates + "). It is not an unbounded theorem -- a larger pool or a longer horizon would require a re-issue of this attestation."
        : "This is a BOUNDED proof over the state space the engine explored. It is not an unbounded theorem -- a larger bound would require a re-issue of this attestation."),
      claims: {
        defensible: "ROTN does NOT claim to compile arbitrary policy text into an equivalent model. It lowers the spend-cap policy class (aggregate-over-events + cap) to a bounded transition system by a mechanical derivation from the parsed policy -- parameterized on amount / cap / pool -- and verifies it with independent engines. The policy<->model correspondence is CHECKED, not argued.",
        not_claimed: "No arbitrary-policy compilation. Every verdict is BOUNDED: it holds over the explored state space, not over all possible states."
      },
      reverify: {
        command: id ? ROT.reverifyCommand(id, t) : null,
        expected_hash: t.hash
      }
    };
  };

  /* ---------------- views ---------------- */

  function showLoading(view, label) {
    if (!view) { return; }
    view.setAttribute("aria-busy", "true");
    view.innerHTML =
      '<div class="loading" role="status">' +
      '<div class="spinner" aria-hidden="true"></div>' +
      '<span>' + esc(label || "Loading\u2026") + "</span></div>";
  }

  function focusMain() {
    // Move focus to the new page's first heading (or the view itself) so
    // keyboard and screen-reader users land at the top of the new content
    // (WCAG 2.4.3 Focus Order). Skipped on the initial render.
    if (!navigated) { return; }
    var view = document.getElementById("view");
    if (!view) { return; }
    view.removeAttribute("aria-busy");
    var h = view.querySelector("h1, h2");
    var target = h || view;
    if (target.getAttribute("tabindex") == null) { target.setAttribute("tabindex", "-1"); }
    if (target.focus) { target.focus({ preventScroll: true }); }
  }

  function notFoundHTML(id) {
    return [
      '<section class="empty-state">',
      "  <h1>Trace not found</h1>",
      '  <p>No trace <code class="mono">' + esc(id) + "</code> in <code class=\"mono\">data/</code>.",
      '  <p><a class="btn" href="#/">&larr; Back to the gallery</a>',
      "</section>"
    ].join("\n");
  }

  function cardHTML(id, t, v) {
    var findings = (t.findings || []).length;
    var engines = (t.engines || []).join(" \u00b7 ");
    var server = (t.policy && t.policy.server) || (t.source && t.source.schema) || "manifest";
    var tier = (t.budget && t.budget.tier) || "?";
    return [
      '<a class="trace-card v-' + v.cls + '" href="#/replay/' + esc(id) + '">',
      '  <div class="card-top"><span class="badge b-' + v.cls + '">' + v.label +
        '</span><span class="card-id mono">' + esc(id) + ".trace.json</span></div>",
      "  <h2>" + esc(server) + "</h2>",
      '  <p class="card-sub mono">' + esc(t.manifest_id || "") + "</p>",
      '  <p class="card-meta">engines: ' + esc(engines || "\u2014") +
        " \u00b7 tier: " + esc(tier) + " \u00b7 " + findings +
        " finding" + (findings === 1 ? "" : "s") + "</p>",
      '  <p class="card-hash">sha256 ' + esc(shortHash(t.hash, 16)) + "</p>",
      '  <span class="card-cta">Replay proof \u2192</span>',
      "</a>"
    ].join("\n");
  }

  function renderGallery() {
    var view = document.getElementById("view");
    if (!view) { return; }
    var ids = ROT.traceIds();
    var html = [
      '<section class="hero">',
      "  <h1>Replay the proof.</h1>",
      "  <p class=\"lede\">ROTN verifies an AI agent's tool policy with independent " +
        "engines and emits a deterministic, hashed trace (RTF v1). Every trace " +
        "below is a self-contained proof \u2014 open one to inspect the verdict, the " +
        "state-space graph, and the counterexample.</p>",
      "</section>"
    ];
    if (!ids.length) {
      html.push(
        '<section class="empty-state">',
        "  <h1>No traces yet</h1>",
        "  <p>Emit one with <code class=\"mono\">rot trace --manifest " +
          "examples/mcp-manifest-good.json --out site/data/good.trace.json</code>, " +
          "then regenerate the registry with " +
          "<code class=\"mono\">python scripts/gen_site_data.py</code>.</p>",
        "</section>"
      );
    } else {
      html.push('<section class="gallery" aria-label="Trace gallery">');
      ids.forEach(function (id) {
        var t = registry()[id];
        html.push(cardHTML(id, t, ROT.verdictInfo(t && t.verdict)));
      });
      html.push("</section>");
    }

    /* Compare affordance: the spend-cap buggy vs correct pair (if present). */
    var reg = registry();
    var pairs = [];
    if (reg["spendcap-buggy"] && reg["spendcap-correct"]) {
      pairs.push(["spendcap-buggy", "spendcap-correct"]);
    }
    if (pairs.length) {
      html.push(
        '<section class="compare-cta" aria-label="Compare">',
        "  <h2>Compare</h2>",
        '  <p class="lede">Put the buggy and correct spend-cap policy side by side, ' +
        "and watch the K-sweep expose the concurrency bound the verdict depends on " +
        "(at K=1 the bug is masked).</p>",
        "  <div class=\"compare-cta-btns\">"
      );
      pairs.forEach(function (pair) {
        html.push(
          '<a class="btn" href="#/compare/' + pair[0] + "/" + pair[1] + '">' +
          esc(pair[0]) + " vs " + esc(pair[1]) + " \u2192</a>"
        );
      });
      html.push("  </div></section>");
    }

    view.innerHTML = html.join("\n");
  }
  /* ---------------- verdict hero (F2) ---------------- */

  function heroHTML(id, t, v) {
    var engines = t.engines || [];
    var budget = t.budget || {};
    var limits = budget.limits || {};
    var server = (t.policy && t.policy.server) || "\u2014";
    var version = (t.policy && t.policy.version) || "";
    var scope = (t.policy && t.policy.tenant_scope) || "";
    var limitsText = Object.keys(limits).sort().map(function (k) {
      return k.replace("max_", "") + " \u2264 " + limits[k];
    }).join(" \u00b7 ");
    return [
      '<section class="verdict-hero v-' + v.cls + '" aria-label="Verdict">',
      "  <div class=\"vh-main\">",
      '    <span class="vh-kicker">RTF v1 \u00b7 ' + esc(t.schema || "caravel.rtf/v1") +
        " \u00b7 " + esc(t.manifest_id || "") + "</span>",
      "    <h1 class=\"vh-verdict\">" + v.label + "</h1>",
      "    <p class=\"vh-desc\">" + esc(v.desc) + "</p>",
      '    <div class="vh-chips">',
      engines.map(function (e) {
        return '<span class="chip" title="engines">' + esc(e) + "</span>";
      }).join(""),
      '<span class="chip chip-tier" title="budget tier">tier: ' + esc(budget.tier || "?") + "</span>",
      '<span class="chip" title="bounded search horizon">horizon: ' +
        esc(t.horizon != null ? t.horizon : "?") + "</span>",
      (t.policy && t.policy.max_inflight != null)
        ? '<span class="chip chip-tier" title="concurrency pool K (max in-flight requests)">K: ' +
          esc(t.policy.max_inflight) + "</span>"
        : "",
      "</div>",
      "  </div>",
      "  <div class=\"vh-side\">",
      "    <dl class=\"vh-facts\">",
      "      <dt>server</dt><dd>" + esc(server) + (version ? " v" + esc(version) : "") + "</dd>",
      '      <dt>tenant scope</dt><dd class="mono">' + esc(scope || "\u2014") + "</dd>",
      '      <dt>manifest hash</dt><dd class="hash-wrap">' +
        esc((t.source && t.source.hash) || (t.policy && t.policy.hash) || "\u2014") +
        ' <button type="button" class="btn copy-btn hash-copy" data-copy-text="' +
        esc((t.source && t.source.hash) || (t.policy && t.policy.hash) || "") + '">copy</button></dd>',
      '      <dt>trace hash</dt><dd class="hash-wrap">' + esc(t.hash || "\u2014") +
        ' <button type="button" class="btn copy-btn hash-copy" data-copy-text="' +
        esc(t.hash || "") + '">copy</button></dd>',
      "      <dt>budget</dt><dd>" + esc(limitsText || "\u2014") +
        (budget.source ? " \u00b7 source: " + esc(budget.source) : "") + "</dd>",
      "    </dl>",
      '    <div class="reverify">',
      '      <span class="rv-label">Re-verify in your terminal</span>',
      '      <code class="rv-cmd mono" id="rv-cmd">' + esc(ROT.reverifyCommand(id, t)) + "</code>",
      '      <button type="button" class="btn copy-btn" data-copy="#rv-cmd">Copy</button>',
      "    </div>",
      (function () {
        var pair = comparePairFor(id);
        if (!pair) { return ""; }
        return (
          '<div class="hero-compare">' +
          '<span class="rv-label">Compare</span>' +
          '<a class="btn" href="#/compare/' + pair[0] + "/" + pair[1] + '">' +
          "buggy vs correct + K-sweep \u2192</a>" +
          "</div>"
        );
      })(),
      (function () {
        var link = ROT.shareLink(t, id);
        return (
          '<div class="hero-att">' +
          '<span class="rv-label">Attestation</span>' +
          '<a class="btn btn-att" href="' + esc(ROT.shareURL(t, id)) + '">' +
          "\u2713 Export attestation \u2192</a>" +
          '<button type="button" class="btn copy-btn att-share" ' +
          'data-copy-text="' + esc(link) + '">Copy share URL (hash-pinned)</button>' +
          "</div>"
        );
      })(),
      "  </div>",
      "</section>"
    ].join("\n");
  }

  function isSpendcap(t) {
    return !!(t && t.spend && t.spend.steps && t.spend.steps.length);
  }

  /* The buggy-vs-correct compare pair for a spend-cap base trace (or null). */
  function comparePairFor(id) {
    if (id === "spendcap-buggy" || id === "spendcap-correct") {
      return ["spendcap-buggy", "spendcap-correct"];
    }
    return null;
  }

  /* ---------------- E2: the four-beat arc (rule -> attack -> proof -> coach)
   *
   * The replay page is a narrative, not a dashboard:
   *
   *   BEAT 1 RULE    -- the policy as written (bounds, fields, hash)
   *   BEAT 2 ATTACK  -- the counterexample in the state space, the cap
   *                     crossing, and the K-sweep (CLIMAX 1)
   *   BEAT 3 PROOF   -- what the engine discharged, under what bounds, and
   *                     the buggy/corrected pair
   *   BEAT 4 COACH   -- blocked call -> five-field refusal -> to_proceed
   *                     (CLIMAX 2) -> the repair, discharged by proof
   *
   * Every beat renders from the SAME RTF v1 trace; the attestation view
   * (E3) is a pure function of it.
   */

  function beat(n, title, tag, sub, body) {
    return (
      '<section class="beat" id="beat-' + n + '" aria-label="' + esc(title) + '">' +
      '<header class="beat-head">' +
      '<span class="beat-n" aria-hidden="true">' + n + "</span>" +
      "<div>" +
      "<h2>" + esc(title) +
      (tag ? ' <span class="beat-tag">' + tag + "</span>" : "") +
      "</h2>" +
      (sub ? '<p class="beat-sub">' + sub + "</p>" : "") +
      "</div>" +
      "</header>" +
      '<div class="beat-body">' + body + "</div>" +
      "</section>"
    );
  }

  /* BEAT 1 -- the rule as written (spend-cap policy or MCP manifest). */
  function ruleBeat(t) {
    var p = t.policy || {};
    var src = t.source || {};
    var rows = [];
    function row(label, val, mono) {
      if (val == null || val === "") { return ""; }
      return '<dt>' + esc(label) + '</dt><dd class="' + (mono ? "mono" : "") + '">' +
        esc(val) + "</dd>";
    }
    if (p.server) {
      rows.push(row("server", p.server));
      rows.push(row("version", p.version));
      rows.push(row("tenant scope", p.tenant_scope, true));
      rows.push(row("allowed write fields", (p.allowed_write_fields || []).join(", "), true));
    } else {
      rows.push(row("property", p.property, true));
      rows.push(row("kind", p.kind));
      rows.push(row("event_kind", p.event_kind, true));
      rows.push(row("AMOUNT", p.amount));
      rows.push(row("CAP", p.cap));
      rows.push(row("K (max in-flight)", p.max_inflight));
      rows.push(row("window", p.window));
    }
    rows.push(row("policy hash", (src.hash || p.hash), true));
    var variant = p.buggy
      ? '<span class="chip chip-buggy">BUGGY variant &mdash; settled-trace accounting</span>'
      : (p.max_inflight != null
        ? '<span class="chip chip-fix">CORRECTED variant &mdash; in-flight-trace accounting</span>'
        : "");
    var constraints = (window.ROT.ROTCompare && t.constraints && t.constraints.length)
      ? '<h4 class="beat-h">constraints</h4>' + ROT.ROTCompare.constraintsHTML(t)
      : "";
    return (
      '<div class="rule-card">' +
      '<dl class="policy-card">' + rows.join("") + "</dl>" +
      (variant ? '<div class="rule-variant">' + variant + "</div>" : "") +
      constraints +
      "</div>"
    );
  }

  /* BEAT 2 -- the attack: state space, counterexample path, cap crossing,
   * and (spend-cap) the K-sweep: CLIMAX 1. */
  function attackBeat(t) {
    var spend = isSpendcap(t);
    var parts = [];
    parts.push('<div id="rot-graph" class="graph-box"></div>');
    if (spend) {
      parts.push('<div id="rot-spendcap"></div>');
    }
    parts.push('<div id="rot-timeline"></div>');
    if (spend && window.ROT.ROTCompare) {
      var series = ROT.ROTCompare.ksweepSeries();
      parts.push(
        '<div class="climax climax-1" id="rot-sweep">' +
        '<div class="climax-tag">CLIMAX 1 &mdash; the K-sweep</div>' +
        ROT.ROTCompare.sweepHTML(series) +
        "</div>"
      );
    }
    return parts.join("\n");
  }

  /* BEAT 3 -- the proof: bounded, re-derivable, and the buggy/corrected pair. */
  function proofBeat(id, t) {
    var parts = [];
    if (window.ROT.ROTCompare) {
      var pair = ROT.ROTCompare.pairAt(t);
      if (pair) {
        parts.push('<h4 class="beat-h">buggy vs corrected &mdash; at this K</h4>');
        parts.push(ROT.ROTCompare.columnsHTML(pair));
      }
    }
    var prov = t.provenance || {};
    var facts = [];
    function f(label, val) {
      if (val == null || val === "") { return; }
      facts.push('<dt>' + esc(label) + "</dt><dd>" + esc(val) + "</dd>");
    }
    f("engines", (t.engines || []).join(" \u00b7 "));
    f("states explored (bounded)", prov.n_states != null ? prov.n_states : null);
    f("horizon", t.horizon != null ? t.horizon : null);
    f("horizon complete", prov.horizon_complete == null ? null : (prov.horizon_complete ? "yes" : "no"));
    f("policy hash", prov.policy_hash || (t.source && t.source.hash));
    if (facts.length) {
      parts.push('<h4 class="beat-h">provenance (bounded)</h4>');
      parts.push('<dl class="proof-facts">' + facts.join("") + "</dl>");
    }
    if (t.policy && t.policy.max_inflight != null) {
      var buggy = !!t.policy.buggy;
      var otherId = buggy ? String(id).replace("-buggy", "-correct")
                          : String(id).replace("-correct", "-buggy");
      parts.push(
        '<p class="proof-cross">' +
        (buggy
          ? "This policy is VIOLATED &mdash; its proof is the <strong>corrected variant</strong>: " +
            '<a href="#/replay/' + esc(otherId) + '"><code>' + esc(otherId) + "</code></a>, " +
            "and the coach in beat 4 re-proves the repair."
          : "This policy is PROVEN &mdash; the attack lives in the <strong>buggy variant</strong>: " +
            '<a href="#/replay/' + esc(otherId) + '"><code>' + esc(otherId) + "</code></a>, " +
            "where the coach in beat 4 is the hero.") +
        "</p>"
      );
    }
    if (!parts.length) { parts.push('<p class="muted">No provenance recorded in this trace.</p>'); }
    return parts.join("\n");
  }

  /* BEAT 4 -- the coach: blocked call -> refusal -> to_proceed (CLIMAX 2).
   * The coach panel (coach.js) is the hero when the trace carries coaching;
   * the idle note is rendered here so the beat is never empty. */
  function coachIdleHTML(id, t) {
    if (t.policy && t.policy.server) {
      return (
        '<div class="coach-idle"><p>The coach is the hero of the spend-cap arc: a ' +
        "blocked call, a five-field refusal, and the computed " +
        "<code class=\"mono\">to_proceed</code>. The MCP / lethal-trifecta " +
        "rule &rarr; attack &rarr; proof arc (and its coach) ships with B2.3 " +
        "&mdash; stated scope, not a gap in this page.</p></div>"
      );
    }
    var buggyId = String(id).replace(/-correct/g, "-buggy");
    return (
      '<div class="coach-idle"><p>The coach is idle here: this policy is proven, ' +
      "so there is no blocked call and <code class=\"mono\">to_proceed</code> is " +
      "never issued. The coach is the hero of the <strong>buggy variant</strong> " +
      '(<a href="#/replay/' + esc(buggyId) + '">' + esc(buggyId) + "</a>), where a " +
      "parallel burst is blocked and the coach hands back the computed enabling " +
      "condition.</p></div>"
    );
  }

  function coachBeat(id, t) {
    var parts = [];
    if (t.coaching && t.coaching.schema) {
      parts.push(
        '<div class="climax climax-2"><div class="climax-tag">CLIMAX 2 &mdash; to_proceed</div></div>'
      );
      parts.push('<div id="rot-coach"></div>');
    } else {
      parts.push(coachIdleHTML(id, t));
    }
    if (t.narration) {
      parts.push('<h4 class="beat-h">narration</h4>');
      parts.push('<div id="rot-narration"></div>');
    }
    return parts.join("\n");
  }

  function replayHTML(id, t, v) {
    var spend = isSpendcap(t);
    return [
      '<nav class="crumbs" aria-label="Breadcrumb"><a href="#/">gallery</a> / <span>' + esc(id) + "</span></nav>",
      heroHTML(id, t, v),
      '<p class="arc-lede">This page walks four beats: <strong>RULE</strong> &rarr; ' +
        "<strong>ATTACK</strong> (the K-sweep &mdash; climax 1) &rarr; <strong>PROOF</strong> " +
        "&rarr; <strong>COACH</strong> (<code class=\"mono\">to_proceed</code> &mdash; climax 2).",
      beat("rule", "RULE", "the rule as written",
        spend
          ? "The spend-cap policy, with the exact bounds the proof holds under."
          : "The MCP manifest: which server, which tenant scope, which writes are permitted.",
        ruleBeat(t)),
      beat("attack", "ATTACK", spend ? "climax 1: the K-sweep" : "the counterexample path",
        spend
          ? "The counterexample in the state space, the cap crossing, and the K-sweep that exposes the concurrency bound."
          : "The counterexample path through the state space.",
        attackBeat(t)),
      beat("proof", "PROOF", "bounded, re-derivable",
        "What the engine discharged, under what bounds, and how to re-derive it byte-for-byte.",
        proofBeat(id, t)),
      beat("coach", "COACH", "climax 2: to_proceed",
        "The blocked call, the five-field refusal, and the computed enabling condition &mdash; the repair discharged by proof.",
        coachBeat(id, t)),
      '<section class="panel evidence" aria-label="Evidence and controls">',
      "  <div class=\"panel-head\"><h2>Evidence &amp; controls</h2>" +
        '<p class="panel-sub">findings mapped to SOC 2 / AIUC controls &mdash; the underwriter&rsquo;s evidence</p></div>',
      '  <div id="rot-findings"></div>',
      '  <div id="rot-compliance"></div>',
      "</section>"
    ].join("\n");
  }

  function renderReplay(id) {
    var view = document.getElementById("view");
    if (!view) { return; }
    showLoading(view, "Loading " + id + "\u2026");
    ROT.loadTrace(id).then(function (t) {
      if (!t) {
        view.innerHTML = notFoundHTML(id);
        focusMain();
        return;
      }
      var v = ROT.verdictInfo(t.verdict);
      view.innerHTML = replayHTML(id, t, v);
      var graphEl = document.getElementById("rot-graph");
      if (graphEl && ROT.ROTGraph) { ROT.ROTGraph.mount(graphEl, t); }
      var spendEl = document.getElementById("rot-spendcap");
      if (spendEl && ROT.ROTSpendcap) { ROT.ROTSpendcap.mount(spendEl, t); }
      var tlEl = document.getElementById("rot-timeline");
      if (tlEl && ROT.ROTTimeline) { ROT.ROTTimeline.mount(tlEl, t); }
      var coachEl = document.getElementById("rot-coach");
      if (coachEl && ROT.ROTCoach) { ROT.ROTCoach.mount(coachEl, t, id); }
      var narrEl = document.getElementById("rot-narration");
      if (narrEl && ROT.ROTNarration) { ROT.ROTNarration.mount(narrEl, t); }
      var findEl = document.getElementById("rot-findings");
      if (findEl && ROT.ROTFindings) { ROT.ROTFindings.mount(findEl, t); }
      var compEl = document.getElementById("rot-compliance");
      if (compEl && ROT.ROTCompliance) { ROT.ROTCompliance.mount(compEl, t); }
      if (window.ROT.ROTCompare) {
        var sweepEl = document.getElementById("rot-sweep");
        if (sweepEl) { ROT.ROTCompare.bindSweep(sweepEl, ROT.ROTCompare.ksweepSeries()); }
      }
      bindCopyButtons(view);
      focusMain();
    }).catch(function () {
      view.innerHTML = notFoundHTML(id);
      focusMain();
    });
  }

  /* ---------------- compare view (Phase H) ---------------- */

  function renderCompare(leftId, rightId) {
    var view = document.getElementById("view");
    if (!view) { return; }
    showLoading(view, "Loading " + leftId + " vs " + rightId + "\u2026");
    function fail() {
      view.innerHTML = notFoundHTML(leftId + " / " + rightId);
      focusMain();
    }
    ROT.loadTrace(leftId).then(function (left) {
      if (!left) { fail(); return null; }
      return ROT.loadTrace(rightId).then(function (right) {
        if (!right) { fail(); return; }
        view.innerHTML =
          '<nav class="crumbs" aria-label="Breadcrumb"><a href="#/">gallery</a> / ' +
          '<a href="#/compare/' + esc(leftId) + '/' + esc(rightId) + '">compare</a> / ' +
          "<span>" + esc(leftId) + " vs " + esc(rightId) + "</span></nav>" +
          '<section class="panel" aria-label="Compare">' +
          '  <div class="panel-head"><h2>Compare — ' + esc(leftId) + " vs " + esc(rightId) + "</h2>" +
          '  <p class="panel-sub">Side-by-side verdicts, hashes, and the controls each trace touched, ' +
          "plus the K-sweep that exposes the concurrency-bound the verdict depends on.</p></div>" +
          '  <div id="rot-compare"></div>' +
          "</section>";
        if (ROT.ROTCompare) {
          ROT.ROTCompare.mount(document.getElementById("rot-compare"), {
            leftId: leftId, rightId: rightId, left: left, right: right
          });
        }
        focusMain();
      });
    }).catch(function () { fail(); });
  }
  /* ---------------- E3: the attestation view (B3 one-pager from the trace)
   *
   * #/attestation/<id> renders the B3 attestation from the SAME trace data
   * the replay page uses. The body is a pure function of the trace
   * (ROT.attestationBody) -- the same fields rot/attestation.py derives.
   * When the URL carries a hash pin (?h=<sha256>) -- the shareable,
   * hash-pinned link (E4) -- the pin is verified against the trace before
   * anything is trusted; a mismatch is flagged STALE, never re-proven.
   */

  function attestationHTML(id, t, pin) {
    var b = ROT.attestationBody(t, id);
    var v = ROT.verdictInfo(t.verdict);
    var pinned = !!(pin && t.hash);
    var match = pinned
      ? (String(pin).toLowerCase() === String(t.hash).toLowerCase())
      : null;
    var parts = [];

    parts.push(
      '<nav class="crumbs" aria-label="Breadcrumb"><a href="#/">gallery</a> / ' +
      '<a href="#/replay/' + esc(id) + '">replay</a> / <span>attestation</span></nav>'
    );

    if (pinned && match) {
      parts.push(
        '<div class="att-pin att-pin-ok" role="status">' +
        '<span class="att-pin-icon" aria-hidden="true">\u2713</span> ' +
        "<strong>HASH PIN VERIFIED</strong> &mdash; the hash in this URL matches the trace " +
        "byte-for-byte. This link <em>is</em> the attestation."
      );
    } else if (pinned) {
      parts.push(
        '<div class="att-pin att-pin-bad" role="alert">' +
        '<span class="att-pin-icon" aria-hidden="true">\u26A0</span> ' +
        "<strong>HASH MISMATCH</strong> &mdash; the hash in this URL does not match the trace. " +
        "STALE or TAMPERED: re-issue the attestation; do not trust this pin."
      );
    }

    parts.push(
      '<section class="att-hero v-' + v.cls + '">' +
      '<div class="att-verdict">' + v.label + '</div>' +
      '<div class="att-id">' +
      '<div class="att-kicker">caravel.attestation/v1 &middot; ' + esc(t.manifest_id || id) + "</div>" +
      "<h1>Attestation &mdash; " + esc(id) + "</h1>" +
      '<p class="att-hashline">trace SHA-256 <code class="mono">' + esc(t.hash || "\u2014") + "</code> " +
      '<button type="button" class="btn copy-btn" data-copy-text="' + esc(t.hash || "") + '">copy</button></p>' +
      '<p class="att-version">version ' + esc(b.version.id) + " &middot; engines " +
      esc((b.version.engines || []).join(" \u00b7 ") || "\u2014") + "</p>" +
      "</div>" +
      "</section>"
    );

    function sec(title, inner) {
      return '<section class="att-sec"><h2>' + esc(title) + "</h2>" + inner + "</section>";
    }
    function list(items) {
      return '<ul class="att-list">' +
        items.map(function (x) { return "<li>" + x + "</li>"; }).join("") +
        "</ul>";
    }

    var scopeRows = [];
    Object.keys(b.scope).forEach(function (k) {
      var val = b.scope[k];
      if (val == null) { return; }
      scopeRows.push("<tr><th>" + esc(k) + "</th><td>" + esc(val) + "</td></tr>");
    });
    parts.push(sec("Scope", '<table class="att-table">' + scopeRows.join("") + "</table>"));

    parts.push(sec("Assumptions (coverage conditions)",
      list(b.coverage_conditions.map(esc)) +
      '<p class="muted att-note">A bounded proof is only as good as its bounds: ' +
      "these are the conditions under which the verdict holds.</p>"));

    parts.push(sec("Out of scope (stated, not implied)", list(b.out_of_scope.map(esc))));

    if (b.counterexample) {
      var ce = b.counterexample;
      var ceTxt = [];
      if (ce.completed != null) { ceTxt.push("completed=" + ce.completed); }
      if (ce.inflight != null) { ceTxt.push("inflight=" + ce.inflight); }
      if (ce.steps) { ceTxt.push(ce.steps.length + " step(s)"); }
      parts.push(sec("Counterexample", '<p class="mono">' + esc(ceTxt.join(" \u00b7 ")) + "</p>"));
    }

    var cLabels = b.controls.labels || {};
    var ctrlRows = b.controls.soc2.concat(b.controls.aiuc).map(function (c) {
      return '<tr><th class="mono">' + esc(c) + "</th><td>" + esc(cLabels[c] || "") + "</td></tr>";
    });
    parts.push(sec("Controls touched (SOC 2 / AIUC)",
      ctrlRows.length
        ? '<table class="att-table">' + ctrlRows.join("") + "</table>"
        : '<p class="muted">No control mapping recorded in this trace.</p>'));

    parts.push(
      '<section class="att-sec att-caveat"><h2>Bounded caveat</h2><p>' +
      esc(b.bounded_caveat) + "</p></section>"
    );

    parts.push(sec("Defensible claim", "<p>" + esc(b.claims.defensible) + "</p>"));
    parts.push(sec("What we do NOT claim", "<p>" + esc(b.claims.not_claimed) + "</p>"));

    parts.push(
      '<section class="att-sec att-reverify"><h2>Re-verify (byte-for-byte)</h2>' +
      '<pre class="mono att-cmd">' + esc(b.reverify.command || "") + "</pre>" +
      '<p class="att-hashline">expected hash <code class="mono">' +
      esc(b.reverify.expected_hash || "\u2014") + "</code> " +
      '<button type="button" class="btn copy-btn" data-copy-text="' +
      esc(b.reverify.expected_hash || "") + '">copy hash</button></p>' +
      "</section>"
    );

    var hier = b.artifact_hierarchy.map(function (h) {
      return "<tr><th>" + esc(h.artifact) + "</th><td>" + esc(h.role) + "</td></tr>";
    }).join("");
    parts.push(sec("Artifact hierarchy", '<table class="att-table">' + hier + "</table>"));

    var share = ROT.shareLink(t, id);
    parts.push(
      '<section class="att-sec att-share"><h2>Share</h2>' +
      '<p class="muted">One URL, hash in the URL &mdash; the link <em>is</em> the attestation. ' +
      "The receiving side re-verifies the pin against the trace before trusting anything.</p>" +
      '<div class="att-share-row">' +
      '<input class="mono att-share-input" readonly value="' + esc(share) + '" ' +
      'onfocus="this.select()" aria-label="Share URL (hash-pinned)">' +
      '<button type="button" class="btn copy-btn att-share" data-copy-text="' + esc(share) +
      '">Copy share URL</button>' +
      "</div>" +
      "</section>"
    );

    parts.push(
      '<footer class="att-foot">' +
      '<p class="muted">caravel.attestation/v1 &middot; RTF v1 = source of truth (hash-pinned) ' +
      "&rarr; one-pager = underwriter view &rarr; site = demo view.</p>" +
      "</footer>"
    );

    return parts.join("\n");
  }

  function renderAttestation(id, pin) {
    var view = document.getElementById("view");
    if (!view) { return; }
    showLoading(view, "Loading attestation for " + id + "\u2026");
    ROT.loadTrace(id).then(function (t) {
      if (!t) {
        view.innerHTML = notFoundHTML(id);
        focusMain();
        return;
      }
      view.innerHTML = attestationHTML(id, t, pin);
      bindCopyButtons(view);
      focusMain();
    }).catch(function () {
      view.innerHTML = notFoundHTML(id);
      focusMain();
    });
  }

  /* ---------------- copy-to-clipboard (works over file://) ---------------- */

  function copyText(text, btn) {
    function done(ok) {
      if (!btn || !btn.textContent) { return; }
      var old = btn.textContent;
      btn.textContent = ok ? "Copied \u2713" : "Copy failed";
      setTimeout(function () { btn.textContent = old; }, 1500);
    }
    function fallback() {
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        var ok = document.execCommand("copy");
        document.body.removeChild(ta);
        done(ok);
      } catch (e) {
        done(false);
      }
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(
        function () { done(true); },
        function () { fallback(); }
      );
    } else {
      fallback();
    }
  }

  function bindCopyButtons(root) {
    var btns = root.querySelectorAll(".copy-btn");
    for (var i = 0; i < btns.length; i++) {
      (function (btn) {
        btn.addEventListener("click", function () {
          var sel = btn.getAttribute("data-copy");
          var target = sel ? root.querySelector(sel) : null;
          var text = target ? target.textContent : (btn.getAttribute("data-copy-text") || "");
          copyText(text, btn);
        });
      })(btns[i]);
    }
  }

  /* ---------------- router ----------------
   *
   * #/attestation/<id>?h=<sha256> carries the hash PIN in the URL itself
   * (E4): the link is the attestation, and the pin is verified against the
   * trace when the view renders. ?view=attestation on the page URL (E3)
   * renders the beachhead attestation from the same trace data.
   */

  function parseQuery() {
    var out = {};
    var qs = (typeof location.search === "string" ? location.search : "").replace(/^\?/, "");
    if (!qs) { return out; }
    qs.split("&").forEach(function (kv) {
      var i = kv.indexOf("=");
      var k = i >= 0 ? kv.slice(0, i) : kv;
      var val = i >= 0 ? kv.slice(i + 1) : "";
      try { out[decodeURIComponent(k)] = decodeURIComponent(val); } catch (e) {}
    });
    return out;
  }

  function parsePin(qs) {
    var i = qs.indexOf("h=");
    if (i < 0) { return null; }
    var val = qs.slice(i + 2).split("&")[0];
    try { return decodeURIComponent(val); } catch (e) { return val; }
  }

  function parseHash() {
    var h = (location.hash || "").replace(/^#\/?/, "");
    var pin = null;
    var qi = h.indexOf("?");
    if (qi >= 0) {
      pin = parsePin(h.slice(qi + 1));
      h = h.slice(0, qi);
    }
    var m = h.match(/^replay\/([^/]+)\/?$/);
    if (m) { return { view: "replay", id: decodeURIComponent(m[1]) }; }
    var c = h.match(/^compare\/([^/]+)\/([^/]+)\/?$/);
    if (c) {
      return { view: "compare",
               left: decodeURIComponent(c[1]),
               right: decodeURIComponent(c[2]) };
    }
    var a = h.match(/^attestation\/([^/]+)\/?$/);
    if (a) { return { view: "attestation", id: decodeURIComponent(a[1]), pin: pin }; }
    if (!h) {
      var q = parseQuery();
      if (q.view === "attestation") {
        return { view: "attestation", id: "spendcap-buggy", pin: q.h || null };
      }
      return { view: "gallery" };
    }
    return { view: "notfound", raw: h };
  }

  function route() {
    var r = parseHash();
    if (r.view === "replay") {
      renderReplay(r.id);            // manages focus on completion
    } else if (r.view === "compare") {
      renderCompare(r.left, r.right); // manages focus on completion
    } else if (r.view === "attestation") {
      renderAttestation(r.id, r.pin); // manages focus on completion
    } else if (r.view === "gallery") {
      renderGallery();
      focusMain();
    } else {
      var view = document.getElementById("view");
      if (view) { view.innerHTML = notFoundHTML(r.raw); focusMain(); }
    }
    if (window.scrollTo) { window.scrollTo(0, 0); }
  }
  ROT.route = route;

  /* Skip-to-content: focus the main region without triggering hash routing. */
  function wireSkipLink() {
    var skip = document.querySelector("[data-skip]");
    if (!skip) { return; }
    skip.addEventListener("click", function (e) {
      e.preventDefault();
      var view = document.getElementById("view");
      if (view && view.focus) { view.focus(); }
    });
  }
  wireSkipLink();

  window.addEventListener("hashchange", function () { navigated = true; route(); });
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", route);
  } else {
    route();
  }
})();
