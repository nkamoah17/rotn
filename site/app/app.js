/* ROTN replay site -- core: boot, hash routing, gallery, replay (Phase F).
 *
 * No framework, no build step, no CDN:
 *   - hash routing:   #/            -> landing + gallery
 *                     #/replay/<id> -> replay page (verdict hero + panels)
 *   - trace loading:  fetch('data/<id>.trace.json') when served over HTTP
 *                     (GitHub Pages), with the generated registry
 *                     data/traces.js (window.ROT_TRACES) as the offline
 *                     file:// fallback (where browsers block local fetch).
 *
 * The RTF v1 trace is the single data contract (see rot/trace.py); this
 * module renders it and adds no verification logic.
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

  function replayHTML(id, t, v) {
    var spendcap = isSpendcap(t);
    var graphSub = spendcap
      ? "nodes = states (in-flight / settled) \u00b7 edges = the counterexample step path \u00b7 " +
        '<span class="hl-note">red = counterexample \u00b7 orange = replay step</span>'
      : "nodes = states (tools, fields) \u00b7 edges = actions (reads, writes) \u00b7 " +
        '<span class="hl-note">red = counterexample</span>';
    var parts = [
      '<nav class="crumbs" aria-label="Breadcrumb"><a href="#/">gallery</a> / <span>' + esc(id) + "</span></nav>",
      heroHTML(id, t, v),
      '<section class="panel" aria-label="State-space graph">',
      "  <div class=\"panel-head\"><h2>State-space graph</h2>" +
        '<p class="panel-sub">' + graphSub + "</p></div>",
      '  <div id="rot-graph" class="graph-box"></div>',
      "</section>"
    ];
    if (spendcap) {
      parts.push(
        '<section class="panel" aria-label="Spend-cap timeline">',
        "  <div class=\"panel-head\"><h2>Spend-cap</h2>" +
          '<p class="panel-sub">G2 \u00b7 cumulative spend vs the cap, with the crossing moment highlighted</p></div>',
        '  <div id="rot-spendcap"></div>',
        "</section>"
      );
    }
    if (t.coaching && t.coaching.schema) {
      parts.push(
        '<section class="panel" aria-label="Coaching">',
        "  <div class=\"panel-head\"><h2>Coaching</h2>" +
          '<p class="panel-sub">the third leg of the triad \u00b7 the agent is coached back in bounds, *with a proof* (detect \u2192 explain \u2192 correct \u2192 re-check \u2192 close)</p></div>',
        '  <div id="rot-coach"></div>',
        "</section>"
      );
    }
    parts.push(
      '<section class="panels-2" aria-label="Timeline and narration">',
      '  <div class="panel">',
      "    <div class=\"panel-head\"><h2>Audit timeline</h2></div>",
      '    <div id="rot-timeline"></div>',
      "  </div>",
      '  <div class="panel">',
      "    <div class=\"panel-head\"><h2>Narration</h2></div>",
      '    <div id="rot-narration"></div>',
      "  </div>",
      "</section>",
      '<section class="panel" aria-label="Findings and controls">',
      "  <div class=\"panel-head\"><h2>Findings &amp; controls</h2>" +
        '<p class="panel-sub">Cedar-AR findings mapped to SOC 2 / AIUC controls</p></div>',
      '  <div id="rot-findings"></div>',
      "</section>",
      '<section class="panel" aria-label="Compliance">',
      "  <div class=\"panel-head\"><h2>Compliance</h2>" +
        '<p class="panel-sub">SOC 2 / AIUC controls touched by this audit, with the evidence that links each to its findings</p></div>',
      '  <div id="rot-compliance"></div>',
      "</section>"
    );
    return parts.join("\n");
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
      if (ROT.ROTGraph) { ROT.ROTGraph.mount(document.getElementById("rot-graph"), t); }
      if (ROT.ROTSpendcap) { ROT.ROTSpendcap.mount(document.getElementById("rot-spendcap"), t); }
      if (ROT.ROTCoach) { ROT.ROTCoach.mount(document.getElementById("rot-coach"), t); }
      if (ROT.ROTTimeline) { ROT.ROTTimeline.mount(document.getElementById("rot-timeline"), t); }
      if (ROT.ROTNarration) { ROT.ROTNarration.mount(document.getElementById("rot-narration"), t); }
      if (ROT.ROTFindings) { ROT.ROTFindings.mount(document.getElementById("rot-findings"), t); }
      if (ROT.ROTCompliance) { ROT.ROTCompliance.mount(document.getElementById("rot-compliance"), t); }
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

  /* ---------------- router ---------------- */

  function parseHash() {
    var h = (location.hash || "").replace(/^#\/?/, "");
    var m = h.match(/^replay\/([^/]+)\/?$/);
    if (m) { return { view: "replay", id: decodeURIComponent(m[1]) }; }
    var c = h.match(/^compare\/([^/]+)\/([^/]+)\/?$/);
    if (c) {
      return { view: "compare",
               left: decodeURIComponent(c[1]),
               right: decodeURIComponent(c[2]) };
    }
    if (!h) { return { view: "gallery" }; }
    return { view: "notfound", raw: h };
  }

  function route() {
    var r = parseHash();
    if (r.view === "replay") {
      renderReplay(r.id);            // manages focus on completion
    } else if (r.view === "compare") {
      renderCompare(r.left, r.right); // manages focus on completion
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
