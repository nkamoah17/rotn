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
      : "<manifest.json>";
    return "rot trace --manifest " + src + " --out site/data/" + id + ".trace.json";
  };

  /* ---------------- views ---------------- */

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
      "</div>",
      "  </div>",
      "  <div class=\"vh-side\">",
      "    <dl class=\"vh-facts\">",
      "      <dt>server</dt><dd>" + esc(server) + (version ? " v" + esc(version) : "") + "</dd>",
      '      <dt>tenant scope</dt><dd class="mono">' + esc(scope || "\u2014") + "</dd>",
      '      <dt>manifest hash</dt><dd class="hash-wrap">' +
        esc((t.source && t.source.hash) || (t.policy && t.policy.hash) || "\u2014") + "</dd>",
      '      <dt>trace hash</dt><dd class="hash-wrap">' + esc(t.hash || "\u2014") + "</dd>",
      "      <dt>budget</dt><dd>" + esc(limitsText || "\u2014") +
        (budget.source ? " \u00b7 source: " + esc(budget.source) : "") + "</dd>",
      "    </dl>",
      '    <div class="reverify">',
      '      <span class="rv-label">Re-verify in your terminal</span>',
      '      <code class="rv-cmd mono" id="rv-cmd">' + esc(ROT.reverifyCommand(id, t)) + "</code>",
      '      <button type="button" class="btn copy-btn" data-copy="#rv-cmd">Copy</button>',
      "    </div>",
      "  </div>",
      "</section>"
    ].join("\n");
  }

  function replayHTML(id, t, v) {
    return [
      '<nav class="crumbs" aria-label="Breadcrumb"><a href="#/">gallery</a> / <span>' + esc(id) + "</span></nav>",
      heroHTML(id, t, v),
      '<section class="panel" aria-label="State-space graph">',
      "  <div class=\"panel-head\"><h2>State-space graph</h2>" +
        '<p class="panel-sub">nodes = states (tools, fields) \u00b7 edges = actions (reads, writes) \u00b7 ' +
        '<span class="hl-note">red = counterexample</span></p></div>',
      '  <div id="rot-graph" class="graph-box"></div>',
      "</section>",
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
      "</section>"
    ].join("\n");
  }

  function renderReplay(id) {
    ROT.loadTrace(id).then(function (t) {
      var view = document.getElementById("view");
      if (!view) { return; }
      if (!t) {
        view.innerHTML = notFoundHTML(id);
        return;
      }
      var v = ROT.verdictInfo(t.verdict);
      view.innerHTML = replayHTML(id, t, v);
      if (ROT.ROTGraph) { ROT.ROTGraph.mount(document.getElementById("rot-graph"), t); }
      if (ROT.ROTTimeline) { ROT.ROTTimeline.mount(document.getElementById("rot-timeline"), t); }
      if (ROT.ROTNarration) { ROT.ROTNarration.mount(document.getElementById("rot-narration"), t); }
      if (ROT.ROTFindings) { ROT.ROTFindings.mount(document.getElementById("rot-findings"), t); }
      bindCopyButtons(view);
    }).catch(function () {
      var view = document.getElementById("view");
      if (view) { view.innerHTML = notFoundHTML(id); }
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

  /* ---------------- router ---------------- */

  function parseHash() {
    var h = (location.hash || "").replace(/^#\/?/, "");
    var m = h.match(/^replay\/([^/]+)\/?$/);
    if (m) { return { view: "replay", id: decodeURIComponent(m[1]) }; }
    if (!h) { return { view: "gallery" }; }
    return { view: "notfound", raw: h };
  }

  function route() {
    var r = parseHash();
    if (r.view === "replay") {
      renderReplay(r.id);
    } else if (r.view === "gallery") {
      renderGallery();
    } else {
      var view = document.getElementById("view");
      if (view) { view.innerHTML = notFoundHTML(r.raw); }
    }
    if (window.scrollTo) { window.scrollTo(0, 0); }
  }
  ROT.route = route;

  window.addEventListener("hashchange", route);
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", route);
  } else {
    route();
  }
})();
