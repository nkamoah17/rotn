/* ROTN replay site -- spend-cap panel (Phase G, G2).
 *
 * Renders the spend-cap timeline (G2): a chart of the total in-flight exposure
 * (settled + in-flight * AMOUNT) against the cap, over the counterexample
 * steps, with the crossing moment highlighted; plus the decision tree (the
 * guard expression and the per-step admit/deny checks).
 *
 * Only shown for traces that carry a ``spend`` section (spend-cap / .dw policy
 * audits). Pure SVG, no framework, no build step -- consistent with the rest
 * of the site.
 */
(function () {
  "use strict";

  var ROT = (window.ROT = window.ROT || {});
  var ROTSpendcap = (ROT.ROTSpendcap = ROT.ROTSpendcap || {});

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function hasSpend(trace) {
    return !!(trace.spend && trace.spend.cap != null);
  }

  /* ---------------- G2: the spend-cap timeline chart (SVG) ---------------- */

  function spendChart(trace) {
    var spend = trace.spend;
    var steps = spend.steps || [];
    var cap = spend.cap || 0;
    var amount = spend.amount || 0;
    var crossing = spend.crossing_step;
    var hasPath = steps.length > 0;

    var W = 560, H = 260;
    var mL = 56, mR = 24, mT = 24, mB = 44;
    var pw = W - mL - mR, ph = H - mT - mB;

    /* Build the points to plot + the x-axis domain. */
    var pts = [];      // {x, y, cross, val}
    var xTicks = [];   // x values to label
    var xLabel;        // x-axis caption
    var maxCum = cap;
    if (hasPath) {
      // Counterexample path: x = step index, y = cumulative exposure.
      steps.forEach(function (s) { if (s.cumulative > maxCum) { maxCum = s.cumulative; } });
      pts = steps.map(function (s, i) {
        return { x: i, y: s.cumulative, cross: crossing === i, val: s.cumulative };
      });
      xTicks = steps.map(function (s, i) { return i; });
      xLabel = "step";
    } else {
      // No counterexample: plot the reachable states (x = in-flight, y = cumulative).
      var states = spend.reachable_states || [];
      var maxInflight = 0;
      states.forEach(function (s) {
        if (s.cumulative > maxCum) { maxCum = s.cumulative; }
        if (s.inflight > maxInflight) { maxInflight = s.inflight; }
      });
      pts = states.map(function (s) {
        return { x: s.inflight, y: s.cumulative, cross: false, val: s.cumulative };
      });
      for (var xi = 0; xi <= maxInflight; xi += 1) { xTicks.push(xi); }
      xLabel = "in-flight";
    }

    /* Scale the y domain: 0 .. max(cap, max cumulative), rounded to a nice step. */
    var niceStep = Math.max(amount, Math.pow(10, Math.floor(Math.log10(maxCum || 1))));
    var yMax = Math.ceil((maxCum * 1.15) / niceStep) * niceStep;
    var maxX = 1;
    pts.forEach(function (p) { if (p.x > maxX) { maxX = p.x; } });
    function x(v) { return mL + (maxX > 0 ? (v / maxX) * pw : pw / 2); }
    function y(v) { return mT + ph - (v / yMax) * ph; }

    var svg = [];
    svg.push('<svg viewBox="0 0 ' + W + " " + H + '" class="spend-svg" role="img" ' +
      'aria-label="Spend-cap: total exposure vs the cap">');

    /* Y gridlines + labels. */
    var ticks = Math.max(1, Math.round(yMax / niceStep));
    for (var t = 0; t <= ticks; t += 1) {
      var val = (yMax / ticks) * t;
      var yy = y(val);
      svg.push('<line x1="' + mL + '" y1="' + yy + '" x2="' + (W - mR) + '" y2="' + yy +
        '" class="spend-grid"/>');
      svg.push('<text x="' + (mL - 8) + '" y="' + (yy + 4) + '" class="spend-axis" ' +
        'text-anchor="end">' + Math.round(val) + "</text>");
    }

    /* X labels. */
    xTicks.forEach(function (v) {
      svg.push('<text x="' + x(v) + '" y="' + (H - mB + 20) + '" class="spend-axis" ' +
        'text-anchor="middle">' + (hasPath ? "t" + v : v) + "</text>");
    });
    svg.push('<text x="' + (mL + pw / 2) + '" y="' + (H - 6) + '" class="spend-axis" ' +
      'text-anchor="middle">' + esc(xLabel) + "</text>");

    /* The cap line (horizontal, red dashed). */
    var capY = y(cap);
    svg.push('<line x1="' + mL + '" y1="' + capY + '" x2="' + (W - mR) + '" y2="' + capY +
      '" class="spend-cap"/>');
    svg.push('<text x="' + (W - mR) + '" y="' + (capY - 6) + '" class="spend-cap-label" ' +
      'text-anchor="end">CAP = ' + cap + "</text>");

    /* The data: a connected line for the counterexample path, points otherwise. */
    if (hasPath) {
      var linePts = pts.map(function (p) { return x(p.x) + "," + y(p.y); }).join(" ");
      svg.push('<polyline points="' + linePts + '" class="spend-line"/>');
    }
    pts.forEach(function (p) {
      svg.push('<circle cx="' + x(p.x) + '" cy="' + y(p.y) + '" r="' +
        (p.cross ? 6 : 4) + '" class="' + (p.cross ? "spend-dot-cross" : "spend-dot") + '"/>');
      svg.push('<text x="' + x(p.x) + '" y="' + (y(p.y) - 12) + '" class="' +
        (p.cross ? "spend-val-cross" : "spend-val") + '" text-anchor="middle">' +
        p.val + "</text>");
    });

    /* Annotation: the crossing moment, or a "no crossing" note. */
    if (hasPath && crossing != null) {
      var cp = pts[crossing];
      svg.push('<text x="' + x(cp.x) + '" y="' + (y(cp.y) + 22) +
        '" class="spend-cross-label" text-anchor="middle">crosses cap</text>');
    } else if (!hasPath) {
      svg.push('<text x="' + (mL + pw / 2) + '" y="' + (capY - 14) +
        '" class="spend-proven-label" text-anchor="middle">no crossing — all states within cap</text>');
    }

    svg.push("</svg>");

    var legend = [
      '<span class="lg"><i class="ln ln-spend"></i>' +
        (hasPath ? "total exposure (counterexample path)" : "reachable states") + "</span>",
      '<span class="lg"><i class="ln ln-cap"></i>cap (' + cap + ")</span>",
      hasPath
        ? '<span class="lg"><i class="sw sw-cross"></i>crossing moment</span>'
        : '<span class="lg"><i class="sw sw-proven"></i>within cap</span>'
    ].join("");

    return (
      '<h3 class="spend-h">Spend-cap timeline</h3>' +
      '<p class="muted spend-sub">AMOUNT=' + amount + " &middot; CAP=" + cap +
      " &middot; max in-flight=" + spend.max_inflight + "</p>" +
      '<div class="spend-chart">' + svg.join("") + "</div>" +
      '<div class="graph-legend">' + legend + "</div>"
    );
  }
  /* ---------------- the decision tree (guard + per-step checks) ---------------- */

  function decisionPanel(trace) {
    var dt = trace.decision_tree || {};
    var guard = dt.guard || "";
    var checks = dt.checks || [];
    var verdict = dt.verdict || "";

    if (!checks.length) {
      /* No counterexample: show the proven verdict. */
      var proven = (verdict === "proven");
      return (
        '<h3 class="spend-h">Decision tree</h3>' +
        '<p class="muted spend-sub">guard: <code class="mono">' + esc(guard) + "</code></p>" +
        '<div class="dt-clean ' + (proven ? "dt-clean-proven" : "dt-clean-other") + '">' +
        '<span class="dt-clean-icon" aria-hidden="true">' + (proven ? "\u2713" : "\u2139") + "</span>" +
        "<div>" +
        "<p class=\"dt-clean-title\">" + esc(proven ? "Proven — no counterexample" : verdict) + "</p>" +
        "<p class=\"dt-clean-msg\">No step sequence crosses the cap. Every reachable state " +
        "satisfies <code class=\"mono\">" + esc(guard) + "</code>.</p>" +
        "</div>" +
        "</div>"
      );
    }

    var rows = checks.map(function (c) {
      var cls = (c.result === "admit") ? "dt-admit" : "dt-deny";
      var state = c.state || {};
      var label = "in=" + state.inflight + ", settled=" + state.completed;
      return (
        '<tr class="' + cls + '">' +
        "<td>t" + c.step + "</td>" +
        "<td>" + esc(c.action) + "</td>" +
        "<td class=\"mono\">" + esc(label) + "</td>" +
        '<td class="dt-result">' + esc(c.result) + "</td>" +
        "</tr>"
      );
    }).join("");

    return (
      '<h3 class="spend-h">Decision tree</h3>' +
      '<p class="muted spend-sub">guard: <code class="mono">' + esc(guard) + "</code></p>" +
      '<table class="dt-table">' +
      "<thead><tr><th>step</th><th>action</th><th>state</th><th>result</th></tr></thead>" +
      "<tbody>" + rows + "</tbody>" +
      "</table>"
    );
  }

  ROTSpendcap.mount = function (container, trace) {
    if (!container || !hasSpend(trace)) { return; }
    var html = spendChart(trace);
    if (trace.decision_tree) { html += decisionPanel(trace); }
    container.innerHTML = html;
  };
})();

