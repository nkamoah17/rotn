/* ROTN replay site -- compare mode (Phase H, H2).
 *
 * Side-by-side comparison of two traces (the buggy vs the correct spend-cap
 * policy), plus an **animated K-sweep**: the concurrency-pool bound ``K``
 * (``--max-inflight``) that the verdict depends on.
 *
 *   K=1  -- the parallel-fire race is structurally unexpressible, so the
 *           buggy policy proves clean: a *masked* bug (false negative).
 *   K>=2 -- the in-flight state space can express the race; the buggy policy
 *           is VIOLATED while the correct policy stays PROVEN.
 *
 * The K-sweep is read straight from the registry (every ``spendcap-<variant>``
 * / ``spendcap-<variant>-k<N>`` trace, keyed by its ``policy.max_inflight``),
 * so it is data-driven and adds no verification logic. No framework, no build
 * step -- consistent with the rest of the site.
 */
(function () {
  "use strict";

  var ROT = (window.ROT = window.ROT || {});
  var ROTCompare = (ROT.ROTCompare = ROT.ROTCompare || {});

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function shortHash(h, n) {
    h = String(h || "");
    n = n || 16;
    return h.length > n ? h.slice(0, n) + "\u2026" : h;
  }
  function registry() { return window.ROT_TRACES || {}; }

  function verdictBadge(v) {
    var cls = v === "proven" ? "b-proven"
      : v === "violated" ? "b-violated" : "b-unknown";
    return '<span class="badge ' + cls + '">' + esc(String(v || "unknown").toUpperCase()) + "</span>";
  }

  /* The K-sweep series, read from the registry (data-driven).
   *
   * Returns [{ K, buggy, correct, buggyId, correctId }] ordered by K. Only K
   * values that have at least one spend-cap trace are included.
   */
  ROTCompare.ksweepSeries = function () {
    var reg = registry();
    var series = {};
    Object.keys(reg).forEach(function (id) {
      var m = id.match(/^spendcap-(buggy|correct)(?:-k(\d+))?$/);
      if (!m) { return; }
      var variant = m[1];
      var t = reg[id];
      var K = (t && t.policy && t.policy.max_inflight != null)
        ? t.policy.max_inflight
        : (m[2] ? parseInt(m[2], 10) : null);
      if (K == null) { return; }
      series[K] = series[K] || {};
      series[K][variant] = t.verdict;
      series[K][variant + "Id"] = id;
    });
    return Object.keys(series).map(Number)
      .sort(function (a, b) { return a - b; })
      .map(function (K) {
        return {
          K: K,
          buggy: series[K].buggy,
          correct: series[K].correct,
          buggyId: series[K].buggyId,
          correctId: series[K].correctId
        };
      });
  };

  /* One side-by-side column for a trace. */
  function columnHTML(id, t) {
    var v = ROT.verdictInfo(t.verdict);
    var s = (ROT.ROTCompliance && ROT.ROTCompliance.summary(t)) || { controls: [] };
    var controls = (s.controls || []).join(" · ") || "\u2014";
    var findings = (t.findings || []).length;
    var K = (t.policy && t.policy.max_inflight != null) ? t.policy.max_inflight : "\u2014";
    return (
      '<div class="compare-col v-' + v.cls + '">' +
      '<div class="cc-head">' + verdictBadge(t.verdict) +
        '<span class="cc-id mono">' + esc(id) + "</span></div>" +
      '<dl class="cc-facts">' +
      '<dt>manifest hash</dt><dd class="mono">' + esc(shortHash((t.source && t.source.hash) || "—", 20)) + "</dd>" +
      '<dt>trace hash</dt><dd class="mono">' + esc(shortHash(t.hash || "—", 20)) + "</dd>" +
      "<dt>K (max in-flight)</dt><dd>" + esc(K) + "</dd>" +
      "<dt>findings</dt><dd>" + findings + "</dd>" +
      "<dt>controls touched</dt><dd>" + esc(controls) + "</dd>" +
      "</dl>" +
      '<a class="btn cc-open" href="#/replay/' + esc(id) + '">Open replay \u2192</a>' +
      "</div>"
    );
  }

  /* The K-sweep table (columns = K, rows = buggy / correct). */
  function ksweepTable(series) {
    var head = "<tr><th></th>" + series.map(function (r) {
      return '<th class="ks-k ks-col-' + r.K + '">K=' + r.K + "</th>";
    }).join("") + "</tr>";
    function row(label, key) {
      return '<tr><td class="ks-rowlabel">' + esc(label) + "</td>" +
        series.map(function (r) {
          return '<td class="ks-cell ks-col-' + r.K + '">' + verdictBadge(r[key]) + "</td>";
        }).join("") + "</tr>";
    }
    return (
      '<table class="ks-table"><thead>' + head + "</thead><tbody>" +
      row("buggy", "buggy") + row("correct", "correct") +
      "</tbody></table>"
    );
  }

  function noteFor(series, K) {
    for (var i = 0; i < series.length; i++) {
      if (series[i].K === K) {
        if (series[i].buggy === "proven") {
          return "K=" + K + " — MASKED: the buggy policy proves clean because a " +
            "single in-flight request cannot overshoot the cap. This is a false " +
            "negative; the correct policy is indistinguishable from it here.";
        }
        return "K=" + K + " — VISIBLE: the buggy policy is violated (the race needs " +
          "this much in-flight), while the correct policy stays proven.";
      }
    }
    return "";
  }

  /* Wire the slider + play/pause animation. */
  function bindKsweep(root, series) {
    var range = root.querySelector("#ksweep-range");
    var play = root.querySelector("#ksweep-play");
    if (!range || !series.length) { return; }
    var kLabel = root.querySelector("#ksweep-k");
    var note = root.querySelector("#ksweep-note");
    var minK = parseInt(range.min, 10);
    var maxK = parseInt(range.max, 10);
    var timer = null;

    function setActive(K) {
      if (kLabel) { kLabel.textContent = K; }
      if (note) { note.textContent = noteFor(series, K); }
      var cols = root.querySelectorAll("[class*='ks-col-']");
      for (var i = 0; i < cols.length; i++) {
        cols[i].classList.toggle("ks-active", cols[i].classList.contains("ks-col-" + K));
      }
    }
    function stop() {
      if (timer) { clearInterval(timer); timer = null; }
      if (play) { play.innerHTML = '<span class="btn-replay-play" aria-hidden="true">\u25B6</span> Play sweep'; }
    }
    function start() {
      if (timer) { stop(); return; }
      if (play) { play.innerHTML = '<span class="btn-replay-play" aria-hidden="true">\u275A\u275A</span> Pause'; }
      var cur = parseInt(range.value, 10);
      if (cur >= maxK) { cur = minK - 1; }
      timer = setInterval(function () {
        cur += 1;
        if (cur > maxK) {
          range.value = maxK;
          setActive(maxK);
          stop();
          return;
        }
        range.value = cur;
        setActive(cur);
      }, 900);
    }

    range.addEventListener("input", function () {
      stop();
      setActive(parseInt(range.value, 10));
    });
    if (play) { play.addEventListener("click", start); }
    setActive(parseInt(range.value, 10));
  }

  /* Mount the full compare view (side-by-side + K-sweep). */
  ROTCompare.mount = function (container, pair) {
    if (!container) { return; }
    var series = ROTCompare.ksweepSeries();
    var hasSweep = series.length >= 2;
    var minK = hasSweep ? series[0].K : 1;
    var maxK = hasSweep ? series[series.length - 1].K : 1;

    var sweep = "";
    if (hasSweep) {
      sweep =
        '<div class="ksweep">' +
        '<h3 class="ks-h">K-sweep — bug visibility vs the concurrency pool K</h3>' +
        '<p class="muted ks-sub">K bounds how many in-flight requests the state space can ' +
        "express (it is structural, shared by both variants). Drag the slider or press " +
        "Play to watch the verdict flip as K grows.</p>" +
        '<div class="ks-controls">' +
        '<button type="button" class="btn btn-replay" id="ksweep-play"><span class="btn-replay-play" aria-hidden="true">\u25B6</span> Play sweep</button>' +
        '<label class="ks-label">K = <span id="ksweep-k" class="mono">' + minK + "</span></label>" +
        '<input type="range" id="ksweep-range" min="' + minK + '" max="' + maxK +
        '" step="1" value="' + minK + '" aria-label="concurrency pool K">' +
        "</div>" +
        '<div class="ks-grid">' + ksweepTable(series) + "</div>" +
        '<p class="ks-note" id="ksweep-note"></p>' +
        "</div>";
    } else {
      sweep = '<p class="muted ks-sub">No K-sweep traces available for this pair.</p>';
    }

    container.innerHTML =
      '<div class="compare">' +
      '<div class="compare-cols">' +
      columnHTML(pair.leftId, pair.left) +
      '<div class="compare-vs" aria-hidden="true">vs</div>' +
      columnHTML(pair.rightId, pair.right) +
      "</div>" +
      sweep +
      "</div>";

    bindKsweep(container, series);
  };
})();