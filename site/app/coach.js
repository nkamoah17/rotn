/* ROTN replay site -- Coaching panel (the third leg of the triad).
 *
 * Renders the CoachingArtifact (``caravel.coach/v1``): the 5-step loop
 * (Detect -> Explain -> Correct -> Re-check -> Close) that coaches a buggy
 * spend-cap back in bounds, *with a proof*. Only shown for traces that carry
 * a ``coaching`` section -- a violated spend-cap policy for which the
 * correction was (or was not) re-proven safe.
 *
 * Pure HTML, no framework, no build step -- consistent with the rest of the
 * site. The panel is fail-closed in its presentation: a ``closed`` coaching
 * (correction re-proven) reads green; an ``open`` coaching (correction did not
 * re-prove) reads amber and is explicitly labelled "NOT discharged".
 */
(function () {
  "use strict";

  var ROT = (window.ROT = window.ROT || {});
  var ROTCoach = (ROT.ROTCoach = ROT.ROTCoach || {});

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function hasCoach(trace) {
    return !!(trace.coaching && trace.coaching.schema);
  }

  function verdictChip(status) {
    var good = (status === "proven" || status === "closed");
    return '<span class="coach-verdict ' + (good ? "coach-verdict-good" : "coach-verdict-bad") + '">' +
      esc(status) + "</span>";
  }

  function witnessChip(witness) {
    if (!witness || (typeof witness === "object" && Object.keys(witness).length === 0)) {
      return "";
    }
    return '<span class="coach-witness">witness <code class="mono">' +
      esc(JSON.stringify(witness)) + "</code></span>";
  }

  function stepRow(n, label, content) {
    return (
      '<tr><td class="coach-step-n">' + n + "</td>" +
      '<td class="coach-step-label">' + esc(label) + "</td>" +
      '<td class="coach-step-body">' + content + "</td></tr>"
    );
  }

  function coachPanel(trace) {
    var c = trace.coaching;
    var closed = (c.status === "closed");
    var p = c.policy || {};
    var detect = c.detect || {};
    var explain = c.explain || {};
    var correct = c.correct || {};
    var recheck = c.recheck || {};
    var close = c.close || {};

    var rows = [
      stepRow(
        "1", "Detect",
        verdictChip(detect.status) + " " + witnessChip(detect.witness) +
        ' <span class="coach-mut">&middot; engine ' + esc(detect.engine || "?") +
        ", " + (detect.n_states != null ? detect.n_states + " states" : "") + "</span>"
      ),
      stepRow(
        "2", "Explain",
        '<p class="coach-rationale">' + esc(explain.rationale || "") + "</p>"
      ),
      stepRow(
        "3", "Correct",
        '<p class="coach-delta">' + esc(correct.delta || "") + "</p>" +
        '<p class="coach-guard">buggy&nbsp;&nbsp;&nbsp;: <code class="mono">' + esc(correct.buggy_guard || "") + "</code></p>" +
        '<p class="coach-guard">corrected: <code class="mono">' + esc(correct.guard || "") + "</code></p>"
      ),
      stepRow(
        "4", "Re-check",
        verdictChip(recheck.status) + " " + witnessChip(recheck.witness) +
        ' <span class="coach-mut">&middot; ' + (recheck.n_states != null ? recheck.n_states + " states" : "") + "</span>"
      ),
      stepRow(
        "5", "Close",
        '<p class="coach-discharge ' + (closed ? "coach-closed" : "coach-open") + '">' +
        esc(close.discharge || "") + "</p>"
      )
    ].join("");

    var badge = closed
      ? '<span class="coach-badge coach-badge-closed"><span class="coach-badge-icon" aria-hidden="true">\u2713</span>CLOSED &middot; discharged by proof</span>'
      : '<span class="coach-badge coach-badge-open"><span class="coach-badge-icon" aria-hidden="true">\u26A0</span>OPEN &middot; NOT discharged (fail-closed)</span>';

    return (
      '<h3 class="coach-h">Coaching &mdash; coach + proof</h3>' +
      '<p class="muted coach-sub">' + esc(c.schema || "") +
      " &middot; K=" + (p.max_inflight != null ? p.max_inflight : "?") +
      " &middot; AMOUNT=" + (p.amount != null ? p.amount : "?") +
      " &middot; CAP=" + (p.cap != null ? p.cap : "?") +
      " &middot; W=" + (p.window != null ? p.window : "?") +
      ' &middot; SHA-256 <code class="mono">' + esc((c.hash || "").slice(0, 16)) + "&hellip;</code></p>" +
      '<div class="coach-status">' + badge + "</div>" +
      '<table class="coach-table">' +
      "<thead><tr><th>#</th><th>step</th><th>record</th></tr></thead>" +
      "<tbody>" + rows + "</tbody>" +
      "</table>"
    );
  }

  ROTCoach.mount = function (container, trace) {
    if (!container || !hasCoach(trace)) { return; }
    container.innerHTML = coachPanel(trace);
  };
})();