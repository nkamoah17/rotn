/* ROTN replay site -- coach panel (E1: the coach is the HERO).
 *
 * The coach is the centerpiece of the arc (beat 4), and the
 * panel is re-sequenced around it:
 *
 *   blocked call  ->  the 5-field refusal  ->  to_proceed  ->  allowed_now
 *
 * The five-step loop (detect -> explain -> correct -> re-check -> close) is
 * the *repair and re-proof that discharges the coaching* -- supporting
 * evidence for the refusal, not the headline.
 *
 * Data source: ``trace.coaching`` (the CoachingArtifact embedded in the caravel.rtf/v1
 * trace). The 5-field refusal is assembled from ``coaching.to_proceed`` (the
 * computed enabling condition) + ``coaching.policy`` + ``coaching.explain`` --
 * the exact shape the runtime emits (``blocked`` / ``rule`` / ``why`` /
 * ``to_proceed`` / ``allowed_now``). Pure rendering: no verification logic is
 * added here.
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

  /* ---------------- E1: the hero (blocked -> refusal -> to_proceed) --------- */

  /* The blocked call card: which action, in which state, under which guard. */
  function blockedCallHTML(c) {
    var tp = c.to_proceed || {};
    var st = tp.state || {};
    var stateTxt = Object.keys(st).sort().map(function (k) {
      return k + " = " + st[k];
    }).join(",  ");
    var action = tp.action || ((c.policy || {}).action || "");
    return (
      '<div class="coach-blocked">' +
      (tp.instruction
        ? '<div class="cb-instruction">' + esc(tp.instruction) + "</div>"
        : "") +
      '<div class="cb-head">' +
      '<span class="cb-action mono">' + esc(action) + "</span>" +
      '<span class="cb-verdict">BLOCKED</span>' +
      "</div>" +
      '<div class="cb-state">state &nbsp;<span class="mono">' +
      (stateTxt ? esc(stateTxt) : "\u2014") + "</span></div>" +
      (tp.guard
        ? '<div class="cb-guard">guard <code class="mono">' + esc(tp.guard) + "</code></div>"
        : "") +
      "</div>"
    );
  }

  function refusalRow(key, content) {
    return '<tr><th class="rf-key">' + esc(key) + "</th><td>" + content + "</td></tr>";
  }

  /* The 5-field refusal -- the exact shape the runtime emits, assembled from
   * the coaching data (the same decision, read from the trace). */
  function refusalHTML(c) {
    var tp = c.to_proceed || {};
    var p = c.policy || {};
    var explain = c.explain || {};
    var rule = p.policy_id || p.action || "policy";
    if (p.action) {
      rule += " \u00B7 action <code class=\"mono\">" + esc(p.action) + "</code>";
    }
    var conds = (tp.conditions || []).join("  &&  ");
    return (
      '<table class="refusal-table">' +
      refusalRow("blocked", '<span class="rf-true">TRUE</span>') +
      refusalRow("rule", rule) +
      refusalRow("why", esc(explain.rationale || "\u2014")) +
      refusalRow("to_proceed", '<code class="mono rf-cond">' + esc(conds || "\u2014") + "</code>") +
      refusalRow("allowed_now", '<span class="rf-false">FALSE</span>') +
      "</table>"
    );
  }

  /* The to_proceed hero -- the computed enabling condition. */
  function tpHeroHTML(c) {
    var tp = c.to_proceed || {};
    var conds = tp.conditions || [];
    return (
      '<div class="tp-hero">' +
      '<div class="tp-kicker">TO PROCEED &mdash; the computed enabling condition</div>' +
      '<div class="tp-conds">' +
      conds.map(function (x) {
        return '<code class="mono tp-cond">' + esc(x) + "</code>";
      }).join("") +
      "</div>" +
      (tp.explanation ? '<p class="tp-explain">' + esc(tp.explanation) + "</p>" : "") +
      '<div class="tp-allowed">allowed_now = <strong>FALSE</strong> &mdash; the call is not ' +
      "allowed as-is. It becomes allowed exactly when the condition above holds: the " +
      "enabling condition is read straight from the guard (the spec) at this state, " +
      "not hand-written.</div>" +
      "</div>"
    );
  }

  /* The 5-step loop: the repair + re-proof that discharges the coaching. */
  function stepsHTML(c) {
    var closed = (c.status === "closed");
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

    return (
      '<table class="coach-table">' +
      "<thead><tr><th>#</th><th>step</th><th>record</th></tr></thead>" +
      "<tbody>" + rows + "</tbody>" +
      "</table>"
    );
  }

  /* The coach idle state (no blocked call) is the replay page's job (E2); the
   * panel itself only renders when the trace carries a coaching artifact. */
  ROTCoach.mount = function (container, trace, id) {
    if (!container || !hasCoach(trace)) { return; }
    var c = trace.coaching;
    var closed = (c.status === "closed");
    var hasTp = !!(c.to_proceed && (c.to_proceed.conditions || []).length);
    var p = c.policy || {};
    var badge = closed
      ? '<span class="coach-badge coach-badge-closed"><span class="coach-badge-icon" aria-hidden="true">\u2713</span>CLOSED &middot; discharged by proof</span>'
      : '<span class="coach-badge coach-badge-open"><span class="coach-badge-icon" aria-hidden="true">\u26A0</span>OPEN &middot; NOT discharged (fail-closed)</span>';

    var html = [];
    html.push('<h3 class="coach-h">The coach &mdash; blocked call, refusal, the way back to allowed</h3>');
    html.push('<p class="muted coach-sub">' + esc(c.schema || "") +
      " &middot; K=" + (p.max_inflight != null ? p.max_inflight : "?") +
      " &middot; AMOUNT=" + (p.amount != null ? p.amount : "?") +
      " &middot; CAP=" + (p.cap != null ? p.cap : "?") +
      " &middot; W=" + (p.window != null ? p.window : "?") +
      ' &middot; SHA-256 <code class="mono">' + esc((c.hash || "").slice(0, 16)) + "&hellip;</code></p>");
    html.push('<div class="coach-status">' + badge + "</div>");
    if (hasTp) {
      html.push(blockedCallHTML(c));
      html.push('<h4 class="coach-refusal-h">The refusal &mdash; the exact five-field shape</h4>');
      html.push(refusalHTML(c));
      html.push(tpHeroHTML(c));
      html.push('<details class="coach-repair"><summary>Repair &amp; re-proof &mdash; how the coaching is discharged (the 5-step loop)</summary>');
      html.push(stepsHTML(c));
      html.push("</details>");
    } else {
      html.push(stepsHTML(c));
    }
    container.innerHTML = html.join("\n");
  };
})();