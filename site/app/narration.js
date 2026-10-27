/* ROTN replay site -- narration panel (Phase F).
 *
 * Renders trace.narration (the engine-generated, blog-ready plain-English
 * narrative) as a scrollable, line-highlighted transcript. Phase G adds the
 * step-by-step animated narration on top of the same data.
 */
(function () {
  "use strict";

  var ROT = (window.ROT = window.ROT || {});
  var ROTNarration = (ROT.ROTNarration = ROT.ROTNarration || {});

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function lineClass(line) {
    if (/^\[ERROR\]/.test(line)) { return "nar-error"; }
    if (/^\[WARN\]/.test(line)) { return "nar-warn"; }
    if (/^RESULT:/.test(line)) { return "nar-result"; }
    if (/^=+$/.test(line)) { return "nar-rule"; }
    if (/Cedar-AR findings: none/.test(line)) { return "nar-good"; }
    return "nar-line";
  }

  ROTNarration.mount = function (container, trace) {
    if (!container) { return; }
    var text = trace && trace.narration;
    if (!text) {
      container.innerHTML = '<p class="muted">No narration in this trace.</p>';
      return;
    }
    var lines = String(text).split("\n");
    var html = ['<div class="narration" role="log" aria-label="Engine narration">'];
    lines.forEach(function (ln) {
      html.push('<div class="' + lineClass(ln) + '">' + (esc(ln) || "&nbsp;") + "</div>");
    });
    html.push("</div>");
    container.innerHTML = html.join("");
  };
})();
