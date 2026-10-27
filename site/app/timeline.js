/* ROTN replay site -- audit timeline panel (Phase F).
 *
 * Renders trace.timeline (the ordered audit steps with their status) as a
 * vertical, colour-coded step list. Phase G replaces this with the animated
 * spend-cap SVG; the data contract (trace.timeline) stays the same.
 */
(function () {
  "use strict";

  var ROT = (window.ROT = window.ROT || {});
  var ROTTimeline = (ROT.ROTTimeline = ROT.ROTTimeline || {});

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function statusClass(status) {
    switch (String(status || "")) {
      case "pass":
      case "ok":
      case "proven":
        return "pass";
      case "fail":
      case "violated":
        return "fail";
      case "unknown":
        return "unknown";
      default:
        return "neutral";
    }
  }

  function iconFor(status, cls) {
    if (cls === "pass") { return "\u2713"; }
    if (cls === "fail") { return "\u2717"; }
    return "\u2022";
  }

  ROTTimeline.mount = function (container, trace) {
    if (!container) { return; }
    var steps = (trace && trace.timeline) || [];
    if (!steps.length) {
      container.innerHTML = '<p class="muted">No timeline recorded in this trace.</p>';
      return;
    }
    var html = ['<ol class="timeline" aria-label="Audit timeline">'];
    steps.forEach(function (s) {
      var status = String(s.status || "");
      var cls = statusClass(status);
      var extra = (s.findings != null)
        ? ' <span class="tl-findings">' + s.findings + " finding" + (s.findings === 1 ? "" : "s") + "</span>"
        : "";
      html.push(
        '<li class="tl-step ' + cls + '">' +
          '<span class="tl-icon" aria-hidden="true">' + iconFor(status, cls) + "</span>" +
          '<span class="tl-name">' + esc(s.step) + "</span>" +
          '<span class="tl-status">' + esc(status) + extra + "</span>" +
        "</li>"
      );
    });
    html.push("</ol>");
    container.innerHTML = html.join("");
  };
})();
