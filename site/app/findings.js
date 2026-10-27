/* ROTN replay site -- findings & controls panel (Phase F).
 *
 * Renders trace.findings: Cedar-AR findings with their severity, message,
 * SOC 2 / AIUC control chips (H1 deepens this into the full compliance
 * panel), evidence, and the collapsed witness (counterexample) JSON.
 */
(function () {
  "use strict";

  var ROT = (window.ROT = window.ROT || {});
  var ROTFindings = (ROT.ROTFindings = ROT.ROTFindings || {});

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  ROTFindings.mount = function (container, trace) {
    if (!container) { return; }
    var findings = (trace && trace.findings) || [];
    if (!findings.length) {
      container.innerHTML =
        '<div class="finding-clean">' +
          '<span class="fc-icon" aria-hidden="true">\u2713</span>' +
          "<div><strong>No findings.</strong>" +
          '<p class="muted">The structural checks passed &mdash; the policy is ' +
          "clean within the verified bounds.</p></div>" +
        "</div>";
      return;
    }
    var html = [];
    findings.forEach(function (f) {
      var sev = String(f.severity || "info");
      html.push('<article class="finding sev-' + esc(sev) + '">');
      html.push(
        '<header class="f-head">' +
          '<span class="f-sev">' + esc(sev.toUpperCase()) + "</span>" +
          "<h3>" + esc(f.finding || f.property || "Finding") + "</h3>" +
          (f.property ? '<span class="f-property">' + esc(f.property) + "</span>" : "") +
        "</header>"
      );
      if (f.message) {
        html.push('<p class="f-msg">' + esc(f.message) + "</p>");
      }
      var controls = f.controls || [];
      if (controls.length) {
        html.push(
          '<div class="f-controls"><span class="f-controls-label">Controls</span>' +
          controls.map(function (c) {
            return '<span class="chip chip-control">' + esc(c) + "</span>";
          }).join("") +
          "</div>"
        );
      }
      if (f.evidence && f.evidence.check) {
        html.push('<p class="f-evidence">check: <code>' + esc(f.evidence.check) + "</code></p>");
      }
      if (f.witness) {
        html.push(
          '<details class="f-witness"><summary>witness (counterexample)</summary>' +
          "<pre>" + esc(JSON.stringify(f.witness, null, 2)) + "</pre></details>"
        );
      }
      html.push("</article>");
    });
    container.innerHTML = html.join("\n");
  };
})();
