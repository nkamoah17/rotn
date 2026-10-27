/* ROTN replay site -- compliance panel (Phase H, H1).
 *
 * Renders the SOC 2 / AIUC controls a trace touched, with the evidence that
 * links each control to the findings that triggered it. The data contract is
 * the RTF v1 ``compliance`` block (see ``rot/trace.py`` + ``rot/compliance.py``):
 *
 *     compliance: {
 *       result:         "proven" | "violated" | ...
 *       frameworks:     ["SOC2", "AIUC"]
 *       profile:        "caravel.compliance/v1"
 *       controls:       { "<id>": "<human label>", ... }
 *       controls_touched: ["CC6.1", "AIUC-1", ...]
 *       evidence: { by_control: { "<id>": <#findings> }, findings_total: N }
 *     }
 *
 * Manifest audits (``--manifest``) carry no top-level ``compliance`` block;
 * their findings each list their ``controls``. This module normalises both
 * shapes into one summary (``ROTCompliance.summary``) and renders the panel,
 * so the same view works for spend-cap and manifest traces. It adds no
 * verification logic -- it only re-presents what the trace already records.
 *
 * No framework, no build step -- consistent with the rest of the site.
 */
(function () {
  "use strict";

  var ROT = (window.ROT = window.ROT || {});
  var ROTCompliance = (ROT.ROTCompliance = ROT.ROTCompliance || {});

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  /* Fallback control labels (mirror rot.compliance.CONTROL_LABELS) for traces
   * that carry control ids but no label map (manifest audits). */
  var LABELS = {
    "CC6.1": "SOC 2 CC6.1 — Logical access security",
    "CC6.3": "SOC 2 CC6.3 — Network security (tenant isolation)",
    "CC6.6": "SOC 2 CC6.6 — Change management / provisioning",
    "AIUC-1": "Caravel AIUC-1 — Autonomy (agent must not act beyond policy)"
  };

  /* Which framework a control id belongs to (derived from the id prefix). */
  function frameworkFor(id) {
    if (/^CC/i.test(id)) { return "SOC 2"; }
    if (/^AIUC/i.test(id)) { return "AIUC"; }
    return "—";
  }

  /* Normalise a trace's compliance info into one stable shape.
   *
   * Returns {
   *   result:    "proven" | "violated" | "unknown",
   *   frameworks: [str],
   *   profile:   str | null,
   *   controls:  [id]            (ordered, de-duplicated, touched first),
   *   byControl: { id: count },  (evidence: # findings touching each control),
   *   labels:    { id: label },
   *   findings:  [finding]       (the findings that carry controls)
   * }
   */
  ROTCompliance.summary = function (trace) {
    trace = trace || {};
    var comp = trace.compliance || {};
    var findings = trace.findings || [];
    var touched = (comp.controls_touched || []).slice();
    var byControl = (comp.evidence && comp.evidence.by_control) || {};
    var labels = comp.controls || {};
    var frameworks = (comp.frameworks || []).slice();
    var result = comp.result || null;
    var profile = comp.profile || null;

    /* Derive the touched controls from the findings when the trace has no
     * top-level compliance block (manifest audits). */
    if (!touched.length) {
      var seen = {};
      findings.forEach(function (f) {
        (f.controls || []).forEach(function (c) { seen[c] = true; });
      });
      touched = Object.keys(seen).sort();
    }

    /* Derive per-control evidence (how many findings touch each control). */
    if (!Object.keys(byControl).length) {
      touched.forEach(function (c) {
        var n = findings.filter(function (f) {
          return (f.controls || []).indexOf(c) >= 0;
        }).length;
        byControl[c] = n;
      });
    }

    /* Fill in any missing labels from the fallback catalog. */
    touched.forEach(function (c) {
      if (!labels[c] && LABELS[c]) { labels[c] = LABELS[c]; }
    });

    /* Derive the result from the verdict when not stated explicitly. */
    if (!result) {
      result = trace.verdict === "proven" ? "proven"
        : trace.verdict === "violated" ? "violated"
        : "unknown";
    }

    /* Derive frameworks from the controls when not stated explicitly. */
    if (!frameworks.length && touched.length) {
      var fw = {};
      touched.forEach(function (c) {
        fw[frameworkFor(c)] = true;
      });
      frameworks = Object.keys(fw);
    }

    return {
      result: result,
      frameworks: frameworks,
      profile: profile,
      controls: touched,
      byControl: byControl,
      labels: labels,
      findings: findings
    };
  };

  /* ---------------- panel rendering ---------------- */

  function controlTable(s) {
    var rows = s.controls.map(function (id) {
      var label = s.labels[id] || LABELS[id] || "";
      var n = s.byControl[id] != null ? s.byControl[id] : 0;
      return (
        "<tr>" +
        '<td class="comp-id mono">' + esc(id) + "</td>" +
        "<td>" + esc(frameworkFor(id)) + "</td>" +
        '<td class="comp-def">' + esc(label) + "</td>" +
        '<td class="comp-ev">' + n + " finding" + (n === 1 ? "" : "s") + "</td>" +
        "</tr>"
      );
    }).join("");
    return (
      '<table class="comp-table">' +
      "<thead><tr><th>Control</th><th>Framework</th><th>Definition</th><th>Evidence</th></tr></thead>" +
      "<tbody>" + rows + "</tbody>" +
      "</table>"
    );
  }

  function evidenceList(s) {
    var rows = s.findings.filter(function (f) { return (f.controls || []).length; });
    if (!rows.length) { return ""; }
    var items = rows.map(function (f) {
      var sev = String(f.severity || "info");
      var chips = (f.controls || []).map(function (c) {
        return '<span class="chip chip-control">' + esc(c) + "</span>";
      }).join(" ");
      return (
        "<li>" +
        '<span class="f-sev">' + esc(sev.toUpperCase()) + "</span> " +
        "<strong>" + esc(f.finding || f.property || "Finding") + "</strong>" +
        (f.message ? ' — ' + esc(f.message) : "") +
        ' <span class="comp-f-chips">' + chips + "</span>" +
        "</li>"
      );
    }).join("");
    return (
      '<div class="comp-findings">' +
      '<h4 class="comp-findings-h">Evidence — the findings that touched these controls</h4>' +
      "<ul>" + items + "</ul>" +
      "</div>"
    );
  }

  ROTCompliance.mount = function (container, trace) {
    if (!container) { return; }
    var s = ROTCompliance.summary(trace);

    if (!s.controls.length) {
      /* No controls touched: a clean compliance state. */
      var clean = (s.result === "proven");
      container.innerHTML =
        '<div class="comp-clean' + (clean ? " comp-clean-proven" : "") + '">' +
        '<span class="fc-icon" aria-hidden="true">' + (clean ? "\u2713" : "\u2139") + "</span>" +
        "<div>" +
        '<p class="comp-clean-title">' + esc(clean ? "No controls flagged" : "No control mapping") + "</p>" +
        '<p class="comp-clean-msg">' + esc(clean
          ? "The audit is clean — no SOC 2 / AIUC controls were touched within the verified bounds."
          : "This trace records no SOC 2 / AIUC control mapping.") + "</p>" +
        "</div>" +
        "</div>";
      return;
    }

    var badge = (s.result === "violated") ? "b-violated"
      : (s.result === "proven") ? "b-proven" : "b-unknown";
    var head = (
      '<div class="comp-head">' +
      '<span class="badge ' + badge + '">' + esc(String(s.result).toUpperCase()) + "</span>" +
      s.frameworks.map(function (fw) {
        return '<span class="chip" title="framework">' + esc(fw) + "</span>";
      }).join("") +
      (s.profile ? '<span class="comp-profile mono" title="compliance profile">' +
        esc(s.profile) + "</span>" : "") +
      "</div>"
    );

    container.innerHTML =
      head + controlTable(s) + evidenceList(s);
  };
})();