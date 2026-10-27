/* ROTN replay site -- Cytoscape state-space graph (Phase F, vendored).
 *
 * Renders trace.graph (nodes = states, edges = actions) with a deterministic
 * preset layout (tools in the left column, fields in the right) and
 * highlights the counterexample when the verdict is VIOLATED:
 *   - counterexample.steps  -> the path of state ids (state-space traces);
 *   - counterexample.tool / over_permission / cross_tenant_fields
 *                             -> the violating tool + field edges (RTF v1
 *                                manifest traces).
 *
 * Degrades to a static list if the vendored Cytoscape is missing.
 */
(function () {
  "use strict";

  var ROT = (window.ROT = window.ROT || {});
  var ROTGraph = (ROT.ROTGraph = ROT.ROTGraph || {});

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  /* Which graph elements do the counterexample / finding witnesses touch? */
  function highlightSets(trace) {
    var out = { nodes: {}, fields: [] };
    /* Collect violation sources: the primary counterexample plus every
       finding witness (a single manifest can violate several rules). */
    var sources = [];
    if (trace.counterexample && typeof trace.counterexample === "object") {
      sources.push(trace.counterexample);
    }
    (trace.findings || []).forEach(function (f) {
      if (f && f.witness && typeof f.witness === "object") { sources.push(f.witness); }
    });
    sources.forEach(function (ce) {
      if (Array.isArray(ce.steps)) {
        ce.steps.forEach(function (s) { out.nodes[String(s)] = true; });
      }
      if (ce.tool) { out.nodes[String(ce.tool)] = true; }
      var fields = [].concat(ce.over_permission || [], ce.cross_tenant_fields || []);
      fields.forEach(function (f) {
        var s = String(f);
        if (out.fields.indexOf(s) === -1) { out.fields.push(s); }
        out.nodes[s] = true;
      });
    });
    return out;
  }

  function isViolatingEdge(edge, hl) {
    return hl.fields.indexOf(String(edge.to)) !== -1;
  }

  function fallbackHTML(trace) {
    var g = trace.graph || {};
    var html = ["<p class=\"muted\">Cytoscape failed to load \u2014 static fallback:</p>", "<ul>"];
    (g.nodes || []).forEach(function (n) {
      html.push("<li><strong>" + esc(n.id) + "</strong> (" + esc(n.kind || "tool") + ")</li>");
    });
    (g.edges || []).forEach(function (e) {
      html.push("<li>" + esc(e.from) + " \u2014" + esc(e.kind || "") + "\u2192 " + esc(e.to) + "</li>");
    });
    html.push("</ul>");
    return html.join("");
  }

  ROTGraph.mount = function (container, trace) {
    if (!container) { return; }
    if (typeof cytoscape === "undefined") {
      container.innerHTML = fallbackHTML(trace);
      return;
    }
    var g = trace.graph || {};
    var nodes = g.nodes || [];
    var edges = g.edges || [];
    var hl = highlightSets(trace);

    /* Field endpoints that are not explicit nodes become field states. */
    var known = {};
    nodes.forEach(function (n) { known[n.id] = true; });
    var fieldIds = [];
    edges.forEach(function (e) {
      if (!known[e.to] && fieldIds.indexOf(e.to) === -1) { fieldIds.push(e.to); }
    });
    fieldIds.sort();

    /* Deterministic preset layout: tools left column, fields right column. */
    var nodeEls = nodes.map(function (n, i) {
      return {
        data: { id: n.id, label: n.id, kind: n.kind || "tool", hl: hl.nodes[n.id] ? 1 : 0 },
        position: { x: 0, y: i * 96 }
      };
    });
    var fieldEls = fieldIds.map(function (f, i) {
      return {
        data: { id: f, label: f, kind: "field", hl: hl.nodes[f] ? 1 : 0 },
        position: { x: 300, y: i * 72 }
      };
    });
    var edgeEls = edges.map(function (e, i) {
      return {
        data: {
          id: "e" + i,
          source: e.from,
          target: e.to,
          kind: e.kind || "",
          hl: isViolatingEdge(e, hl) ? 1 : 0
        }
      };
    });
    /* ---------------- mount (Cytoscape, deterministic preset layout) */

    var wrap = document.createElement("div");
    wrap.className = "graph-wrap";
    var canvas = document.createElement("div");
    canvas.className = "graph-canvas";
    var legend = document.createElement("div");
    legend.className = "graph-legend";
    legend.innerHTML = [
      '<span class="lg"><i class="sw sw-tool"></i>tool (state)</span>',
      '<span class="lg"><i class="sw sw-field"></i>field</span>',
      '<span class="lg"><i class="ln ln-read"></i>read</span>',
      '<span class="lg"><i class="ln ln-write"></i>write</span>',
      '<span class="lg"><i class="ln ln-hl"></i>counterexample</span>'
    ].join("");
    var controls = document.createElement("div");
    controls.className = "graph-controls";
    controls.innerHTML =
      '<button type="button" data-g="in" aria-label="Zoom in">+</button>' +
      '<button type="button" data-g="out" aria-label="Zoom out">\u2212</button>' +
      '<button type="button" data-g="fit" aria-label="Fit graph">fit</button>';
    wrap.appendChild(canvas);
    wrap.appendChild(legend);
    wrap.appendChild(controls);
    container.innerHTML = "";
    container.appendChild(wrap);

    var cy = cytoscape({
      container: canvas,
      elements: nodeEls.concat(fieldEls, edgeEls),
      style: [
        {
          selector: "node",
          style: {
            "label": "data(label)",
            "font-size": 11,
            "text-valign": "bottom",
            "text-margin-y": 8,
            "text-wrap": "wrap",
            "text-max-width": 170,
            "color": "#1f2328"
          }
        },
        {
          selector: "node[kind = 'tool']",
          style: {
            "shape": "round-rectangle", "width": 20, "height": 20,
            "background-color": "#0b5cad", "border-width": 1.5, "border-color": "#0b5cad"
          }
        },
        {
          selector: "node[kind = 'field']",
          style: {
            "shape": "ellipse", "width": 16, "height": 16,
            "background-color": "#6e7781", "border-width": 1.5, "border-color": "#6e7781"
          }
        },
        {
          selector: "edge",
          style: {
            "width": 1.5,
            "line-color": "#8c959f",
            "target-arrow-color": "#8c959f",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            "font-size": 9,
            "color": "#57606a",
            "label": "data(kind)",
            "text-rotation": "autorotate",
            "text-background-color": "#ffffff",
            "text-background-opacity": 0.85
          }
        },
        {
          selector: "edge[kind = 'read']",
          style: { "line-style": "dashed", "line-color": "#57606a", "target-arrow-color": "#57606a" }
        },
        {
          selector: "edge[kind = 'write']",
          style: { "line-style": "solid", "line-color": "#0b5cad", "target-arrow-color": "#0b5cad" }
        },
        {
          selector: "node[hl = 1]",
          style: {
            "background-color": "#cf222e", "border-color": "#a40e26", "border-width": 2.5
          }
        },
        {
          selector: "edge[hl = 1]",
          style: {
            "line-color": "#cf222e", "target-arrow-color": "#cf222e",
            "width": 2.5, "line-style": "solid"
          }
        }
      ],
      layout: { name: "preset" },
      minZoom: 0.3,
      maxZoom: 3
    });
    ROTGraph.cy = cy;
    cy.fit({ padded: true });

    controls.addEventListener("click", function (ev) {
      var btn = ev.target && ev.target.getAttribute
        ? ev.target.getAttribute("data-g") : null;
      if (btn === "in") { cy.zoom({ level: cy.zoom() * 1.25, animated: true }); }
      else if (btn === "out") { cy.zoom({ level: cy.zoom() / 1.25, animated: true }); }
      else if (btn === "fit") { cy.fit({ padded: true, animated: true }); }
    });
  };
})();
