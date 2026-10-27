/* ROTN replay site -- state-space + manifest graph (Phase F/G, vendored Cytoscape).
 *
 * Two graph kinds (both RTF v1, rendered from trace.graph):
 *   - manifest (MCP Manifest v1 audit): nodes = tools/fields, edges = reads/writes;
 *     the counterexample highlights the violating tool + field edges.
 *   - state (spend-cap / .dw policy audit): nodes = concrete states, edges = the
 *     counterexample step path (the attack path). G1 adds an *animated replay* of
 *     that path: the "Replay attack path" button lights the path step by step, so
 *     the in-flight amount visibly grows past the cap at the crossing moment.
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

  function isStateGraph(trace) {
    var g = trace.graph || {};
    if (g.kind === "state") { return true; }
    var nodes = g.nodes || [];
    return nodes.length > 0 && nodes.every(function (n) { return n.kind === "state"; });
  }

  /* Which graph elements do the counterexample / finding witnesses touch? */
  function highlightSets(trace) {
    var out = { nodes: {}, fields: [] };
    var sources = [];
    if (trace.counterexample && typeof trace.counterexample === "object") {
      sources.push(trace.counterexample);
    }
    (trace.findings || []).forEach(function (f) {
      if (f && f.witness && typeof f.witness === "object") { sources.push(f.witness); }
    });
    sources.forEach(function (ce) {
      if (Array.isArray(ce.steps)) {
        ce.steps.forEach(function (s) {
          if (s && s.state) { out.nodes["s" + s.state.completed + "_" + s.state.inflight] = true; }
          if (s && s.step != null) { out.nodes["s" + s.step] = true; }
        });
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
    return hl.fields.indexOf(String(edge.to)) !== -1 || edge.witness === true;
  }

  function fallbackHTML(trace) {
    var g = trace.graph || {};
    var html = ['<p class="muted">Cytoscape failed to load \u2014 static fallback:</p>', "<ul>"];
    (g.nodes || []).forEach(function (n) {
      var extra = (n.kind === "state")
        ? " (inflight=" + n.inflight + ", cumulative=" + n.cumulative + ")"
        : " (" + esc(n.kind || "tool") + ")";
      html.push("<li><strong>" + esc(n.id) + "</strong>" + extra + "</li>");
    });
    (g.edges || []).forEach(function (e) {
      html.push("<li>" + esc(e.from) + " \u2014" + esc(e.action || e.kind || "") + "\u2192 " + esc(e.to) + "</li>");
    });
    html.push("</ul>");
    return html.join("");
  }
  /* ---------------- shared Cytoscape style (state + manifest) ---------------- */

  function baseStyle() {
    return [
      {
        selector: "node",
        style: {
          "label": "data(label)", "font-size": 11, "text-valign": "bottom",
          "text-margin-y": 8, "text-wrap": "wrap", "text-max-width": 170,
          "color": "#1f2328"
        }
      },
      {
        selector: "node[kind = 'tool']",
        style: { "shape": "round-rectangle", "width": 20, "height": 20,
                 "background-color": "#0b5cad", "border-width": 1.5, "border-color": "#0b5cad" }
      },
      {
        selector: "node[kind = 'field']",
        style: { "shape": "ellipse", "width": 16, "height": 16,
                 "background-color": "#6e7781", "border-width": 1.5, "border-color": "#6e7781" }
      },
      {
        selector: "node[kind = 'state']",
        style: { "shape": "ellipse", "width": "data(size)", "height": "data(size)",
                 "background-color": "#0b5cad", "border-width": 1.5, "border-color": "#0b5cad" }
      },
      {
        selector: "edge",
        style: { "width": 1.5, "line-color": "#8c959f", "target-arrow-color": "#8c959f",
                 "target-arrow-shape": "triangle", "curve-style": "bezier",
                 "font-size": 9, "color": "#57606a", "label": "data(label)",
                 "text-rotation": "autorotate", "text-background-color": "#ffffff",
                 "text-background-opacity": 0.85 }
      },
      { selector: "edge[kind = 'read']",
        style: { "line-style": "dashed", "line-color": "#57606a", "target-arrow-color": "#57606a" } },
      { selector: "edge[kind = 'write']",
        style: { "line-style": "solid", "line-color": "#0b5cad", "target-arrow-color": "#0b5cad" } },
      { selector: "node[hl = 1]",
        style: { "background-color": "#cf222e", "border-color": "#a40e26", "border-width": 2.5 } },
      { selector: "edge[hl = 1]",
        style: { "line-color": "#cf222e", "target-arrow-color": "#cf222e", "width": 2.5, "line-style": "solid" } },
      /* G1: the active step of the animated replay (the "hot" node / edge). */
      { selector: "node.active",
        style: { "background-color": "#ff7b00", "border-color": "#c2410c", "border-width": 4, "z-index": 10 } },
      { selector: "edge.active",
        style: { "line-color": "#ff7b00", "target-arrow-color": "#ff7b00", "width": 4, "z-index": 10 } }
    ];
  }

  /* ---------------- G1: the animated attack-path replay ---------------- */

  function startReplay(cy, path) {
    /* ``path`` is the ordered list of node ids (the counterexample step path).
       Light the path step by step: node[0], then edge->node[1], and so on,
       so the in-flight amount visibly grows to the crossing moment. */
    var edgeByTarget = {};
    cy.edges().forEach(function (e) { edgeByTarget[e.target().id()] = e; });
    var i = 0;
    var timer = null;
    function clearActive() {
      cy.nodes().forEach(function (n) { n.removeClass("active"); });
      cy.edges().forEach(function (e) { e.removeClass("active"); });
    }
    function step() {
      clearActive();
      var node = cy.getElementById(path[i]);
      if (node && node.nonempty()) { node.addClass("active"); }
      if (i > 0) {
        var edge = edgeByTarget[path[i]];
        if (edge && edge.nonempty()) { edge.addClass("active"); }
      }
      i += 1;
      if (i >= path.length) {
        if (timer) { clearInterval(timer); timer = null; }
        return;
      }
    }
    step();
    timer = setInterval(step, 900);
    return function stop() { if (timer) { clearInterval(timer); timer = null; } clearActive(); };
  }

  function legendHTML(state) {
    if (state) {
      return [
        '<span class="lg"><i class="sw sw-state"></i>state (in-flight / cumulative)</span>',
        '<span class="lg"><i class="sw sw-state-hl"></i>counterexample</span>',
        '<span class="lg"><i class="sw sw-state-active"></i>replay step</span>'
      ].join("");
    }
    return [
      '<span class="lg"><i class="sw sw-tool"></i>tool (state)</span>',
      '<span class="lg"><i class="sw sw-field"></i>field</span>',
      '<span class="lg"><i class="ln ln-read"></i>read</span>',
      '<span class="lg"><i class="ln ln-write"></i>write</span>',
      '<span class="lg"><i class="ln ln-hl"></i>counterexample</span>'
    ].join("");
  }

  function graphControls(state, hasPath) {
    var controls = document.createElement("div");
    controls.className = "graph-controls";
    var replayBtn = "";
    if (state && hasPath) {
      replayBtn = '<button type="button" data-g="replay" class="btn-replay" ' +
        'aria-label="Replay the attack path">\u25b6 Replay attack path</button>';
    }
    controls.innerHTML =
      '<button type="button" data-g="in" aria-label="Zoom in">+</button>' +
      '<button type="button" data-g="out" aria-label="Zoom out">\u2212</button>' +
      '<button type="button" data-g="fit" aria-label="Fit graph">fit</button>' +
      replayBtn;
    return controls;
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
    var state = isStateGraph(trace);
    var hl = highlightSets(trace);

    /* ---------------- element construction (state vs manifest) ---------------- */

    var nodeEls, fieldEls = [], edgeEls;
    if (state) {
      /* Deterministic grid layout (path order preserved). */
      var cols = Math.max(1, Math.ceil(Math.sqrt(nodes.length)));
      nodeEls = nodes.map(function (n, i) {
        var col = i % cols, row = Math.floor(i / cols);
        var size = 26 + Math.min(34, (n.cumulative || 0) / 20);
        return {
          data: {
            id: n.id,
            label: "in=" + n.inflight + "\n$" + n.cumulative,
            kind: "state",
            size: size,
            hl: hl.nodes[n.id] ? 1 : 0
          },
          position: { x: col * 190, y: row * 150 }
        };
      });
      edgeEls = edges.map(function (e, i) {
        return {
          data: {
            id: "e" + i, source: e.from, target: e.to,
            kind: "", label: e.action || "", hl: isViolatingEdge(e, hl) ? 1 : 0
          }
        };
      });
    } else {
      /* Field endpoints that are not explicit nodes become field states. */
      var known = {};
      nodes.forEach(function (n) { known[n.id] = true; });
      var fieldIds = [];
      edges.forEach(function (e) {
        if (!known[e.to] && fieldIds.indexOf(e.to) === -1) { fieldIds.push(e.to); }
      });
      fieldIds.sort();
      nodeEls = nodes.map(function (n, i) {
        return {
          data: { id: n.id, label: n.id, kind: n.kind || "tool", hl: hl.nodes[n.id] ? 1 : 0 },
          position: { x: 0, y: i * 96 }
        };
      });
      fieldEls = fieldIds.map(function (f, i) {
        return {
          data: { id: f, label: f, kind: "field", hl: hl.nodes[f] ? 1 : 0 },
          position: { x: 300, y: i * 72 }
        };
      });
      edgeEls = edges.map(function (e, i) {
        return {
          data: {
            id: "e" + i, source: e.from, target: e.to,
            kind: e.kind || "", label: e.kind || "", hl: isViolatingEdge(e, hl) ? 1 : 0
          }
        };
      });
    }

    /* The ordered counterexample path (for the G1 replay). */
    var path = [];
    if (trace.counterexample && Array.isArray(trace.counterexample.steps)) {
      trace.counterexample.steps.forEach(function (s) {
        if (s && s.state) { path.push("s" + s.state.completed + "_" + s.state.inflight); }
      });
    } else if (Array.isArray(g.witness_path)) {
      path = g.witness_path.slice();
    }
    var hasPath = path.length > 1;

    /* ---------------- mount (Cytoscape, deterministic preset layout) ---------------- */

    var wrap = document.createElement("div");
    wrap.className = "graph-wrap";
    var canvas = document.createElement("div");
    canvas.className = "graph-canvas";
    var legend = document.createElement("div");
    legend.className = "graph-legend";
    legend.innerHTML = legendHTML(state);
    var controls = graphControls(state, hasPath);
    wrap.appendChild(canvas);
    wrap.appendChild(legend);
    wrap.appendChild(controls);
    container.innerHTML = "";
    container.appendChild(wrap);

    var cy = cytoscape({
      container: canvas,
      elements: nodeEls.concat(fieldEls, edgeEls),
      style: baseStyle(),
      layout: { name: "preset" },
      minZoom: 0.3,
      maxZoom: 3
    });
    ROTGraph.cy = cy;
    cy.fit({ padded: true });

    var stopReplay = null;
    controls.addEventListener("click", function (ev) {
      var btn = ev.target && ev.target.getAttribute
        ? ev.target.getAttribute("data-g") : null;
      if (btn === "in") { cy.zoom({ level: cy.zoom() * 1.25, animated: true }); }
      else if (btn === "out") { cy.zoom({ level: cy.zoom() / 1.25, animated: true }); }
      else if (btn === "fit") { cy.fit({ padded: true, animated: true }); }
      else if (btn === "replay") {
        if (stopReplay) { stopReplay(); stopReplay = null; return; }
        stopReplay = startReplay(cy, path);
      }
    });
  };
})();

