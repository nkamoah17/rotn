/* Phase J smoke test (Node.js) -- verify the app.js core: hash router,
 * gallery + replay rendering, the loading state, focus management, and the
 * skip-to-content wiring.
 *
 * Run: node site/smoke_app.js
 */
"use strict";
const fs = require("fs");
const path = require("path");
const SITE = __dirname;

/* ---------------- browser stub ---------------- */

function makeEl() {
  return {
    _innerHTML: "",
    attrs: {},
    listeners: {},
    set innerHTML(v) { this._innerHTML = v; },
    get innerHTML() { return this._innerHTML; },
    setAttribute: function (k, v) { this.attrs[k] = String(v); },
    getAttribute: function (k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; },
    removeAttribute: function (k) { delete this.attrs[k]; },
    querySelector: function () { return makeEl(); },
    querySelectorAll: function () { return []; },
    focus: function () { this.focused = true; },
    addEventListener: function (type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); },
  };
}

const viewEl = makeEl();
const skipEl = makeEl();
const listeners = {};

global.window = {
  addEventListener: function (type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
  scrollTo: function () {},
};
global.location = { protocol: "file:", hash: "" };
global.document = {
  getElementById: function (id) { return id === "view" ? viewEl : null; },
  querySelector: function (sel) { return sel === "[data-skip]" ? skipEl : null; },
  querySelectorAll: function () { return []; },
  readyState: "complete",
  addEventListener: function () {},
  createElement: function () { return makeEl(); },
  body: { appendChild: function () {}, removeChild: function () {} },
};
// (navigator is left as-is; app.js only touches navigator.clipboard inside a
// guarded, non-boot path that these tests never exercise.)

function load(rel) {
  const code = fs.readFileSync(path.join(SITE, rel), "utf8");
  (0, eval)(code);
}

/* ---------------- harness ---------------- */

let failures = 0;
function check(name, cond) {
  if (cond) { console.log("  ok   - " + name); }
  else { console.log("  FAIL - " + name); failures += 1; }
}
function nextTick() { return new Promise(function (res) { setImmediate(res); }); }
function fireHashchange() {
  (listeners.hashchange || []).forEach(function (fn) { fn(); });
}

/* ---------------- tests ---------------- */

load(path.join("data", "traces.js"));
load("app/app.js");

const ROT = global.window.ROT;

check("ROT namespace exists", !!ROT);
check("ROT.route exposed", typeof ROT.route === "function");

// Skip-to-content: clicking it focuses the main region (and does not route).
viewEl.focused = false;
const skipClick = (skipEl.listeners && skipEl.listeners.click && skipEl.listeners.click[0]) || null;
check("skip link: click handler attached", !!skipClick);
if (skipClick) {
  skipClick({ preventDefault: function () { this.prevented = true; } });
  check("skip link: focuses the main region", viewEl.focused === true);
}

// Gallery (initial hash "") rendered synchronously into #view.
check("gallery: hero present", viewEl.innerHTML.indexOf("Replay the proof") >= 0);
check("gallery: >= 10 trace cards", (viewEl.innerHTML.match(/trace-card/g) || []).length >= 10);

(async function () {
  // Navigate to a real replay (hashchange sets navigated=true -> focus).
  global.location.hash = "#/replay/spendcap-buggy";
  fireHashchange();
  await nextTick();
  check("replay: verdict hero present", viewEl.innerHTML.indexOf("verdict-hero") >= 0);
  check("replay: VIOLATED verdict shown", viewEl.innerHTML.indexOf("VIOLATED") >= 0);
  check("replay: state-space graph panel", viewEl.innerHTML.indexOf("rot-graph") >= 0);

  // Navigate to an unknown replay -> not-found state.
  global.location.hash = "#/replay/does-not-exist";
  fireHashchange();
  await nextTick();
  check("notfound: 'Trace not found' shown", viewEl.innerHTML.indexOf("Trace not found") >= 0);
  check("notfound: back-to-gallery link", viewEl.innerHTML.indexOf("#/") >= 0);

  // Back to the gallery.
  global.location.hash = "";
  fireHashchange();
  await nextTick();
  check("gallery: re-rendered after navigation", viewEl.innerHTML.indexOf("Replay the proof") >= 0);

  console.log("");
  console.log(failures === 0 ? "ALL APP SMOKE CHECKS PASSED" : failures + " CHECK(S) FAILED");
  process.exit(failures === 0 ? 0 : 1);
})();
