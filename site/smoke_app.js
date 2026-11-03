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
/* compare.js BEFORE app.js: app.js boots (route()) at load time, and the
   landing K-sweep section needs ROT.ROTCompare -- mirroring index.html,
   where compare.js (line 52) loads ahead of app.js (line 53). */
load("app/compare.js");
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
check("gallery: story hero present (rule / attack / proof / coach)",
  viewEl.innerHTML.indexOf("story-beats") >= 0 &&
  viewEl.innerHTML.indexOf("sb-k") >= 0 &&
  viewEl.innerHTML.indexOf(">rule<") >= 0 &&
  viewEl.innerHTML.indexOf(">attack<") >= 0 &&
  viewEl.innerHTML.indexOf(">proof<") >= 0 &&
  viewEl.innerHTML.indexOf(">coach<") >= 0);
check("P9: K-sweep table moved up top (above the gallery)",
  viewEl.innerHTML.indexOf("sweep-hero") >= 0 &&
  viewEl.innerHTML.indexOf("ksweep") >= 0 &&
  viewEl.innerHTML.indexOf("sweep-hero") < viewEl.innerHTML.indexOf("class=\"gallery\""));
check("gallery: >= 10 trace cards", (viewEl.innerHTML.match(/trace-card/g) || []).length >= 10);

(async function () {
  // Navigate to a real replay (hashchange sets navigated=true -> focus).
  global.location.hash = "#/replay/spendcap-buggy";
  fireHashchange();
  await nextTick();
  check("replay: verdict hero present", viewEl.innerHTML.indexOf("verdict-hero") >= 0);
  check("replay: VIOLATED verdict shown", viewEl.innerHTML.indexOf("VIOLATED") >= 0);
  check("replay: state-space graph panel", viewEl.innerHTML.indexOf("rot-graph") >= 0);

  // E2: the narrative arc (rule -> attack -> proof -> coach), not a dashboard.
  check("E2: arc lede present", viewEl.innerHTML.indexOf("arc-lede") >= 0);
  ["rule", "attack", "proof", "coach"].forEach(function (b) {
    check("E2: beat section " + b, viewEl.innerHTML.indexOf('id="beat-' + b + '"') >= 0);
  });
  check("E2: K-sweep beat tagged", viewEl.innerHTML.indexOf('beat-tag">the K-sweep') >= 0);
  check("E2: to_proceed beat tagged", viewEl.innerHTML.indexOf('beat-tag">to_proceed') >= 0);
  check("E2: coach panel mount point (the hero)", viewEl.innerHTML.indexOf('id="rot-coach"') >= 0);

  // E4: the hero carries the hash-pinned attestation link.
  const reg = global.window.ROT_TRACES || {};
  const buggyHash = reg["spendcap-buggy"] && reg["spendcap-buggy"].hash;
  check("E4: hero 'Export attestation' CTA", viewEl.innerHTML.indexOf("Export attestation") >= 0);
  check("E4: attestation URL hash-pinned",
    !!buggyHash && viewEl.innerHTML.indexOf("#/attestation/spendcap-buggy?h=" + buggyHash) >= 0);

  // E3 + E4: attestation view from the same trace data, pin verified.
  global.location.hash = "#/attestation/spendcap-buggy?h=" + buggyHash;
  fireHashchange();
  await nextTick();
  check("E3: attestation hero present", viewEl.innerHTML.indexOf("att-hero") >= 0);
  check("E4: hash pin VERIFIED banner", viewEl.innerHTML.indexOf("HASH PIN VERIFIED") >= 0);
  check("E3: scope section", viewEl.innerHTML.indexOf(">Scope<") >= 0);
  check("E3: coverage conditions", viewEl.innerHTML.indexOf("Assumptions (coverage conditions)") >= 0);
  check("E3: out of scope stated", viewEl.innerHTML.indexOf("Out of scope") >= 0);
  check("E3: corrected policy attested by re-proof",
    viewEl.innerHTML.indexOf("Corrected policy (attested by re-proof)") >= 0);
  check("E3: corrected policy PROVEN by the re-proof engine",
    viewEl.innerHTML.indexOf("<strong>PROVEN</strong> by engine(s): <code class=\"mono\">symbolic</code>") >= 0);
  check("E3: bounded caveat", viewEl.innerHTML.indexOf("Bounded caveat") >= 0);
  check("E3: defensible claim (the moat)", viewEl.innerHTML.indexOf("Defensible claim") >= 0);
  check("E3: what we do NOT claim", viewEl.innerHTML.indexOf("What we do NOT claim") >= 0);
  check("E3: re-verify command + expected hash",
    viewEl.innerHTML.indexOf("Re-verify (byte-for-byte)") >= 0 &&
    viewEl.innerHTML.indexOf("expected hash") >= 0);
  check("E3: artifact hierarchy stated once", viewEl.innerHTML.indexOf("Artifact hierarchy") >= 0);
  check("E3: share row with the hash-pinned URL",
    viewEl.innerHTML.indexOf("att-share-input") >= 0 &&
    viewEl.innerHTML.indexOf("?h=" + buggyHash) >= 0);

  // E4: a WRONG pin must be flagged STALE, never silently trusted.
  global.location.hash = "#/attestation/spendcap-buggy?h=deadbeef";
  fireHashchange();
  await nextTick();
  check("E4: wrong pin -> HASH MISMATCH banner", viewEl.innerHTML.indexOf("HASH MISMATCH") >= 0);
  check("E4: mismatch flagged STALE", viewEl.innerHTML.indexOf("STALE") >= 0);

  // E3: ?view=attestation on the page URL (no hash) renders the beachhead attestation.
  global.location.hash = "";
  global.location.search = "?view=attestation";
  fireHashchange();
  await nextTick();
  check("E3: ?view=attestation renders the attestation",
    viewEl.innerHTML.indexOf("att-hero") >= 0 && viewEl.innerHTML.indexOf("Attestation") >= 0);
  global.location.search = "";

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
  check("gallery: re-rendered after navigation",
    viewEl.innerHTML.indexOf("story-beats") >= 0 &&
    viewEl.innerHTML.indexOf("trace-card") >= 0);

  console.log("");
  console.log(failures === 0 ? "ALL APP SMOKE CHECKS PASSED" : failures + " CHECK(S) FAILED");
  process.exit(failures === 0 ? 0 : 1);
})();
