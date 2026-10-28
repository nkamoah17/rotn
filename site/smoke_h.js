/* Phase H smoke test (Node.js) -- verify compliance.js + compare.js render.
 * Run: node site/smoke_h.js
 */
"use strict";
const fs = require("fs");
const path = require("path");

const SITE = __dirname;

// Minimal browser stub.
global.window = {};
global.location = { protocol: "file:", hash: "" };
global.document = {
  getElementById: function () { return null; },
  readyState: "complete",
  addEventListener: function () {},
  createElement: function () { return { style: {} }; },
  body: { appendChild: function () {}, removeChild: function () {} },
};

function load(rel) {
  const code = fs.readFileSync(path.join(SITE, rel), "utf8");
  (0, eval)(code);
}

// Load the registry (window.ROT_TRACES) then the app modules.
load(path.join("data", "traces.js"));
load("app/compliance.js");
load("app/compare.js");
load("app/coach.js");

const ROT = global.window.ROT;
const reg = global.window.ROT_TRACES;
let failures = 0;
function check(name, cond) {
  if (cond) { console.log("  ok   - " + name); }
  else { console.log("  FAIL - " + name); failures += 1; }
}

// ---- registry ----
check("registry has 10 traces", Object.keys(reg).length === 10);
["spendcap-buggy", "spendcap-correct", "spendcap-buggy-k1", "spendcap-buggy-k2",
 "spendcap-buggy-k3", "spendcap-correct-k1", "spendcap-correct-k2",
 "spendcap-correct-k3", "bad", "good"].forEach(function (id) {
  check("registry has " + id, !!reg[id]);
});

// ---- compliance summary: spendcap buggy ----
const buggy = reg["spendcap-buggy"];
const sBuggy = ROT.ROTCompliance.summary(buggy);
check("buggy: result violated", sBuggy.result === "violated");
check("buggy: controls CC6.1 + AIUC-1",
  sBuggy.controls.indexOf("CC6.1") >= 0 && sBuggy.controls.indexOf("AIUC-1") >= 0);
check("buggy: frameworks SOC2 + AIUC",
  sBuggy.frameworks.indexOf("SOC2") >= 0 && sBuggy.frameworks.indexOf("AIUC") >= 0);
check("buggy: evidence by_control CC6.1=1", sBuggy.byControl["CC6.1"] === 1);
check("buggy: label present for CC6.1", !!sBuggy.labels["CC6.1"]);

// ---- compliance summary: spendcap correct (clean) ----
const sCorrect = ROT.ROTCompliance.summary(reg["spendcap-correct"]);
check("correct: no controls touched", sCorrect.controls.length === 0);
check("correct: result proven", sCorrect.result === "proven");

// ---- compliance summary: manifest (bad) -- derived from findings ----
const bad = reg["bad"];
const sBad = ROT.ROTCompliance.summary(bad);
check("bad(manifest): controls derived from findings", sBad.controls.length > 0);
check("bad(manifest): result violated", sBad.result === "violated");
check("bad(manifest): has evidence counts",
  Object.keys(sBad.byControl).length === sBad.controls.length);

// ---- compliance mount (fake container) ----
function mountHTML(mod, trace) {
  const container = { innerHTML: "" };
  mod.mount(container, trace);
  return container.innerHTML;
}
let html = mountHTML(ROT.ROTCompliance, buggy);
check("compliance mount (buggy): has table", html.indexOf("comp-table") >= 0);
check("compliance mount (buggy): lists CC6.1", html.indexOf("CC6.1") >= 0);
check("compliance mount (buggy): evidence heading", html.indexOf("Evidence") >= 0);
html = mountHTML(ROT.ROTCompliance, reg["spendcap-correct"]);
check("compliance mount (correct): clean state", html.indexOf("comp-clean") >= 0);
html = mountHTML(ROT.ROTCompliance, bad);
check("compliance mount (bad): has table", html.indexOf("comp-table") >= 0);

// ---- compare: K-sweep series ----
const series = ROT.ROTCompare.ksweepSeries();
check("ksweep series has 4 K values", series.length === 4);
check("ksweep K values are 1,2,3,4",
  series.map(function (r) { return r.K; }).join(",") === "1,2,3,4");
const byK = {};
series.forEach(function (r) { byK[r.K] = r; });
check("K=1 buggy proven (masked)", byK[1].buggy === "proven");
check("K=1 correct proven", byK[1].correct === "proven");
check("K=2 buggy violated", byK[2].buggy === "violated");
check("K=2 correct proven", byK[2].correct === "proven");
check("K=3 buggy violated", byK[3].buggy === "violated");
check("K=4 buggy violated", byK[4].buggy === "violated");
check("K=4 correct proven", byK[4].correct === "proven");

// ---- compare mount (needs a querySelector stub) ----
// app.js defines ROT.verdictInfo; stub it here (it is a pure lookup).
ROT.verdictInfo = function (v) {
  var key = String(v == null ? "" : v).toLowerCase();
  var cls = key === "proven" ? "proven" : key === "violated" ? "violated" : "unknown";
  return { label: cls.toUpperCase(), cls: cls, desc: "" };
};
function fakeEl() {
  return {
    innerHTML: "", value: "1", min: "1", max: "4", textContent: "1",
    classList: { add: function () {}, remove: function () {},
                 toggle: function () {}, contains: function () { return false; } },
    addEventListener: function () {},
    querySelector: function () { return null; },
    querySelectorAll: function () { return []; },
  };
}
const cmpContainer = {
  innerHTML: "",
  querySelector: function () { return fakeEl(); },
  querySelectorAll: function () { return []; },
};
ROT.ROTCompare.mount(cmpContainer, {
  leftId: "spendcap-buggy", rightId: "spendcap-correct",
  left: reg["spendcap-buggy"], right: reg["spendcap-correct"],
});
const cmpHTML = cmpContainer.innerHTML;
check("compare mount: two columns", (cmpHTML.match(/compare-col/g) || []).length >= 2);
check("compare mount: buggy VIOLATED badge", cmpHTML.indexOf("b-violated") >= 0);
check("compare mount: correct PROVEN badge", cmpHTML.indexOf("b-proven") >= 0);
check("compare mount: K-sweep table", cmpHTML.indexOf("ks-table") >= 0);
check("compare mount: K=1..4 columns",
  ["K=1", "K=2", "K=3", "K=4"].every(function (k) { return cmpHTML.indexOf(k) >= 0; }));
check("compare mount: play button", cmpHTML.indexOf("ksweep-play") >= 0);
check("compare mount: slider", cmpHTML.indexOf('type="range"') >= 0);
check("compare mount: manifest hash shown", cmpHTML.indexOf("manifest hash") >= 0);

// ---- coaching panel (the third leg of the triad) ----
const coachContainer = { innerHTML: "" };
ROT.ROTCoach.mount(coachContainer, reg["spendcap-buggy"]);
const coachHTML = coachContainer.innerHTML;
check("coach (buggy): renders the panel", coachHTML.indexOf("coach-table") >= 0);
check("coach (buggy): CLOSED badge (discharged by proof)",
  coachHTML.indexOf("coach-badge-closed") >= 0);
check("coach (buggy): 5-step loop present",
  ["Detect", "Explain", "Correct", "Re-check", "Close"].every(
    function (s) { return coachHTML.indexOf(s) >= 0; }));
check("coach (buggy): rationale derived from the witness",
  coachHTML.indexOf("coach-rationale") >= 0);
check("coach (buggy): corrected policy (request-sum) shown",
  coachHTML.indexOf("request") >= 0 && coachHTML.indexOf("coach-guard") >= 0);
check("coach (buggy): re-check proven", coachHTML.indexOf("proven") >= 0);
check("coach (buggy): SHA-256 hash shown", coachHTML.indexOf("SHA-256") >= 0);

// Proven / non-coachable traces must NOT render the panel.
const coachClean = { innerHTML: "" };
ROT.ROTCoach.mount(coachClean, reg["spendcap-correct"]);
check("coach (correct): stays empty", coachClean.innerHTML === "");
const coachMasked = { innerHTML: "" };
ROT.ROTCoach.mount(coachMasked, reg["spendcap-buggy-k1"]);
check("coach (buggy K=1, masked): stays empty", coachMasked.innerHTML === "");

console.log("");
console.log(failures === 0 ? "ALL SMOKE CHECKS PASSED" : failures + " CHECK(S) FAILED");
process.exit(failures === 0 ? 0 : 1);