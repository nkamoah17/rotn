// Reusable CLI-bundle scanner.
// Usage: node scan_hdr.js <preset> [max]
// Presets: parse | hdrnames | session | defn
const fs = require("fs");
const path = require("path");
const p = path.join(
  process.env.APPDATA, "npm", "node_modules", "@aws", "agentcore", "dist", "main.js"
);
const s = fs.readFileSync(p, "utf8");
const preset = process.argv[2] || "defn";
const max = parseInt(process.argv[3] || "6", 10);
function show(re, label, before, after) {
  before = before == null ? 60 : before; after = after == null ? 600 : after;
  let n = 0, m;
  re.lastIndex = 0;
  while ((m = re.exec(s)) !== null && n < max) {
    const c = s.slice(Math.max(0, m.index - before), m.index + after).replace(/\n/g, " ");
    console.log("==== " + label + " @" + m.index + " ====");
    console.log(c);
    n++;
  }
  if (!n) console.log("==== " + label + ": (none) ====");
}
if (preset === "parse") {
  show(new RegExp("function parseGatewayInvokeHeaders", "g"), "parseGatewayInvokeHeaders", 40, 700);
} else if (preset === "defn") {
  show(new RegExp("function parseGatewayInvokeHeaders", "g"), "function parseGatewayInvokeHeaders");
  show(new RegExp("parseGatewayInvokeHeaders=", "g"), "parseGatewayInvokeHeaders=");
  show(new RegExp("parseHeaderPair|parseHeader\\b", "g"), "parseHeader");
} else if (preset === "hdrnames") {
  show(new RegExp("x-amzn-bedrock-agentcore-[a-z-]+", "gi"), "agentcore-hdr", 120, 80);
} else if (preset === "session") {
  show(new RegExp("policy-session-id|policySessionId", "gi"), "policy-session", 80, 200);
} else {
  console.log("unknown preset: " + preset);
}