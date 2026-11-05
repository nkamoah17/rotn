// Show writeGatewayInvokeResponse / writeStreamingResponse (output file format).
const fs = require("fs");
const src = fs.readFileSync(
  process.env.APPDATA + "\\npm\\node_modules\\@aws\\agentcore\\dist\\main.js",
  "utf8"
);
function show(label, needle, before = 100, after = 1600) {
  const i = src.indexOf(needle);
  if (i < 0) { console.log("== " + label + ": NOT FOUND =="); return; }
  console.log("== " + label + " @" + i + " ==");
  console.log(src.slice(Math.max(0, i - before), i + after).replace(/\n/g, "\\n"));
}
show("write-invoke", "function writeGatewayInvokeResponse", 0, 1200);
show("write-streaming", "function writeStreamingResponse", 0, 2200);
