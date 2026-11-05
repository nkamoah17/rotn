// Show how the gateway invoke request is built (endpoint, path, signing, body).
const fs = require("fs");
const src = fs.readFileSync(
  process.env.APPDATA + "\\npm\\node_modules\\@aws\\agentcore\\dist\\main.js",
  "utf8"
);
function show(re, label, max = 8) {
  let n = 0, m;
  re.lastIndex = 0;
  while ((m = re.exec(src)) !== null && n < max) {
    const i = m.index;
    console.log("==== " + label + " @" + i + " ====");
    console.log(src.slice(Math.max(0, i - 300), i + 700).replace(/\n/g, "\\n"));
    n++;
  }
  if (!n) console.log("==== " + label + ": (none) ====");
}
show(/gateway\.bedrock-agentcore|bedrock-agentcore[^"]{0,40}gateway/gi, "gw-host", 6);
show(/parseGatewayInvokeHeaders/g, "parse-use", 4);
show(/InvokeGateway|invokeGateway/g, "op", 8);
