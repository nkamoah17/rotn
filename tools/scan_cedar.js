// Search AgentCore CLI bundle for Cedar policy examples (temporal, entity types).
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
    console.log(src.slice(Math.max(0, i - 300), i + 500).replace(/\n/g, "\\n"));
    n++;
  }
  if (!n) console.log("==== " + label + ": (none) ====");
}
show(/temporal/g, "temporal", 6);
show(/::response|::request/g, "event-kind", 8);
show(/AgentCore::[A-Za-z]+/g, "ent-ns", 8);
show(/formerly within/g, "cedar-ex", 4);
show(/cedar/gi, "cedar", 6);
