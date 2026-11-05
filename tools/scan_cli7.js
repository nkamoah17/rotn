// Show the tail of GatewayClient.invokeGateway (signing + fetch).
const fs = require("fs");
const src = fs.readFileSync(
  process.env.APPDATA + "\\npm\\node_modules\\@aws\\agentcore\\dist\\main.js",
  "utf8"
);
const i = src.indexOf("let fetchHeaders=head");
if (i < 0) { console.log("not found"); process.exit(1); }
console.log(src.slice(i, i + 2600).replace(/\n/g, "\\n"));
