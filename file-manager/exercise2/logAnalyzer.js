import fs from "fs";
import readline from "readline";
import path from "path";
const logFile = process.argv[2];
if (!logFile) {
  console.log("Usage: ./logAnalyzer.js app.log");
  process.exit(1);
}
const fullPath = path.resolve(logFile);
let total = 0;
let errors = 0;
let warnings = 0;
const rl = readline.createInterface({
  input: fs.createReadStream(fullPath),
  crlfDelay: Infinity
});
rl.on("line", line => {
  total++;
  if (line.includes("ERROR")) errors++;
  if (line.includes("WARN")) warnings++;
});

rl.on("close", () => {
  console.log("Summary Report");
  console.log("----------------");
  console.log("Total lines:", total);
  console.log("Errors:", errors);
  console.log("Warnings:", warnings);
});
