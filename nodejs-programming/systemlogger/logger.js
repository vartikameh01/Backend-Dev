//log
import os from "os";
import fs from "fs";

function getSystemInfo() {
  return `
Time: ${new Date().toLocaleString()}
Platform: ${os.platform()}
CPU Model: ${os.cpus()[0].model}
CPU Cores: ${os.cpus().length}
Total Memory: ${(os.totalmem() / 1024 / 1024).toFixed(2)} MB
Free Memory: ${(os.freemem() / 1024 / 1024).toFixed(2)} MB
----------------------------
`;
}

function logInfo() {
  fs.appendFile("system-log.txt", getSystemInfo(), (err) => {
    if (err) console.log(err);
    else console.log("Logged...");
  });
}
const intervalId = setInterval(logInfo, 5000);

setTimeout(() => {
  clearInterval(intervalId);
  console.log("Logging stopped ");
}, 30000);
