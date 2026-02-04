import fs from "fs";
import { fileURLToPath } from "url";
import { dirname } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log("Start");

fs.readFile(__filename, () => {
  setTimeout(() => {
    console.log("setTimeout");
  }, 0);

  setImmediate(() => {
    console.log("setImmediate");
  });

  process.nextTick(() => {
    console.log("process.nextTick");
  });

  Promise.resolve().then(() => {
    console.log("Promise.then");
  });
});

console.log("End");
