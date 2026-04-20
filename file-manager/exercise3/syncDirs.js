#!/usr/bin/env node

import fs from "fs/promises";
import path from "path";

async function syncDirs(src, dest) {
  await fs.mkdir(dest, { recursive: true });

  const files = await fs.readdir(src, { withFileTypes: true });

  for (const file of files) {
    const srcPath = path.join(src, file.name);
    const destPath = path.join(dest, file.name);

    if (file.isDirectory()) {
      await syncDirs(srcPath, destPath);
    } else {
      try {
        const [srcStat, destStat] = await Promise.all([
          fs.stat(srcPath),
          fs.stat(destPath).catch(() => null)
        ]);

        if (!destStat || srcStat.mtimeMs > destStat.mtimeMs) {
          await fs.copyFile(srcPath, destPath);
          console.log("Synced:", srcPath);
        }
      } catch (err) {
        console.error("Failed:", srcPath, err.message);
      }
    }
  }
}

const [sourceDir, targetDir] = process.argv.slice(-2);

if (!sourceDir || !targetDir) {
  console.log("Usage: ./syncDirs.js <source-directory> <target-directory>");
  process.exit(1);
}

syncDirs(path.resolve(sourceDir), path.resolve(targetDir))
  .then(() => console.log("Sync complete."))
  .catch(err => console.error(err));
