#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { createCanary, scanPath, type Canary } from "./index.js";

const [command, target, ...args] = process.argv.slice(2);
if (command === "generate") {
  const canary = createCanary(target ?? "secret");
  console.log(JSON.stringify(canary, null, 2));
} else if (command === "scan" && target) {
  const canaryFileIndex = args.indexOf("--canaries");
  if (canaryFileIndex < 0 || !args[canaryFileIndex + 1]) {
    console.error("Usage: jev-sentinel scan <path> --canaries <canaries.json>");
    process.exit(1);
  }
  try {
    const payload = JSON.parse(await readFile(args[canaryFileIndex + 1]!, "utf8")) as Canary | Canary[];
    const leaks = await scanPath(target, Array.isArray(payload) ? payload : [payload]);
    console.log(JSON.stringify({ clean: leaks.length === 0, leaks }, null, 2));
    if (leaks.length) process.exitCode = 2;
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 2;
  }
} else {
  console.error("Usage: jev-sentinel generate [name] | scan <path> --canaries <canaries.json>");
  process.exit(1);
}
