import assert from "node:assert/strict";
import { createCanary, detectLeaks } from "../src/index.ts";

const canary = createCanary("synthetic_key");
const findings = detectLeaks({ [canary.value]: "safe" }, [canary]);
assert.equal(findings.length, 1);
assert.equal(JSON.stringify(findings).includes(canary.value), false);
console.log(JSON.stringify({ caseId: "object_key", leakDetected: true, rawCanaryExposed: false }, null, 2));
