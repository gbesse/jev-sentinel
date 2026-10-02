import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assertNoLeaks, constantTimeContains, createCanary, detectLeaks, probe, redact, scanPath } from "../src/index.js";

test("detects raw and encoded canary variants without revealing them", () => {
  const canary = createCanary("api");
  const leaks = detectLeaks({ log: `failed ${canary.value}`, encoded: canary.variants.base64 }, [canary]);
  assert.equal(leaks.length, 2);
  assert.ok(leaks.every(leak => !leak.excerpt.includes(canary.value)));
  assert.throws(() => assertNoLeaks({ key: canary.value }, [canary]), /canary leak/);
});

test("redacts secret fields and inline credentials recursively", () => {
  const input = { authorization: "Bearer abcdefghijklmnop", nested: [{ api_key: "secret" }], note: "token-abcdefghijklmnop" };
  const output = redact(input);
  assert.equal(output.authorization, "[REDACTED]");
  assert.equal(output.nested[0]?.api_key, "[REDACTED]");
  assert.equal(output.note, "[REDACTED]");
  assert.equal(input.nested[0]?.api_key, "secret");
});

test("probes returned values and collected sinks", async () => {
  const canary = createCanary("session");
  const report = await probe({ canaries: [canary], run: ({ session }) => ({ ok: true, debug: session }), collect: () => [] });
  assert.equal(report.leaks.length, 1);
});

test("scans artifacts while ignoring dependencies and symlinks", async () => {
  const directory = await mkdtemp(join(tmpdir(), "sentinel-"));
  const canary = createCanary("db");
  await writeFile(join(directory, "app.log"), `error ${canary.value}`);
  await mkdir(join(directory, "node_modules"));
  await writeFile(join(directory, "node_modules", "ignored.log"), canary.value);
  const leaks = await scanPath(directory, [canary]);
  assert.equal(leaks.length, 1);
  assert.equal(leaks[0]?.path, "app.log");
});

test("constant-time helper handles exact secret matching", () => {
  assert.equal(constantTimeContains("prefix-sensitive-value-suffix", "sensitive-value"), true);
  assert.equal(constantTimeContains("clean", "sensitive-value"), false);
});
