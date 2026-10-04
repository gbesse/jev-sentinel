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

test("findings redact every neighboring canary before trimming context", () => {
  const first = { name: "first", value: "FIRST_CANARY", variants: { raw: "FIRST_CANARY" } };
  const second = { name: "second", value: "SECOND_CANARY", variants: { raw: "SECOND_CANARY" } };
  const long = { name: "long", value: "LONG_CANARY_WITH_A_SENSITIVE_SUFFIX", variants: { raw: "LONG_CANARY_WITH_A_SENSITIVE_SUFFIX" } };
  const leaks = detectLeaks(`${long.value} ${first.value} ${second.value}`, [first, second, long]);
  assert.equal(leaks.length, 3);
  const report = JSON.stringify(leaks);
  for (const canary of [first, second, long]) assert.ok(!report.includes(canary.value));
  assert.ok(!report.includes("SENSITIVE_SUFFIX"));
});

test("canaries in object keys are detected without exposing them in paths", () => {
  const canary = createCanary("key");
  const leaks = detectLeaks({ [canary.value]: "clean", child: canary.value }, [canary], canary.value);
  assert.equal(leaks.length, 2);
  assert.ok(!JSON.stringify(leaks).includes(canary.value));
  assert.throws(() => assertNoLeaks({ [canary.value]: "clean" }, [canary]), /canary leak/);
});

test("overlapping canaries are fully masked in findings", () => {
  const a = { name: "a", value: "abcde", variants: { raw: "abcde" } };
  const b = { name: "b", value: "defgh", variants: { raw: "defgh" } };
  const leaks = detectLeaks("abcdefgh", [a, b]);
  assert.equal(leaks.length, 2);
  assert.ok(leaks.every(leak => leak.excerpt === "[REDACTED_CANARY]"));
});

test("global secret-key expressions redact every matching field", () => {
  const secretKeys = /token/g;
  const output = redact({ token: "first", tokenAgain: "second" }, { secretKeys });
  assert.equal(output.token, "[REDACTED]");
  assert.equal(output.tokenAgain, "[REDACTED]");
  assert.equal(secretKeys.lastIndex, 0);
});
