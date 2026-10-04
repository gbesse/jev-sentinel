# Jev Sentinel

Canary-based secret leak detection and safe redaction for AI applications. It tests the actual outputs of loggers, traces, error handlers and exported artifacts instead of assuming that a redaction configuration works.

## Dynamic probe

```ts
import { createCanary, probe } from "@gbesse/jev-sentinel";

const apiKey = createCanary("typesafe_api_key");
const report = await probe({
  canaries: [apiKey],
  run: async secrets => exerciseApplication({ TYPESAFE_API_KEY: secrets.typesafe_api_key }),
  collect: async () => [await readTestLogs(), await readTestTraces()],
});

if (report.leaks.length) throw new Error("Secret reached an observable sink");
```

Sentinel detects raw, URL-encoded, Base64, hexadecimal and JSON-escaped canaries. Findings contain a redacted excerpt, never the canary itself.

Object keys are scanned as well as values. Paths and context mask every known canary before excerpts are shortened, so neighboring or overlapping matches cannot expose another canary through a finding.

## Artifact scanner

```sh
jev-sentinel generate typesafe > .local/canary.json
jev-sentinel scan ./test-output --canaries .local/canary.json
```

The scanner does not follow symlinks, ignores `.git`, `node_modules` and `dist`, caps file size and restricts default extensions. Exit status `2` means a leak or scan failure.

## Redaction

`redact(value)` clones objects and masks common credential fields, bearer tokens, API-key-shaped strings and private keys. Add exact field names with `extraKeys`. Redaction is defense in depth; a passing canary probe is stronger evidence for the path actually exercised.

## Limits

Sentinel cannot detect transformed secrets it has not been taught to encode, uncollected remote telemetry, screenshots or data retained inside a provider. Use synthetic canaries only—never store a production credential in a fixture or canary file.

```sh
npm install
npm run release:check
```

MIT licensed and provider-independent.
