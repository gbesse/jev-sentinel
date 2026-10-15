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

## Contrôle d’adoption · Adoption check · Comprobación de adopción

[Français : essayer un cas synthétique](examples/adoption-check.md) · [English: try a synthetic case](examples/adoption-check.md) · [Español: pruebe un caso sintético](examples/adoption-check.md).

## Honest file coverage / Couverture explicite / Cobertura explícita

EN: `scanPathReport` and the CLI expose scanned/skipped counts. Oversized eligible files or skipped symlinks make a leak-free result `incomplete` with `clean: null`, not a clean assertion. CLI codes: 0 clean within configured extensions/exclusions, 2 leaks, 3 incomplete. The legacy `scanPath` still returns findings only. Reads are bounded, filenames are checked, and canary values are masked in report paths. Redaction preserves own prototype-like keys safely. Unsupported formats and ignored directories remain outside scope; no canary scan proves absence of all secret types.

FR : `scanPathReport` et le CLI exposent comptages de fichiers lus/omis. Un fichier éligible trop grand ou un lien ignoré rend le résultat sans fuite `incomplete` avec `clean: null`, pas propre. Codes : 0 propre dans extensions/exclusions configurées, 2 fuites, 3 incomplet. `scanPath` conserve sa sortie de constats seuls. Les lectures sont bornées, noms de fichiers vérifiés, canaris masqués dans les chemins du rapport. La rédaction préserve les clés de type prototype sans danger. Formats non pris en charge et répertoires ignorés restent hors périmètre ; aucun scan ne prouve l’absence de tous les secrets.

ES: `scanPathReport` y CLI muestran recuentos leídos/omitidos. Archivos elegibles excesivos o enlaces omitidos hacen `incomplete` con `clean: null` si no hay fugas, no una afirmación limpia. Códigos: 0 limpio dentro de extensiones/exclusiones, 2 fugas, 3 incompleto. `scanPath` mantiene solo hallazgos. Lecturas limitadas, nombres comprobados y canarios ocultos en rutas del informe. Redacción conserva claves similares a prototipos de forma segura. Formatos no admitidos/directorios ignorados quedan fuera; ningún scan demuestra ausencia de todos los secretos.
