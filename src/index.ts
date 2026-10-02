import { randomBytes, timingSafeEqual } from "node:crypto";
import { lstat, readdir, readFile } from "node:fs/promises";
import { extname, join, relative, resolve } from "node:path";

export interface Canary { name: string; value: string; variants: Record<string, string>; }
export interface Leak { canary: string; variant: string; path: string; offset: number; excerpt: string; }
export interface ScanOptions { maxFileBytes?: number; ignore?: string[]; extensions?: string[]; }

const DEFAULT_SECRET_KEYS = /^(authorization|cookie|set-cookie|token|access[_-]?token|refresh[_-]?token|api[_-]?key|password|passwd|secret|private[_-]?key)$/i;
const DEFAULT_TOKEN_PATTERNS = [
  /\bBearer\s+[A-Za-z0-9._~+\/-]{8,}={0,2}\b/gi,
  /\b(?:sk|pk|api|key|token)[-_][A-Za-z0-9_-]{12,}\b/gi,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
];

function assert(condition: unknown, message: string): asserts condition { if (!condition) throw new Error(message); }
function escapeRegExp(value: string): string { return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

export function createCanary(name = "secret", bytes = 24): Canary {
  assert(/^[a-zA-Z0-9_-]{1,64}$/.test(name), "Canary name must be 1-64 safe characters");
  assert(Number.isInteger(bytes) && bytes >= 16 && bytes <= 128, "Canary entropy must be 16-128 bytes");
  const value = `JEV_SENTINEL_${name}_${randomBytes(bytes).toString("base64url")}`;
  return {
    name, value,
    variants: {
      raw: value,
      url: encodeURIComponent(value),
      base64: Buffer.from(value).toString("base64"),
      hex: Buffer.from(value).toString("hex"),
      json: JSON.stringify(value).slice(1, -1),
    },
  };
}

export function detectLeaks(value: unknown, canaries: Canary[], rootPath = "$", seen = new WeakSet<object>()): Leak[] {
  const leaks: Leak[] = [];
  const visit = (current: unknown, path: string) => {
    if (typeof current === "string") {
      for (const canary of canaries) for (const [variant, needle] of Object.entries(canary.variants)) {
        if (!needle) continue;
        let offset = current.indexOf(needle);
        while (offset >= 0) {
          const start = Math.max(0, offset - 24);
          const end = Math.min(current.length, offset + needle.length + 24);
          const excerpt = `${current.slice(start, offset)}[REDACTED_CANARY]${current.slice(offset + needle.length, end)}`;
          leaks.push({ canary: canary.name, variant, path, offset, excerpt });
          offset = current.indexOf(needle, offset + needle.length);
        }
      }
      return;
    }
    if (!current || typeof current !== "object") return;
    if (seen.has(current)) return;
    seen.add(current);
    if (Array.isArray(current)) current.forEach((item, index) => visit(item, `${path}[${index}]`));
    else for (const [key, item] of Object.entries(current)) visit(item, `${path}.${key}`);
  };
  visit(value, rootPath);
  return deduplicateLeaks(leaks);
}

function deduplicateLeaks(leaks: Leak[]): Leak[] {
  const seen = new Set<string>();
  return leaks.filter(leak => {
    const key = `${leak.canary}:${leak.path}:${leak.offset}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function assertNoLeaks(value: unknown, canaries: Canary[], rootPath?: string): void {
  const leaks = detectLeaks(value, canaries, rootPath);
  if (leaks.length) throw new Error(`Jev Sentinel found ${leaks.length} canary leak(s): ${leaks.map(leak => `${leak.canary}@${leak.path}`).join(", ")}`);
}

export interface RedactOptions { secretKeys?: RegExp; extraKeys?: string[]; tokenPatterns?: RegExp[]; replacement?: string; }

export function redact<T>(value: T, options: RedactOptions = {}): T {
  const replacement = options.replacement ?? "[REDACTED]";
  const extra = new Set((options.extraKeys ?? []).map(key => key.toLowerCase()));
  const keyPattern = options.secretKeys ?? DEFAULT_SECRET_KEYS;
  const patterns = options.tokenPatterns ?? DEFAULT_TOKEN_PATTERNS;
  const seen = new WeakMap<object, unknown>();
  const visit = (current: unknown, key?: string): unknown => {
    if (key && (keyPattern.test(key) || extra.has(key.toLowerCase()))) return replacement;
    if (typeof current === "string") return patterns.reduce((text, pattern) => text.replace(new RegExp(pattern.source, pattern.flags), replacement), current);
    if (!current || typeof current !== "object") return current;
    const existing = seen.get(current);
    if (existing) return existing;
    if (Array.isArray(current)) {
      const output: unknown[] = [];
      seen.set(current, output);
      current.forEach(item => output.push(visit(item)));
      return output;
    }
    const output: Record<string, unknown> = {};
    seen.set(current, output);
    for (const [childKey, child] of Object.entries(current)) output[childKey] = visit(child, childKey);
    return output;
  };
  return visit(value) as T;
}

export async function probe<T>(options: { canaries: Canary[]; run: (secrets: Record<string, string>) => Promise<T> | T; collect?: () => Promise<unknown[]> | unknown[] }): Promise<{ result: T; leaks: Leak[] }> {
  const secrets = Object.fromEntries(options.canaries.map(canary => [canary.name, canary.value]));
  const result = await options.run(secrets);
  const artifacts = options.collect ? await options.collect() : [];
  const leaks = detectLeaks({ result, artifacts }, options.canaries);
  return { result, leaks };
}

export async function scanPath(target: string, canaries: Canary[], options: ScanOptions = {}): Promise<Leak[]> {
  const root = resolve(target);
  const rootStat = await lstat(root);
  assert(!rootStat.isSymbolicLink(), "Refusing to scan a symlink root");
  const maxFileBytes = options.maxFileBytes ?? 2_000_000;
  const ignore = new Set([".git", "node_modules", "dist", ...options.ignore ?? []]);
  const extensions = new Set(options.extensions ?? [".txt", ".log", ".json", ".jsonl", ".md", ".html", ".xml", ".yaml", ".yml", ".csv"]);
  const leaks: Leak[] = [];
  const scan = async (path: string) => {
    const stat = await lstat(path);
    if (stat.isSymbolicLink()) return;
    if (stat.isDirectory()) {
      for (const entry of await readdir(path)) if (!ignore.has(entry)) await scan(join(path, entry));
      return;
    }
    if (!stat.isFile() || stat.size > maxFileBytes || (rootStat.isDirectory() && !extensions.has(extname(path).toLowerCase()))) return;
    const content = await readFile(path, "utf8");
    leaks.push(...detectLeaks(content, canaries, relative(rootStat.isDirectory() ? root : resolve(root, ".."), path) || path));
  };
  await scan(root);
  return leaks;
}

export function constantTimeContains(text: string, secret: string): boolean {
  if (!secret || text.length < secret.length) return false;
  const secretBytes = Buffer.from(secret);
  for (let index = 0; index <= text.length - secret.length; index++) {
    const candidate = Buffer.from(text.slice(index, index + secret.length));
    if (candidate.length === secretBytes.length && timingSafeEqual(candidate, secretBytes)) return true;
  }
  return false;
}
