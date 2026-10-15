import { randomBytes, timingSafeEqual } from "node:crypto";
import { lstat, readdir, readFile, open } from "node:fs/promises";
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
interface CanaryMatch { canary: string; variant: string; offset: number; end: number; }

function canaryMatches(text: string, canaries: Canary[]): CanaryMatch[] {
  const matches: CanaryMatch[] = [];
  for (const canary of canaries) for (const [variant, needle] of Object.entries(canary.variants)) {
    if (!needle) continue;
    let offset = text.indexOf(needle);
    while (offset >= 0) {
      matches.push({ canary: canary.name, variant, offset, end: offset + needle.length });
      offset = text.indexOf(needle, offset + 1);
    }
  }
  return matches;
}

const CANARY_MASK = "[REDACTED_CANARY]";
function maskMatches(text: string, matches: CanaryMatch[]) {
  const spans: { start: number; end: number; maskedStart: number }[] = [];
  const sorted = [...matches].sort((a, b) => a.offset - b.offset);
  for (const match of sorted) {
    const last = spans.at(-1);
    if (last && match.offset <= last.end) last.end = Math.max(last.end, match.end);
    else spans.push({ start: match.offset, end: match.end, maskedStart: 0 });
  }
  let masked = "";
  let cursor = 0;
  let matchIndex = 0;
  const maskedOffsets = new Map<number, number>();
  for (const span of spans) {
    masked += text.slice(cursor, span.start);
    span.maskedStart = masked.length;
    masked += CANARY_MASK;
    while (matchIndex < sorted.length && sorted[matchIndex]!.offset < span.end) {
      maskedOffsets.set(sorted[matchIndex]!.offset, span.maskedStart);
      matchIndex++;
    }
    cursor = span.end;
  }
  return { text: masked + text.slice(cursor), maskedOffsets };
}

function maskCanaries(text: string, canaries: Canary[]): string {
  return maskMatches(text, canaryMatches(text, canaries)).text;
}

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
      const matches = canaryMatches(current, canaries);
      const masked = maskMatches(current, matches);
      for (const match of matches) {
        const maskedOffset = masked.maskedOffsets.get(match.offset)!;
        const excerpt = masked.text.slice(Math.max(0, maskedOffset - 24), maskedOffset + CANARY_MASK.length + 24);
        leaks.push({ canary: maskCanaries(match.canary, canaries), variant: maskCanaries(match.variant, canaries), path: maskCanaries(path, canaries), offset: match.offset, excerpt });
      }
      return;
    }
    if (!current || typeof current !== "object") return;
    if (seen.has(current)) return;
    seen.add(current);
    if (Array.isArray(current)) current.forEach((item, index) => visit(item, `${path}[${index}]`));
    else Object.entries(current).forEach(([key, item], index) => {
      visit(key, `${path}[key:${index}]`);
      visit(item, `${path}.${maskCanaries(key, canaries)}`);
    });
  };
  visit(value, maskCanaries(rootPath, canaries));
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
  const configuredKeys = options.secretKeys ?? DEFAULT_SECRET_KEYS;
  const keyPattern = new RegExp(configuredKeys.source, configuredKeys.flags);
  const patterns = options.tokenPatterns ?? DEFAULT_TOKEN_PATTERNS;
  const seen = new WeakMap<object, unknown>();
  const visit = (current: unknown, key?: string): unknown => {
    keyPattern.lastIndex = 0;
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
    for (const [childKey, child] of Object.entries(current)) Object.defineProperty(output,childKey,{value:visit(child,childKey),enumerable:true,writable:true,configurable:true});
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

export interface ScanReport {
  status: 'clean'|'leaks'|'incomplete';
  clean: boolean|null;
  leaks: Leak[];
  filesScanned: number;
  skipped: {path:string;reason:'oversized'|'symlink'}[];
  ignoredEntries: number;
  unsupportedFiles: number;
  maxFileBytes: number;
}
export async function scanPathReport(target:string,canaries:Canary[],options:ScanOptions={}):Promise<ScanReport>{
  const root=resolve(target),rootStat=await lstat(root);
  assert(!rootStat.isSymbolicLink(),'Refusing to scan a symlink root');
  const maxFileBytes=options.maxFileBytes??2000000;
  assert(Number.isSafeInteger(maxFileBytes)&&maxFileBytes>0&&maxFileBytes<=100000000,'FR : limite de fichier invalide. EN: invalid file limit. ES: límite de archivo no válido.');
  const ignore=new Set(['.git','node_modules','dist',...(options.ignore??[])]),extensions=new Set(options.extensions??['.txt','.log','.json','.jsonl','.md','.html','.xml','.yaml','.yml','.csv']);
  const leaks:Leak[]=[],skipped:ScanReport['skipped']=[];let filesScanned=0,ignoredEntries=0,unsupportedFiles=0;
  const display=(path:string)=>maskCanaries(relative(rootStat.isDirectory()?root:resolve(root,'..'),path)||path,canaries);
  const scan=async(path:string):Promise<void>=>{
    const stat=await lstat(path);
    if(stat.isSymbolicLink()){skipped.push({path:display(path),reason:'symlink'});return;}
    if(stat.isDirectory()){for(const entry of await readdir(path)){if(ignore.has(entry)){ignoredEntries++;continue;}await scan(join(path,entry));}return;}
    if(!stat.isFile()||(rootStat.isDirectory()&&!extensions.has(extname(path).toLowerCase()))){unsupportedFiles++;return;}
    const rawPath=relative(rootStat.isDirectory()?root:resolve(root,'..'),path)||path;
    leaks.push(...detectLeaks(rawPath,canaries,'[file path]'));
    if(stat.size>maxFileBytes){skipped.push({path:display(path),reason:'oversized'});return;}
    const handle=await open(path,'r');let bytesRead=0;const buffer=Buffer.alloc(maxFileBytes+1);
    try{while(bytesRead<buffer.length){const result=await handle.read(buffer,bytesRead,buffer.length-bytesRead,bytesRead);if(!result.bytesRead)break;bytesRead+=result.bytesRead;}}finally{await handle.close();}
    if(bytesRead>maxFileBytes){skipped.push({path:display(path),reason:'oversized'});return;}
    filesScanned++;leaks.push(...detectLeaks(buffer.subarray(0,bytesRead).toString('utf8'),canaries,display(path)));
  };
  await scan(root);const unique=deduplicateLeaks(leaks);
  return {status:unique.length?'leaks':skipped.length?'incomplete':'clean',clean:unique.length?false:skipped.length?null:true,leaks:unique,filesScanned,skipped,ignoredEntries,unsupportedFiles,maxFileBytes};
}
export async function scanPath(target:string,canaries:Canary[],options:ScanOptions={}):Promise<Leak[]>{
 return (await scanPathReport(target,canaries,options)).leaks;
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
