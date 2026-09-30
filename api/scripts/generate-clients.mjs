#!/usr/bin/env node
// Generate the typed TypeScript client (clients/typescript/<svc>.d.ts) from
// every authored OpenAPI spec (openapi/<svc>.openapi.yaml).
//
//   npm run generate                  # every spec
//   npm run generate -- audit-service # just the named ones
//
// Derived from the directory rather than listed per service. A per-service
// list is one more place a new service has to be registered — and, for a
// service that ships only in some editions, one more place that would name it
// in a tree that must not (the public-tree export removes such a service's
// spec and its generated client together, and this script then simply has one
// spec fewer to read).
import { spawnSync } from 'node:child_process';
import { readdirSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const apiDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const specDir = path.join(apiDir, 'openapi');
const outDir = path.join(apiDir, 'clients', 'typescript');
const SUFFIX = '.openapi.yaml';

const all = readdirSync(specDir)
  .filter((f) => f.endsWith(SUFFIX))
  .map((f) => f.slice(0, -SUFFIX.length))
  .sort();
if (all.length === 0) {
  console.error(`no *${SUFFIX} specs found in ${specDir}`);
  process.exit(1);
}

const wanted = process.argv.slice(2);
for (const w of wanted) {
  if (!all.includes(w)) {
    console.error(`no spec named ${w}${SUFFIX} in ${specDir} (have: ${all.join(', ')})`);
    process.exit(1);
  }
}

// The binary lives in this package's node_modules/.bin, or — installed as an
// npm workspace — in the repository root's, where npm hoists it.
const exe = process.platform === 'win32' ? 'openapi-typescript.cmd' : 'openapi-typescript';
let bin = null;
for (let dir = apiDir; ; dir = path.dirname(dir)) {
  const candidate = path.join(dir, 'node_modules', '.bin', exe);
  if (existsSync(candidate)) {
    bin = candidate;
    break;
  }
  if (path.dirname(dir) === dir) break;
}
if (!bin) {
  console.error(`openapi-typescript is not installed — run npm install in ${apiDir}`);
  process.exit(1);
}

for (const svc of wanted.length ? wanted : all) {
  const r = spawnSync(bin, [path.join('openapi', `${svc}${SUFFIX}`), '--output', path.join('clients', 'typescript', `${svc}.d.ts`)], {
    cwd: apiDir,
    stdio: 'inherit',
  });
  if (r.status !== 0) {
    console.error(`generating the ${svc} client failed`);
    process.exit(r.status ?? 1);
  }
}
if (!existsSync(outDir)) process.exit(1);
