#!/usr/bin/env node
/**
 * Helm release-record size guard.
 *
 * Helm stores every release as ONE Secret, sh.helm.release.v1.<name>.v<n>,
 * whose single data value is base64(gzip(JSON(release))). The JSON carries
 * every chart file (templates/ and files/, each base64-encoded) AND the
 * rendered manifest, so anything a template reads from files/ into a
 * ConfigMap is in the record twice. Kubernetes refuses a Secret whose data
 * exceeds 1 MiB (1,048,576 bytes), and Helm reports that as
 *
 *   Secret "sh.helm.release.v1.vista.v1" is invalid: data: Too long: may not be more than 1048576 bytes
 *
 * before creating a single object. The commercial 5.1.0 chart shipped at
 * ~1.0 MB on this measure and could not be installed; Core 5.1.0 sat ~8%
 * under the ceiling. Nothing measured the record until then: the ConfigMap
 * guard checked each object, not the record that holds all of them.
 *
 * This guard simulates the record for a packaged chart and fails above
 * RELEASE_RECORD_LIMIT_BYTES (default 900 KB, leaving ~145 KB of headroom
 * for a release's growth) — and it first proves it CAN fail, by measuring a
 * mutated copy of the chart that carries the SQL the way 5.1.0 did.
 *
 * The simulation mirrors helm.sh/helm/v3/pkg/release.Release as json.Marshal
 * writes it: chart.templates[] and chart.files[] with base64 data, the parsed
 * values, the values schema, the rendered manifest (helm template, hooks
 * included) and a little metadata. The values map is approximated by the
 * comment-stripped values.yaml; the error is a few KB on a ~1 MB measure.
 *
 *   node scripts/test-chart-release-record-size.mjs             # the repo chart, staged as a release packages it
 *   node scripts/test-chart-release-record-size.mjs --tgz X.tgz # a packaged chart (the release workflows)
 *   node scripts/test-chart-release-record-size.mjs --chart DIR # an unpacked chart directory
 *
 * No npm dependencies: the release workflows run it on bare runners.
 */
import { execFileSync, spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import zlib from 'zlib';
import { fileURLToPath } from 'url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SECRET_DATA_LIMIT = 1048576; // Kubernetes' limit on a Secret's data
const LIMIT = Number(process.env.RELEASE_RECORD_LIMIT_BYTES || 900 * 1024);

const args = process.argv.slice(2);
const opt = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

let failures = 0;
function check(desc, ok, detail = '') {
  console.log(`  ${ok ? '✓' : '✗'} ${desc}${ok || !detail ? '' : `\n      ${detail}`}`);
  if (!ok) failures++;
}

function walk(dir, rel = '') {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    const r = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory()) out.push(...walk(p, r));
    else out.push(r);
  }
  return out;
}

function helmTemplate(chart) {
  const setArgs = [
    '--set', 'tls.dnsName=vista.example.com',
    '--set', 'platform.jwtSecret=x',
    '--set', 'platform.internalAuthSecret=x',
    '--set', 'platform.encryptionMasterKey=x',
    '--set', 'agentMtls.backends.sensor-manager.dnsName=sensors.example.com',
    '--set', 'agentMtls.backends.device-interrogation-service.dnsName=agents.example.com',
  ];
  // A commercial chart carries the Enterprise verification key; render the
  // larger shape a licensed install produces.
  if (fs.existsSync(path.join(chart, 'files', 'ee', 'edition-public-key.pem'))) {
    setArgs.push('--set', 'enterprise.contentBundle.enabled=true');
  }
  const r = spawnSync('helm', ['template', 'vista', chart, '--kube-version', '1.35.0', ...setArgs], {
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
  });
  if (r.status !== 0) throw new Error(`helm template failed for ${chart}:\n${r.stderr}`);
  return r.stdout;
}

/** Simulate Helm's release record for an unpacked chart directory. Returns byte sizes. */
export function simulateRecord(chart) {
  const files = walk(chart);
  const templates = [];
  const other = [];
  let values = '';
  let schema = '';
  let metadata = '';
  for (const f of files) {
    const data = fs.readFileSync(path.join(chart, f));
    if (f.startsWith('templates/')) templates.push({ name: f, data: data.toString('base64') });
    else if (f === 'Chart.yaml') metadata = data.toString('utf8');
    else if (f === 'values.yaml') values = data.toString('utf8').split('\n').filter((l) => !/^\s*(#|$)/.test(l)).join('\n');
    else if (f === 'values.schema.json') schema = data.toString('base64');
    else other.push({ name: f, data: data.toString('base64') });
  }
  const manifest = helmTemplate(chart);
  const release = {
    name: 'vista',
    info: { first_deployed: '2026-01-01T00:00:00Z', last_deployed: '2026-01-01T00:00:00Z', deleted: '', description: 'Install complete', status: 'deployed' },
    chart: { metadata, lock: null, templates, values, schema, files: other },
    config: { tls: { dnsName: 'vista.example.com' } },
    manifest,
    hooks: [],
    version: 1,
    namespace: 'vista',
  };
  const json = Buffer.from(JSON.stringify(release));
  const gz = zlib.gzipSync(json);
  const record = Buffer.byteLength(gz.toString('base64'));
  const filesRaw = other.reduce((a, f) => a + Buffer.from(f.data, 'base64').length, 0);
  return { record, json: json.length, gzip: gz.length, filesRaw, manifest: Buffer.byteLength(manifest), files: other.map((f) => f.name) };
}

function unpackTgz(tgz, into) {
  fs.mkdirSync(into, { recursive: true });
  execFileSync('tar', ['xzf', tgz, '-C', into]);
  const [dir] = fs.readdirSync(into);
  return path.join(into, dir);
}

/** The 5.1.0 shape: the SQL under files/ AND rendered into ConfigMaps. */
function mutate(chart) {
  // .helmignore refuses files/schema/*.sql; the regression this simulates predates it.
  fs.rmSync(path.join(chart, '.helmignore'), { force: true });
  const sqlDir = path.join(chart, 'files', 'schema');
  fs.mkdirSync(sqlDir, { recursive: true });
  for (const k of ['schema', 'seed']) {
    fs.copyFileSync(path.join(ROOT, 'scripts', 'database', `${k}.sql`), path.join(sqlDir, `${k}.sql`));
  }
  fs.writeFileSync(
    path.join(chart, 'templates', 'zz-mutation-sql-configmap.yaml'),
    'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: mutation-sql\ndata:\n  schema.sql: |\n{{ .Files.Get "files/schema/schema.sql" | indent 4 }}\n  seed.sql: |\n{{ .Files.Get "files/schema/seed.sql" | indent 4 }}\n',
  );
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'release-record-'));
try {
  let chart;
  const tgz = opt('--tgz');
  const dir = opt('--chart');
  if (tgz) {
    chart = unpackTgz(path.resolve(tgz), path.join(tmp, 'unpacked'));
  } else if (dir) {
    // Package first, so .helmignore applies exactly as it does for a release.
    const pkg = path.join(tmp, 'pkg');
    fs.mkdirSync(pkg);
    execFileSync('helm', ['package', path.resolve(dir), '-d', pkg], { stdio: 'pipe' });
    const [packaged] = fs.readdirSync(pkg);
    chart = unpackTgz(path.join(pkg, packaged), path.join(tmp, 'unpacked'));
  } else {
    // The repo chart, staged exactly as scripts/stage-chart-sql.sh stages it
    // for a release, plus the Enterprise verification key a commercial
    // package carries — the larger of the two editions.
    chart = path.join(tmp, 'vistaplatform');
    fs.cpSync(path.join(ROOT, 'charts', 'vistaplatform'), chart, { recursive: true });
    execFileSync('bash', [path.join(ROOT, 'scripts', 'stage-chart-sql.sh')], {
      cwd: ROOT,
      env: { ...process.env, CHART_SQL_DIR: path.join(chart, 'files', 'schema') },
      stdio: 'pipe',
    });
    fs.mkdirSync(path.join(chart, 'files', 'ee'), { recursive: true });
    fs.writeFileSync(path.join(chart, 'files', 'ee', 'edition-public-key.pem'), '-----BEGIN PUBLIC KEY-----\nplaceholder\n-----END PUBLIC KEY-----\n');
    const pkg = path.join(tmp, 'pkg');
    fs.mkdirSync(pkg);
    execFileSync('helm', ['package', chart, '-d', pkg], { stdio: 'pipe' });
    const [packaged] = fs.readdirSync(pkg);
    chart = unpackTgz(path.join(pkg, packaged), path.join(tmp, 'unpacked'));
  }

  console.log('Helm release-record size');
  const real = simulateRecord(chart);
  console.log(`  chart files/: ${real.filesRaw} bytes raw (${real.files.join(', ') || 'none'}); manifest ${real.manifest} bytes; JSON ${real.json} → gzip ${real.gzip} → record ${real.record} bytes`);

  // The guard must be able to fail: the 5.1.0 shape goes over the limit.
  const mutated = path.join(tmp, 'mutated');
  fs.cpSync(chart, mutated, { recursive: true });
  mutate(mutated);
  const bad = simulateRecord(mutated);
  check(`a chart carrying the SQL under files/ and in the manifest measures over ${LIMIT} (self-test: ${bad.record} bytes)`, bad.record > LIMIT);
  check('…and that shape would not fit the Secret at all (self-test against the real ceiling)', bad.record > SECRET_DATA_LIMIT, `${bad.record} ≤ ${SECRET_DATA_LIMIT}`);

  check('the record carries no SQL under files/', !real.files.some((f) => /\.sql$/.test(f)), real.files.join(', '));
  check(`the simulated release record is under ${LIMIT} bytes (${real.record} bytes, ${Math.round((100 * real.record) / SECRET_DATA_LIMIT)}% of the 1 MiB Secret limit)`, real.record <= LIMIT);
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}

if (failures) {
  console.error(`\n❌ ${failures} release-record check(s) failed`);
  process.exit(1);
}
console.log('✅ Helm release record stays well under the 1 MiB Secret limit');
