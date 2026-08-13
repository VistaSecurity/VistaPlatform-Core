#!/usr/bin/env node
/**
 * Chart render tests for asymmetric JWT signing.
 *
 * The property this change buys is simple and mechanical: the PRIVATE signing
 * key reaches exactly two pods, and once the migration window closes the shared
 * HS256 secret reaches only those same two. If a future template edit widens
 * either set, the platform quietly goes back to "any of 17 pods can mint a
 * token for any tenant" — with nothing failing and no error anywhere. That is
 * precisely the class of regression this repo keeps hitting, so it gets a test
 * rather than a comment.
 *
 * Run: node scripts/test-chart-jwt-signing.mjs
 */

import { execFileSync } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CHART = path.join(ROOT, 'charts', 'vistaplatform');
const SUPPORTED_KUBE_VERSION = '1.35.0';

// The only services that may ever hold a signing key. Spelled out here as well
// as in the template so that widening it takes two deliberate edits.
const ISSUERS = ['auth-service', 'admin-service'];

let failures = 0;
function check(desc, ok, detail = '') {
  if (ok) {
    console.log(`  ✓ ${desc}`);
  } else {
    failures++;
    console.error(`  ✗ ${desc}${detail ? `\n      ${detail}` : ''}`);
  }
}

function render(extra = []) {
  const out = execFileSync(
    'helm',
    [
      'template', 't', CHART,
      '--kube-version', SUPPORTED_KUBE_VERSION,
      '--set', 'tls.dnsName=vista.example.com',
      '--set', 'platform.jwtSecret=x',
      '--set', 'platform.internalAuthSecret=x',
      '--set', 'platform.encryptionMasterKey=x',
      ...extra,
    ],
    { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }
  );
  const deployments = [];
  for (const doc of yaml.parseAllDocuments(out)) {
    const d = doc.toJS();
    if (!d || d.kind !== 'Deployment') continue;
    const c = d.spec.template.spec.containers[0];
    deployments.push({
      name: d.metadata.name,
      env: new Set((c.env || []).map((e) => e.name)),
      mounts: new Set((c.volumeMounts || []).map((m) => m.name)),
    });
  }
  return deployments;
}

// A backend for this purpose is one that participates in JWT auth at all.
const backends = (ds) => ds.filter((d) => d.env.has('JWT_SECRET') || d.env.has('JWT_JWKS_URL'));

console.log('Chart JWT signing (#584)');

// ─── Default: signing on, migration window open ────────────────────────────
{
  const ds = backends(render());
  const withKeyEnv = ds.filter((d) =>
    [...d.env].some((e) => e.endsWith('_SIGNING_KEY_FILE'))).map((d) => d.name).sort();
  const withKeyVol = ds.filter((d) => d.mounts.has('jwt-signing')).map((d) => d.name).sort();

  check('the private signing key env reaches only the two issuers',
    JSON.stringify(withKeyEnv) === JSON.stringify([...ISSUERS].sort()),
    `got ${JSON.stringify(withKeyEnv)}`);
  check('the private signing key VOLUME is mounted only into the two issuers',
    JSON.stringify(withKeyVol) === JSON.stringify([...ISSUERS].sort()),
    `got ${JSON.stringify(withKeyVol)}`);
  check('every JWT-authenticating backend is told where to fetch public keys',
    ds.every((d) => d.env.has('JWT_JWKS_URL')),
    `missing on ${ds.filter((d) => !d.env.has('JWT_JWKS_URL')).map((d) => d.name).join(', ')}`);
  check('the JWKS URL targets the PLAINTEXT listener, not the mTLS one',
    ds.length > 0 && !JSON.stringify(ds[0]).includes(':8443'),
    'a :8443 JWKS URL would need a client cert to fetch the keys needed to authenticate');
  check('during the migration window every backend keeps the legacy secret',
    ds.every((d) => d.env.has('JWT_SECRET')),
    'sessions minted before the cutover would stop verifying');
}

// ─── Migration window closed: the point of the whole change ────────────────
{
  const ds = backends(render(['--set', 'jwtSigning.acceptLegacyHmac=false']));
  const withSecret = ds.filter((d) => d.env.has('JWT_SECRET')).map((d) => d.name).sort();

  check('with the window closed, the shared secret reaches ONLY the two issuers',
    JSON.stringify(withSecret) === JSON.stringify([...ISSUERS].sort()),
    `got ${JSON.stringify(withSecret)} — every extra pod here is one that can forge a token for any tenant`);
  check('and that is strictly fewer pods than before',
    withSecret.length < ds.length,
    `${withSecret.length} of ${ds.length} still hold it`);
}

// ─── Opt-out must be a true no-op ──────────────────────────────────────────
{
  const ds = backends(render(['--set', 'jwtSigning.enabled=false']));
  check('jwtSigning.enabled=false restores the exact legacy shape',
    ds.every((d) => d.env.has('JWT_SECRET'))
      && ds.every((d) => !d.env.has('JWT_JWKS_URL'))
      && ds.every((d) => !d.mounts.has('jwt-signing')),
    'the opt-out must leave no trace, or "roll it back" is not actually available');
}

// ─── The Secret itself ─────────────────────────────────────────────────────
{
  const out = execFileSync('helm', [
    'template', 't', CHART,
    '--kube-version', SUPPORTED_KUBE_VERSION,
    '--set', 'tls.dnsName=vista.example.com',
    '--set', 'platform.jwtSecret=x',
    '--set', 'platform.internalAuthSecret=x',
    '--set', 'platform.encryptionMasterKey=x',
    '--show-only', 'templates/secrets-jwt-signing.yaml',
  ], { encoding: 'utf8' });
  const sec = yaml.parse(out);
  const pem = sec?.stringData?.['signing-key.pem'] || '';

  check('a P-256 private key is generated', pem.includes('-----BEGIN EC PRIVATE KEY-----') || pem.includes('-----BEGIN PRIVATE KEY-----'),
    `got: ${pem.slice(0, 40)}`);
  check('the Secret survives uninstall so sessions are not invalidated',
    sec?.metadata?.annotations?.['helm.sh/resource-policy'] === 'keep');
}

if (failures) {
  console.error(`\n❌ ${failures} chart JWT-signing check(s) failed`);
  process.exit(1);
}
console.log('✅ Chart JWT signing render tests passed');
