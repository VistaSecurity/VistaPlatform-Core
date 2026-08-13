#!/usr/bin/env node
// Regression tests for the tls.mode=existingSecret pre-existence guard.
//
// WHY THE GUARD EXISTS
// An IngressRoute pointing at an absent Secret does not fail. Traefik falls
// back to its own generated default certificate (CN=<hash>.traefik.default) and
// serves that, so `helm install --wait` returns success, every pod goes Ready,
// and every health check is green — while every TLS client fails with a
// hostname mismatch against a certificate nobody configured. This happened on a
// real install: it was only caught when a sensor refused to register, hours
// later. Checking that the NAME is non-empty was never a check.
//
// WHAT THIS FILE CAN AND CANNOT TEST
// The guard uses `lookup`, which returns empty unless helm is talking to a real
// apiserver. `helm template` therefore CANNOT exercise the failing path, and
// pretending otherwise would produce a test that passes against a deleted
// guard. So this file pins the two properties a render test can honestly prove:
//
//   1. The guard must NOT fire offline. If it did, `helm template`, `helm lint`
//      and `make audit` would break for everyone — the most likely way to get
//      this wrong, and the reason the cert-manager probe alongside it carries
//      the same kube-system companion check.
//   2. The guard must still be present and live-gated in the helper. A
//      source-level assertion is weak, but it catches outright deletion, which
//      is the realistic regression.
//
// The failing direction was mutation-verified by hand against a live cluster
// and must be re-verified the same way if the guard is reworked:
//
//   helm upgrade <rel> charts/vistaplatform -n <ns> -f <values> --dry-run=server \
//     --set tls.existingSecretName=nope-does-not-exist
//   => must fail naming the Secret and namespace
//
//   kubectl -n <ns> create secret generic wrong-shape \
//     --from-literal=cert.pem=x --from-literal=key.pem=y
//   helm upgrade ... --dry-run=server --set tls.existingSecretName=wrong-shape
//   => must fail naming the missing tls.crt key
//
// (`--dry-run=server` is required: plain `--dry-run` does not perform lookups.)

import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');
const chartPath = path.join(root, 'charts', 'vistaplatform');
const supportedKubeVersion = '1.35.0';

let failures = 0;
const pass = (m) => console.log(`  PASS ${m}`);
const fail = (m) => { console.error(`  FAIL ${m}`); failures++; };

function renderOffline(extraArgs) {
  return execFileSync('helm', [
    'template', 'tls-existing-secret-test', chartPath,
    '--kube-version', supportedKubeVersion,
    '--set', 'platform.jwtSecret=l',
    '--set', 'platform.internalAuthSecret=l',
    '--set', 'platform.encryptionMasterKey=l',
    ...extraArgs,
  ], { cwd: root, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
}

console.log('tls.mode=existingSecret guard');

// 1. Offline render with a Secret that certainly does not exist must SUCCEED.
//    Offline, `lookup` cannot distinguish "missing" from "no cluster", so the
//    guard must stay silent rather than block every template/lint invocation.
try {
  const out = renderOffline([
    '--set', 'tls.mode=existingSecret',
    '--set', 'tls.dnsName=vista.example.com',
    '--set', 'tls.existingSecretName=definitely-not-present',
  ]);
  if (!out.includes('secretName: definitely-not-present')) {
    fail('offline render did not wire the IngressRoute to the named Secret');
  } else {
    pass('offline `helm template` renders (guard does not fire without a cluster)');
  }
} catch (err) {
  fail(`offline \`helm template\` failed — the guard is firing without a cluster, which breaks helm template/lint/audit:\n${(err.stderr || err.message).toString().trim()}`);
}

// 2. An EMPTY name must still be rejected offline. Note which layer does it:
//    values.schema.json enforces minLength on tls.existingSecretName, so this
//    is refused before the template's own `fail` is ever reached. Both are
//    real; the assertion accepts either so that moving the check between
//    layers does not produce a spurious failure, but an empty name silently
//    rendering does.
try {
  renderOffline([
    '--set', 'tls.mode=existingSecret',
    '--set', 'tls.dnsName=vista.example.com',
    '--set', 'tls.existingSecretName=',
  ]);
  fail('empty tls.existingSecretName rendered successfully; it must be rejected');
} catch (err) {
  const msg = (err.stderr || '').toString();
  const bySchema = /existingSecretName.*minLength/s.test(msg);
  const byTemplate = msg.includes('tls.existingSecretName is required');
  if (bySchema || byTemplate) {
    pass(`empty tls.existingSecretName rejected offline (${bySchema ? 'values.schema.json' : 'template fail'})`);
  } else {
    fail(`empty tls.existingSecretName failed for an unrelated reason: ${msg.trim().split('\n').slice(-2).join(' ')}`);
  }
}

// 3. The live guard must still be present, and still be live-gated.
const helpers = fs.readFileSync(path.join(chartPath, 'templates', '_helpers.tpl'), 'utf8');
const checks = [
  ['looks up the named Secret', /lookup\s+"v1"\s+"Secret"\s+\.Release\.Namespace\s+\.Values\.tls\.existingSecretName/],
  ['gated on a live cluster (kube-system companion probe)', /lookup\s+"v1"\s+"Namespace"\s+""\s+"kube-system"/],
  ['gated on install/upgrade only', /or\s+\.Release\.IsInstall\s+\.Release\.IsUpgrade/],
  ['rejects a Secret with no tls.crt', /index\s+\$tlsSecret\.data\s+"tls\.crt"/],
];
for (const [label, re] of checks) {
  if (re.test(helpers)) pass(`guard ${label}`);
  else fail(`guard no longer ${label} — the silent-default-cert failure is reachable again`);
}

if (failures > 0) {
  console.error(`\n❌ tls.mode=existingSecret guard: ${failures} check(s) failed`);
  process.exit(1);
}
console.log('✅ tls.mode=existingSecret guard intact (offline-safe, live-gated)');
