#!/usr/bin/env node
// Render-level regression tests for config checksum pod annotations.
// These annotations are the only signal Helm sees for config-only upgrades:
// envFrom ConfigMaps and subPath-mounted frontend config files do not refresh in
// running pods. If the checksums drift or disappear, config changes can report a
// green upgrade while the old values stay in memory.

import { execFileSync } from 'child_process';
import { readFileSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');
const chartPath = path.join(root, 'charts', 'vistaplatform');
const valuesPath = path.join(chartPath, 'values.yaml');
const supportedKubeVersion = '1.35.0';

const requiredSetArgs = [
  '--set', 'platform.jwtSecret=l',
  '--set', 'platform.internalAuthSecret=l',
  '--set', 'platform.encryptionMasterKey=l',
];

function render(extraArgs = []) {
  let rendered;
  try {
    rendered = execFileSync('helm', [
      'template',
      'config-checksum-test',
      chartPath,
      '--kube-version',
      supportedKubeVersion,
      ...requiredSetArgs,
      ...extraArgs,
    ], {
      cwd: root,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error('helm is required to run chart config checksum tests');
    }
    const stderr = err.stderr ? `\n${err.stderr}` : '';
    throw new Error(`helm template failed${stderr}`);
  }

  try {
    return yaml
      .parseAllDocuments(rendered)
      .map((doc) => doc.toJSON())
      .filter(Boolean);
  } catch (err) {
    throw new Error(`failed to parse rendered chart YAML: ${err.message}`);
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function deploymentByName(docs, name) {
  return docs.find((doc) => doc.kind === 'Deployment' && doc.metadata?.name === name);
}

function configChecksum(docs, name) {
  const deployment = deploymentByName(docs, name);
  assert(deployment, `${name} Deployment was not rendered`);

  const checksum = deployment.spec?.template?.metadata?.annotations?.['checksum/config'];
  assert(typeof checksum === 'string' && checksum.length > 0, `${name} Deployment must carry checksum/config`);
  return checksum;
}

function backendNames() {
  const values = yaml.parse(readFileSync(valuesPath, 'utf8'));
  return Object.keys(values.backends || {}).sort();
}

function checksumsByBackend(docs) {
  return Object.fromEntries(backendNames().map((name) => [name, configChecksum(docs, name)]));
}

function uniqueValues(values) {
  return [...new Set(Object.values(values))];
}

function assertBackendChecksumsChanged(before, after, reason) {
  for (const [name, checksum] of Object.entries(before)) {
    assert(after[name] !== undefined, `${name} backend disappeared from rendered chart`);
    assert(after[name] !== checksum, `${name} checksum/config did not change when ${reason}`);
  }
}

const hostA = render(['--set', 'tls.dnsName=vista-a.example.com']);
const hostB = render(['--set', 'tls.dnsName=vista-b.example.com']);
const backendA = checksumsByBackend(hostA);
const backendB = checksumsByBackend(hostB);
const backendUniqueA = uniqueValues(backendA);

assert(
  backendUniqueA.length === 1,
  `all backend Deployments should hash the same app ConfigMap; got ${JSON.stringify(backendA)}`,
);
assertBackendChecksumsChanged(backendA, backendB, 'tls.dnsName changed the app ConfigMap');

const webA = configChecksum(hostA, 'web-ui');
const webB = configChecksum(hostB, 'web-ui');
assert(webA !== webB, 'web-ui checksum/config must change when tls.dnsName changes runtime config');
assert(
  webA !== backendUniqueA[0],
  'web-ui checksum/config must hash its runtime ConfigMap, not the backend app ConfigMap',
);

const logLevelDebug = render([
  '--set', 'tls.dnsName=vista-a.example.com',
  '--set', 'appConfig.logLevel=debug',
]);
const backendDebug = checksumsByBackend(logLevelDebug);
assertBackendChecksumsChanged(backendA, backendDebug, 'appConfig.logLevel changed the backend app ConfigMap');
assert(
  configChecksum(logLevelDebug, 'web-ui') === webA,
  'web-ui checksum/config must not change for backend-only appConfig changes',
);

console.log('✅ Chart config checksum render tests passed');
