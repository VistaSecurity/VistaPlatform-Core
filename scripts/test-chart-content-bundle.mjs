#!/usr/bin/env node
// Render-level regression tests for the Enterprise compliance content bundle
// chart wiring. The critical behavior is fail-closed: Core charts must not
// reference Enterprise bundle files, while enabling the flag without packaged
// bundle files must fail during Helm rendering instead of installing an empty
// or unverified seed Job.

import { execFileSync } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');
const chartPath = path.join(root, 'charts', 'vistaplatform');
const supportedKubeVersion = '1.35.0';

const commonSetArgs = [
  '--set', 'tls.dnsName=lint.example',
  '--set', 'tls.issuerRef.name=lint',
  '--set', 'platform.jwtSecret=l',
  '--set', 'platform.internalAuthSecret=l',
  '--set', 'platform.encryptionMasterKey=l',
];

function helmTemplate(extraArgs) {
  return execFileSync('helm', [
    'template',
    'content-bundle-test',
    chartPath,
    '--kube-version',
    supportedKubeVersion,
    ...commonSetArgs,
    ...extraArgs,
  ], {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function render(extraArgs = []) {
  let rendered;
  try {
    rendered = helmTemplate(extraArgs);
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error('helm is required to run chart content bundle tests');
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

function findDocByComponent(docs, kind, component) {
  return docs.find((doc) => doc.kind === kind && doc.metadata?.labels?.['app.kubernetes.io/component'] === component);
}

function assertCoreRenderDoesNotReferenceBundle() {
  const docs = render();

  const seedConfig = findDocByComponent(docs, 'ConfigMap', 'seed-data');
  assert(seedConfig, 'seed-data ConfigMap was not rendered');
  assert(seedConfig.data?.['seed.sql'] !== undefined, 'seed-data ConfigMap must include seed.sql');
  for (const key of [
    'frameworks-regulated.sql',
    'frameworks-regulated.sql.sig',
    'edition-public-key.pem',
  ]) {
    assert(seedConfig.data?.[key] === undefined, `Core seed ConfigMap must not include ${key}`);
  }

  const seedJob = findDocByComponent(docs, 'Job', 'seed-data');
  assert(seedJob, 'seed-data Job was not rendered');
  const podSpec = seedJob.spec?.template?.spec;
  assert(!podSpec?.initContainers, 'Core seed-data Job must not render Enterprise verification init containers');

  const psql = podSpec?.containers?.find((container) => container.name === 'psql');
  assert(psql, 'seed-data Job must include the psql container');
  const shellScript = psql.command?.join('\n') || '';
  assert(!shellScript.includes('frameworks-regulated.sql'), 'Core psql command must not apply the regulated framework bundle');
  assert(!shellScript.includes('Enterprise content bundle'), 'Core psql command must not mention Enterprise bundle application');
}

function assertMissingBundleFailsFast() {
  try {
    helmTemplate(['--set', 'enterprise.contentBundle.enabled=true']);
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error('helm is required to run chart content bundle tests');
    }

    const output = `${err.stdout || ''}\n${err.stderr || ''}`;
    assert(
      output.includes('enterprise.contentBundle.enabled=true but this chart was packaged WITHOUT the Enterprise content bundle'),
      `missing bundle render should fail with the explicit packaged-without-bundle message; got:\n${output}`,
    );
    return;
  }

  throw new Error('enabling enterprise.contentBundle without packaged bundle files must fail helm template');
}

assertCoreRenderDoesNotReferenceBundle();
assertMissingBundleFailsFast();
console.log('✅ Chart Enterprise content bundle render tests passed');
