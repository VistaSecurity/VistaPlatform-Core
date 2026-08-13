#!/usr/bin/env node
// Render-level regression tests for the agent/sensor mTLS passthrough chart
// wiring. This protects the fail-closed agentMtls path from drifting: Traefik
// can render a valid IngressRouteTCP while NetworkPolicy still blackholes the
// backend port, which is exactly the outage class this test covers.

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

function render(extraArgs) {
  let rendered;
  try {
    rendered = execFileSync('helm', [
      'template',
      'agent-mtls-test',
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
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error('helm is required to run chart agent mTLS tests');
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

function findDoc(docs, kind, name) {
  return docs.find((doc) => doc.kind === kind && doc.metadata?.name === name);
}

function findDocByComponent(docs, kind, component) {
  return docs.find((doc) => doc.kind === kind && doc.metadata?.labels?.['app.kubernetes.io/component'] === component);
}

function backendIngressPorts(docs) {
  const policy = findDoc(docs, 'NetworkPolicy', 'allow-ingress-to-backends');
  if (!policy) {
    throw new Error('allow-ingress-to-backends NetworkPolicy was not rendered');
  }
  return new Set((policy.spec?.ingress || [])
    .flatMap((rule) => rule.ports || [])
    .map((port) => Number(port.port)));
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function assertAgentMtlsEnabledRender() {
  const docs = render([
    '--set', 'serviceMtls.enabled=true',
    '--set', 'agentMtls.enabled=true',
    '--set', 'agentMtls.port=8444',
    '--set-string', 'agentMtls.backends.sensor-manager.dnsName=sensors.example.com',
    '--set-string', 'agentMtls.backends.device-interrogation-service.dnsName=agents.example.com',
  ]);

  const ports = backendIngressPorts(docs);
  assert(ports.has(8443), 'service mTLS API port 8443 must be allowed when serviceMtls is enabled');
  assert(ports.has(8444), 'agentMtls passthrough port 8444 must be allowed to backend pods');

  for (const [service, host] of [
    ['sensor-manager', 'sensors.example.com'],
    ['device-interrogation-service', 'agents.example.com'],
  ]) {
    const route = findDocByComponent(docs, 'IngressRouteTCP', service);
    assert(route, `IngressRouteTCP for ${service} was not rendered`);
    assert(route.spec?.tls?.passthrough === true, `${service} IngressRouteTCP must use TLS passthrough`);
    assert(route.spec?.routes?.[0]?.match === `HostSNI(\`${host}\`)`, `${service} HostSNI match drifted`);
    assert(Number(route.spec?.routes?.[0]?.services?.[0]?.port) === 8444, `${service} route must target agentMtls port 8444`);
  }
}

function assertAgentMtlsDisabledRender() {
  const docs = render([
    '--set', 'serviceMtls.enabled=true',
    '--set', 'agentMtls.enabled=false',
  ]);

  const ports = backendIngressPorts(docs);
  assert(!ports.has(8444), 'agentMtls port 8444 must not be allowed when agentMtls is disabled');
  const passthroughRoutes = docs.filter((doc) => doc.kind === 'IngressRouteTCP' && [
    'sensor-manager',
    'device-interrogation-service',
  ].includes(doc.metadata?.labels?.['app.kubernetes.io/component']));
  assert(passthroughRoutes.length === 0, 'agentMtls IngressRouteTCPs must not render when agentMtls is disabled');
}

assertAgentMtlsEnabledRender();
assertAgentMtlsDisabledRender();
console.log('✅ Chart agent mTLS render tests passed');
