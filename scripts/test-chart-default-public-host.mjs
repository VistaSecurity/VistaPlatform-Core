#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => fs.readFileSync(path.join(root, rel), 'utf8');

const helpers = read('charts/vistaplatform/templates/_helpers.tpl');
assert.match(
  helpers,
  /define "vistaplatform\.publicHost"[\s\S]*default "vista\.local" \.Values\.tls\.dnsName/,
  'publicHost helper must default empty tls.dnsName to vista.local'
);

for (const rel of [
  'charts/vistaplatform/templates/ingress/ingressroutes.yaml',
  'charts/vistaplatform/templates/ingress/middlewares.yaml',
]) {
  const text = read(rel);
  assert.match(
    text,
    /\{\{- \$dnsName := include "vistaplatform\.publicHost" \. -\}\}/,
    `${rel} must derive $dnsName from the publicHost helper`
  );
  assert.doesNotMatch(
    text,
    /\$dnsName := \.Values\.tls\.dnsName/,
    `${rel} must not route the default self-signed install to an empty Host()`
  );
}

assert.match(
  read('charts/vistaplatform/templates/ingress/middlewares.yaml'),
  /- "https:\/\/\{\{ \$dnsName \}\}"/,
  'CORS defaults must use the same public host as the IngressRoute rules'
);

const runtimeTemplates = [
  'charts/vistaplatform/templates/configmap-app.yaml',
  'charts/vistaplatform/templates/frontend/web-ui.yaml',
  'charts/vistaplatform/templates/ingress/selfsigned-cert.yaml',
  'charts/vistaplatform/templates/NOTES.txt',
];

for (const rel of runtimeTemplates) {
  const text = read(rel);
  assert.match(
    text,
    /vistaplatform\.publicHost|\$publicHost/,
    `${rel} must share the publicHost fallback used by the self-signed certificate`
  );
}

console.log('✅ chart default public host templates use vista.local consistently');
