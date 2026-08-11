#!/usr/bin/env node
// Generate the registry-derived view of charts/vistaplatform/values.yaml's
// backends: block. Emits a side-by-side file (values-backends.generated.yaml)
// rather than rewriting values.yaml in place, so the user can `diff` the
// generated view against the live chart and reconcile drift deliberately.
//
// What this generator owns (derived from standards/service-registry.yaml):
//   - needs.{postgres,redis,nats,influxdb}  — from docker.dependencies
//   - secrets.{internalAuthSecret,encryptionMasterKey,jwtSecret} — from
//     required_secrets
//   - secrets.redisUrl                       — implied by needs.redis
//
// What this generator does NOT own (carried forward from the existing
// values.yaml so the output is a complete drop-in once the user accepts it):
//   - resources.{requests,limits}
//   - replicas
//   - colocateWith
//   - extraVolumes / extraVolumeMounts
//   - extraEnv
//
// Once the registry has been reconciled against the chart (i.e. make
// chart-parity passes strict mode), the natural next step is to extract the
// chart-only fields into a registry sub-block (services[].chart) and have
// the chart consume the generated backends file directly. That refactor is
// intentionally out of scope here — the goal of this script is to make the
// drift visible without rewriting values.yaml under the user's feet.

import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

const REGISTRY_PATH = path.join(root, 'standards', 'service-registry.yaml');
const CHART_VALUES_PATH = path.join(root, 'charts', 'vistaplatform', 'values.yaml');
const OUT_PATH = path.join(root, 'charts', 'vistaplatform', 'values-backends.generated.yaml');

// Registry required_secrets → chart secrets.* key
const SECRET_MAPPING = {
  INTERNAL_AUTH_SECRET: 'internalAuthSecret',
  ENCRYPTION_MASTER_KEY: 'encryptionMasterKey',
  JWT_SECRET: 'jwtSecret',
};

// Chart-only fields preserved from the existing values.yaml entry. The order
// here is the emit order in the generated file.
const PRESERVED_OVERLAY_FIELDS = [
  'resources',
  'replicas',
  'colocateWith',
  'extraVolumes',
  'extraVolumeMounts',
  'extraEnv',
];

const NEEDS_KEYS = ['postgres', 'redis', 'nats', 'influxdb'];

async function main() {
  const registry = yaml.parse(await fs.readFile(REGISTRY_PATH, 'utf8'));
  const chartValues = yaml.parse(await fs.readFile(CHART_VALUES_PATH, 'utf8'));
  const liveBackends = chartValues.backends || {};
  const services = registry.services || [];

  const generated = {};
  let activeCount = 0;
  let overlayCarried = 0;

  for (const svc of services) {
    if (svc.status === 'optional') continue;
    if (svc.docker?.type && svc.docker.type !== 'go-service') continue;
    activeCount++;

    const name = svc.name;
    const deps = new Set(svc.docker?.dependencies || []);
    const required = new Set(svc.required_secrets || []);
    const live = liveBackends[name] || {};

    // Derived: needs (always emit all four keys so the YAML is uniform)
    const needs = {};
    for (const k of NEEDS_KEYS) needs[k] = deps.has(k);

    // Derived: secrets — only emit keys that are true, matching the existing
    // values.yaml shape and keeping the diff against live values tight.
    const secrets = {};
    for (const [envName, chartKey] of Object.entries(SECRET_MAPPING)) {
      if (required.has(envName)) secrets[chartKey] = true;
    }
    if (needs.redis) secrets.redisUrl = true;

    const entry = { needs, secrets };

    // Carry forward chart-only overlay fields from the live values.yaml.
    let carriedAny = false;
    for (const field of PRESERVED_OVERLAY_FIELDS) {
      if (live[field] !== undefined) {
        entry[field] = live[field];
        carriedAny = true;
      }
    }
    if (carriedAny) overlayCarried++;

    generated[name] = entry;
  }

  const header = `# GENERATED: DO NOT EDIT. Source: standards/service-registry.yaml
#
# Run \`make generate-chart-values\` to refresh.
#
# This is a side-by-side preview of what charts/vistaplatform/values.yaml's
# backends: block should be according to the service registry. It is NOT
# consumed by the chart today — diff it against values.yaml to spot drift:
#
#   diff <(yq '.backends' charts/vistaplatform/values.yaml) \\
#        <(yq '.backends' charts/vistaplatform/values-backends.generated.yaml)
#
# Fields owned by this generator (from the registry):
#   needs.{postgres,redis,nats,influxdb}  ← docker.dependencies
#   secrets.{internalAuthSecret,encryptionMasterKey,jwtSecret}  ← required_secrets
#   secrets.redisUrl                       ← implied by needs.redis
#
# Fields carried forward from the existing values.yaml (chart-only):
#   resources, replicas, colocateWith, extraVolumes, extraVolumeMounts, extraEnv
#
# Last generated: ${new Date().toISOString()}
`;

  const body = yaml.stringify({ backends: generated }, {
    indent: 2,
    lineWidth: 120,
    // Keep `needs: {...}` and `secrets: {...}` inline like values.yaml.
    defaultStringType: 'PLAIN',
  });

  await fs.writeFile(OUT_PATH, header + '\n' + body);

  console.log(`Generated: ${path.relative(root, OUT_PATH)}`);
  console.log(`  - ${activeCount} active go-services emitted`);
  console.log(`  - ${overlayCarried} entries carried chart-only overlay fields from values.yaml`);
  console.log();
  console.log('Next: diff against the live values.yaml to spot drift:');
  console.log('  diff <(yq \'.backends\' charts/vistaplatform/values.yaml) \\');
  console.log('       <(yq \'.backends\' charts/vistaplatform/values-backends.generated.yaml)');
}

main().catch(err => {
  console.error('generate-chart-values failed:', err);
  process.exit(1);
});
