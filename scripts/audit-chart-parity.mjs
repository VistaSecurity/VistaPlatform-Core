#!/usr/bin/env node
// Audit chart values + templates against the service registry. The previous
// two weeks of fix(chart): commits all had the same shape: a service env var,
// volume mount, or probe was added to docker-compose (or implied by the
// registry) but the chart's hand-maintained `backends:` map and Deployment
// template lagged behind. This audit makes that drift surface as a check
// instead of a customer-install incident.
//
// What it checks, per active go-service in the registry:
//   1. The service has an entry in charts/vistaplatform/values.yaml `backends:`.
//   2. backends.<svc>.needs.{postgres,redis,nats} matches the registry's
//      docker.dependencies. Influxdb is intentionally not in the chart's
//      `needs` model — flagged as informational, not failure.
//   3. backends.<svc>.secrets.{internalAuthSecret,encryptionMasterKey}
//      matches the registry's required_secrets list.
//   4. backends.<svc>.secrets.redisUrl is on iff needs.redis is on
//      (chart-internal consistency — Redis URL implies Redis client).
//   5. backends.<svc>.secrets.jwtSecret is reported as a registry gap when
//      it's set in the chart but the registry's required_secrets does not
//      list JWT_SECRET. Likely the registry needs the secret added.
//   6. Template regression guard: charts/vistaplatform/templates/backend/
//      _deployment.tpl still defines livenessProbe AND readinessProbe.
//      Reflects the fix from commit 9b32615 — probes silently disappearing
//      from the template is exactly the class of bug this audits.
//
// Exit codes:
//   0  no drift detected
//   0  drift detected, --strict not set (warnings printed; `make audit` keeps
//      passing while teams reconcile the registry/chart)
//   1  drift detected with --strict (CI, `make chart-parity`)
//
// Wired into `make audit` (non-strict) and `make chart-parity` (strict).

import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

const STRICT = process.argv.includes('--strict');

const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const RESET = '\x1b[0m';

const REGISTRY_PATH = path.join(root, 'standards', 'service-registry.yaml');
const CHART_VALUES_PATH = path.join(root, 'charts', 'vistaplatform', 'values.yaml');
const DEPLOYMENT_TPL_PATH = path.join(
  root, 'charts', 'vistaplatform', 'templates', 'backend', '_deployment.tpl'
);

// Maps registry required_secrets → chart values.backends.<svc>.secrets.* keys.
// Anything not in this map is informational only (e.g. INFLUX_TOKEN — not
// currently modeled in the chart values).
// All three STRIPE_* env vars share the chart flag `stripeKeys` — the
// _deployment.tpl injects all three from the billing secret when it's set,
// so they're a single chart-side opt-in, not three independent toggles.
const SECRET_MAPPING = {
  INTERNAL_AUTH_SECRET: 'internalAuthSecret',
  ENCRYPTION_MASTER_KEY: 'encryptionMasterKey',
  JWT_SECRET: 'jwtSecret',
  STRIPE_SECRET_KEY: 'stripeKeys',
  STRIPE_PUBLISHABLE_KEY: 'stripeKeys',
  STRIPE_WEBHOOK_SECRET: 'stripeKeys',
};

// Datastore dependencies the chart's `needs:` block models. Keep in sync
// with the keys read by charts/vistaplatform/templates/backend/_deployment.tpl.
const TRACKED_NEEDS = ['postgres', 'redis', 'nats', 'influxdb'];

const drifts = [];
function drift(service, kind, detail) {
  drifts.push({ service, kind, detail });
}

async function main() {
  const registry = yaml.parse(await fs.readFile(REGISTRY_PATH, 'utf8'));
  const chartValues = yaml.parse(await fs.readFile(CHART_VALUES_PATH, 'utf8'));
  const deploymentTpl = await fs.readFile(DEPLOYMENT_TPL_PATH, 'utf8');

  const backends = chartValues.backends || {};
  const services = registry.services || [];

  console.log(`${BLUE}Chart parity audit — registry ↔ charts/vistaplatform${RESET}`);
  console.log(`  Registry services:  ${services.length}`);
  console.log(`  Chart backends:     ${Object.keys(backends).length}`);
  console.log();

  // 1-5: per-service comparison
  for (const svc of services) {
    if (svc.status === 'optional') continue;
    if (svc.docker?.type && svc.docker.type !== 'go-service') continue;

    const name = svc.name;
    const backend = backends[name];

    // 1. presence
    if (!backend) {
      drift(name, 'missing-backend',
        `registry has active go-service '${name}' but charts/vistaplatform/values.yaml backends:.${name} is missing`);
      continue;
    }

    // 2. datastore needs
    const deps = new Set(svc.docker?.dependencies || []);
    const needs = backend.needs || {};
    for (const ds of TRACKED_NEEDS) {
      const registrySays = deps.has(ds);
      const chartSays = !!needs[ds];
      if (registrySays !== chartSays) {
        drift(name, 'needs-mismatch',
          `needs.${ds} = ${chartSays} in chart but registry docker.dependencies ${
            registrySays ? 'includes' : 'does not include'
          } '${ds}'`);
      }
    }

    // 3. registry-required secrets must appear in chart.secrets
    const required = new Set(svc.required_secrets || []);
    const chartSecrets = backend.secrets || {};
    for (const [envName, chartKey] of Object.entries(SECRET_MAPPING)) {
      const registrySays = required.has(envName);
      const chartSays = !!chartSecrets[chartKey];
      if (registrySays && !chartSays) {
        drift(name, 'secret-missing-in-chart',
          `registry required_secrets includes ${envName} but chart secrets.${chartKey} is not set`);
      }
      if (!registrySays && chartSays && envName !== 'JWT_SECRET') {
        // JWT_SECRET handled separately in (5) as a registry-side gap.
        drift(name, 'secret-extra-in-chart',
          `chart sets secrets.${chartKey}=true but registry required_secrets does not list ${envName}`);
      }
    }

    // 4. redisUrl ↔ needs.redis chart-internal consistency
    const chartRedisUrl = !!chartSecrets.redisUrl;
    const chartNeedsRedis = !!needs.redis;
    if (chartRedisUrl !== chartNeedsRedis) {
      drift(name, 'redis-url-inconsistent',
        `chart has secrets.redisUrl=${chartRedisUrl} but needs.redis=${chartNeedsRedis} — these should match`);
    }

    // 5. JWT_SECRET registry gap
    if (chartSecrets.jwtSecret && !required.has('JWT_SECRET')) {
      drift(name, 'jwt-secret-not-in-registry',
        `chart sets secrets.jwtSecret=true but registry required_secrets does not list JWT_SECRET — add to registry`);
    }
  }

  // Reverse direction: chart has backends the registry doesn't know about
  for (const name of Object.keys(backends)) {
    const inRegistry = services.find(s => s.name === name);
    if (!inRegistry) {
      drift(name, 'extra-backend',
        `chart has backends:.${name} but no matching service in registry (or registry status=optional/non-go)`);
    }
  }

  // 6. template regression guard
  if (!/livenessProbe:/.test(deploymentTpl)) {
    drift('_deployment.tpl', 'missing-liveness-probe',
      'charts/vistaplatform/templates/backend/_deployment.tpl no longer defines livenessProbe — every backend deployment will start without one');
  }
  if (!/readinessProbe:/.test(deploymentTpl)) {
    drift('_deployment.tpl', 'missing-readiness-probe',
      'charts/vistaplatform/templates/backend/_deployment.tpl no longer defines readinessProbe — every backend deployment will start without one');
  }

  // Report
  if (drifts.length === 0) {
    console.log(`${GREEN}✅ Chart and registry are in parity.${RESET}`);
    process.exit(0);
  }

  const levelColor = STRICT ? RED : YELLOW;
  const levelGlyph = STRICT ? '❌' : '⚠️ ';

  // Group by service for readability.
  const grouped = new Map();
  for (const d of drifts) {
    if (!grouped.has(d.service)) grouped.set(d.service, []);
    grouped.get(d.service).push(d);
  }
  for (const [svc, items] of grouped) {
    console.log(`${levelColor}${levelGlyph} ${svc}${RESET}`);
    for (const item of items) {
      console.log(`     [${item.kind}] ${item.detail}`);
    }
  }
  console.log();
  console.log(`${levelColor}Found ${drifts.length} chart/registry parity issue(s) across ${grouped.size} target(s).${RESET}`);

  if (STRICT) {
    console.log(`${RED}Run \`make audit\` (non-strict) to see the same report without failing the build.${RESET}`);
    process.exit(1);
  } else {
    console.log(`${YELLOW}This audit is in warning mode — \`make audit\` will still pass.${RESET}`);
    console.log(`${YELLOW}Run \`make chart-parity\` (or this script with --strict) to fail on drift.${RESET}`);
    process.exit(0);
  }
}

main().catch(err => {
  console.error(`${RED}audit-chart-parity failed:${RESET}`, err);
  process.exit(2);
});
