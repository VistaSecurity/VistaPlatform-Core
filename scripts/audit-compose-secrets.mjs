#!/usr/bin/env node
// Audit that every docker-compose file injects every secret declared by a
// service's `required_secrets` list in standards/service-registry.yaml.
//
// Goals:
//   1. Every backend service that needs a secret (per the registry) has it
//      injected as an environment variable in every compose file that defines
//      the service.
//   2. The injection uses the strict `${VAR:?...}` form so docker compose
//      refuses to start when the secret is missing — matching the dev compose
//      behaviour and avoiding the silent ec2-smoke/prod failure mode.
//   3. Optional services (status: optional) and infrastructure services
//      (postgres, redis, etc.) are skipped.
//
// Wired into `make standards-check` via `make audit`. Exit non-zero on any
// failure so CI catches drift the moment a compose file falls behind the
// registry.

import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

const COMPOSE_FILES = [
  'docker-compose.yml',
  'docker-compose.ec2-smoke.yml',
  'docker-compose.prod.yml',
];

// Permits the lax `${VAR}` and the literal-default `${VAR:-...}` forms in dev
// only, where `start-session.sh` always populates the .env. For ec2-smoke and
// prod, we require the strict `${VAR:?...}` form.
const STRICT_FILES = new Set(['docker-compose.ec2-smoke.yml', 'docker-compose.prod.yml']);

function strictPattern(secret) {
  // Strict form: ${SECRET:?error message}. Compose refuses to start when SECRET is unset/empty.
  return new RegExp(`\\$\\{${secret}:\\?[^}]*\\}`);
}
function laxPattern(secret) {
  // Lax form: any of ${SECRET}, ${SECRET:-default}, ${SECRET:?error}, etc.
  return new RegExp(`\\$\\{${secret}(:[-?][^}]*)?\\}`);
}

function envHasSecret(envList, secret, strict) {
  if (!Array.isArray(envList)) return false;
  const re = strict ? strictPattern(secret) : laxPattern(secret);
  for (const entry of envList) {
    if (typeof entry !== 'string') continue;
    const eq = entry.indexOf('=');
    if (eq < 0) continue;
    const name = entry.slice(0, eq).trim();
    const val = entry.slice(eq + 1);
    if (name !== secret) continue;
    if (re.test(val)) return true;
  }
  return false;
}

async function loadRegistry() {
  const registryPath = path.resolve(root, 'standards', 'service-registry.yaml');
  const content = await fs.readFile(registryPath, 'utf8');
  return yaml.parse(content);
}

async function loadCompose(file) {
  const full = path.resolve(root, file);
  if (!(await fs.pathExists(full))) return null;
  const text = await fs.readFile(full, 'utf8');
  return yaml.parse(text);
}

async function main() {
  const registry = await loadRegistry();
  const services = (registry.services || []).filter(s => s.status !== 'optional');
  const failures = [];
  const checkedCount = { files: 0, services: 0, secrets: 0 };

  for (const file of COMPOSE_FILES) {
    const compose = await loadCompose(file);
    if (!compose) {
      console.log(`skip: ${file} (not present)`);
      continue;
    }
    checkedCount.files++;
    const strict = STRICT_FILES.has(file);
    const composeServices = compose.services || {};

    for (const svc of services) {
      const required = Array.isArray(svc.required_secrets) ? svc.required_secrets : [];
      if (required.length === 0) continue;
      const block = composeServices[svc.name];
      if (!block) {
        // Service not defined in this compose file; skip silently. Some
        // compose files may legitimately omit services (none today, but the
        // audit should not assume universal presence).
        continue;
      }
      checkedCount.services++;

      for (const secret of required) {
        checkedCount.secrets++;
        if (!envHasSecret(block.environment, secret, strict)) {
          failures.push({
            file,
            service: svc.name,
            secret,
            strict,
          });
        }
      }
    }
  }

  if (failures.length > 0) {
    console.error('');
    console.error(`AUDIT FAILED: ${failures.length} missing secret injection(s)`);
    console.error('');
    console.error('Each row below means the named compose file declares the service');
    console.error('but does NOT inject the secret listed in registry required_secrets.');
    console.error(`Strict files (${[...STRICT_FILES].join(', ')}) require \`\${VAR:?...}\` form.`);
    console.error('');
    const byFile = new Map();
    for (const f of failures) {
      if (!byFile.has(f.file)) byFile.set(f.file, []);
      byFile.get(f.file).push(f);
    }
    for (const [file, items] of byFile) {
      console.error(`  ${file}:`);
      for (const it of items) {
        const fixHint = it.strict
          ? `      - ${it.secret}=\${${it.secret}:?Set ${it.secret} in env}`
          : `      - ${it.secret}=\${${it.secret}}`;
        console.error(`    - service ${it.service} missing ${it.secret}`);
        console.error(`      add to its environment: list:`);
        console.error(fixHint);
      }
    }
    console.error('');
    console.error('Fix the compose files (or update required_secrets in standards/service-registry.yaml');
    console.error('if the service genuinely no longer needs the secret).');
    process.exit(1);
  }

  console.log(`compose-secrets audit OK: ${checkedCount.files} files, ${checkedCount.services} service blocks, ${checkedCount.secrets} secret checks`);
}

main().catch(err => {
  console.error('audit-compose-secrets crashed:', err);
  process.exit(1);
});
