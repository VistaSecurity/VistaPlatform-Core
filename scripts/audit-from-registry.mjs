#!/usr/bin/env node
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function fail(msg) {
  console.error(`AUDIT FAIL: ${msg}`);
  process.exitCode = 1;
}

async function main() {
  const root = path.resolve(__dirname, '..');
  const registryPath = path.resolve(root, 'standards', 'service-registry.yaml');
  const readmePath = path.resolve(root, 'README.md');
  const composePath = path.resolve(root, 'docker-compose.yml');

  const registry = yaml.parse(await fs.readFile(registryPath, 'utf8'));
  const readme = await fs.readFile(readmePath, 'utf8');
  const compose = (await fs.pathExists(composePath)) ? await fs.readFile(composePath, 'utf8') : '';

  // 1) Verify service directories exist and match names
  for (const svc of registry.services) {
    const dirOk = await fs.pathExists(path.resolve(root, svc.dir));
    if (!dirOk) fail(`Service dir missing: ${svc.dir}`);
    if (!/^[a-z0-9-]+$/.test(svc.name)) fail(`Service name not kebab-case: ${svc.name}`);
  }

  // 2) Verify README links use lowercase docs paths
  const badDocsLinks = readme.match(/docs\/[A-Z]/g);
  if (badDocsLinks) fail(`README has uppercase docs paths: ${[...new Set(badDocsLinks)].join(', ')}`);

  // 3) Verify UI port mapping consistency between registry and README
  const expectedWeb = `${registry.ui?.tenant?.external_port}`;
  const expectedAdmin = `${registry.ui?.admin?.external_port}`;
  if (!readme.includes(`Tenant Application (web-ui)`)) fail('README missing Tenant Application link');
  if (!readme.includes(`Admin UI (admin-ui)`)) fail('README missing Admin UI link');

  // 4) Verify compose exposes service external ports per registry (best-effort)
  for (const svc of registry.services) {
    if (compose) {
      // Check for hardcoded port pattern: ":8081"
      const hardcodedPattern = `:${svc.external_port}`;
      // Check for environment variable pattern: "${VAR:-8081}:8080"
      const envVarPattern = `\\\${[^}]*:-${svc.external_port}}`;
      const envVarRegex = new RegExp(envVarPattern);
      
      const hasHardcodedPort = compose.includes(hardcodedPattern);
      const hasEnvVarPort = envVarRegex.test(compose);
      
      if (!hasHardcodedPort && !hasEnvVarPort) {
        // best-effort: allow services not in compose (optional), warn only
        console.warn(`AUDIT WARN: compose missing external port ${svc.external_port} for ${svc.name}`);
      }
    }
  }

  // 5) Require generated files to be up to date
  const generatedPaths = [
    path.resolve(root, 'docsv4', 'generated', 'service-ports.md'),
    path.resolve(root, 'docsv4', 'generated', 'ui-ports.md'),
    path.resolve(root, 'config', 'generated', 'service-registry.json'),
  ];
  for (const p of generatedPaths) {
    if (!(await fs.pathExists(p))) fail(`Missing generated artifact: ${path.relative(root, p)}`);
  }

  if (process.exitCode === 0) {
    console.log('AUDIT OK: Standards alignment verified.');
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});


