#!/usr/bin/env node
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function fail(msg) {
  console.error(`❌ REGISTRY VALIDATION FAIL: ${msg}`);
  process.exitCode = 1;
}

function warn(msg) {
  console.warn(`⚠️  WARNING: ${msg}`);
}

async function main() {
  const root = path.resolve(__dirname, '..');
  const registryPath = path.resolve(root, 'standards', 'service-registry.yaml');
  const composePath = path.resolve(root, 'docker-compose.yml');
  const traefikDynamicPath = path.resolve(root, 'config/traefik/dynamic-development.yaml');
  const readmePath = path.resolve(root, 'README.md');
  const generatedDockerPath = path.resolve(root, 'config/generated/docker-compose-services.yml');

  console.log('🔍 Validating Registry-First Compliance...');
  console.log('==========================================');

  // Load registry
  if (!(await fs.pathExists(registryPath))) {
    fail('Service registry not found. This should be the single source of truth.');
  }
  const registry = yaml.parse(await fs.readFile(registryPath, 'utf8'));

  // Load configuration files
  const compose = (await fs.pathExists(composePath)) ? await fs.readFile(composePath, 'utf8') : '';
  const gatewayConfig = (await fs.pathExists(traefikDynamicPath)) ? await fs.readFile(traefikDynamicPath, 'utf8') : '';
  const readme = (await fs.pathExists(readmePath)) ? await fs.readFile(readmePath, 'utf8') : '';

  let hasErrors = false;

  // 1. Validate service directory structure
  console.log('\n1. Validating Service Directories...');
  for (const svc of registry.services) {
    const dirPath = path.resolve(root, svc.dir);
    if (!(await fs.pathExists(dirPath))) {
      fail(`Service directory missing: ${svc.dir}`);
      hasErrors = true;
    }

    // Check for Dockerfile
    const dockerfilePath = path.resolve(dirPath, 'Dockerfile.dev');
    if (!(await fs.pathExists(dockerfilePath))) {
      warn(`Service ${svc.name} missing Dockerfile.dev`);
    }
  }

  // 2. Validate port assignments in docker-compose.yml
  console.log('\n2. Validating Port Assignments...');
  for (const svc of registry.services) {
    const portPattern = `"${svc.external_port}:${svc.internal_port}"`;
    const envVarPattern = `\\\${[^}]*:-${svc.external_port}}`;
    const envVarRegex = new RegExp(envVarPattern);

    if (compose) {
      const hasHardcodedPort = compose.includes(portPattern);
      const hasEnvVarPort = envVarRegex.test(compose);

      if (!hasHardcodedPort && !hasEnvVarPort) {
        fail(`Service ${svc.name} port ${svc.external_port} not found in docker-compose.yml`);
        hasErrors = true;
      }
    }
  }

  // 3. Validate API routes in Traefik gateway config
  console.log('\n3. Validating API Routes...');
  for (const svc of registry.services) {
    // Skip optional services - they may not be in gateway config until deployed
    if (svc.status === 'optional') {
      continue;
    }
    const routePattern = `/api/v1${svc.route_prefix}/`;
    if (gatewayConfig && !gatewayConfig.includes(routePattern)) {
      fail(`Service ${svc.name} route ${routePattern} not found in gateway config`);
      hasErrors = true;
    }
  }

  // 4. Validate UI port consistency
  console.log('\n4. Validating UI Ports...');
  if (registry.ui?.tenant) {
    const expectedPort = registry.ui.tenant.external_port;
    const portPattern = `:${expectedPort}`;
    const envVarPattern = `\\\${[^}]*:-${expectedPort}}`;
    const envVarRegex = new RegExp(envVarPattern);

    if (compose) {
      const hasHardcodedPort = compose.includes(portPattern);
      const hasEnvVarPort = envVarRegex.test(compose);

      if (!hasHardcodedPort && !hasEnvVarPort) {
        fail(`Web UI port ${expectedPort} not found in docker-compose.yml`);
        hasErrors = true;
      }
    }
    if (readme && !readme.includes(`localhost:${expectedPort}`)) {
      warn(`Web UI port ${expectedPort} not mentioned in README`);
    }
  }

  if (registry.ui?.admin) {
    const expectedPort = registry.ui.admin.external_port;
    const portPattern = `:${expectedPort}`;
    const envVarPattern = `\\\${[^}]*:-${expectedPort}}`;
    const envVarRegex = new RegExp(envVarPattern);

    if (compose) {
      const hasHardcodedPort = compose.includes(portPattern);
      const hasEnvVarPort = envVarRegex.test(compose);

      if (!hasHardcodedPort && !hasEnvVarPort) {
        fail(`Admin UI port ${expectedPort} not found in docker-compose.yml`);
        hasErrors = true;
      }
    }
    if (readme && !readme.includes(`localhost:${expectedPort}`)) {
      warn(`Admin UI port ${expectedPort} not mentioned in README`);
    }
  }

  // 5. Check for port conflicts
  console.log('\n5. Checking for Port Conflicts...');
  const usedPorts = new Set();
  for (const svc of registry.services) {
    if (usedPorts.has(svc.external_port)) {
      fail(`Port conflict: ${svc.external_port} used by multiple services`);
      hasErrors = true;
    }
    usedPorts.add(svc.external_port);
  }

  // 6. Validate generated files are up to date
  console.log('\n6. Validating Generated Files...');
  const generatedFiles = [
    'docsv4/generated/service-ports.md',
    'docsv4/generated/ui-ports.md',
    'config/generated/service-registry.json'
  ];

  for (const file of generatedFiles) {
    const filePath = path.resolve(root, file);
    if (!(await fs.pathExists(filePath))) {
      fail(`Generated file missing: ${file}`);
      hasErrors = true;
    } else {
      // Check if file is recent (within last 5 minutes)
      const stats = await fs.stat(filePath);
      const age = Date.now() - stats.mtime.getTime();
      if (age > 5 * 60 * 1000) { // 5 minutes
        warn(`Generated file ${file} may be outdated (last modified: ${stats.mtime.toISOString()})`);
      }
    }
  }

  // 7. Validate CORS configuration consistency
  console.log('\n7. Validating CORS Configuration...');
  if (registry.ui?.tenant && compose) {
    const webUIPort = registry.ui.tenant.external_port;
    const adminUIPort = registry.ui.admin?.external_port;

    // Check WEB_UI_HOST_PORT default value
    const webUIEnvPattern = /WEB_UI_HOST_PORT:-(\d+)/g;
    const webUIMatches = [...compose.matchAll(webUIEnvPattern)];

    for (const match of webUIMatches) {
      if (parseInt(match[1]) !== webUIPort) {
        fail(`WEB_UI_HOST_PORT default is ${match[1]}, but registry specifies ${webUIPort}`);
        hasErrors = true;
        break;
      }
    }

    // Check ADMIN_UI_HOST_PORT default value
    if (adminUIPort) {
      const adminUIEnvPattern = /ADMIN_UI_HOST_PORT:-(\d+)/g;
      const adminUIMatches = [...compose.matchAll(adminUIEnvPattern)];

      for (const match of adminUIMatches) {
        if (parseInt(match[1]) !== adminUIPort) {
          fail(`ADMIN_UI_HOST_PORT default is ${match[1]}, but registry specifies ${adminUIPort}`);
          hasErrors = true;
          break;
        }
      }
    }

    // Verify port mapping for web-ui service
    const webUIPortMapping = `"\${WEB_UI_HOST_PORT:-${webUIPort}}:`;
    if (!compose.includes(webUIPortMapping)) {
      fail(`Web UI port mapping should be \${WEB_UI_HOST_PORT:-${webUIPort}}:${registry.ui.tenant.internal_port}`);
      hasErrors = true;
    }

    // Verify port mapping for admin-ui service
    if (adminUIPort) {
      const adminUIPortMapping = `"\${ADMIN_UI_HOST_PORT:-${adminUIPort}}:`;
      if (!compose.includes(adminUIPortMapping)) {
        fail(`Admin UI port mapping should be \${ADMIN_UI_HOST_PORT:-${adminUIPort}}:${registry.ui.admin.internal_port}`);
        hasErrors = true;
      }
    }
  }

  // 8. Check for manual configuration edits
  console.log('\n8. Checking for Manual Configuration Edits...');
  if (compose) {
    // Look for hardcoded service names that should come from registry
    const registryServiceNames = registry.services.map(s => s.name);
    const hardcodedServices = compose.match(/^\s*[a-z-]+-service:/gm) || [];

    for (const hardcoded of hardcodedServices) {
      const serviceName = hardcoded.trim().replace(':', '');
      if (!registryServiceNames.includes(serviceName)) {
        warn(`Hardcoded service in docker-compose.yml: ${serviceName} (not in registry)`);
      }
    }
  }

  // 9. Check Docker Compose Generation
  console.log('\n9. Checking Docker Compose Generation...');
  if (!(await fs.pathExists(generatedDockerPath))) {
    fail('Generated docker-compose-services.yml not found. Run: make generate-docker-compose');
    hasErrors = true;
  } else {
    const generatedDocker = await fs.readFile(generatedDockerPath, 'utf8');
    const generatedDockerYaml = yaml.parse(generatedDocker);

    // Check that all services in registry have corresponding docker entries
    const registryServices = registry.services || [];
    const generatedServices = Object.keys(generatedDockerYaml.services || {});

    for (const service of registryServices) {
      if (!generatedServices.includes(service.name)) {
        fail(`Service ${service.name} missing from generated docker-compose-services.yml`);
        hasErrors = true;
      }
    }

    // Check that infrastructure exceptions are not in generated file
    const infrastructureExceptions = registry.infrastructure?.exceptions || [];
    for (const infra of infrastructureExceptions) {
      if (generatedServices.includes(infra)) {
        fail(`Infrastructure service ${infra} should not be in generated docker-compose-services.yml`);
        hasErrors = true;
      }
    }

    console.log(`✅ Generated docker-compose-services.yml contains ${generatedServices.length} services`);
  }

  // 10. Check Dockerfile.dev files have correct go.work pattern
  console.log('\n10. Checking Dockerfile.dev Go Workspace Pattern...');
  const goServices = registry.services.filter(s => s.docker?.type === 'go-service');
  for (const service of goServices) {
    const dockerfilePath = path.resolve(root, service.dir, 'Dockerfile.dev');
    if (await fs.pathExists(dockerfilePath)) {
      const dockerfile = await fs.readFile(dockerfilePath, 'utf8');
      if (!dockerfile.includes('COPY go.work ./')) {
        fail(`Dockerfile.dev for ${service.name} missing 'COPY go.work ./' pattern`);
        hasErrors = true;
      }
      if (!dockerfile.includes('ENV GOWORK=/workspace/go.work')) {
        fail(`Dockerfile.dev for ${service.name} missing 'ENV GOWORK=/workspace/go.work'`);
        hasErrors = true;
      }
    }
  }
  console.log(`✅ Checked ${goServices.length} Go service Dockerfiles`);

  // 11. Validate ALL Environment Generators Read from Registry
  console.log('\n11. Validating Environment Generators Registry-First...');
  const generators = [
    { name: 'dev', path: 'scripts/generate-dev-env.mjs', envFile: '.env' },
    { name: 'smoke', path: 'scripts/generate-ec2-smoke-env.mjs', envFile: '.env.ec2-smoke' },
    { name: 'prod', path: 'scripts/generate-prod-env.mjs', envFile: '.env.prod' }
  ];

  for (const gen of generators) {
    const genPath = path.resolve(root, gen.path);
    if (await fs.pathExists(genPath)) {
      const content = await fs.readFile(genPath, 'utf8');

      // Must read from registry
      if (!content.includes('service-registry.yaml') ||
          !content.includes('yaml.parse')) {
        fail(`${gen.name} generator must read from service-registry.yaml`);
        hasErrors = true;
      }

      // Must extract service ports dynamically
      if (!content.includes('registry.services') ||
          !content.includes('external_port')) {
        fail(`${gen.name} generator must extract service ports from registry.services`);
        hasErrors = true;
      }

      // Dev-specific: must use dev_port_generation
      if (gen.name === 'dev' && !content.includes('dev_port_generation')) {
        fail('generate-dev-env.mjs must use infrastructure.dev_port_generation');
        hasErrors = true;
      }

      console.log(`✅ ${gen.name} generator reads from registry`);
    } else {
      // Only fail for dev generator (required), warn for smoke/prod (optional)
      if (gen.name === 'dev') {
        fail(`scripts/${gen.path} missing - required for dev environment generation`);
        hasErrors = true;
      } else {
        warn(`scripts/${gen.path} missing - optional for ${gen.name} environment`);
      }
    }
  }

  // Summary
  console.log('\n==========================================');
  if (hasErrors) {
    console.log('❌ Registry validation failed!');
    console.log('\n💡 To fix:');
    console.log('1. Update standards/service-registry.yaml first');
    console.log('2. Run: make generate');
    console.log('3. Run: make audit');
    console.log('4. Commit changes');
    process.exit(1);
  } else {
    console.log('✅ Registry validation passed!');
    console.log('🎉 All configurations are in sync with registry.');
  }
}

main().catch(err => {
  console.error('Validation error:', err);
  process.exit(1);
});
