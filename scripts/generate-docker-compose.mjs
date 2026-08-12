#!/usr/bin/env node
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function main() {
  const root = path.resolve(__dirname, '..');
  const registryPath = path.resolve(root, 'standards', 'service-registry.yaml');
  
  if (!(await fs.pathExists(registryPath))) {
    console.error(`Registry not found: ${registryPath}`);
    process.exit(1);
  }
  
  const content = await fs.readFile(registryPath, 'utf8');
  const registry = yaml.parse(content);
  
  await fs.ensureDir(path.resolve(root, 'config', 'generated'));
  
  const services = registry.services || [];
  const infrastructure = registry.infrastructure?.exceptions || [];
  const images = registry.docker_images || {};
  const fixedPorts = registry.ports?.fixed_ports || {};
  const webUIPort = fixedPorts.web_ui || 3000;
  const adminUIPort = fixedPorts.admin_ui || 3006;

  // Generate service definitions for all services in registry
  const serviceDefinitions = {};
  
  for (const service of services) {
    if (service.status === 'optional') {
      // Add profile for optional services
      serviceDefinitions[service.name] = generateServiceDefinition(service, true, images, webUIPort, adminUIPort);
    } else {
      serviceDefinitions[service.name] = generateServiceDefinition(service, false, images, webUIPort, adminUIPort);
    }
  }
  
  // Generate the docker-compose services fragment
  const dockerComposeServices = {
    services: serviceDefinitions
  };
  
  const outputPath = path.resolve(root, 'config', 'generated', 'docker-compose-services.yml');
  const yamlContent = yaml.stringify(dockerComposeServices, { 
    indent: 2,
    lineWidth: 120,
    noRefs: true
  });
  
  const header = `# GENERATED: DO NOT EDIT. Source: standards/service-registry.yaml
# This file contains application service definitions generated from the service registry.
# Infrastructure services (postgres, redis, nats, influxdb) are defined in docker-compose.yml
# Last generated: ${new Date().toISOString()}

`;
  
  await fs.writeFile(outputPath, header + yamlContent);
  
  console.log(`Generated: config/generated/docker-compose-services.yml`);
  console.log(`  - ${services.length} services generated`);
  console.log(`  - Infrastructure exceptions: ${infrastructure.join(', ')}`);
}

function getBuildArgs(service, images = {}) {
  const goBuilder = images.go_builder || 'golang:1.26-alpine';
  const runtime   = images.runtime    || 'alpine:3.24.1';
  const node      = images.node       || 'node:24-alpine';
  const python    = images.python     || 'python:3.11-slim';

  const type = service.docker?.type;
  if (type === 'go-service') {
    return {
      GO_BUILDER_IMAGE: `\${GO_BUILDER_IMAGE:-${goBuilder}}`,
      RUNTIME_IMAGE: `\${RUNTIME_IMAGE:-${runtime}}`
    };
  } else if (type === 'python-service') {
    return {
      PYTHON_IMAGE: `\${PYTHON_IMAGE:-${python}}`
    };
  } else if (type === 'node-app') {
    return {
      NODE_IMAGE: `\${NODE_IMAGE:-${node}}`
    };
  }
  return null;
}

function generateServiceDefinition(service, isOptional = false, images = {}, webUIPort = 3000, adminUIPort = 3006) {
  const buildArgs = getBuildArgs(service, images);
  const buildDef = {
    context: '.',
    dockerfile: `./${service.dir}/Dockerfile.dev`
  };
  if (buildArgs) {
    buildDef.args = buildArgs;
  }

  const serviceDef = {
    build: buildDef,
    container_name: `crypto-${service.name}`,
    environment: generateEnvironmentVariables(service, webUIPort, adminUIPort),
    ports: [
      `"\${${getEnvVarName(service.name)}:-${service.external_port}}:${service.internal_port}"`
    ],
    depends_on: generateDependencies(service),
    networks: {
      'crypto-network': {
        aliases: [service.name]
      }
    },
    restart: 'unless-stopped'
  };
  
  // Add profile for optional services
  if (isOptional) {
    serviceDef.profiles = ['ai'];
  }
  
  // Note: Volume mounts removed to prevent interference with built binary
  // For development hot-reloading, use docker-compose.yml directly
  
  return serviceDef;
}

function generateEnvironmentVariables(service, webUIPort = 3000, adminUIPort = 3006) {
  const baseEnv = [
    `PORT=${service.internal_port}`,
    'ENV=development',
    'GIN_MODE=release',
    'DATABASE_URL=postgres://crypto_user:crypto_pass_dev@postgres:5432/crypto_inventory?sslmode=disable',
    'JWT_SECRET=dev-secret-key-change-in-production',
    'LOG_LEVEL=debug',
    `CORS_ORIGINS=\${DEV_CORS_ORIGINS:-http://localhost:\${WEB_UI_HOST_PORT:-${webUIPort}},http://localhost:\${ADMIN_UI_HOST_PORT:-${adminUIPort}}}`,
    // Version envs surfaced on /health. In dev the image isn't tagged with
    // a release version, so SERVICE_VERSION/CHART_VERSION resolve to "dev"
    // — accurate, and the About page renders "dev" instead of "unknown".
    'SERVICE_VERSION=${SERVICE_VERSION:-dev}',
    'CHART_VERSION=${CHART_VERSION:-dev}',
    'CHART_APP_VERSION=${CHART_APP_VERSION:-dev}'
  ];

  // Services that sign OR verify HMAC service-to-service requests
  // (shared/serviceauth) need the shared secret. Registry-driven: every service
  // that declares INTERNAL_AUTH_SECRET in required_secrets gets it — not a
  // single hardcoded service. (Hardcoding it to resource-tracker-service only
  // meant HMAC clients like compliance-engine silently sent unsigned calls and
  // got 401s in dev compose, matching the K8s bug.)
  if ((service.required_secrets || []).includes('INTERNAL_AUTH_SECRET')) {
    baseEnv.push('INTERNAL_AUTH_SECRET=dev-internal-auth-secret-change-in-production');
  }
  
  // Add service-specific environment variables
  if (service.name === 'auth-service') {
    baseEnv.push(
      'REDIS_URL=redis://:redis_pass_dev@redis:6379/0',
      'JWT_EXPIRY=24h',
      // Empty by default on purpose — auth-service treats "no SMTP host" as
      // "cannot deliver mail" and therefore does not demand email verification
      // it could never satisfy. A literal localhost here reinstates the lockout.
      'SMTP_HOST=${SMTP_HOST:-}',
      'SMTP_PORT=${SMTP_PORT:-587}',
      'SMTP_USERNAME=${SMTP_USERNAME:-}',
      'SMTP_PASSWORD=${SMTP_PASSWORD:-}',
      'FROM_EMAIL=${FROM_EMAIL:-noreply@example.com}',
      'FROM_NAME=${FROM_NAME:-Vista}'
    );
  } else if (service.name === 'inventory-service') {
    baseEnv.push(
      'SERVER_HOST=0.0.0.0'
    );
  } else if ([
    'compliance-engine', 'sensor-manager', 'cbom-service',
    'discovery-processor-service', 'device-interrogation-service',
    'admin-service', 'monitoring-service', 'audit-service',
    'cluster-sensor-service', 'inventory-service',
    'notification-service', 'resource-tracker-service',
    'tenant-health-service'
  ].includes(service.name)) {
    baseEnv.push(
      'NATS_URL=nats://nats_user:nats_pass_dev@nats:4222'
    );
  }
  
  // Agent-facing services fail closed by default: with no AGENT_MTLS_REQUIRED
  // set they demand a per-agent client certificate. Compose dev has no agent CA
  // and no TLS-passthrough listener, so state the opt-out explicitly here rather
  // than letting a dev sensor 401 with no obvious cause. Never set this false in
  // a real deployment — it accepts any caller that knows an agent UUID.
  if (['sensor-manager', 'device-interrogation-service'].includes(service.name)) {
    baseEnv.push(
      'AGENT_MTLS_REQUIRED=false'
    );
  }

  if (['inventory-service', 'sensor-manager', 'cbom-service'].includes(service.name)) {
    baseEnv.push(
      'INFLUXDB_URL=http://influxdb:8086',
      'INFLUXDB_TOKEN=dev-token-1234567890',
      'INFLUXDB_ORG=crypto-inventory',
      'INFLUXDB_BUCKET=metrics'
    );
  }
  
  if (['cbom-service'].includes(service.name)) {
    baseEnv.push(
      'REDIS_URL=redis://:redis_pass_dev@redis:6379/0'
    );
  }
  
  return baseEnv;
}

function generateDependencies(service) {
  const deps = service.name === 'resource-tracker-service' ? ['postgres', 'nats'] : ['postgres'];
  
  // Add service-specific dependencies
  if (['auth-service', 'cbom-service'].includes(service.name)) {
    deps.push('redis');
  }
  
  if (['inventory-service', 'sensor-manager', 'cbom-service'].includes(service.name)) {
    deps.push('influxdb');
  }
  
  if ([
    'compliance-engine', 'sensor-manager', 'cbom-service',
    'discovery-processor-service', 'device-interrogation-service',
    'admin-service', 'monitoring-service', 'audit-service',
    'cluster-sensor-service', 'inventory-service',
    'notification-service', 'resource-tracker-service',
    'tenant-health-service'
  ].includes(service.name)) {
    deps.push('nats');
  }
  
  // Convert to depends_on format with health conditions
  return deps.map(dep => ({
    [dep]: { condition: 'service_healthy' }
  }));
}

function getEnvVarName(serviceName) {
  const envVarMap = {
    'auth-service': 'AUTH_SERVICE_HOST_PORT',
    'inventory-service': 'INVENTORY_SERVICE_HOST_PORT',
    'compliance-engine': 'COMPLIANCE_ENGINE_HOST_PORT',
    'cbom-service': 'REPORT_GENERATOR_HOST_PORT',
    'sensor-manager': 'SENSOR_MANAGER_HOST_PORT',
    'cluster-sensor-service': 'CLUSTER_SENSOR_HOST_PORT',
    'admin-service': 'ADMIN_SERVICE_HOST_PORT',
    'monitoring-service': 'MONITORING_SERVICE_HOST_PORT',
    'resource-tracker-service': 'RESOURCE_TRACKER_HOST_PORT',
    'tenant-health-service': 'TENANT_HEALTH_HOST_PORT'
  };
  
  return envVarMap[serviceName] || `${serviceName.toUpperCase().replace(/-/g, '_')}_HOST_PORT`;
}

main().catch(err => {
  console.error('Docker compose generation error:', err);
  process.exit(1);
});
