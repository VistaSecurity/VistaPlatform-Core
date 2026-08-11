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
  await fs.ensureDir(path.resolve(root, 'docsv4', 'generated'));

  const services = registry.services || [];
  const ui = registry.ui || {};

  const tableHeader = '| Service | Dir | External:Internal | Route Prefix |\n|---|---|---|---|';
  const rows = services.map(s => {
    return `| ${s.name} | ${s.dir} | ${s.external_port}:${s.internal_port} | /api/v1${s.route_prefix} |`;
  });
  const table = [tableHeader, ...rows].join('\n');

  const portsMd = `<!-- GENERATED: DO NOT EDIT. Source: standards/service-registry.yaml -->\n${table}\n`;
  await fs.writeFile(path.resolve(root, 'docsv4', 'generated', 'service-ports.md'), portsMd);

  const uiTableHeader = '| UI | Path | External:Internal |';
  const uiRows = [
    `| tenant (${ui.tenant?.name || 'web-ui'}) | ${ui.tenant?.path || 'web-ui'} | ${ui.tenant?.external_port || ''}:${ui.tenant?.internal_port || ''} |`,
    `| admin (${ui.admin?.name || 'admin-ui'}) | ${ui.admin?.path || 'admin-ui'} | ${ui.admin?.external_port || ''}:${ui.admin?.internal_port || ''} |`
  ];
  const uiTable = [uiTableHeader, '|---|---|---|', ...uiRows].join('\n');
  await fs.writeFile(path.resolve(root, 'docsv4', 'generated', 'ui-ports.md'), `<!-- GENERATED: DO NOT EDIT. Source: standards/service-registry.yaml -->\n${uiTable}\n`);

  // Generate gateway route snippets (legacy format kept for reference tooling)
  const gatewayRoutes = services.map(s => {
    return `# ${s.name}: /api/v1${s.route_prefix}/ -> ${s.name}:8080`;
  }).join('\n');
  await fs.writeFile(path.resolve(root, 'config', 'generated', 'gateway-routes.txt'), `# GENERATED. Do not edit. Source: standards/service-registry.yaml\n${gatewayRoutes}\n`);

  // Generate a JSON summary for other tooling
  await fs.writeJson(path.resolve(root, 'config', 'generated', 'service-registry.json'), registry, { spaces: 2 });

  // No UI runtime config.json is generated: the active UIs (web-ui from
  // frontend-v2, admin-ui from admin-ui-v2/) use relative /api paths and read
  // no config.json.

  console.log('Generated: docsv4/generated/service-ports.md, docsv4/generated/ui-ports.md, config/generated/gateway-routes.txt, config/generated/service-registry.json');
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});


