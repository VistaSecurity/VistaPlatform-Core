#!/usr/bin/env node
import { promises as fs } from 'fs';
import path from 'path';

const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const outDir = path.join(repoRoot, 'architecture_docs', 'diagrams');

async function ensureOutDir() {
  await fs.mkdir(outDir, { recursive: true });
}

function toMermaidFlowchart(nodes, edges, title) {
  const lines = [
    '%% Auto-generated. Edit scripts/generate-diagrams.mjs instead.',
    `flowchart TD`,
    `%% ${title}`,
  ];
  for (const n of nodes) {
    lines.push(`${n.id}[${n.label}]`);
  }
  for (const e of edges) {
    const label = e.label ? `|${e.label}|` : '';
    lines.push(`${e.from} -->${label} ${e.to}`);
  }
  return lines.join('\n') + '\n';
}

async function readFileSafe(file) {
  try {
    return await fs.readFile(file, 'utf8');
  } catch (_) {
    return '';
  }
}

function extractReactRoutes(appTsxContent) {
  // Very simple heuristic parser for <Route path="..." element={...} />
  const routeRegex = /<Route\s+path=\"([^\"]+)\"/g;
  const paths = new Set();
  let m;
  while ((m = routeRegex.exec(appTsxContent)) !== null) {
    paths.add(m[1]);
  }
  return Array.from(paths);
}

async function genFrontendRoutes(projectName, appFilePath) {
  const src = await readFileSafe(appFilePath);
  if (!src) return null;
  const routes = extractReactRoutes(src).sort();
  const nodes = [{ id: 'root', label: `${projectName}` }];
  const edges = [];
  for (const p of routes) {
    const id = `r_${p.replace(/[^a-zA-Z0-9_]/g, '_') || 'root'}`;
    nodes.push({ id, label: p });
    edges.push({ from: 'root', to: id });
  }
  const mermaid = toMermaidFlowchart(nodes, edges, `${projectName} Routes`);
  const outFile = path.join(outDir, `${projectName}-routes.mmd`);
  await fs.writeFile(outFile, mermaid, 'utf8');
  return outFile;
}

function extractGinRoutes(goContent) {
  // Match lines like: router.METHOD("/path", ...), group.GET("/x", ...)
  // Capture method and path
  const routeRegex = /(GET|POST|PUT|DELETE|PATCH)\(\s*\"([^\"]+)\"/g;
  const routes = [];
  let m;
  while ((m = routeRegex.exec(goContent)) !== null) {
    routes.push({ method: m[1], path: m[2] });
  }
  return routes;
}

async function genGoServiceRoutes(serviceName, files) {
  const nodes = [{ id: 'svc', label: `${serviceName}` }];
  const edges = [];
  for (const f of files) {
    const content = await readFileSafe(f);
    if (!content) continue;
    const routes = extractGinRoutes(content);
    for (const r of routes) {
      const id = `g_${r.method}_${r.path.replace(/[^a-zA-Z0-9_]/g, '_')}`;
      nodes.push({ id, label: `${r.method} ${r.path}` });
      edges.push({ from: 'svc', to: id });
    }
  }
  const mermaid = toMermaidFlowchart(nodes, edges, `${serviceName} API`);
  const outFile = path.join(outDir, `${serviceName}-api.mmd`);
  await fs.writeFile(outFile, mermaid, 'utf8');
  return outFile;
}

async function main() {
  await ensureOutDir();
  const outputs = [];

  // Frontends
  outputs.push(await genFrontendRoutes('web-ui', path.join(repoRoot, 'web-ui', 'src', 'App.tsx')));
  outputs.push(await genFrontendRoutes('saas-admin-ui', path.join(repoRoot, 'saas-admin-ui', 'src', 'App.tsx')));

  // Go services (known routers)
  const authRouter = path.join(repoRoot, 'services', 'auth-service', 'internal', 'api', 'router.go');
  const saasAdminServer = path.join(repoRoot, 'services', 'saas-admin-service', 'internal', 'api', 'server.go');
  outputs.push(await genGoServiceRoutes('auth-service', [authRouter]));
  outputs.push(await genGoServiceRoutes('saas-admin-service', [saasAdminServer]));

  const filtered = outputs.filter(Boolean);
  console.log(`Generated ${filtered.length} diagram(s):`);
  for (const f of filtered) console.log(` - ${path.relative(repoRoot, f)}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});


