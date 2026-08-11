#!/usr/bin/env node
/**
 * Regression tests for the static audit guardrails added around local install
 * safety. The audits are meant to catch mutation-style failures, so the tests
 * run each real audit script in a temporary mini-repo with deliberately good
 * and bad fixtures.
 */

import { spawnSync } from 'node:child_process';
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

let failures = 0;

function check(desc, ok, detail = '') {
  if (ok) {
    console.log(`  ✓ ${desc}`);
  } else {
    failures++;
    console.error(`  ✗ ${desc}${detail ? `\n      ${detail}` : ''}`);
  }
}

function fixtureRoot(scriptName) {
  const dir = mkdtempSync(path.join(tmpdir(), 'audit-guardrail-test-'));
  mkdirSync(path.join(dir, 'scripts'), { recursive: true });
  copyFileSync(path.join(root, 'scripts', scriptName), path.join(dir, 'scripts', scriptName));
  return dir;
}

function runAudit(scriptName, setup) {
  const dir = fixtureRoot(scriptName);
  try {
    setup(dir);
    const result = spawnSync(process.execPath, [path.join(dir, 'scripts', scriptName), '--strict'], {
      cwd: dir,
      encoding: 'utf8',
    });
    return {
      status: result.status,
      output: `${result.stdout}${result.stderr}`,
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function expectAudit(desc, scriptName, setup, expectedStatus, expectedText = '') {
  const result = runAudit(scriptName, setup);
  check(
    desc,
    result.status === expectedStatus && (!expectedText || result.output.includes(expectedText)),
    `expected status ${expectedStatus}${expectedText ? ` and output containing ${JSON.stringify(expectedText)}` : ''}, ` +
      `got status ${result.status}\n${result.output}`,
  );
}

function writeEnv(dir, text) {
  writeFileSync(path.join(dir, 'env.example'), text.trimStart());
}

function writeCompose(dir, text) {
  writeFileSync(path.join(dir, 'docker-compose.yml'), text.trimStart());
}

function writeBootstrap(dir, text) {
  mkdirSync(path.join(dir, 'public'), { recursive: true });
  writeFileSync(path.join(dir, 'public', 'bootstrap-env.sh'), text.trimStart());
}

function writeShellScript(dir, name, text) {
  writeFileSync(path.join(dir, 'scripts', name), text.trimStart());
}

function runDockerScopeTest(setup, command, extraEnv = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), 'docker-scope-test-'));
  mkdirSync(path.join(dir, 'scripts', 'lib'), { recursive: true });
  copyFileSync(path.join(root, 'scripts', 'lib', 'docker-scope.sh'), path.join(dir, 'scripts', 'lib', 'docker-scope.sh'));
  try {
    setup(dir);
    const env = { ...process.env, ...extraEnv };
    if (!Object.prototype.hasOwnProperty.call(extraEnv, 'COMPOSE_PROJECT_NAME')) {
      delete env.COMPOSE_PROJECT_NAME;
    }
    return spawnSync('bash', ['-c', command], {
      cwd: dir,
      env,
      encoding: 'utf8',
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function expectDockerScope(desc, setup, command, expectedStatus, expectedStdout, extraEnv = {}) {
  const result = runDockerScopeTest(setup, command, extraEnv);
  check(
    desc,
    result.status === expectedStatus && result.stdout.trim() === expectedStdout,
    `expected status ${expectedStatus} and stdout ${JSON.stringify(expectedStdout)}, ` +
      `got status ${result.status}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
}

console.log('Audit guardrail regression tests');

// ─── Host-port audit ───────────────────────────────────────────────────────

expectAudit(
  'host-port audit accepts pinned, unique compose port variables',
  'audit-host-ports.mjs',
  (dir) => {
    writeEnv(dir, `
API_HOST_PORT=48080
WEB_HOST_PORT=43000
`);
    writeCompose(dir, `
services:
  api:
    ports:
      - "\${API_HOST_PORT:-8080}:8080"
  web:
    ports:
      - "\${WEB_HOST_PORT:-3000}:3000"
`);
  },
  0,
  'OK: every published host port is pinned',
);

expectAudit(
  'host-port audit fails when a published variable is missing from env.example',
  'audit-host-ports.mjs',
  (dir) => {
    writeEnv(dir, 'API_HOST_PORT=48080\n');
    writeCompose(dir, `
services:
  prometheus:
    ports:
      - "\${PROMETHEUS_HOST_PORT:-9091}:9091"
`);
  },
  1,
  'PROMETHEUS_HOST_PORT',
);

expectAudit(
  'host-port audit fails when two variables claim the same host port',
  'audit-host-ports.mjs',
  (dir) => {
    writeEnv(dir, `
API_HOST_PORT=48080
WEB_HOST_PORT=48080
`);
    writeCompose(dir, `
services:
  api:
    ports:
      - "\${API_HOST_PORT:-8080}:8080"
  web:
    ports:
      - "\${WEB_HOST_PORT:-3000}:3000"
`);
  },
  1,
  '48080: API_HOST_PORT',
);

// ─── Bootstrap-secret audit ────────────────────────────────────────────────

expectAudit(
  'bootstrap-secret audit accepts credentials whose placeholders are rotated',
  'audit-bootstrap-secrets.mjs',
  (dir) => {
    writeEnv(dir, `
POSTGRES_PASSWORD=postgres_dev
JWT_SECRET=jwt_dev_secret
`);
    writeBootstrap(dir, `
#!/usr/bin/env bash
rotate() { :; }
rotate POSTGRES_PASSWORD postgres_dev
rotate JWT_SECRET jwt_dev_secret
`);
  },
  0,
  'OK: every published credential placeholder is rotated',
);

expectAudit(
  'bootstrap-secret audit fails when a rotate line has a stale placeholder',
  'audit-bootstrap-secrets.mjs',
  (dir) => {
    writeEnv(dir, 'INFLUXDB_PASSWORD=adminpass123\n');
    writeBootstrap(dir, `
#!/usr/bin/env bash
rotate() { :; }
rotate INFLUXDB_PASSWORD influx_pass_dev
`);
  },
  1,
  'expects the placeholder',
);

expectAudit(
  'bootstrap-secret audit fails when a secret-like env value is never rotated',
  'audit-bootstrap-secrets.mjs',
  (dir) => {
    writeEnv(dir, `
POSTGRES_PASSWORD=postgres_dev
API_TOKEN=token_dev_123
`);
    writeBootstrap(dir, `
#!/usr/bin/env bash
rotate() { :; }
rotate POSTGRES_PASSWORD postgres_dev
`);
  },
  1,
  'API_TOKEN=token_dev_123',
);

// ─── Destructive-script audit ──────────────────────────────────────────────

expectAudit(
  'destructive-script audit accepts Docker removal scoped by compose project',
  'audit-destructive-scripts.mjs',
  (dir) => {
    writeShellScript(dir, 'cleanup.sh', `
#!/usr/bin/env bash
docker ps --filter "label=com.docker.compose.project=\${COMPOSE_PROJECT_NAME}" -aq | xargs -r docker rm -f
`);
  },
  0,
  'OK: no unscoped container/volume/network/image removal',
);

expectAudit(
  'destructive-script audit fails on unfiltered Docker container removal',
  'audit-destructive-scripts.mjs',
  (dir) => {
    writeShellScript(dir, 'cleanup.sh', `
#!/usr/bin/env bash
docker ps -aq | xargs -r docker rm -f
`);
  },
  1,
  'unfiltered list piped into a remove',
);

expectAudit(
  'destructive-script audit fails on ungated builder cache pruning',
  'audit-destructive-scripts.mjs',
  (dir) => {
    writeShellScript(dir, 'clean-cache.sh', `
#!/usr/bin/env bash
docker builder prune -af
`);
  },
  1,
  "'docker builder prune' cannot be scoped",
);

// ─── Docker-scope helper ──────────────────────────────────────────────────

const sourceDockerScope = `
docker() { return 0; }
source "$PWD/scripts/lib/docker-scope.sh"
`;

expectDockerScope(
  'docker-scope uses COMPOSE_PROJECT_NAME from the shell first',
  (dir) => {
    writeFileSync(path.join(dir, '.env'), 'COMPOSE_PROJECT_NAME=env_project\n');
  },
  `${sourceDockerScope}
compose_project_name "$PWD"
`,
  0,
  'shell_project',
  { COMPOSE_PROJECT_NAME: 'shell_project' },
);

expectDockerScope(
  'docker-scope uses COMPOSE_PROJECT_NAME from default .env before the directory basename',
  (dir) => {
    writeFileSync(path.join(dir, '.env'), 'COMPOSE_PROJECT_NAME=env_project\n');
  },
  `${sourceDockerScope}
compose_project_name "$PWD"
`,
  0,
  'env_project',
);

expectDockerScope(
  'docker-scope uses COMPOSE_PROJECT_NAME from the explicit compose env file',
  (dir) => {
    writeFileSync(path.join(dir, '.env'), 'COMPOSE_PROJECT_NAME=default_project\n');
    writeFileSync(path.join(dir, '.env.prod'), 'COMPOSE_PROJECT_NAME=prod_project\n');
  },
  `${sourceDockerScope}
compose_project_name "$PWD" ".env.prod"
`,
  0,
  'prod_project',
);

if (failures) {
  console.error(`\n❌ ${failures} audit guardrail regression check(s) failed`);
  process.exit(1);
}

console.log('✅ Audit guardrails catch the expected mutation failures');
