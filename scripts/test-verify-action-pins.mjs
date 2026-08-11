#!/usr/bin/env node
// Regression tests for scripts/verify-action-pins.sh. The tests copy the real
// verifier into a temp repo and provide a fake `gh` so pin checks are hermetic.

import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');
const verifier = path.join(root, 'scripts', 'verify-action-pins.sh');
const tempRoot = mkdtempSync(path.join(tmpdir(), 'verify-action-pins-test-'));

const validCheckoutSha = '1111111111111111111111111111111111111111';
const validSetupNodeSha = '2222222222222222222222222222222222222222';
const missingSha = '3333333333333333333333333333333333333333';

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function writeExecutable(filePath, content) {
  writeFileSync(filePath, content);
  chmodSync(filePath, 0o755);
}

function createRepo(name, files, validRoutes = []) {
  const repo = path.join(tempRoot, name);
  const bin = path.join(repo, 'bin');
  mkdirSync(path.join(repo, 'scripts'), { recursive: true });
  mkdirSync(bin, { recursive: true });
  writeExecutable(path.join(repo, 'scripts', 'verify-action-pins.sh'), readFileSync(verifier, 'utf8'));

  for (const [relPath, content] of Object.entries(files)) {
    const target = path.join(repo, relPath);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, content);
  }

  writeExecutable(
    path.join(bin, 'gh'),
    [
      '#!/usr/bin/env bash',
      'set -euo pipefail',
      'route="${2:-}"',
      `case "$route" in`,
      ...validRoutes.map((route) => `  "${route}") exit 0 ;;`),
      '  *) exit 1 ;;',
      'esac',
      '',
    ].join('\n'),
  );

  return { repo, bin };
}

function runVerifier(repo, bin) {
  return spawnSync('bash', [path.join(repo, 'scripts', 'verify-action-pins.sh')], {
    cwd: repo,
    env: { ...process.env, GITHUB_TOKEN: '', PATH: `${bin}:${process.env.PATH}` },
    encoding: 'utf8',
  });
}

function output(result) {
  return `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`;
}

function assertPassesYamlFixtures() {
  const { repo, bin } = createRepo(
    'passes-yaml-fixtures',
    {
      '.github/workflows/ci.yaml': [
        'name: CI',
        'jobs:',
        '  test:',
        '    runs-on: ubuntu-latest',
        '    steps:',
        `      - uses: actions/checkout@${validCheckoutSha}`,
        '      - uses: ./.github/actions/local-tool',
        '',
      ].join('\n'),
      '.github/actions/composite/action.yaml': [
        'name: composite',
        'runs:',
        '  using: composite',
        '  steps:',
        `    - uses: actions/setup-node@${validSetupNodeSha}`,
        '',
      ].join('\n'),
    },
    [
      `repos/actions/checkout/commits/${validCheckoutSha}`,
      `repos/actions/setup-node/commits/${validSetupNodeSha}`,
    ],
  );

  const result = runVerifier(repo, bin);
  assert(result.status === 0, `expected verifier to pass, got ${result.status}\n${output(result)}`);
  assert(
    result.stdout.includes('2 pinned action(s) verified'),
    `expected both .yaml fixtures to be checked, got:\n${result.stdout}`,
  );
}

function assertRejectsTagPins() {
  const { repo, bin } = createRepo('rejects-tag-pins', {
    '.github/workflows/release.yml': [
      'name: Release',
      'jobs:',
      '  release:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '',
    ].join('\n'),
  });

  const result = runVerifier(repo, bin);
  assert(result.status === 1, `expected tag pin rejection to exit 1, got ${result.status}\n${output(result)}`);
  assert(result.stdout.includes('actions/checkout@v4'), `expected rejected tag pin in stdout, got:\n${output(result)}`);
}

function assertRejectsUnresolvedShaPins() {
  const { repo, bin } = createRepo('rejects-unresolved-sha-pins', {
    '.github/workflows/release.yml': [
      'name: Release',
      'jobs:',
      '  release:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      `      - uses: actions/checkout@${missingSha}`,
      '',
    ].join('\n'),
  });

  const result = runVerifier(repo, bin);
  assert(result.status === 1, `expected missing SHA rejection to exit 1, got ${result.status}\n${output(result)}`);
  assert(result.stdout.includes('does not exist'), `expected missing SHA message in stdout, got:\n${output(result)}`);
}

try {
  assertPassesYamlFixtures();
  assertRejectsTagPins();
  assertRejectsUnresolvedShaPins();
  console.log('✅ action-pin verifier regression tests passed');
} finally {
  rmSync(tempRoot, { recursive: true, force: true });
}
