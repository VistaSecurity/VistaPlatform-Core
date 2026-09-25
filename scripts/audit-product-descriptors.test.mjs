#!/usr/bin/env node

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

const audit = join(import.meta.dirname, 'audit-product-descriptors.mjs');

function fixture({ descriptor = '', index = '', source = true } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'product-descriptor-audit-'));
  const dir = join(root, 'docsv4', 'internal', 'product-descriptors');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'README.md'), `
### \`topics\`
- \`asset-inventory\`
### \`audiences\`
- \`auditor\`
### \`regulatory\`
- \`soc2\`
### \`editions\`
`);
  writeFileSync(join(dir, 'INDEX.md'), index || `
| Slug | Maturity | Editions | Topics | Audiences | Regulatory | Last verified |
|------|----------|----------|--------|-----------|------------|---------------|
| [fixture](./fixture.md) | shipped | core, enterprise, msp | asset-inventory | auditor | soc2 | 2099-01-01 |
`);
  writeFileSync(join(dir, 'fixture.md'), descriptor || `---
title: Fixture
slug: fixture
summary: A fixture.
topics: [asset-inventory]
audiences: [auditor]
regulatory: [soc2]
editions: [core, enterprise, msp]
maturity: shipped
last_verified: 2099-01-01
source_of_truth:
  - evidence.txt
---
# Fixture

## Differentiators

- Evidence.

## Anti-claims

- No overclaim.

## Evidence pointers

- Source: \`evidence.txt\`
`);
  if (source) writeFileSync(join(root, 'evidence.txt'), 'evidence\n');
  return root;
}

function run(root, args = ['--strict']) {
  const result = spawnSync(process.execPath, [audit, ...args], {
    encoding: 'utf8',
    env: { ...process.env, PRODUCT_DESCRIPTOR_ROOT: root },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return {
    ok: result.status === 0,
    output: `${result.stdout ?? ''}${result.stderr ?? ''}`,
  };
}

test('accepts a complete descriptor whose index and evidence agree', (t) => {
  const root = fixture();
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const result = run(root);
  assert.equal(result.ok, true, result.output);
  assert.match(result.output, /audit passed: 1 descriptors/);
});

test('rejects a descriptor missing from the index', (t) => {
  const root = fixture({ index: '# Empty index\n' });
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const result = run(root);
  assert.equal(result.ok, false);
  assert.match(result.output, /missing from INDEX\.md full table/);
});

test('rejects a source_of_truth path that does not exist', (t) => {
  const root = fixture({ source: false });
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const result = run(root);
  assert.equal(result.ok, false);
  assert.match(result.output, /source_of_truth path does not exist/);
});

test('rejects undocumented controlled-vocabulary values', (t) => {
  const root = fixture();
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, 'docsv4', 'internal', 'product-descriptors', 'fixture.md');
  const original = readFileSync(path, 'utf8');
  writeFileSync(path, original.replace('topics: [asset-inventory]', 'topics: [invented-topic]'));
  const result = run(root);
  assert.equal(result.ok, false);
  assert.match(result.output, /uses undocumented value invented-topic/);
});

test('strict mode rejects stale verification while advisory mode warns', (t) => {
  const root = fixture();
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, 'docsv4', 'internal', 'product-descriptors', 'fixture.md');
  const indexPath = join(root, 'docsv4', 'internal', 'product-descriptors', 'INDEX.md');
  writeFileSync(path, readFileSync(path, 'utf8').replaceAll('2099-01-01', '2000-01-01'));
  writeFileSync(indexPath, readFileSync(indexPath, 'utf8').replaceAll('2099-01-01', '2000-01-01'));

  const advisory = run(root, []);
  assert.equal(advisory.ok, true, advisory.output);
  assert.match(advisory.output, /freshness warnings/);

  const strict = run(root);
  assert.equal(strict.ok, false);
  assert.match(strict.output, /Strict mode rejects stale product descriptors/);
});
