// Tests for scripts/generate-dcim-types.mjs. Every case builds a throwaway tree
// from the real registries and drives the generator's CLI, so a guard that stops
// guarding turns a test red.
//
//   node --test scripts/generate-dcim-types.test.mjs
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '..');
const GEN = path.join(here, 'generate-dcim-types.mjs');
const made = [];
after(() => { for (const d of made) fs.rmSync(d, { recursive: true, force: true }); });

const SPEC = `openapi: 3.0.3
info: { title: t, version: '1' }
components:
  schemas:
    Existing:
      type: object
    # BEGIN GENERATED: dcim types — from standards/interface-types.yaml and standards/cable-types.yaml (make generate)
    # END GENERATED: dcim types
`;

function tree({ specSrc = SPEC } = {}) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'dcim-types-'));
  made.push(d);
  fs.mkdirSync(path.join(d, 'standards'));
  for (const f of ['vocabulary.yaml', 'interface-types.yaml', 'cable-types.yaml']) {
    fs.copyFileSync(path.join(repo, 'standards', f), path.join(d, 'standards', f));
  }
  fs.mkdirSync(path.join(d, 'api', 'openapi'), { recursive: true });
  fs.writeFileSync(path.join(d, 'api', 'openapi', 'inventory-service.openapi.yaml'), specSrc);
  // the vocabulary loader reads the reserved nouns' tables from nothing else, but
  // buildOutputs of the vocabulary generator is not run here.
  return d;
}
const run = (d, ...args) => spawnSync('node', [GEN, '--root', d, ...args], { encoding: 'utf8' });
const edit = (d, file, fn) => { const p = path.join(d, file); fs.writeFileSync(p, fn(fs.readFileSync(p, 'utf8'))); };
const sub = (a, b) => (s) => { assert.ok(s.includes(a), `fixture edit "${a}" matched nothing`); return s.replace(a, b); };

describe('generate-dcim-types', () => {
  it('generates all artefacts, then --check passes and a second run changes nothing', () => {
    const d = tree();
    assert.equal(run(d).status, 0);
    const snap = (f) => fs.readFileSync(path.join(d, f), 'utf8');
    const files = ['shared/dcim/types_gen.go', 'packages/primitives/src/dcim/types.gen.ts', 'api/openapi/inventory-service.openapi.yaml'];
    const before = files.map(snap);
    assert.equal(run(d, '--check').status, 0);
    assert.equal(run(d).status, 0);
    assert.deepEqual(files.map(snap), before);
    assert.match(before[2], /InterfaceType:[\s\S]*- 10gbase-x-sfpp[\s\S]*CableType:/);
  });

  it('--check fails on a hand-edited generated file', () => {
    for (const f of ['shared/dcim/types_gen.go', 'packages/primitives/src/dcim/types.gen.ts']) {
      const d = tree();
      run(d);
      fs.appendFileSync(path.join(d, f), '\n// hand edit\n');
      const r = run(d, '--check');
      assert.notEqual(r.status, 0, f);
      assert.match(r.stderr, /out of date/);
    }
  });

  it('--check fails when the YAML changes without regenerating', () => {
    const d = tree();
    run(d);
    edit(d, 'standards/cable-types.yaml', sub('key: "cat3", label: "CAT3"', 'key: "cat3", label: "CAT-3"'));
    assert.notEqual(run(d, '--check').status, 0);
  });

  it('--check fails when the spec region was edited by hand', () => {
    const d = tree();
    run(d);
    edit(d, 'api/openapi/inventory-service.openapi.yaml', sub('- cat3', '- cat3x'));
    assert.notEqual(run(d, '--check').status, 0);
  });

  it('rejects a duplicate key, a bad key and a key in two groups', () => {
    let d = tree();
    edit(d, 'standards/cable-types.yaml', sub('key: "cat5", label', 'key: "cat3", label'));
    assert.match(run(d).stderr, /duplicate key cat3/);
    d = tree();
    edit(d, 'standards/interface-types.yaml', sub('key: "virtual"', 'key: "Virtual_Thing"'));
    assert.match(run(d).stderr, /bad key/);
    d = tree();
    edit(d, 'standards/interface-types.yaml', sub('key: "lag"', 'key: "virtual"'));
    assert.match(run(d).stderr, /two groups|duplicate|collide/);
  });

  it('rejects a cable group outside the enum and an unlabeled entry', () => {
    let d = tree();
    edit(d, 'standards/cable-types.yaml', sub('group: power', 'group: wireless'));
    assert.match(run(d).stderr, /group "wireless"/);
    d = tree();
    edit(d, 'standards/interface-types.yaml', sub('label: "Virtual"', 'label: ""'));
    assert.match(run(d).stderr, /no label/);
  });

  it('rejects an asymmetric termination matrix', () => {
    const d = tree();
    edit(d, 'standards/cable-types.yaml', sub('power_outlet: [power_port]', 'power_outlet: [power_port, power_feed]'));
    const r = run(d);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /must be symmetric/);
  });

  it('rejects a matrix kind that is not an ObjectKind', () => {
    const d = tree();
    edit(d, 'standards/cable-types.yaml', sub('power_feed: [power_port]', 'power_feeed: [power_port]'));
    assert.match(run(d).stderr, /not an ObjectKind/);
  });

  it('fails loudly when the spec markers are missing', () => {
    const d = tree({ specSrc: SPEC.replace('# BEGIN GENERATED', '# BEGIN GENERATEDX') });
    const r = run(d);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /region markers/);
  });

  it('the repository itself is in sync', () => {
    const r = spawnSync('node', [GEN, '--check'], { encoding: 'utf8', cwd: repo });
    assert.equal(r.status, 0, r.stderr);
  });
});
