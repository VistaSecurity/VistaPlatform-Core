// Tests for scripts/generate-vocabulary.mjs and scripts/audit-vocabulary.mjs.
// Every case builds a throwaway tree in a temp dir and drives the real scripts
// (the audit through runAudit, the generator through its CLI), so a guard that
// stops guarding turns a test red. Mutation expectations are recorded in the PR.
//
//   node --test scripts/audit-vocabulary.test.mjs
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { runAudit } from './audit-vocabulary.mjs';
import { pluralKey } from './generate-vocabulary.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const GEN = path.join(here, 'generate-vocabulary.mjs');
const made = [];
after(() => { for (const d of made) fs.rmSync(d, { recursive: true, force: true }); });

const SPEC = `openapi: 3.0.3
info: { title: t, version: '1' }
components:
  schemas:
    Existing:
      type: object
      properties:
        name: { type: string }
    # BEGIN GENERATED: object kind — from standards/vocabulary.yaml (make generate)
    # END GENERATED: object kind
`;
const SCHEMA = `CREATE TABLE IF NOT EXISTS public.assets (id uuid, name text);
CREATE TABLE IF NOT EXISTS public.asset_endpoints (id uuid, port int);
`;

function vocab({ phase = 0, allow = ['frontend-v2/src/legacy.tsx'], forbidden } = {}) {
  return `version: 1
current_phase: ${phase}
audit:
  scopes:
    ui_strings: ['frontend-v2/src/**/*.{ts,tsx}']
    openapi: [api/openapi/*.yaml]
    schema: [scripts/database/schema.sql]
    customer_docs: [docsv4/core/**/*.md]
  allow_files: [${allow.join(', ')}]
reserved:
  - { key: asset, label: Asset, plural: Assets, meaning: A thing., netbox: dcim/device }
  - { key: endpoint, label: Endpoint, plural: Endpoints, meaning: A listener., netbox: ipam/service }
objects:
  - key: rack
    label: Rack
    plural: Racks
    table: racks
    netbox: dcim/rack
    phase: 2
    forbidden:
${forbidden ?? '      - { word: cabinet, where: [ui_strings, openapi, customer_docs, schema] }'}
  - key: prefix
    label: Prefix
    plural: Prefixes
    table: prefixes
    netbox: ipam/prefix
    phase: 1
`;
}

function fixture(opts = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vocab-'));
  made.push(root);
  const w = (rel, body) => { fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true }); fs.writeFileSync(path.join(root, rel), body); };
  w('standards/vocabulary.yaml', vocab(opts));
  w('api/openapi/inventory-service.openapi.yaml', SPEC);
  w('scripts/database/schema.sql', opts.schema ?? SCHEMA);
  w('frontend-v2/src/ok.tsx', 'export const A = () => <h1>Rack</h1>;\n');
  w('docsv4/core/a.md', '# Racks\n\nA rack holds devices.\n');
  const r = spawnSync('node', [GEN, '--root', root], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  return { root, w };
}

const words = (res) => res.hits.map((h) => h.word);

describe('forbidden words', () => {
  it('a baseline fixture is clean', () => {
    const { root } = fixture();
    const res = runAudit(root);
    assert.deepEqual(res.hits, []);
    assert.deepEqual(res.issues, []);
  });

  it('(a) a forbidden word in a UI string fails, with file:line', () => {
    const { root, w } = fixture();
    w('frontend-v2/src/bad.tsx', "const x = 1;\nexport const L = 'Server Cabinet';\n");
    const res = runAudit(root);
    assert.deepEqual(words(res), ['cabinet']);
    assert.equal(res.hits[0].file, 'frontend-v2/src/bad.tsx');
    assert.equal(res.hits[0].line, 2);
  });

  it('(a) JSX text is scanned; comments, imports and identifiers are not', () => {
    const { root, w } = fixture();
    w('frontend-v2/src/jsx.tsx', 'export const J = () => <p>the Cabinets</p>;\n');
    assert.deepEqual(words(runAudit(root)), ['cabinet']);
    w('frontend-v2/src/jsx.tsx', [
      "import { cabinetThing } from './cabinet';",
      '// a cabinet in a comment',
      '/* cabinet */',
      'const cabinetCount = 1; const CabinetRow = 2; const cabinet_id = 3;',
      "export const K = 'rack';",
    ].join('\n'));
    assert.deepEqual(words(runAudit(root)), []);
  });

  it('(b) the same word in an allow_files path passes', () => {
    const { root, w } = fixture();
    w('frontend-v2/src/legacy.tsx', "export const L = 'Server Cabinet';\n");
    assert.deepEqual(runAudit(root).hits, []);
    w('frontend-v2/src/other.tsx', "export const L = 'Server Cabinet';\n");
    assert.deepEqual(words(runAudit(root)), ['cabinet']);
  });

  it('(c) after_phase: 1 is not enforced at phase 0 and is at phase 1', () => {
    const f = "      - { word: cabinet, where: [ui_strings], after_phase: 1 }";
    const a = fixture({ phase: 0, forbidden: f });
    a.w('frontend-v2/src/bad.tsx', "export const L = 'Cabinet';\n");
    assert.deepEqual(runAudit(a.root).hits, []);
    const b = fixture({ phase: 1, forbidden: f });
    b.w('frontend-v2/src/bad.tsx', "export const L = 'Cabinet';\n");
    assert.deepEqual(words(runAudit(b.root)), ['cabinet']);
    const c = fixture({ phase: 2, forbidden: f });
    c.w('frontend-v2/src/bad.tsx', "export const L = 'Cabinet';\n");
    assert.deepEqual(words(runAudit(c.root)), ['cabinet']);
  });

  it('(e) the canonical label never fails', () => {
    const { root, w } = fixture({ phase: 9 });
    w('frontend-v2/src/canon.tsx', "export const L = ['Rack', 'Racks', 'Prefix', 'Prefixes'];\nexport const J = () => <b>Rack</b>;\n");
    w('docsv4/core/canon.md', 'A Rack is a Rack. Prefixes are listed.\n');
    assert.deepEqual(runAudit(root).hits, []);
  });

  it('multi-word terms match with spaces or hyphens, not snake_case keys', () => {
    const f = '      - { word: network space, where: [ui_strings, customer_docs] }';
    const { root, w } = fixture({ forbidden: f });
    w('frontend-v2/src/k.tsx', "export const keys = ['network_space', 'networkSpace'];\n");
    assert.deepEqual(runAudit(root).hits, []);
    w('frontend-v2/src/k.tsx', "export const a = 'Network  spaces'; export const b = 'network-space';\n");
    assert.equal(runAudit(root).hits.length, 2);
  });

  it('openapi: schema names, property names, title and description; not enum values', () => {
    const f = '      - { word: cabinet, where: [openapi] }';
    const { root, w } = fixture({ forbidden: f });
    w('api/openapi/x.openapi.yaml', `components:
  schemas:
    CabinetRow:
      type: object
      properties:
        cabinet_id: { type: string }
        ok: { type: string, description: 'lives in a cabinet' }
        kind: { type: string, enum: [cabinet] }
`);
    const res = runAudit(root);
    assert.deepEqual(res.hits.map((h) => [h.match, h.line]), [['CabinetRow', 3], ['cabinet_id', 6], ['cabinet', 7]]);
  });

  it('openapi names_only: schema names fail, property names and prose pass', () => {
    const f = '      - { word: cabinet, where: [openapi], names_only: true }';
    const { root, w } = fixture({ forbidden: f });
    w('api/openapi/x.openapi.yaml', `components:
  schemas:
    Fine:
      type: object
      description: 'lives in a cabinet'
      properties:
        cabinet_id: { type: string }
`);
    assert.deepEqual(runAudit(root).hits, []);
    w('api/openapi/x.openapi.yaml', `components:
  schemas:
    CabinetRow:
      type: object
`);
    assert.deepEqual(runAudit(root).hits.map((h) => h.match), ['CabinetRow']);
  });

  it('paths: an entry is enforced only in the listed files', () => {
    const f = "      - { word: cabinet, where: [customer_docs], paths: ['docsv4/core/inventory/**'] }";
    const { root, w } = fixture({ forbidden: f });
    w('docsv4/core/elsewhere.md', 'A cabinet.\n');
    assert.deepEqual(runAudit(root).hits, []);
    w('docsv4/core/inventory/x.md', 'A cabinet.\n');
    assert.deepEqual(runAudit(root).hits.map((h) => h.file), ['docsv4/core/inventory/x.md']);
  });

  it('allow_paths: an entry is exempt in the listed files only', () => {
    const f = "      - { word: cabinet, where: [ui_strings], allow_paths: ['frontend-v2/src/cmdb/**'] }";
    const { root, w } = fixture({ forbidden: f });
    w('frontend-v2/src/cmdb/x.tsx', "export const L = 'Cabinet';\n");
    assert.deepEqual(runAudit(root).hits, []);
    w('frontend-v2/src/inventory.tsx', "export const L = 'Cabinet';\n");
    assert.deepEqual(runAudit(root).hits.map((h) => h.file), ['frontend-v2/src/inventory.tsx']);
  });

  it('except: a named phrase is exempt in every scope, the bare word still fails', () => {
    const f = "      - { word: subnet, where: [ui_strings, openapi, customer_docs], except: ['subnet-router anycast'] }";
    const { root, w } = fixture({ forbidden: f });
    w('frontend-v2/src/a.tsx', "export const L = 'the subnet-router anycast address';\n");
    w('docsv4/core/a.md', 'The Subnet router anycast address.\n');
    w('api/openapi/x.openapi.yaml', `components:
  schemas:
    Ok:
      type: object
      description: 'reports the subnet-router anycast address'
      properties:
        subnet_router_anycast: { type: string }
`);
    assert.deepEqual(runAudit(root).hits, []);
    w('frontend-v2/src/b.tsx', "export const L = 'Add a subnet';\n");
    w('docsv4/core/b.md', 'Every subnet-router anycast and one subnet.\n');
    w('api/openapi/y.openapi.yaml', `components:
  schemas:
    Ok:
      type: object
      properties:
        subnet_mask: { type: string }
`);
    assert.deepEqual(runAudit(root).hits.map((h) => h.file).sort(), ['api/openapi/y.openapi.yaml', 'docsv4/core/b.md', 'frontend-v2/src/b.tsx']);
  });

  it('schema: table and column identifiers, not comments or string literals', () => {
    const f = '      - { word: cabinet, where: [schema] }';
    const { root } = fixture({ forbidden: f, schema: `${SCHEMA}-- a cabinet comment
CREATE TABLE IF NOT EXISTS public.cabinets (id uuid, cabinet_label text, note text DEFAULT 'cabinet');
` });
    const res = runAudit(root);
    assert.deepEqual(res.hits.map((h) => [h.match, h.line]), [['cabinets', 4], ['cabinet_label', 4]]);
  });

  it('customer_docs: prose is scanned, code is not, the generated glossary region is skipped', () => {
    const { root, w } = fixture();
    w('docsv4/core/p.md', 'See the cabinet.\n\n```\ncabinet in code\n```\n\nAnd `cabinet` inline.\n');
    assert.deepEqual(runAudit(root).hits.map((h) => h.line), [1]);
    w('docsv4/core/p.md', '<!-- BEGIN GENERATED: vocabulary — x -->\ncabinet\n<!-- END GENERATED: vocabulary -->\n');
    assert.deepEqual(runAudit(root).hits, []);
  });
});

describe('structural parity', () => {
  it('(d) a table carrying custom_fields with no vocabulary row fails', () => {
    const { root } = fixture({ schema: `${SCHEMA}CREATE TABLE IF NOT EXISTS public.widgets (id uuid, custom_fields jsonb);\n` });
    const res = runAudit(root);
    assert.equal(res.issues.length, 1);
    assert.match(res.issues[0].msg, /"widgets" carries custom_fields/);
    assert.equal(res.issues[0].line, 3);
  });

  it('a vocabulary table with custom_fields passes', () => {
    const { root } = fixture({ schema: `${SCHEMA}CREATE TABLE IF NOT EXISTS public.racks (id uuid, custom_fields jsonb);\n` });
    assert.deepEqual(runAudit(root).issues, []);
  });

  it('a singular table where the registry says plural fails', () => {
    const { root } = fixture({ schema: `${SCHEMA}CREATE TABLE IF NOT EXISTS public.rack (id uuid);\n` });
    const res = runAudit(root);
    assert.equal(res.issues.length, 1);
    assert.match(res.issues[0].msg, /must be named "racks"/);
  });

  it('a registry table in the schema with no generated ObjectKind constant fails', () => {
    const { root } = fixture({ schema: `${SCHEMA}CREATE TABLE IF NOT EXISTS public.racks (id uuid);\n` });
    const gen = path.join(root, 'shared/dcim/objectkind_gen.go');
    fs.writeFileSync(gen, fs.readFileSync(gen, 'utf8').replace(/^.*ObjectKindRack .*$/m, ''));
    const res = runAudit(root);
    assert.equal(res.issues.length, 1);
    assert.match(res.issues[0].msg, /no constant ObjectKindRack/);
  });

  it('the reserved kinds need their existing tables', () => {
    const { root } = fixture({ schema: 'CREATE TABLE IF NOT EXISTS public.assets (id uuid);\n' });
    assert.match(runAudit(root).issues[0].msg, /asset_endpoints/);
  });

  it('a registry table that is not the plural of its key is rejected by the generator', () => {
    const { root } = fixture();
    fs.writeFileSync(path.join(root, 'standards/vocabulary.yaml'), vocab().replace('table: racks', 'table: rack'));
    const r = spawnSync('node', [GEN, '--root', root], { encoding: 'utf8' });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /must be the plural of the key/);
    assert.match(runAudit(root).issues[0].msg, /must be the plural/);
  });

  it('pluralKey', () => {
    assert.equal(pluralKey('prefix'), 'prefixes');
    assert.equal(pluralKey('ip_address'), 'ip_addresses');
    assert.equal(pluralKey('journal_entry'), 'journal_entries');
    assert.equal(pluralKey('ike_policy'), 'ike_policies');
    assert.equal(pluralKey('virtual_chassis'), 'virtual_chassis');
    assert.equal(pluralKey('vrf'), 'vrfs');
  });
});

describe('generate --check', () => {
  const OUTPUTS = [
    'shared/dcim/objectkind_gen.go',
    'packages/primitives/src/dcim/object-kinds.gen.ts',
    'api/openapi/components/object-kind.yaml',
    'api/openapi/inventory-service.openapi.yaml',
    'docsv4/core/concepts/vocabulary.md',
  ];
  const check = (root) => spawnSync('node', [GEN, '--check', '--root', root], { encoding: 'utf8' });

  it('passes on a fresh tree', () => {
    const { root } = fixture();
    assert.equal(check(root).status, 0);
  });

  // Whole-file outputs take an appended line; the two region outputs take an
  // edit INSIDE the generated region (text outside it is hand-owned).
  const EDIT = {
    'api/openapi/inventory-service.openapi.yaml': (t) => t.replace('      - endpoint\n', '      - endpointx\n'),
    'docsv4/core/concepts/vocabulary.md': (t) => t.replace('| Asset |', '| Assetx |'),
  };
  for (const out of OUTPUTS) {
    it(`(f) a hand edit to ${out} is detected`, () => {
      const { root } = fixture();
      const p = path.join(root, out);
      const before = fs.readFileSync(p, 'utf8');
      const after = EDIT[out] ? EDIT[out](before) : `${before}\n# hand edit\n`;
      assert.notEqual(after, before, 'the edit must change the file');
      fs.writeFileSync(p, after);
      const r = check(root);
      assert.notEqual(r.status, 0);
      assert.ok(r.stderr.includes(out), r.stderr);
    });
  }

  it('hand-written text outside the generated regions is preserved and not drift', () => {
    const { root } = fixture();
    for (const out of ['api/openapi/inventory-service.openapi.yaml', 'docsv4/core/concepts/vocabulary.md']) {
      const p = path.join(root, out);
      fs.writeFileSync(p, `# hand-written preamble\n${fs.readFileSync(p, 'utf8')}`);
    }
    assert.equal(check(root).status, 0);
  });

  it('a changed registry without regeneration is detected', () => {
    const { root } = fixture();
    fs.writeFileSync(path.join(root, 'standards/vocabulary.yaml'), vocab().replace('label: Rack\n', 'label: Rackk\n'));
    assert.notEqual(check(root).status, 0);
  });

  it('is idempotent: a second generate changes nothing', () => {
    const { root } = fixture();
    const before = OUTPUTS.map((o) => fs.readFileSync(path.join(root, o), 'utf8'));
    spawnSync('node', [GEN, '--root', root]);
    assert.deepEqual(OUTPUTS.map((o) => fs.readFileSync(path.join(root, o), 'utf8')), before);
  });
});

describe('the real tree', () => {
  const repo = path.resolve(here, '..');
  it('is clean at its current_phase', () => {
    const res = runAudit(repo);
    assert.deepEqual(res.hits.slice(0, 5), []);
    assert.deepEqual(res.issues, []);
  });
  it('is wired into make generate, make audit and make standards-check', () => {
    const mk = fs.readFileSync(path.join(repo, 'Makefile'), 'utf8');
    const recipe = (name) => {
      const m = mk.match(new RegExp(`^${name}:.*\\n((?:\\t.*\\n|#.*\\n|\\n(?=\\t))*)`, 'm'));
      assert.ok(m, `no ${name} target`);
      return m[1];
    };
    assert.match(recipe('generate'), /generate-vocabulary\.mjs\s*\n/);
    assert.match(recipe('audit'), /generate-vocabulary\.mjs --check/);
    assert.match(recipe('audit'), /audit-vocabulary\.mjs\s*\n/);
    assert.match(mk.match(/^standards-check:.*$/m)[0], /\bvocabulary-test\b/);
  });
  it('generated outputs are current', () => {
    const r = spawnSync('node', [GEN, '--check'], { encoding: 'utf8', cwd: repo });
    assert.equal(r.status, 0, r.stderr);
  });
});
