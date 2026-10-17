// Tests for scripts/generate-sync-authority.mjs. Every case builds a throwaway
// tree from the real registries and schema and drives the generator's CLI, so a
// guard that stops guarding turns a test red.
//
//   node --test scripts/generate-sync-authority.test.mjs
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '..');
const GEN = path.join(here, 'generate-sync-authority.mjs');
const OUT = 'shared/syncauthority/authority_gen.go';
const made = [];
after(() => { for (const d of made) fs.rmSync(d, { recursive: true, force: true }); });

function tree() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'sync-authority-'));
  made.push(d);
  fs.mkdirSync(path.join(d, 'standards'));
  for (const f of ['vocabulary.yaml', 'sync-authority.yaml']) {
    fs.copyFileSync(path.join(repo, 'standards', f), path.join(d, 'standards', f));
  }
  fs.mkdirSync(path.join(d, 'scripts', 'database'), { recursive: true });
  fs.copyFileSync(path.join(repo, 'scripts', 'database', 'schema.sql'), path.join(d, 'scripts', 'database', 'schema.sql'));
  return d;
}
const run = (d, ...args) => spawnSync('node', [GEN, '--root', d, ...args], { encoding: 'utf8' });
const edit = (d, file, fn) => { const p = path.join(d, file); fs.writeFileSync(p, fn(fs.readFileSync(p, 'utf8'))); };
const sub = (a, b) => (s) => { assert.ok(s.includes(a), `fixture edit "${a}" matched nothing`); return s.replace(a, b); };

describe('generate-sync-authority', () => {
  it('generates, then --check passes and a second run changes nothing', () => {
    const d = tree();
    assert.equal(run(d).status, 0);
    const before = fs.readFileSync(path.join(d, OUT), 'utf8');
    assert.equal(run(d, '--check').status, 0);
    assert.equal(run(d).status, 0);
    assert.equal(fs.readFileSync(path.join(d, OUT), 'utf8'), before);
    assert.match(before, /Kind: dcim\.ObjectKind\("prefix"\), NetBox: "ipam\/prefixes"/);
    assert.match(before, /\{Field: "business_unit_id", Authority: DeclaredHere\}/);
  });

  it('the committed output is current', () => {
    assert.equal(spawnSync('node', [GEN, '--check'], { encoding: 'utf8' }).status, 0);
  });

  it('--check fails on a hand-edited output and on a YAML change not regenerated', () => {
    let d = tree();
    run(d);
    fs.appendFileSync(path.join(d, OUT), '\n// hand edit\n');
    let r = run(d, '--check');
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /out of date/);

    d = tree();
    run(d);
    edit(d, 'standards/sync-authority.yaml', sub('newest_window_seconds: 300', 'newest_window_seconds: 600'));
    assert.notEqual(run(d, '--check').status, 0);
  });

  const refusals = [
    ['a kind not in the vocabulary', sub('  - kind: vrf\n', '  - kind: vrff\n'), /not an object kind/],
    ['a field that is not a column', sub('      rd: declared_here', '      route_distinguisher: declared_here'), /not a column of vrfs/],
    ['an identity column that is not a column', sub('identity: [vrf_id, prefix]', 'identity: [vrf, prefix]'), /identity column "vrf"/],
    ['an unknown authority', sub('      rd: declared_here', '      rd: theirs'), /authority "theirs"/],
    ['an identity column synced as a field', sub('      operational_status: declared_here\n      role_id: declared_here\n      vlan_id', '      prefix: newest\n      operational_status: declared_here\n      role_id: declared_here\n      vlan_id'), /identity column and cannot also be a synced field/],
    ['a bad netbox endpoint', sub('netbox: ipam/vrfs', 'netbox: vrfs'), /netbox endpoint/],
    // Row 3.5: a cable's ends are not columns of cables; `computed` admits them
    // and only them.
    ['a cable end not declared computed', sub('    computed: [a_terminations, b_terminations]\n', ''), /identity column "a_terminations" is not a column of cables/],
    ['a computed name that is a real column', sub('computed: [a_terminations, b_terminations]', 'computed: [a_terminations, b_terminations, label]'), /computed name "label" is a column of cables/],
    ['a computed name nothing uses', sub('computed: [a_terminations, b_terminations]', 'computed: [a_terminations, b_terminations, c_terminations]'), /computed name "c_terminations" is neither/],
  ];
  for (const [name, fn, msg] of refusals) {
    it(`refuses ${name}`, () => {
      const d = tree();
      edit(d, 'standards/sync-authority.yaml', fn);
      const r = run(d);
      assert.notEqual(r.status, 0, name);
      assert.match(r.stderr, msg);
      assert.notEqual(run(d, '--check').status, 0, `${name} under --check`);
    });
  }

  it('refuses a field whose column was renamed in the schema', () => {
    const d = tree();
    edit(d, 'scripts/database/schema.sql', sub('    rd text,', '    route_distinguisher text,'));
    const r = run(d);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /field "rd" is not a column of vrfs/);
  });

  it('reads a quoted column (ike_proposals."group") and still refuses one that is gone', () => {
    const d = tree();
    assert.equal(run(d).status, 0, 'the committed registry syncs ike_proposal.group');
    edit(d, 'scripts/database/schema.sql', sub('    "group" integer,', '    "dh_group" integer,'));
    const r = run(d);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /field "group" is not a column of ike_proposals/);
  });

  it('accepts a NetBox endpoint with a digit (vpn/l2vpns) and refuses a malformed one', () => {
    const d = tree();
    edit(d, 'standards/sync-authority.yaml', sub('netbox: vpn/l2vpns\n', 'netbox: vpn/L2VPNs\n'));
    const r = run(d);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /kind "l2vpn": netbox endpoint/);
  });
});
