#!/usr/bin/env node
// Tests for scripts/generate-oui-registry.mjs, including mutation tests of its
// own guards: each failure mode is provoked against the REAL committed inputs
// with one deliberate defect, so a guard that stopped firing goes red here.
//
//   node --test scripts/generate-oui-registry.test.mjs   (make oui-registry-test)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build, readInputs, GenError, parsePin, displayPrefix, cleanName } from './generate-oui-registry.mjs';
import { convert, parseCSV, cleanName as refreshCleanName } from './refresh-oui-snapshot.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const real = await readInputs();

const withVendors = (yaml) => ({ ...real, vendorsYAML: yaml });
const appendVendor = (entry) => withVendors(`${real.vendorsYAML}\n${entry}\n`);
const throwsGen = (inputs, re) => assert.throws(() => build(inputs), (err) => err instanceof GenError && re.test(err.message));

test('the committed inputs build, and the committed outputs are current', () => {
  const out = build(real);
  assert.ok(out.stats.rows > 40000, `only ${out.stats.rows} rows`);
  assert.equal(fs.readFileSync(path.join(root, 'shared/ouiregistry/registry_gen.tsv'), 'utf8'), out.tsv);
  assert.equal(fs.readFileSync(path.join(root, 'shared/ouiregistry/canonical_gen.go'), 'utf8'), out.go);
});

test('generation is deterministic', () => {
  assert.equal(build(real).tsv, build(real).tsv);
  assert.equal(build(real).go, build(real).go);
});

test('MUTATION: a registrant typo fails generation', () => {
  // Target the registrants list, not the header comment that quotes the
  // same string: a mutation of a comment proves nothing.
  const typo = real.vendorsYAML.replace('registrants: ["Cisco Systems, Inc"', 'registrants: ["Cisco Sytems, Inc"');
  assert.notEqual(typo, real.vendorsYAML, 'mutation did not apply');
  throwsGen(withVendors(typo), /"Cisco Sytems, Inc" matches no row/);
});

test('MUTATION: an unsourced pin absent from the snapshot fails generation', () => {
  const unsourced = real.vendorsYAML.replace(/\n    source: https:\/\/libvirt\.org\/formatdomain\.html/, '');
  assert.notEqual(unsourced, real.vendorsYAML, 'mutation did not apply');
  throwsGen(withVendors(unsourced), /pin 52:54:00 is not in the IEEE snapshot/);
});

test('MUTATION: a prefix pinned to two vendors fails generation', () => {
  throwsGen(appendVendor('  - vendor: Second Claimant\n    pins: ["00:0B:86"]'), /pinned to two vendors/);
});

test('MUTATION: a vendor listed twice fails generation', () => {
  throwsGen(appendVendor('  - vendor: cisco systems\n    pins: ["AA:AA:AA"]\n    source: https://example.com/'), /listed twice/);
});

test('MUTATION: a registrant claimed by two vendors fails generation', () => {
  throwsGen(appendVendor('  - vendor: Another Cisco\n    registrants: ["Cisco Systems, Inc"]'), /already belongs to "Cisco Systems"/);
});

test('MUTATION: a canonical name over 64 characters fails generation', () => {
  throwsGen(appendVendor(`  - vendor: ${'X'.repeat(65)}\n    registrants: ["Cisco Meraki"]`), /longer than 64/);
});

test('MUTATION: "IEEE Registration Authority" / "Private" cannot be vendors or registrants', () => {
  throwsGen(appendVendor('  - vendor: Private\n    pins: ["AA:AA:AA"]\n    source: https://example.com/'), /not determined/);
  throwsGen(appendVendor('  - vendor: IEEE Registration Authority\n    pins: ["AA:AA:AA"]\n    source: https://example.com/'), /not determined/);
  throwsGen(appendVendor('  - vendor: Hidden\n    registrants: ["Private"]'), /not determined/);
});

test('MUTATION: an unparseable snapshot row fails generation', () => {
  const broken = { ...real, snapshotTexts: { ...real.snapshotTexts } };
  broken.snapshotTexts['ieee-mam.tsv'] += 'NOT-A-ROW\n';
  throwsGen(broken, /unparseable row/);
  broken.snapshotTexts['ieee-mam.tsv'] = real.snapshotTexts['ieee-mam.tsv'] + 'ABCDEF\tSix digits in the 28-bit file\n';
  throwsGen(broken, /bad assignment/);
  broken.snapshotTexts['ieee-mam.tsv'] = real.snapshotTexts['ieee-mam.tsv'] + 'ABCDEF0\tTrailing space \n';
  throwsGen(broken, /not whitespace-normalised/);
});

test('MUTATION: an unknown key or a malformed pin fails generation', () => {
  throwsGen(appendVendor('  - vendor: Typo Key\n    registrant: ["Cisco Meraki"]'), /unknown key/);
  throwsGen(appendVendor('  - vendor: Bad Pin\n    pins: ["aa:bb:cc"]\n    source: https://example.com/'), /bad pin/);
});

test('pins beat registrants; RA, Private and ambiguous rows are omitted', () => {
  const rows = new Map(
    build(real)
      .tsv.split('\n')
      .filter((l) => l && !l.startsWith('#'))
      .map((l) => l.split('\t')),
  );
  assert.equal(rows.get('000B86'), 'Aruba Networks'); // registered to HPE
  assert.equal(rows.get('00155D'), 'Microsoft Hyper-V'); // registered to Microsoft
  assert.equal(rows.get('525400'), 'QEMU virtual NIC'); // not in the IEEE at all
  assert.equal(rows.get('00000C'), 'Cisco Systems');
  assert.equal(rows.has('0050C2'), false, 'Registration Authority row emitted');
  assert.equal(rows.has('000101'), false, 'Private row emitted');
  assert.equal(rows.has('080030'), false, 'ambiguous assignment emitted');
  for (const v of rows.values()) assert.ok(v !== 'IEEE Registration Authority' && v !== 'Private');
});

test('pin and prefix helpers', () => {
  assert.deepEqual(parsePin('00:50:C2'), { hex: '0050C2', bits: 24 });
  assert.deepEqual(parsePin('00:50:C2:0'), { hex: '0050C20', bits: 28 });
  assert.deepEqual(parsePin('00:50:C2:00:1'), { hex: '0050C2001', bits: 36 });
  assert.equal(parsePin('00:50:c2'), null);
  assert.equal(parsePin('00:50:C2:00'), null);
  assert.equal(displayPrefix('0050C2001'), '00:50:c2:00:1');
});

test('refresh: name cleaning matches the generator and handles real IEEE noise', () => {
  for (const raw of ['Acme  Corp \r\n', '\tAcme Corp', 'Acme Corp', 'Acme，Corp', 'Acme , Corp']) {
    assert.equal(refreshCleanName(raw), cleanName(raw));
    assert.ok(!/\s\s|^\s|\s$|，|[\t\r\n]/.test(cleanName(raw)), JSON.stringify(cleanName(raw)));
  }
  assert.equal(cleanName('Acme，Corp'), 'Acme, Corp');
});

test('refresh: CSV parsing and conversion', () => {
  const src = { registry: 'MA-M', hex: 7, url: 'test://mam' };
  const body =
    'Registry,Assignment,Organization Name,Organization Address\r\n' +
    'MA-M,ABCDEF1,"Zed, Inc. ","1 Road\r\nTown"\r\n' +
    'MA-M,ABCDEF0,"Quote ""Q"" Ltd",Addr\r\n' +
    'MA-M,ABCDEF0,Second Registrant,Addr\r\n';
  assert.deepEqual(convert(src, body), [
    ['ABCDEF0', 'Quote "Q" Ltd'],
    ['ABCDEF0', 'Second Registrant'],
    ['ABCDEF1', 'Zed, Inc.'],
  ]);
  assert.equal(parseCSV('a,"b\nc"\n').length, 1);
  assert.throws(() => convert(src, ''), /empty body/);
  assert.throws(() => convert(src, '<html>Request Rejected</html>'), /unexpected header/);
  assert.throws(() => convert(src, 'Registry,Assignment,Organization Name,Organization Address\nMA-L,ABCDEF,X,Y\n'), /registry "MA-L"/);
  assert.throws(() => convert(src, 'Registry,Assignment,Organization Name,Organization Address\nMA-M,ABCDEF,X,Y\n'), /bad assignment/);
});
