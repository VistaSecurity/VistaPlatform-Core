#!/usr/bin/env node
// Tests for scripts/generate-classification-rules.mjs, including mutation tests
// of its guards: each failure mode is provoked against the REAL committed inputs
// with one deliberate defect, so a guard that stopped firing goes red here.
//
//   node --test scripts/generate-classification-rules.test.mjs   (make classification-rules-test)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import yaml from 'yaml';
import { build, readInputs, GenError } from './generate-classification-rules.mjs';

const real = readInputs();

const withRules = (rulesYAML) => ({ ...real, rulesYAML });
const withVendors = (vendorsYAML) => ({ ...real, vendorsYAML });
const throwsGen = (inputs, re) => assert.throws(
  () => build(inputs),
  (err) => err instanceof GenError && re.test(err.message),
  `expected a GenError matching ${re}`,
);
const mutate = (text, from, to) => {
  const out = text.replace(from, to);
  assert.notEqual(out, text, `mutation ${from} did not apply`);
  return out;
};

test('the committed inputs build: one oui_vendor rule per oui_classes entry, no per-prefix rows', () => {
  const { rules } = build(real);
  const classes = Object.keys(yaml.parse(real.rulesYAML, { maxAliasCount: 10000 }).oui_classes);
  const vendorRules = rules.filter((r) => r.kind === 'oui_vendor');
  assert.equal(vendorRules.length, classes.length);
  assert.deepEqual(vendorRules.map((r) => r.pattern).sort(), [...classes].sort());
  for (const r of vendorRules) {
    assert.equal(r.vendor, r.pattern, `${r.pattern}: a vendor rule's vendor is its pattern`);
    assert.ok(r.class, `${r.pattern}: an oui_vendor rule exists only to carry a class`);
  }
  assert.equal(rules.filter((r) => r.kind === 'oui').length, 0, 'the shipped table carries no per-prefix rules');
});

test('a vendor whose prefixes the IEEE does not truthfully attribute cites its vendors.yaml source', () => {
  const byVendor = new Map(build(real).rules.filter((r) => r.kind === 'oui_vendor').map((r) => [r.pattern, r.sourceURL]));
  assert.equal(byVendor.get('QEMU virtual NIC'), 'https://libvirt.org/formatdomain.html');
  assert.equal(byVendor.get('Oracle VirtualBox'), 'https://www.virtualbox.org/manual/ch06.html');
  assert.equal(byVendor.get('VMware'), 'https://standards-oui.ieee.org/');
});

test('MUTATION: an oui_classes key that is not a canonical vendor fails generation', () => {
  throwsGen(withRules(mutate(real.rulesYAML, /\n  Brother Industries: /, '\n  Brother: ')),
    /oui_classes key names vendor "Brother", which standards\/oui\/vendors\.yaml spells "Brother Industries"/);
});

test('MUTATION: the gate reads vendors.yaml — renaming a vendor there fails generation here', () => {
  throwsGen(withVendors(mutate(real.vendorsYAML, /\n {2}- vendor: Brother Industries\n/, '\n  - vendor: Brother Industries Renamed\n')),
    /oui_classes key names vendor "Brother Industries"/);
});

test('MUTATION: a hand-written rule naming a non-canonical vendor fails, and names the spelling to use', () => {
  throwsGen(withRules(mutate(real.rulesYAML, /\n {4}vendor: Hewlett Packard\n/, '\n    vendor: Hewlett Packard Inc.\n')),
    /names vendor "Hewlett Packard Inc\.", which standards\/oui\/vendors\.yaml spells "Hewlett Packard"/);
});

test('MUTATION: vendors_outside_oui_table may not list a canonical vendor', () => {
  throwsGen(withRules(mutate(real.rulesYAML, 'vendors_outside_oui_table: []', 'vendors_outside_oui_table: [Zyxel]')),
    /vendors_outside_oui_table lists "Zyxel", which IS a canonical vendor/);
});

test('a vendor declared outside the registry is accepted for a hand-written rule, and not for oui_classes', () => {
  const declared = mutate(real.rulesYAML, 'vendors_outside_oui_table: []', 'vendors_outside_oui_table: [Nobody Networks]');
  const ruled = mutate(declared, /\n {4}vendor: Hewlett Packard\n/, '\n    vendor: Nobody Networks\n');
  assert.doesNotThrow(() => build(withRules(ruled)));
  throwsGen(withRules(mutate(declared, /\n {2}Brother Industries: /, '\n  Nobody Networks: ')),
    /oui_classes names "Nobody Networks", which is not a canonical vendor/);
});

test('MUTATION: a retired key fails rather than looking like it still does something', () => {
  throwsGen(withRules(`${real.rulesYAML}\noui_sources:\n  '52:54:00': https://libvirt.org/formatdomain.html\n`),
    /oui_sources is no longer read/);
  throwsGen(withRules(`${real.rulesYAML}\noui_vendor_only_confidence: 0.85\n`), /oui_vendor_only_confidence is no longer read/);
});

test('MUTATION: an oui_vendor rule written by hand in the rules list fails', () => {
  const extra = '\n  - kind: oui_vendor\n    pattern: Canon\n    class: printer\n    confidence: 0.80\n    source_url: *ieee\n';
  throwsGen(withRules(`${real.rulesYAML}${extra}`), /oui_vendor rules are generated from the oui_classes map/);
});

test('a hand-written oui PREFIX rule is accepted, and a malformed one is not', () => {
  const ok = '\n  - kind: oui\n    pattern: 00000C\n    class: router\n    confidence: 0.75\n    source_url: *ieee\n';
  const { rules } = build(withRules(`${real.rulesYAML}${ok}`));
  assert.equal(rules.filter((r) => r.kind === 'oui').length, 1);
  throwsGen(withRules(`${real.rulesYAML}${ok.replace('00000C', '"00:00:0c"')}`), /must be 6 uppercase hex digits/);
});

test('the dhcp_vendor_class rules build, every one anchored and carrying a class', () => {
  const dhcp = build(real).rules.filter((r) => r.kind === 'dhcp_vendor_class');
  assert.ok(dhcp.length >= 3, `only ${dhcp.length} dhcp_vendor_class rules built`);
  for (const r of dhcp) {
    assert.match(r.pattern, /^(\(\?[a-zA-Z]+\))?\^/, `${r.pattern}: not anchored`);
    assert.ok(r.class, `${r.pattern}: a dhcp_vendor_class rule exists to carry a class`);
  }
  assert.ok(dhcp.some((r) => r.pattern === '^MSFT 5\\.0$' && r.class === 'computer' && !r.vendor),
    'MSFT 5.0 must be computer with NO vendor: the OS vendor is not the hardware vendor');
});

test('MUTATION: an unanchored dhcp_vendor_class pattern fails generation', () => {
  throwsGen(withRules(mutate(real.rulesYAML, 'pattern: ^android-dhcp-', 'pattern: android-dhcp-')),
    /dhcp_vendor_class pattern "android-dhcp-" must be anchored/);
});

test('MUTATION: a dhcp_vendor_class pattern RE2 cannot compile, or that is malformed, fails generation', () => {
  throwsGen(withRules(mutate(real.rulesYAML, 'pattern: ^android-dhcp-', 'pattern: ^android-dhcp-(?!9)')),
    /dhcp_vendor_class pattern .* uses negative lookahead/);
  throwsGen(withRules(mutate(real.rulesYAML, 'pattern: ^android-dhcp-', 'pattern: ^android-(dhcp-')),
    /dhcp_vendor_class pattern .* has an unmatched '\('/);
});

test('MUTATION: dropping dhcp_vendor_class from kinds fails generation', () => {
  throwsGen(withRules(mutate(real.rulesYAML, '\n  - dhcp_vendor_class\n', '\n')), /kinds must be exactly/);
});
