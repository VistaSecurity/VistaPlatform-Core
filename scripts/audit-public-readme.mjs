#!/usr/bin/env node
// public/README.md drift guard.
//
// The README is the first thing a prospective user reads and, until this
// check, the ONLY edition surface not cross-checked against source: the
// edition matrix (docsv4/core/editions.md) is generated and audited, the free
// framework list is pinned by free_frameworks_test.go, the lens registry is
// TypeScript — and the hand-written README said "six frameworks" and "nine
// lenses" for weeks after both had grown. A count in prose is a fact the
// reader will repeat; this asserts the README's numbers against the code
// that defines them.
//
// Sources of truth:
//   shared/services/free_frameworks.go          FreeFrameworkCodes  (Core frameworks)
//   frontend-v2/src/sections/inventory/lenses.ts INVENTORY_LENSES    (lenses)
//   shared/entitlements/editions.go              editionByItem       (paid keys)
//
// Adding a framework or a lens without touching the README fails `make audit`
// with the exact numbers to fix.
import { readFileSync } from 'node:fs';

const readme = readFileSync('public/README.md', 'utf8');
const failures = [];

// --- free frameworks ---------------------------------------------------------
const ffGo = readFileSync('shared/services/free_frameworks.go', 'utf8');
const ffBlock = ffGo.match(/FreeFrameworkCodes\s*=\s*\[\]string\{([\s\S]*?)\n\}/);
if (!ffBlock) failures.push('could not locate FreeFrameworkCodes in shared/services/free_frameworks.go');
const frameworkCount = ffBlock ? (ffBlock[1].match(/"[a-z0-9-]+"/g) || []).length : 0;
const words = { 5: 'five', 6: 'six', 7: 'seven', 8: 'eight', 9: 'nine', 10: 'ten', 11: 'eleven', 12: 'twelve', 13: 'thirteen' };
const frameworkWord = words[frameworkCount] ?? String(frameworkCount);

if (!new RegExp(`Core ships ${frameworkWord}\\s+frameworks`, 'i').test(readme.replace(/\n/g, ' '))) {
  failures.push(`README prose does not say "Core ships ${frameworkWord} frameworks" (FreeFrameworkCodes has ${frameworkCount})`);
}
if (!readme.includes(`Compliance engine + ${frameworkCount} frameworks`)) {
  failures.push(`README matrix row must read "Compliance engine + ${frameworkCount} frameworks"`);
}

// --- lenses ------------------------------------------------------------------
const lensTs = readFileSync('frontend-v2/src/sections/inventory/lenses.ts', 'utf8');
const lensBlock = lensTs.match(/INVENTORY_LENSES[^=]*=\s*\[([\s\S]*?)\n\];/);
if (!lensBlock) failures.push('could not locate INVENTORY_LENSES in frontend-v2/src/sections/inventory/lenses.ts');
const lensCount = lensBlock ? (lensBlock[1].match(/^\s*\{\s*key:/gm) || lensBlock[1].match(/\bkey:\s*'/g) || []).length : 0;
const lensWord = words[lensCount] ?? String(lensCount);
if (!new RegExp(`${lensWord}\\s+lenses`, 'i').test(readme.replace(/\n/g, ' '))) {
  failures.push(`README prose does not mention "${lensWord} lenses" (INVENTORY_LENSES has ${lensCount})`);
}
if (!readme.includes(`all ${lensWord} lenses`)) {
  failures.push(`README matrix row must read "all ${lensWord} lenses" (INVENTORY_LENSES has ${lensCount})`);
}

// --- edition rows vs. the gate ------------------------------------------------
// Every capability editionByItem gates must appear on a paid row, and nothing
// on a Core-only row may be gated. Matched by the README's own row wording
// via this small map, which is the one hand-maintained part: adding a gated
// key without a README row fails here with the key named.
const goEd = readFileSync('shared/entitlements/editions.go', 'utf8');
// Derive the gated keys TWICE, by two regexes that fail independently, and
// require the counts to agree. The framework and lens blocks above each fail
// loudly when their own pattern stops matching; this one used not to — an
// empty gatedKeys made the entire loop below a no-op and the audit passed
// while checking nothing. A key the strict pattern cannot read (renamed
// Edition constant, camelCase key, reformatted literal) now names itself
// here instead of silently dropping out of the audit.
const edBlock = goEd.match(/^var editionByItem = map\[string\]Edition\{([\s\S]*?)^\}/m);
if (!edBlock) failures.push('could not locate the editionByItem map literal in shared/entitlements/editions.go');
const gatedEntryCount = edBlock ? (edBlock[1].match(/:\s*Edition[A-Za-z]+\s*,/g) || []).length : 0;
const gatedMatches = [...goEd.matchAll(/^\s*"([a-z0-9_]+)":\s*Edition(Enterprise|MSP),/gm)];
const gatedKeys = gatedMatches.map((m) => m[1]);
// The minimum edition per key. An MSP-only key (billing_portal) must NOT tick
// Enterprise: an Enterprise licence does not cover it (shared/entitlements
// EditionCovers), and a README that ticks it sells something the resolver denies.
const editionOf = Object.fromEntries(gatedMatches.map((m) => [m[1], m[2]]));
if (edBlock && gatedKeys.length !== gatedEntryCount) {
  failures.push(
    `editionByItem has ${gatedEntryCount} entr${gatedEntryCount === 1 ? 'y' : 'ies'} but only ${gatedKeys.length} could be read ` +
      '— the key pattern in scripts/audit-public-readme.mjs no longer matches every entry, so some are going unchecked',
  );
}
if (edBlock && gatedEntryCount === 0) {
  failures.push('editionByItem parsed as empty — refusing to pass an edition-row audit that checked nothing');
}
const rowFor = {
  custom_policies: 'Custom policies + threshold overrides',
  threshold_overrides: 'Custom policies + threshold overrides',
  cbom_signing: 'CBOM evidence',
  sso_saml: 'SSO',
  billing_portal: 'Self-service billing',
  custom_branding: 'White-label branding',
  cmdb_sync: 'CMDB/ITSM sync',
  connector_netbox: 'NetBox network source of truth',
  siem_export: 'SIEM forwarding',
  ot_active_probing: 'OT/ICS active probing',
  ot_primary_lens: 'OT inventory lens',
};
const matrix = readme.split('\n').filter((l) => /^\|/.test(l));
for (const key of gatedKeys) {
  const label = rowFor[key];
  if (!label) {
    failures.push(`gated key "${key}" has no README row mapping in scripts/audit-public-readme.mjs — add the row and the mapping`);
    continue;
  }
  const row = matrix.find((l) => l.includes(label));
  if (!row) {
    failures.push(`README matrix has no row containing "${label}" for gated key "${key}"`);
    continue;
  }
  const cells = row.split('|').map((c) => c.trim());
  // cells: ['', label, core, enterprise, msp, '']
  if (cells[2] === '✅') failures.push(`README row "${label}" ticks Core, but "${key}" is edition-gated`);
  if (cells[4] !== '✅') failures.push(`README row "${label}" must tick MSP for gated key "${key}" — an MSP licence covers every gated capability`);
  if (editionOf[key] === 'MSP') {
    if (cells[3] === '✅') {
      failures.push(`README row "${label}" ticks Enterprise, but "${key}" is MSP-only — an Enterprise licence does not cover it`);
    }
  } else if (cells[3] !== '✅') {
    failures.push(`README row "${label}" must tick Enterprise for Enterprise-gated key "${key}"`);
  }
}
// Tier authoring is Core in the shipping build (admin-service mounts tier CRUD
// unconditionally); the README must not present it as paid.
const tierRow = matrix.find((l) => /entitlement authoring/i.test(l));
if (!tierRow) failures.push('README matrix has no "Plan and entitlement authoring" row');
else if (tierRow.split('|').map((c) => c.trim())[2] !== '✅') failures.push('README matrix must tick Core for plan/entitlement authoring — Core mounts it');

if (failures.length) {
  console.error('public README audit FAILED:');
  for (const f of failures) console.error('  - ' + f);
  process.exit(1);
}
console.log(`public README audit OK: ${frameworkCount} free frameworks, ${lensCount} lenses, ${gatedKeys.length} gated keys mapped to paid rows`);
