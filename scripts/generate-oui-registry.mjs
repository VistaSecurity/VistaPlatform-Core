#!/usr/bin/env node
// Generates the platform-side IEEE OUI registry (shared/ouiregistry) from:
//
//   standards/oui/ieee-mal.tsv   MA-L (24-bit) snapshot  } vendored by
//   standards/oui/ieee-mam.tsv   MA-M (28-bit) snapshot  } `make refresh-oui`
//   standards/oui/ieee-mas.tsv   MA-S (36-bit) snapshot  }
//   standards/oui/vendors.yaml   registrant -> canonical vendor map, plus pins
//
// Outputs:
//
//   shared/ouiregistry/registry_gen.tsv   prefix<TAB>vendor, embedded by the
//                                         Go package (one row per assignment)
//   shared/ouiregistry/canonical_gen.go   the canonical map, the pin set and
//                                         SnapshotID()
//
// Run via `make generate`; `make audit` runs it with --check and fails on
// drift. Offline by construction: it reads only the committed snapshot.
//
// Resolution of one assignment, in order:
//   1. a pin for exactly that prefix wins, whatever the registrant;
//   2. otherwise each registrant is canonicalised (the vendor map, or a
//      registrant spelled exactly like a canonical vendor), and the cleaned IEEE
//      spelling is kept for one the map does not name;
//   3. "IEEE Registration Authority" and "Private" are dropped: they mean the
//      registry does not say who owns the block, so the row is omitted;
//   4. an assignment the IEEE lists under registrants that resolve to
//      DIFFERENT vendors is omitted as ambiguous — picking one would be a guess.
//
// Strict on purpose. A registrant or pin that matches nothing fails the build:
// a vendor entry that silently resolves nothing is a check that cannot fail.
import fs from 'fs-extra';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
import { goStr } from './lib/registry-codegen.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');

export const SNAPSHOTS = [
  { file: 'ieee-mal.tsv', bits: 24, hex: 6 },
  { file: 'ieee-mam.tsv', bits: 28, hex: 7 },
  { file: 'ieee-mas.tsv', bits: 36, hex: 9 },
];

/** Registrant strings that mean "not determined", never a manufacturer. */
export const NOT_DETERMINED = new Set(['IEEE Registration Authority', 'Private']);

export const MAX_VENDOR_LEN = 64;

export class GenError extends Error {}
const fail = (msg) => {
  throw new GenError(msg);
};

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/** The same normalisation the refresh script applies to registrant names. */
export function cleanName(name) {
  return String(name)
    .replace(/，/g, ', ')
    .replace(/\s+/gu, ' ')
    .replace(/ ,/g, ',')
    .trim();
}

/**
 * Parses one snapshot TSV into a Map<assignment, string[]> of registrants.
 * Rejects anything that is not exactly the shape `make refresh-oui` writes.
 */
export function parseSnapshot(text, { file, hex }) {
  const re = new RegExp(`^[0-9A-F]{${hex}}$`);
  const out = new Map();
  const lines = text.split('\n');
  if (lines.at(-1) === '') lines.pop();
  lines.forEach((line, i) => {
    const where = `${file}:${i + 1}`;
    if (line.startsWith('#')) return;
    const cols = line.split('\t');
    if (cols.length !== 2) fail(`${where}: unparseable row (want "assignment<TAB>registrant"): ${JSON.stringify(line)}`);
    const [a, name] = cols;
    if (!re.test(a)) fail(`${where}: bad assignment ${JSON.stringify(a)} (want ${hex} upper-case hex digits)`);
    if (!name || name !== cleanName(name)) {
      fail(`${where}: registrant ${JSON.stringify(name)} is empty or not whitespace-normalised`);
    }
    if (!out.has(a)) out.set(a, []);
    const regs = out.get(a);
    if (regs.includes(name)) fail(`${where}: duplicate row ${a} ${JSON.stringify(name)}`);
    regs.push(name);
  });
  if (!out.size) fail(`${file}: no rows`);
  return out;
}

const PIN_RES = [
  { bits: 24, re: /^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}$/ },
  { bits: 28, re: /^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]$/ },
  { bits: 36, re: /^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]$/ },
];

/** "AA:BB:CC:D" -> { hex: "AABBCCD", bits: 28 }. */
export function parsePin(pin) {
  const s = String(pin);
  const m = PIN_RES.find((p) => p.re.test(s));
  if (!m) return null;
  return { hex: s.replace(/:/g, ''), bits: m.bits };
}

/** "AABBCCD" -> "aa:bb:cc:d", the Go package's Entry.Prefix form. */
export function displayPrefix(hex) {
  return hex
    .toLowerCase()
    .match(/.{1,2}/g)
    .join(':');
}

/** Validates vendors.yaml and returns its maps. */
export function parseVendors(doc, snapshots) {
  if (!doc || typeof doc !== 'object' || !Array.isArray(doc.vendors)) fail('vendors.yaml: top-level `vendors:` list is required');
  const allRegistrants = new Set();
  const assignmentsByBits = new Map();
  for (const s of SNAPSHOTS) assignmentsByBits.set(s.bits, snapshots.get(s.bits));
  for (const m of snapshots.values()) for (const regs of m.values()) for (const r of regs) allRegistrants.add(r);

  const registrantToVendor = new Map();
  const pins = new Map(); // hex -> { vendor, bits }
  const vendorNames = new Map(); // lower-case -> spelling
  const canonical = [];

  doc.vendors.forEach((e, i) => {
    const where = `vendors.yaml entry ${i + 1}`;
    if (!e || typeof e !== 'object' || Array.isArray(e)) fail(`${where}: not a mapping`);
    for (const k of Object.keys(e)) {
      if (!['vendor', 'registrants', 'pins', 'source'].includes(k)) fail(`${where}: unknown key ${JSON.stringify(k)}`);
    }
    const vendor = e.vendor;
    if (typeof vendor !== 'string' || !vendor.trim() || vendor !== cleanName(vendor)) {
      fail(`${where}: vendor must be a non-empty, whitespace-normalised string`);
    }
    const at = `${where} (${vendor})`;
    if (vendor.length > MAX_VENDOR_LEN) fail(`${at}: canonical name longer than ${MAX_VENDOR_LEN} characters`);
    if (NOT_DETERMINED.has(vendor)) fail(`${at}: ${JSON.stringify(vendor)} means "not determined" and cannot be a vendor`);
    const prior = vendorNames.get(vendor.toLowerCase());
    if (prior) fail(`${at}: vendor listed twice (already ${JSON.stringify(prior)})`);
    vendorNames.set(vendor.toLowerCase(), vendor);
    canonical.push(vendor);

    const registrants = e.registrants ?? [];
    const pinList = e.pins ?? [];
    if (!Array.isArray(registrants) || !Array.isArray(pinList)) fail(`${at}: registrants and pins must be lists`);
    if (!registrants.length && !pinList.length) fail(`${at}: needs at least one registrant or pin`);
    if (e.source !== undefined && (typeof e.source !== 'string' || !/^https:\/\/\S+$/.test(e.source))) {
      fail(`${at}: source must be an https URL`);
    }

    for (const r of registrants) {
      if (typeof r !== 'string' || !r) fail(`${at}: registrant must be a non-empty string`);
      if (NOT_DETERMINED.has(r)) fail(`${at}: registrant ${JSON.stringify(r)} means "not determined" and cannot be mapped to a vendor`);
      if (!allRegistrants.has(r)) {
        fail(`${at}: registrant ${JSON.stringify(r)} matches no row in the IEEE snapshot (typo, or renamed upstream?)`);
      }
      const owner = registrantToVendor.get(r);
      if (owner) fail(`${at}: registrant ${JSON.stringify(r)} already belongs to ${JSON.stringify(owner)}`);
      registrantToVendor.set(r, vendor);
    }

    for (const p of pinList) {
      const parsed = parsePin(p);
      if (!parsed) fail(`${at}: bad pin ${JSON.stringify(p)} (want "AA:BB:CC", "AA:BB:CC:D" or "AA:BB:CC:DE:F", upper case)`);
      const owner = pins.get(parsed.hex);
      if (owner) fail(`${at}: prefix ${p} is pinned to two vendors (${JSON.stringify(owner.vendor)} and ${JSON.stringify(vendor)})`);
      const inSnapshot = assignmentsByBits.get(parsed.bits).has(parsed.hex);
      if (!inSnapshot && !e.source) {
        fail(`${at}: pin ${p} is not in the IEEE snapshot, so the entry needs a \`source:\` saying what the prefix is`);
      }
      pins.set(parsed.hex, { vendor, bits: parsed.bits, pin: p });
    }
  });

  // A registrant spelled exactly like a canonical vendor IS that vendor. Doing
  // this implicitly keeps the invariant the Go package relies on: a resolved
  // name equal to a canonical name was canonicalised.
  const canonicalSet = new Set(canonical);
  for (const r of allRegistrants) {
    if (canonicalSet.has(r) && !registrantToVendor.has(r)) registrantToVendor.set(r, r);
  }
  return { registrantToVendor, pins, canonical: canonical.slice().sort(cmp), canonicalSet };
}

/** Resolves every assignment to the vendor the registry reports for it. */
export function resolve(snapshots, vendors) {
  const rows = [];
  const stats = { notDetermined: 0, ambiguous: [], pinned: 0, canonical: 0, raw: 0 };
  for (const { bits } of SNAPSHOTS) {
    for (const [a, regs] of snapshots.get(bits)) {
      const pin = vendors.pins.get(a);
      if (pin) {
        rows.push([a, pin.vendor]);
        stats.pinned++;
        continue;
      }
      const names = new Set();
      for (const r of regs) {
        if (NOT_DETERMINED.has(r)) continue;
        names.add(vendors.registrantToVendor.get(r) ?? r);
      }
      if (!names.size) {
        stats.notDetermined++;
        continue;
      }
      if (names.size > 1) {
        stats.ambiguous.push(`${a} (${[...names].join(' | ')})`);
        continue;
      }
      const [name] = names;
      if (name.length > 255 || /[\t\n]/.test(name)) fail(`${a}: unrepresentable vendor ${JSON.stringify(name)}`);
      rows.push([a, name]);
      if (vendors.canonicalSet.has(name)) stats.canonical++;
      else stats.raw++;
    }
  }
  // Pins outside the snapshot (locally-administered convention prefixes).
  for (const [hex, pin] of vendors.pins) {
    if (!snapshots.get(pin.bits).has(hex)) {
      rows.push([hex, pin.vendor]);
      stats.pinned++;
    }
  }
  rows.sort((x, y) => cmp(x[0], y[0]));
  return { rows, stats };
}

export function renderTSV(rows) {
  return rows.map(([a, v]) => `${a}\t${v}\n`).join('');
}

/** A short, stable fingerprint of the emitted rows. */
export function snapshotID(tsvBody) {
  return crypto.createHash('sha256').update(tsvBody).digest('hex').slice(0, 16);
}

const TSV_HEADER =
  '# Code generated by scripts/generate-oui-registry.mjs from standards/oui/. DO NOT EDIT.\n' +
  '# prefix (6, 7 or 9 upper-case hex digits = 24, 28 or 36 bits) <TAB> vendor\n';

export function renderGo(vendors, id, rowCount) {
  const regs = [...vendors.registrantToVendor].sort((a, b) => cmp(a[0], b[0]));
  const pins = [...vendors.pins].sort((a, b) => cmp(a[0], b[0]));
  return `// Code generated by scripts/generate-oui-registry.mjs from
// standards/oui/vendors.yaml and the IEEE snapshot in standards/oui/.
// DO NOT EDIT — edit vendors.yaml (or run \`make refresh-oui\`) and run
// \`make generate\`.

package ouiregistry

// snapshotID fingerprints the ${rowCount} rows of registry_gen.tsv (header
// excluded). It changes whenever any prefix or resolved vendor does.
const snapshotID = ${goStr(id)}

// SnapshotID returns a short, stable hash of the embedded registry, for
// anything that must change when the registry does (a learned model's
// feature-schema fingerprint, a cache key).
func SnapshotID() string { return snapshotID }

// registrantCanonicalPairs maps an IEEE registrant string (whitespace-
// normalised) to its canonical vendor name. A slice rather than a map literal
// so the generated file is gofmt-stable without column alignment; registry.go
// indexes it.
var registrantCanonicalPairs = [...][2]string{
${regs.map(([r, v]) => `\t{${goStr(r)}, ${goStr(v)}},`).join('\n')}
}

// canonicalVendorNames is every canonical name in standards/oui/vendors.yaml.
var canonicalVendorNames = [...]string{
${vendors.canonical.map((v) => `\t${goStr(v)},`).join('\n')}
}

// pinnedPrefixPairs are the prefixes vendors.yaml claims by name, whatever the
// IEEE registrant, in Entry.Prefix form.
var pinnedPrefixPairs = [...][2]string{
${pins.map(([hex, p]) => `\t{${goStr(displayPrefix(hex))}, ${goStr(p.vendor)}},`).join('\n')}
}
`;
}

/** Builds every output from already-read inputs. Throws GenError on bad input. */
export function build({ snapshotTexts, vendorsYAML }) {
  const snapshots = new Map();
  for (const s of SNAPSHOTS) snapshots.set(s.bits, parseSnapshot(snapshotTexts[s.file], s));
  let doc;
  try {
    doc = YAML.parse(vendorsYAML);
  } catch (err) {
    fail(`vendors.yaml: ${err.message}`);
  }
  const vendors = parseVendors(doc, snapshots);
  const { rows, stats } = resolve(snapshots, vendors);
  const body = renderTSV(rows);
  const id = snapshotID(body);
  const counts = Object.fromEntries(SNAPSHOTS.map((s) => [s.bits, snapshots.get(s.bits).size]));
  return {
    tsv: TSV_HEADER + body,
    go: renderGo(vendors, id, rows.length),
    stats: { ...stats, rows: rows.length, counts, vendors: vendors.canonical.length, pins: vendors.pins.size },
  };
}

export async function readInputs(dir = path.join(root, 'standards', 'oui')) {
  const snapshotTexts = {};
  for (const s of SNAPSHOTS) snapshotTexts[s.file] = await fs.readFile(path.join(dir, s.file), 'utf8');
  return { snapshotTexts, vendorsYAML: await fs.readFile(path.join(dir, 'vendors.yaml'), 'utf8') };
}

async function main() {
  const checkOnly = process.argv.includes('--check');
  const outDir = path.join(root, 'shared', 'ouiregistry');
  const outputs = [
    [path.join(outDir, 'registry_gen.tsv'), 'tsv'],
    [path.join(outDir, 'canonical_gen.go'), 'go'],
  ];
  let result;
  try {
    result = build(await readInputs());
  } catch (err) {
    if (err instanceof GenError) {
      console.error(`❌ oui-registry: ${err.message}`);
      process.exit(1);
    }
    throw err;
  }
  const { stats } = result;
  const summary =
    `${stats.rows} prefixes (MA-L ${stats.counts[24]}, MA-M ${stats.counts[28]}, MA-S ${stats.counts[36]} assignments; ` +
    `${stats.notDetermined} not determined, ${stats.ambiguous.length} ambiguous omitted), ` +
    `${stats.vendors} canonical vendors, ${stats.pins} pins`;

  if (checkOnly) {
    for (const [p, k] of outputs) {
      const current = (await fs.pathExists(p)) ? await fs.readFile(p, 'utf8') : '';
      if (current !== result[k]) {
        console.error(`❌ oui-registry: ${path.relative(root, p)} is out of date — run \`make generate\``);
        process.exit(1);
      }
    }
    console.log(`oui-registry check OK (${summary})`);
    return;
  }
  await fs.ensureDir(outDir);
  for (const [p, k] of outputs) await fs.writeFile(p, result[k]);
  console.log(`Generated: shared/ouiregistry/{registry_gen.tsv,canonical_gen.go} (${summary})`);
  if (stats.ambiguous.length) console.log(`  ambiguous (omitted): ${stats.ambiguous.join('; ')}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
