#!/usr/bin/env node
// Generates the classification-rule artefacts from
// standards/classification-rules.yaml (asset-inventory ADR-0004 D6;
// BUILD_PLAN workstream 2.10a).
//
// Outputs:
//   shared/classify/rules_gen.go   (whole file)  — the engine's default table
//   scripts/database/seed.sql      (1 region)    — the seeded rows
//
// Run via `make generate`; `make audit` runs `--check` and fails on drift.
//
// The Go table and the seeded rows are the SAME rules in two places on
// purpose. The Go table is what `classify.Default()` loads, so the sensor, the
// device agent and every unit test classify identically with no database at
// all; the seeded rows are what a platform admin then curates, and what the
// services load at runtime. Generating both from one file is what stops the
// two from drifting — which is the failure this repo has paid for often enough
// to generate everything with two homes.
//
// MAC-keyed rules are written against the VENDOR, not the prefix. The IEEE
// registry (shared/ouiregistry, generated from standards/oui/) resolves a MAC
// to a canonical manufacturer inside the engine, so the vendor needs no rule
// at all; a CLASS for a manufacturer whose networked products are all one
// thing comes from the YAML's `oui_classes` map, which this generator turns
// into one `oui_vendor` rule per entry. Every vendor named anywhere must be a
// canonical name in standards/oui/vendors.yaml (read here, never restated) or
// be declared in `vendors_outside_oui_table`.
//
// Validation here is the FIRST of the two gates the rules pass. This one
// checks shape: known kind, well-formed pattern for that kind, a class key
// that exists in standards/asset-classes.yaml, a confidence in range, a source
// URL present. The second gate is shared/classify's own validation, which runs
// against the same rules at load time and additionally compiles every banner
// regexp with Go's RE2 — a JS RegExp accepts constructs RE2 rejects, so the
// check that matters happens in the language that will run them.
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';
import { goStr, fail as sharedFail } from './lib/registry-codegen.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

/** A generation failure. Thrown so the tests can provoke each guard; main()
 * turns it into the usual message and exit status. */
export class GenError extends Error {}
const fail = (msg) => { throw new GenError(msg); };

// Confidence bounds. The floor is 0.50 because a rule that is less than
// even money is not a proposal, it is noise in the approval queue; the ceiling
// is 0.95 because nothing in this file is a measurement — every row is an
// inference from an identifier, and 1.0 would say otherwise.
const MIN_CONFIDENCE = 0.5;
const MAX_CONFIDENCE = 0.95;

const KIND_ORDER = [
  'oui', 'oui_vendor', 'sysobjectid', 'enip', 'cloud_type', 'banner', 'port_profile', 'model', 'platform',
  'cdp_capabilities', 'lldp_capability', 'mdns_service', 'os_name', 'dhcp_vendor_class',
];

const OUI = /^[0-9A-F]{6}$/;
const SYSOBJECTID = /^1\.3\.6\.1\.4\.1(\.\d+)+$/;
const DECIMAL = /^\d+$/;
const CLOUD_TYPE = /^[a-z][a-z0-9_]*$/;
const PORT_PROFILE = /^\d+(,\d+)+$/;
// A capability SET: one or more lowercase capability names, ascending and
// deduplicated. One name is a perfectly good set -- most rules name exactly one
// -- which is the difference from a port profile, where one port is explicitly
// not a profile.
const CAPABILITY_SET = /^[a-z0-9_]+(,[a-z0-9_]+)*$/;
// DNS-SD `<Service>.<Proto>` (RFC 6763 section 7), lowercase.
const MDNS_SERVICE = /^_[a-z0-9][a-z0-9-]*\._(tcp|udp)$/;

// ---------------------------------------------------------------------------
// load + validate
// ---------------------------------------------------------------------------

const VENDORS_YAML = path.join('standards', 'oui', 'vendors.yaml');

/**
 * Reads the canonical vendor names from standards/oui/vendors.yaml, with the
 * `source:` each one carries where it has one.
 *
 * Read here rather than restated: that file is the ONE place a manufacturer's
 * spelling is decided (scripts/generate-oui-registry.mjs compiles it into
 * shared/ouiregistry, which is what the engine resolves MACs against). A second
 * list in this generator would be a second spelling authority, which is the
 * drift this whole arrangement exists to prevent.
 *
 * Returns Map<vendor, sourceURL|null>.
 */
export function loadCanonicalVendors(text) {
  const doc = yaml.parse(text);
  const out = new Map();
  for (const [i, e] of (doc?.vendors || []).entries()) {
    const name = e?.vendor;
    if (typeof name !== 'string' || !name) fail(`${VENDORS_YAML}: vendors[${i}] has no vendor name`);
    out.set(name, typeof e.source === 'string' && e.source ? e.source : null);
  }
  if (out.size < 50) fail(`${VENDORS_YAML}: only ${out.size} canonical vendors read; the parse is not finding the list`);
  return out;
}

/**
 * Turns the YAML's vendor -> class map into `oui_vendor` rules, one per entry.
 *
 * A vendor that is NOT in the map needs no rule at all: the engine reports the
 * registry's canonical vendor for every MAC it resolves, rule or none. The map
 * exists only for the minority of manufacturers whose networked products are
 * all one thing.
 *
 * The canonical-vendor gate is the check that has to be able to fail. An
 * `oui_vendor` rule matches only a CANONICAL name, so a key spelled any other
 * way — "Brother" for "Brother Industries" — is a class that silently applies
 * to nothing, ever. `vendors_outside_oui_table` does not excuse it either: a
 * vendor the registry lacks can never be what a MAC resolves to.
 */
export function ouiVendorRules(reg, classKeys, canonical) {
  const map = reg.oui_classes || {};
  const ieee = reg.sources?.ieee;
  if (typeof ieee !== 'string' || !/^https?:\/\//.test(ieee)) {
    fail('sources.ieee must be the IEEE registry URL — it is the citation every oui_vendor rule carries');
  }

  return Object.entries(map).map(([vendor, entry]) => {
    if (!canonical.has(vendor)) {
      fail(`oui_classes names ${JSON.stringify(vendor)}, which is not a canonical vendor in ${VENDORS_YAML}. `
        + 'An oui_vendor rule matches only the canonical spelling, so this class would apply to nothing. '
        + `Spell it as ${VENDORS_YAML} does, or add the vendor (with its IEEE registrant strings) there first.`);
    }
    if (!entry || typeof entry !== 'object') fail(`oui_classes[${JSON.stringify(vendor)}] is not a mapping`);
    if (!entry.class) fail(`oui_classes[${JSON.stringify(vendor)}] has no class`);
    if (!classKeys.has(entry.class)) {
      fail(`oui_classes[${JSON.stringify(vendor)}]: class ${JSON.stringify(entry.class)} is not in standards/asset-classes.yaml`);
    }
    if (typeof entry.confidence !== 'number') {
      fail(`oui_classes[${JSON.stringify(vendor)}] has no numeric confidence`);
    }
    if (entry.confidence < MIN_CONFIDENCE || entry.confidence > MAX_CONFIDENCE) {
      fail(`oui_classes[${JSON.stringify(vendor)}]: confidence ${entry.confidence} is outside ${MIN_CONFIDENCE}-${MAX_CONFIDENCE}`);
    }
    if (Math.round(entry.confidence * 100) !== entry.confidence * 100) {
      fail(`oui_classes[${JSON.stringify(vendor)}]: confidence ${entry.confidence} has more than two decimal places`);
    }
    for (const key of Object.keys(entry)) {
      if (!['class', 'confidence'].includes(key)) {
        fail(`oui_classes[${JSON.stringify(vendor)}]: unknown field ${JSON.stringify(key)}`);
      }
    }
    // The citation. IEEE by default, because that is where MAC -> vendor comes
    // from. A vendor whose entry in vendors.yaml carries a `source:` is one the
    // IEEE does not (truthfully) attribute — a locally-administered convention
    // such as QEMU's 52:54:00, or a prefix registered to someone else that only
    // ever carries one product (08:00:27, VirtualBox) — and citing the IEEE for
    // it would be a citation that does not say what the rule says.
    const sourceURL = canonical.get(vendor) ?? ieee;
    return {
      kind: 'oui_vendor', pattern: vendor, class: entry.class, vendor, model: '',
      confidence: entry.confidence, sourceURL,
    };
  });
}

/**
 * Keys this generator used to read and no longer does. Present in the YAML,
 * each would look like it still did something.
 */
const RETIRED_KEYS = {
  oui_sources: `per-prefix citations now live in ${VENDORS_YAML} as a pin's \`source:\``,
  oui_vendor_only_confidence: 'the registry\'s own vendor statement carries classify.RegistryVendorConfidence; no vendor-only rows are generated',
};

/**
 * Checks that every vendor a rule names — and every `oui_classes` key — is
 * spelled exactly as standards/oui/vendors.yaml spells a canonical vendor, or
 * is declared in `vendors_outside_oui_table`.
 *
 * One manufacturer, one name. Two spellings is not a cosmetic problem here: the
 * engine's vendor arbitration refuses to choose between two statements naming
 * DIFFERENT vendors at similar confidence, so `Dell` from the registry and
 * `Dell Inc.` on a sysObjectID rule do not disagree loudly — they cancel, and a
 * Dell server seen by both MAC and SNMP comes back with no vendor at all. The
 * same pair also breaks the hw.vendor join the end-of-life catalogue exists for.
 *
 * A manufacturer the IEEE registry genuinely lacks is legitimate, but it has to
 * be DECLARED, so that adding it to vendors.yaml later cannot quietly introduce
 * a second spelling — and a declared one that IS canonical fails, because the
 * declaration would then be hiding nothing.
 */
export function checkVendorSpellings(reg, rules, canonical) {
  const declared = reg.vendors_outside_oui_table ?? [];
  if (!Array.isArray(declared)) fail('vendors_outside_oui_table must be a list');

  for (const vendor of declared) {
    if (canonical.has(vendor)) {
      fail(`vendors_outside_oui_table lists ${JSON.stringify(vendor)}, which IS a canonical vendor in ${VENDORS_YAML}. `
        + 'Remove it from the list — vendors.yaml is the spelling, and the list is only for manufacturers the IEEE registry lacks.');
    }
  }
  const allowed = new Set(declared);

  const fold = (s) => s.toLowerCase().replace(/[^a-z0-9]/g, '');
  // Near-match the way the engine's own vendorAgrees does — fold-equal, or one
  // folded name a prefix of the other — so the message can NAME the spelling to
  // use. "Dell Inc." against "Dell" is the common shape and the one an exact
  // lookup would miss, leaving the author to go and grep the vendor file.
  const near = (vendor) => {
    const f = fold(vendor);
    for (const v of canonical.keys()) {
      const g = fold(v);
      if (f === g) return v;
      const [short, long] = f.length <= g.length ? [f, g] : [g, f];
      if (short.length >= 3 && long.startsWith(short)) return v;
    }
    return null;
  };

  const named = [
    ...Object.keys(reg.oui_classes || {}).map((v) => ({ what: `oui_classes key`, vendor: v })),
    ...rules.filter((r) => r.vendor).map((r) => ({ what: `${r.kind} rule ${JSON.stringify(r.pattern)}`, vendor: r.vendor })),
  ];
  for (const { what, vendor } of named) {
    if (canonical.has(vendor) || allowed.has(vendor)) continue;
    const suggestion = near(vendor);
    fail(`${what} names vendor ${JSON.stringify(vendor)}, `
      + (suggestion
        ? `which ${VENDORS_YAML} spells ${JSON.stringify(suggestion)}. One manufacturer, one name: the engine `
          + 'refuses to choose between two statements naming different vendors at similar confidence, so two '
          + 'spellings do not disagree — they cancel, and the asset comes back with no vendor.'
        : `which is not a canonical vendor in ${VENDORS_YAML}. Either add it there (with its IEEE registrant `
          + 'strings), or — only if the IEEE registry genuinely lacks it — declare the name in vendors_outside_oui_table.'));
  }
}

function loadClassKeys() {
  const reg = yaml.parse(
    fs.readFileSync(path.join(root, 'standards', 'asset-classes.yaml'), 'utf8'),
  );
  const keys = new Set();
  const walk = (nodes) => {
    for (const n of nodes || []) {
      if (n && n.key) keys.add(n.key);
      if (n && n.children) walk(n.children);
    }
  };
  walk(reg.classes);
  if (keys.size < 20) {
    fail(`only ${keys.size} asset-class keys were read from standards/asset-classes.yaml; the walk is not finding the tree`);
  }
  return keys;
}

/** Validates one rule and returns it normalised. */
function normalise(rule, index, classKeys, kinds) {
  const where = `rules[${index}]`;
  if (!rule || typeof rule !== 'object') fail(`${where} is not a mapping`);

  const kind = rule.kind;
  if (!kind) fail(`${where} has no kind`);
  if (!kinds.has(kind)) fail(`${where}: unknown kind ${JSON.stringify(kind)}`);

  // A YAML scalar like `1.3.6.1.4.1.9` parses as a string, but a bare `1`
  // parses as a NUMBER, and `631,9100` as a string. Coerce so a pattern is
  // always compared and emitted as text — this is exactly how an ENIP vendor
  // id written unquoted would otherwise reach the generated Go as an int and
  // the database as '1' anyway, i.e. silently fine in one place and not the
  // other.
  const pattern = String(rule.pattern ?? '');
  if (!pattern) fail(`${where}: has no pattern`);

  switch (kind) {
    case 'oui':
      // A PREFIX rule, for the rare assignment a vendor-level statement cannot
      // express. It outranks the vendor rules for the MACs it covers. Not the
      // way to name a vendor (the registry does that) or to give one a class
      // (oui_classes does that).
      if (!OUI.test(pattern)) {
        fail(`${where}: oui pattern ${JSON.stringify(pattern)} must be 6 uppercase hex digits with no separators`);
      }
      break;
    case 'oui_vendor':
      // Generated from oui_classes, one per entry. A hand-written one here
      // would be a second place a vendor's class is decided.
      fail(`${where}: oui_vendor rules are generated from the oui_classes map — `
        + 'do not write one in the rules list. To give a vendor a class, add it to oui_classes.');
      break;
    case 'sysobjectid':
      if (!SYSOBJECTID.test(pattern)) {
        fail(`${where}: sysobjectid pattern ${JSON.stringify(pattern)} must be an OID under the 1.3.6.1.4.1 private-enterprise arc`);
      }
      break;
    case 'enip':
      if (!DECIMAL.test(pattern)) {
        fail(`${where}: enip pattern ${JSON.stringify(pattern)} must be a decimal ODVA vendor id`);
      }
      break;
    case 'cloud_type':
      if (!CLOUD_TYPE.test(pattern)) {
        fail(`${where}: cloud_type pattern ${JSON.stringify(pattern)} must be a lower_snake resource type`);
      }
      break;
    // `os_name` and `dhcp_vendor_class` share every check here: all three kinds
    // are RE2 patterns carrying their own anchoring, and a second copy of the
    // RE2-vs-JS reasoning below is a second copy that drifts.
    case 'banner':
    case 'os_name':
    case 'dhcp_vendor_class': {
      // NOT `new RegExp(pattern)`. These patterns are Go RE2, and the two
      // engines disagree in both directions: JS rejects RE2's inline `(?i)`
      // flag group outright, and JS ACCEPTS backreferences and lookaround,
      // which RE2 refuses. Compiling here would therefore have rejected every
      // correct pattern in this file while passing the ones Go will choke on.
      //
      // So this checks for the constructs that would pass a JS compile and
      // fail a Go one, and the authoritative compile happens in Go:
      // shared/classify's Rule.Validate builds every banner, os_name and
      // dhcp_vendor_class regexp
      // at engine construction, and TestGeneratedRules_AreValid runs it over
      // this table.
      const unsupported = [
        [/\(\?=/, 'lookahead (?=…)'],
        [/\(\?!/, 'negative lookahead (?!…)'],
        [/\(\?<[=!]/, 'lookbehind (?<=…) / (?<!…)'],
        [/\\[1-9]/, 'a backreference (\\1)'],
      ];
      for (const [re, what] of unsupported) {
        if (re.test(pattern)) {
          fail(`${where}: ${kind} pattern ${JSON.stringify(pattern)} uses ${what}, which Go's RE2 does not support`);
        }
      }
      // Balance check, so an obviously malformed pattern fails at `make
      // generate` rather than at the Go build after it.
      let depth = 0;
      let inClass = false;
      for (let i = 0; i < pattern.length; i += 1) {
        if (pattern[i] === '\\') { i += 1; continue; }
        // A parenthesis inside a character class is a literal — `[/( ]` is a
        // set of three characters, not the start of a group.
        if (inClass) {
          if (pattern[i] === ']') inClass = false;
          continue;
        }
        if (pattern[i] === '[') { inClass = true; continue; }
        if (pattern[i] === '(') depth += 1;
        if (pattern[i] === ')') depth -= 1;
        if (depth < 0) fail(`${where}: ${kind} pattern ${JSON.stringify(pattern)} has an unmatched ')'`);
      }
      if (inClass) fail(`${where}: ${kind} pattern ${JSON.stringify(pattern)} has an unclosed '['`);
      if (depth !== 0) fail(`${where}: ${kind} pattern ${JSON.stringify(pattern)} has an unmatched '('`);
      // A shipped option 60 rule must be anchored at the start. The identifier
      // is one short string the client chose, and an unanchored pattern
      // (`MSFT`, `AP`) matches inside somebody else's — `Cisco AP c3700`
      // contains `AP`, `MSFT 5.0 XBOX` contains `MSFT 5.0`. Shipped rules
      // only: an admin's rule is the engine's to validate, and it compiles.
      if (kind === 'dhcp_vendor_class' && !/^(\(\?[a-zA-Z]+\))?\^/.test(pattern)) {
        fail(`${where}: dhcp_vendor_class pattern ${JSON.stringify(pattern)} must be anchored with a leading ^ `
          + '(after an optional flag group such as (?i)) — an option 60 identifier is one short string, and an '
          + 'unanchored pattern matches inside another client\'s');
      }
      break;
    }
    case 'port_profile': {
      if (!PORT_PROFILE.test(pattern)) {
        fail(`${where}: port_profile pattern ${JSON.stringify(pattern)} must be two or more comma-separated ports`);
      }
      const ports = pattern.split(',').map(Number);
      for (const p of ports) {
        if (p < 1 || p > 65535) fail(`${where}: port ${p} is out of range`);
      }
      // Ascending and deduplicated, so one profile has exactly one spelling
      // and the (kind, pattern) unique index means what it says.
      const sorted = [...new Set(ports)].sort((a, b) => a - b);
      if (sorted.join(',') !== pattern) {
        fail(`${where}: port_profile pattern ${JSON.stringify(pattern)} must be ascending and deduplicated — write ${JSON.stringify(sorted.join(','))}`);
      }
      break;
    }
    case 'model':
    case 'platform':
      if (pattern.trim() !== pattern) {
        fail(`${where}: ${kind} pattern ${JSON.stringify(pattern)} has leading or trailing whitespace`);
      }
      break;
    case 'cdp_capabilities':
    case 'lldp_capability': {
      if (!CAPABILITY_SET.test(pattern)) {
        fail(`${where}: ${kind} pattern ${JSON.stringify(pattern)} must be comma-separated lowercase `
          + 'capability names, spelled as the decoder in shared/hostobs spells them');
      }
      const caps = pattern.split(',');
      const sorted = [...new Set(caps)].sort();
      if (sorted.join(',') !== pattern) {
        fail(`${where}: ${kind} pattern ${JSON.stringify(pattern)} must be ascending and deduplicated `
          + `-- write ${JSON.stringify(sorted.join(','))}. One set, one spelling: (rule_kind, pattern) `
          + 'is the table\'s unique index, and two orderings would be two rows an admin could edit to disagree.');
      }
      break;
    }
    case 'mdns_service':
      if (!MDNS_SERVICE.test(pattern)) {
        fail(`${where}: mdns_service pattern ${JSON.stringify(pattern)} must be a DNS-SD service type in `
          + 'its registry spelling, lowercase -- `_ipp._tcp`, `_printer._tcp`');
      }
      break;
    default:
      fail(`${where}: kind ${kind} has no validation — add one before adding rules for it`);
  }

  const cls = rule.class ?? '';
  if (cls && !classKeys.has(cls)) {
    fail(`${where}: class ${JSON.stringify(cls)} is not in standards/asset-classes.yaml`);
  }

  const confidence = rule.confidence;
  if (typeof confidence !== 'number') {
    fail(`${where}: confidence is required and must be a number`);
  }
  if (confidence < MIN_CONFIDENCE || confidence > MAX_CONFIDENCE) {
    fail(`${where}: confidence ${confidence} is outside ${MIN_CONFIDENCE}–${MAX_CONFIDENCE}`);
  }
  if (Math.round(confidence * 100) !== confidence * 100) {
    fail(`${where}: confidence ${confidence} has more than two decimal places — the column is numeric(3,2)`);
  }

  const sourceURL = rule.source_url ?? '';
  if (!sourceURL) {
    fail(`${where}: source_url is required — a rule that cannot cite anything is somebody's memory`);
  }
  if (!/^https?:\/\//.test(sourceURL)) {
    fail(`${where}: source_url ${JSON.stringify(sourceURL)} is not an http(s) URL`);
  }

  const vendor = rule.vendor ?? '';
  const model = rule.model ?? '';
  if (!cls && !vendor && !model) {
    fail(`${where}: asserts nothing — a rule needs at least one of class, vendor, model`);
  }

  for (const key of Object.keys(rule)) {
    if (!['kind', 'pattern', 'class', 'vendor', 'model', 'confidence', 'source_url'].includes(key)) {
      fail(`${where}: unknown field ${JSON.stringify(key)}`);
    }
  }

  return { kind, pattern, class: cls, vendor, model, confidence, sourceURL };
}

/** The committed inputs, as text, so a test can mutate one and rebuild. */
export function readInputs() {
  return {
    rulesYAML: fs.readFileSync(path.join(root, 'standards', 'classification-rules.yaml'), 'utf8'),
    vendorsYAML: fs.readFileSync(path.join(root, VENDORS_YAML), 'utf8'),
  };
}

/** Builds the ordered rule table from the inputs, or throws a GenError. */
export function build(inputs = readInputs()) {
  // maxAliasCount: the IEEE and IANA citations are YAML anchors reused by every
  // rule in their block, which trips the library's default billion-laughs guard
  // at 100 expansions. The guard is for untrusted input; this file is in the
  // repo and is reviewed like code, and the alternative — spelling the same URL
  // out 150 times — is the version that drifts.
  const reg = yaml.parse(inputs.rulesYAML, { maxAliasCount: 10000 });

  for (const [key, why] of Object.entries(RETIRED_KEYS)) {
    if (key in reg) fail(`${key} is no longer read: ${why}. Remove it.`);
  }

  const kinds = reg.kinds || [];
  if (!kinds.length) fail('no kinds declared');
  const kindSet = new Set(kinds);
  if (kindSet.size !== kinds.length) fail('duplicate entry in kinds');
  // The kind list is also a CHECK constraint in scripts/database/schema.sql
  // and a switch in shared/classify. Pinning the order here means the three
  // stay comparable by eye as well as by the drift check below.
  if (kinds.join(',') !== KIND_ORDER.join(',')) {
    fail(`kinds must be exactly [${KIND_ORDER.join(', ')}] in that order — adding one is a schema change (the rule_kind CHECK) and an engine change (the matcher), not a YAML edit`);
  }

  const classKeys = loadClassKeys();
  const rules = (reg.rules || []).map((r, i) => normalise(r, i, classKeys, kindSet));
  if (!rules.length) fail('no rules defined');

  const canonical = loadCanonicalVendors(inputs.vendorsYAML);
  checkVendorSpellings(reg, rules, canonical);

  // The vendor rules are derived, not authored. Appended after the YAML's rules
  // and then sorted with them below, so the two outputs are one ordered table.
  rules.push(...ouiVendorRules(reg, classKeys, canonical));

  // (kind, pattern) is the table's unique index. A duplicate here would make
  // the seed's ON CONFLICT silently collapse two rules into one, and the Go
  // table would carry both — the two homes disagreeing, quietly.
  const seen = new Map();
  for (const r of rules) {
    const id = `${r.kind} ${r.pattern}`;
    if (seen.has(id)) {
      fail(`duplicate rule: kind ${r.kind}, pattern ${JSON.stringify(r.pattern)} appears twice`);
    }
    seen.set(id, r);
  }

  // Deterministic order for both outputs: kind in declared order, then pattern.
  // Byte order, not locale order — a locale-sensitive sort makes the --check
  // drift audit depend on the machine's LANG.
  const kindRank = new Map(kinds.map((k, i) => [k, i]));
  rules.sort((a, b) => {
    const d = kindRank.get(a.kind) - kindRank.get(b.kind);
    if (d !== 0) return d;
    return a.pattern < b.pattern ? -1 : a.pattern > b.pattern ? 1 : 0;
  });

  return { rules, kinds };
}

// ---------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------

function emitGo(rules, kinds) {
  const counts = kinds.map((k) => `${k} ${rules.filter((r) => r.kind === k).length}`);
  const lines = [
    '// Code generated by scripts/generate-classification-rules.mjs from',
    '// standards/classification-rules.yaml. DO NOT EDIT — edit the YAML and run',
    '// `make generate`.',
    'package classify',
    '',
    '// generatedRules is the seeded rule table, compiled in.',
    '//',
    '// It is the SAME content as the classification_rules rows seed.sql writes,',
    '// from the same source file, so a runtime with no database (the sensor, the',
    '// device agent, a unit test) classifies exactly as a service with one does',
    '// until an admin curates the table.',
    '//',
    `// ${rules.length} rules: ${counts.join(', ')}.`,
    'var generatedRules = []Rule{',
  ];
  for (const r of rules) {
    const fields = [
      `Kind: ${goStr(r.kind)}`,
      `Pattern: ${goStr(r.pattern)}`,
    ];
    if (r.class) fields.push(`Class: ${goStr(r.class)}`);
    if (r.vendor) fields.push(`Vendor: ${goStr(r.vendor)}`);
    if (r.model) fields.push(`Model: ${goStr(r.model)}`);
    fields.push(`Confidence: ${r.confidence}`);
    fields.push(`SourceURL: ${goStr(r.sourceURL)}`);
    lines.push(`\t{${fields.join(', ')}},`);
  }
  lines.push('}', '');
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// SQL
// ---------------------------------------------------------------------------

/** Quotes a value as a SQL string literal, or NULL when empty. */
function sqlStr(s) {
  if (s === '' || s === null || s === undefined) return 'NULL';
  return `'${String(s).replace(/'/g, "''")}'`;
}

function emitSeedUpsert(rules) {
  const values = rules.map((r) => (
    `    (${sqlStr(r.kind)}, ${sqlStr(r.pattern)}, ${sqlStr(r.class)}, ${sqlStr(r.vendor)}, ` +
    `${sqlStr(r.model)}, ${r.confidence.toFixed(2)}, ${sqlStr(r.sourceURL)})`
  ));
  return [
    'INSERT INTO public.classification_rules (',
    '    rule_kind, pattern, class_key, vendor, model, confidence, source_url',
    ') VALUES',
    values.join(',\n'),
    // The upsert restates every generated column so re-applying after a YAML
    // change reconciles the existing row rather than leaving the old values in
    // place. A rule an admin edited in the console is overwritten by the next
    // seed run — which is the documented contract: this file owns the seeded
    // rules, and an admin who wants a different answer adds a rule rather than
    // editing a seeded one. Rules an admin ADDED are untouched: they are not
    // in this VALUES list and nothing here deletes.
    'ON CONFLICT (rule_kind, pattern) DO UPDATE SET',
    '    class_key  = EXCLUDED.class_key,',
    '    vendor     = EXCLUDED.vendor,',
    '    model      = EXCLUDED.model,',
    '    confidence = EXCLUDED.confidence,',
    '    source_url = EXCLUDED.source_url,',
    '    updated_at = now();',
  ].join('\n');
}

// ---------------------------------------------------------------------------
// Region splicing (same shape as scripts/generate-asset-classes.mjs)
// ---------------------------------------------------------------------------

function spliceRegion(src, marker, body, commentPrefix) {
  const begin = `${commentPrefix} BEGIN GENERATED: ${marker} — from standards/classification-rules.yaml (make generate)`;
  const end = `${commentPrefix} END GENERATED: ${marker}`;
  const bi = src.indexOf(begin);
  const ei = src.indexOf(end);
  if (bi === -1 || ei === -1 || ei < bi) {
    fail(`region markers for "${marker}" not found (or out of order) — expected:\n  ${begin}\n  ${end}`);
  }
  return `${src.slice(0, bi + begin.length)}\n${body}\n${src.slice(ei)}`;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

async function main() {
  const checkOnly = process.argv.includes('--check');
  const { rules, kinds } = build();

  const seedPath = path.join(root, 'scripts', 'database', 'seed.sql');
  const seed = spliceRegion(
    fs.readFileSync(seedPath, 'utf8'),
    'classification rules',
    emitSeedUpsert(rules),
    '--',
  );

  const outputs = [
    [seedPath, seed],
    [path.join(root, 'shared', 'classify', 'rules_gen.go'), emitGo(rules, kinds)],
  ];

  const summary = kinds
    .map((k) => `${k} ${rules.filter((r) => r.kind === k).length}`)
    .join(', ');

  if (checkOnly) {
    const stale = [];
    for (const [p, content] of outputs) {
      const current = fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '';
      if (current !== content) stale.push(path.relative(root, p));
    }
    if (stale.length) {
      fail(`out of date — run \`make generate\`:\n  ${stale.join('\n  ')}`);
    }
    console.log(`classification-rules check OK (${rules.length} rules: ${summary})`);
    return;
  }

  for (const [p, content] of outputs) {
    await fs.ensureDir(path.dirname(p));
    await fs.writeFile(p, content);
    console.log(`Generated: ${path.relative(root, p)}`);
  }
  console.log(`  ${rules.length} rules: ${summary}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  main().catch((e) => sharedFail('classification-rules', e instanceof GenError ? e.message : (e.stack || e.message)));
}
