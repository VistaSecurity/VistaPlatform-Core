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
// OUI rules are NOT written out in the YAML. standards/oui-vendors.csv owns
// OUI -> vendor (workstream 2.5 compiles it into the sensor as
// shared/hostobs/oui_gen.go), and this generator reads it: one `oui` rule per
// CSV prefix, carrying the CSV's vendor, plus the class the YAML's
// `oui_classes` map attaches to that vendor. A second hand-written copy of the
// same mapping is a second copy that drifts, and it already had — see the note
// above `oui_classes` in the YAML.
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

const fail = (msg) => sharedFail('classification-rules', msg);

// Confidence bounds. The floor is 0.50 because a rule that is less than
// even money is not a proposal, it is noise in the approval queue; the ceiling
// is 0.95 because nothing in this file is a measurement — every row is an
// inference from an identifier, and 1.0 would say otherwise.
const MIN_CONFIDENCE = 0.5;
const MAX_CONFIDENCE = 0.95;

const KIND_ORDER = [
  'oui', 'sysobjectid', 'enip', 'cloud_type', 'banner', 'port_profile', 'model', 'platform',
  'cdp_capabilities', 'lldp_capability', 'mdns_service',
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

const OUI_CSV = path.join('standards', 'oui-vendors.csv');
const CSV_PREFIX = /^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}$/;

/**
 * Reads standards/oui-vendors.csv into [{pattern, vendor}], pattern rendered
 * the way a classification rule spells it: 6 uppercase hex digits, no
 * separators.
 *
 * Deliberately a second parser rather than an import of
 * generate-oui-table.mjs's: that one's job is to emit a Go map and it fails the
 * whole run on a malformed row, which is right for it. This one only needs the
 * pairs, and any row IT would reject has already failed `make generate` before
 * reaching here, because the OUI generator runs first.
 */
function loadOUIVendors() {
  const csv = fs.readFileSync(path.join(root, OUI_CSV), 'utf8');
  const out = [];
  const seen = new Set();
  for (const raw of csv.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line === 'prefix,vendor') continue;
    const comma = line.indexOf(',');
    if (comma < 0) fail(`${OUI_CSV}: expected "prefix,vendor", got ${JSON.stringify(line)}`);
    const prefix = line.slice(0, comma).trim();
    const vendor = line.slice(comma + 1).trim();
    if (!CSV_PREFIX.test(prefix)) fail(`${OUI_CSV}: bad prefix ${JSON.stringify(prefix)}`);
    if (!vendor) fail(`${OUI_CSV}: ${prefix} has no vendor`);
    const pattern = prefix.replace(/:/g, '');
    if (seen.has(pattern)) fail(`${OUI_CSV}: duplicate prefix ${prefix}`);
    seen.add(pattern);
    out.push({ pattern, vendor });
  }
  if (out.length < 100) fail(`${OUI_CSV}: only ${out.length} prefixes read; the parse is not finding the table`);
  return out;
}

/**
 * Turns the CSV plus the YAML's vendor -> class map into `oui` rules.
 *
 * A vendor the map does not mention gets a VENDOR-ONLY rule, which is the
 * majority and the intended default: of the prefixes in the CSV only about a
 * third belong to a manufacturer whose networked products are all one thing.
 */
function ouiRules(reg, classKeys, vendors) {
  const map = reg.oui_classes || {};
  const sources = ouiSources(reg, vendors);

  const defaultConfidence = reg.oui_vendor_only_confidence;
  if (typeof defaultConfidence !== 'number') {
    fail('oui_vendor_only_confidence is required and must be a number');
  }
  if (defaultConfidence < MIN_CONFIDENCE || defaultConfidence > MAX_CONFIDENCE) {
    fail(`oui_vendor_only_confidence ${defaultConfidence} is outside ${MIN_CONFIDENCE}-${MAX_CONFIDENCE}`);
  }

  // A vendor in the map that the CSV does not contain is a typo that would
  // otherwise be a class silently applying to nothing — the shape of a check
  // that cannot fail.
  const known = new Set(vendors.map((v) => v.vendor));
  for (const vendor of Object.keys(map)) {
    if (!known.has(vendor)) {
      fail(`oui_classes names ${JSON.stringify(vendor)}, which is not a vendor in ${OUI_CSV}. `
        + 'Spell it exactly as the CSV does, or add the prefix there first.');
    }
  }

  return vendors.map(({ pattern, vendor }) => {
    const sourceURL = sources.get(pattern) ?? IEEE_URL;
    const entry = map[vendor];
    if (entry === undefined) {
      return {
        kind: 'oui', pattern, class: '', vendor, model: '',
        confidence: defaultConfidence, sourceURL,
      };
    }
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
    for (const key of Object.keys(entry)) {
      if (!['class', 'confidence'].includes(key)) {
        fail(`oui_classes[${JSON.stringify(vendor)}]: unknown field ${JSON.stringify(key)}`);
      }
    }
    return {
      kind: 'oui', pattern, class: entry.class, vendor, model: '',
      confidence: entry.confidence, sourceURL,
    };
  });
}

const IEEE_URL = 'https://standards-oui.ieee.org/';

/**
 * Reads `oui_sources` — the per-prefix citation override — and checks it covers
 * exactly the prefixes IEEE did not assign.
 *
 * An OUI rule cites the IEEE registry, because that is where OUI -> vendor comes
 * from. For a LOCALLY-ADMINISTERED prefix that citation is simply false: the U/L
 * bit means nobody registered it, and `FA:16:3E -> OpenStack` is a convention of
 * that platform's own, documented by that platform. Pointing at
 * standards-oui.ieee.org for it is worse than citing nothing — it is a citation
 * that does not say what the rule says, aimed at a reader who will not go and
 * check.
 *
 * So: a locally-administered prefix MUST carry an override, and an override for
 * a prefix the CSV does not have is a typo. A universally-administered prefix
 * MAY carry one, for the case where the registry assigned the prefix to somebody
 * other than the name the table uses (08:00:27 is registered to Cadmus Computer
 * Systems; every frame carrying it in practice is a VirtualBox guest).
 */
function ouiSources(reg, vendors) {
  const raw = reg.oui_sources || {};
  const byPrefix = new Map(vendors.map((v) => [v.pattern, v.vendor]));
  const out = new Map();

  for (const [prefix, url] of Object.entries(raw)) {
    const pattern = String(prefix).replace(/:/g, '').toUpperCase();
    if (!byPrefix.has(pattern)) {
      fail(`oui_sources names prefix ${JSON.stringify(prefix)}, which is not in ${OUI_CSV}`);
    }
    if (typeof url !== 'string' || !/^https?:\/\//.test(url)) {
      fail(`oui_sources[${JSON.stringify(prefix)}]: ${JSON.stringify(url)} is not an http(s) URL`);
    }
    out.set(pattern, url);
  }

  // The check that has to be able to fail: every locally-administered prefix
  // needs its own citation, because the IEEE default is wrong for all of them.
  for (const { pattern, vendor } of vendors) {
    if (!isLocallyAdministered(pattern) || out.has(pattern)) continue;
    fail(`${OUI_CSV}: ${pattern} (${vendor}) is a LOCALLY-ADMINISTERED prefix — the U/L bit is set, `
      + 'so IEEE assigned it to nobody and the default citation would be false. '
      + 'Add an oui_sources entry pointing at the platform that documents the convention.');
  }
  return out;
}

/** True when the U/L bit of the first octet is set — i.e. IEEE assigned nothing. */
function isLocallyAdministered(pattern) {
  return (parseInt(pattern.slice(0, 2), 16) & 0x02) !== 0;
}

/**
 * Checks that every vendor named by a HAND-WRITTEN rule is spelled exactly as
 * standards/oui-vendors.csv spells it.
 *
 * One manufacturer, one name. Two spellings is not a cosmetic problem here: the
 * engine's vendor arbitration refuses to choose between two rules naming
 * DIFFERENT vendors at similar confidence, so `Dell` on the OUI rule and
 * `Dell Inc.` on the sysObjectID rule did not disagree loudly — they cancelled,
 * and a Dell server seen by both MAC and SNMP came back with no vendor and no
 * class at all. The same pair also breaks the hw.vendor join the end-of-life
 * catalogue exists for.
 *
 * A vendor with no prefix in the CSV is legitimate — Zyxel, Brocade and Citrix
 * are reached by SNMP and have never turned up in the MAC table — but it has to
 * be DECLARED, so that adding their OUI later cannot quietly introduce a second
 * spelling.
 */
function checkVendorSpellings(reg, rules, vendors) {
  const csvVendors = new Set(vendors.map((v) => v.vendor));
  const declared = reg.vendors_outside_oui_table || [];
  if (!Array.isArray(declared)) fail('vendors_outside_oui_table must be a list');

  for (const vendor of declared) {
    if (csvVendors.has(vendor)) {
      fail(`vendors_outside_oui_table lists ${JSON.stringify(vendor)}, which IS in ${OUI_CSV} now. `
        + 'Remove it from the list — the CSV is the spelling, and the list is only for manufacturers absent from it.');
    }
  }
  const allowed = new Set(declared);

  const fold = (s) => s.toLowerCase().replace(/[^a-z0-9]/g, '');
  // Near-match the way the engine's own vendorAgrees does — fold-equal, or one
  // folded name a prefix of the other — so the message can NAME the spelling to
  // use. "Dell Inc." against "Dell" is the common shape and the one an exact
  // lookup would miss, leaving the author to go and grep the CSV.
  const near = (vendor) => {
    const f = fold(vendor);
    for (const v of csvVendors) {
      const g = fold(v);
      if (f === g) return v;
      const [short, long] = f.length <= g.length ? [f, g] : [g, f];
      if (short.length >= 3 && long.startsWith(short)) return v;
    }
    return null;
  };

  for (const r of rules) {
    if (r.kind === 'oui' || !r.vendor || csvVendors.has(r.vendor) || allowed.has(r.vendor)) continue;
    const suggestion = near(r.vendor);
    fail(`${r.kind} rule ${JSON.stringify(r.pattern)} names vendor ${JSON.stringify(r.vendor)}, `
      + (suggestion
        ? `which ${OUI_CSV} spells ${JSON.stringify(suggestion)}. One manufacturer, one name: the engine `
          + 'refuses to choose between two rules naming different vendors at similar confidence, so two '
          + 'spellings do not disagree — they cancel, and the asset comes back with no vendor.'
        : `which is not in ${OUI_CSV}. Either add the prefix there, or declare the name in `
          + 'vendors_outside_oui_table with the reason it has no MAC prefix.'));
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
      // OUI rules come from standards/oui-vendors.csv plus `oui_classes`, not
      // from the rules list. A hand-written one here would be the second copy
      // this arrangement exists to prevent.
      fail(`${where}: oui rules are generated from ${OUI_CSV} and the oui_classes map — `
        + 'do not write one in the rules list. To give a vendor a class, add it to oui_classes; '
        + 'to add a prefix, add it to the CSV.');
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
    case 'banner': {
      // NOT `new RegExp(pattern)`. These patterns are Go RE2, and the two
      // engines disagree in both directions: JS rejects RE2's inline `(?i)`
      // flag group outright, and JS ACCEPTS backreferences and lookaround,
      // which RE2 refuses. Compiling here would therefore have rejected every
      // correct pattern in this file while passing the ones Go will choke on.
      //
      // So this checks for the constructs that would pass a JS compile and
      // fail a Go one, and the authoritative compile happens in Go:
      // shared/classify's Rule.Validate builds every banner regexp at engine
      // construction, and TestGeneratedRules_AreValid runs it over this table.
      const unsupported = [
        [/\(\?=/, 'lookahead (?=…)'],
        [/\(\?!/, 'negative lookahead (?!…)'],
        [/\(\?<[=!]/, 'lookbehind (?<=…) / (?<!…)'],
        [/\\[1-9]/, 'a backreference (\\1)'],
      ];
      for (const [re, what] of unsupported) {
        if (re.test(pattern)) {
          fail(`${where}: banner pattern ${JSON.stringify(pattern)} uses ${what}, which Go's RE2 does not support`);
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
        if (depth < 0) fail(`${where}: banner pattern ${JSON.stringify(pattern)} has an unmatched ')'`);
      }
      if (inClass) fail(`${where}: banner pattern ${JSON.stringify(pattern)} has an unclosed '['`);
      if (depth !== 0) fail(`${where}: banner pattern ${JSON.stringify(pattern)} has an unmatched '('`);
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

function load() {
  const file = path.join(root, 'standards', 'classification-rules.yaml');
  // maxAliasCount: the IEEE and IANA citations are YAML anchors reused by every
  // rule in their block, which trips the library's default billion-laughs guard
  // at 100 expansions. The guard is for untrusted input; this file is in the
  // repo and is reviewed like code, and the alternative — spelling the same URL
  // out 150 times — is the version that drifts.
  const reg = yaml.parse(fs.readFileSync(file, 'utf8'), { maxAliasCount: 10000 });

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

  const ouiVendors = loadOUIVendors();
  checkVendorSpellings(reg, rules, ouiVendors);

  // The OUI rules are derived, not authored. Appended after the YAML's rules
  // and then sorted with them below, so the two outputs are one ordered table.
  rules.push(...ouiRules(reg, classKeys, ouiVendors));

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
  const { rules, kinds } = load();

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

main().catch((e) => fail(e.stack || e.message));
