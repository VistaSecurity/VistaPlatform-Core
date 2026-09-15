#!/usr/bin/env node
// Generates the measurement-type artefacts from standards/measurement-types.yaml
// (ADR-0005 D5; BUILD_PLAN workstream 3.6).
//
// What a compliance control can measure used to live twice: as a switch of
// nineteen SQL blocks in the compliance-engine and as nineteen INSERTed rows in
// scripts/database/seed.sql, with nothing holding the two together. A control
// could name a measurement type the extractor did not implement (it evaluated
// to nothing and the control read as "not assessed" forever), and the extractor
// could implement one no seed row offered (it was unreachable from the rule
// builder). Both are generated from one file now.
//
// Outputs:
//   services/compliance-engine/internal/services/measurement_registry_gen.go
//   scripts/database/seed.sql                     (1 generated region)
//
// Run via `make generate`; `make audit` runs `--check` and fails on drift.
//
// This generator validates the registry's INTERNAL consistency (shapes declared
// here, subjects matching, rule types legal for the data type). It cannot check
// that a row names a selectable or a transform that exists in Go — that is what
// TestMeasurementRegistryCompiles does, by building every row's plan.
import { execFileSync } from 'child_process';
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

const CODE = /^[a-z][a-z0-9_]*$/;

// NAME is the shape every field that resolves to a Go whitelist entry must
// have: a selectable, a transform, a row filter, an ordering, a measured-at, a
// finding `via`, an evidence `from`. None of them ever reaches SQL as text —
// each is a map lookup in Go and a miss is an error — so this is not the thing
// standing between the registry and an injection. It is the thing that makes
// such a row fail HERE, at `make generate` / `make audit`, instead of only in
// the Go test that builds every plan.
//
// The distinction matters because a row the generator accepts is a row that
// ships: the seed writes its catalogue entry, `GET /measurement-types` offers
// it, and an admin can author a control against a measurement type whose
// extraction errors on every call. Refusing `value: "1; DROP TABLE assets; --"`
// at generation time is the cheap half of that, and it is the half the registry
// file's own header promises.
const NAME = /^[a-z][a-z0-9_]*$/;
const DATA_TYPES = new Set(['integer', 'string', 'enum', 'date', 'boolean']);
const RULE_TYPES = new Set(['threshold', 'presence', 'pattern', 'range']);
const SUBJECTS = new Set(['asset', 'certificate']);
const OPERATORS = new Set(['<=', '>=', '<', '>', '==', '!=']);

// Which rule types make sense for which data type. It mirrors
// MeasurementValidator.ValidateRuleTypeCompatibility's defaults: the validator
// refuses an incompatible rule at authoring time, so a registry row that offers
// one would advertise a rule the rule builder then rejects.
const COMPATIBLE = {
  integer: new Set(['threshold', 'range', 'presence']),
  date: new Set(['threshold', 'range', 'presence']),
  enum: new Set(['pattern', 'presence']),
  string: new Set(['pattern', 'presence']),
  boolean: new Set(['presence']),
};

function fail(msg) {
  console.error(`measurement-types: ${msg}`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Load + validate
// ---------------------------------------------------------------------------

function load() {
  const registryPath = path.join(root, 'standards', 'measurement-types.yaml');
  const reg = yaml.parse(fs.readFileSync(registryPath, 'utf8'));

  const shapes = new Map();
  for (const s of reg.shapes || []) {
    if (!CODE.test(s.name || '')) fail(`bad shape name: ${JSON.stringify(s.name)}`);
    if (!SUBJECTS.has(s.subject)) fail(`shape ${s.name}: bad subject ${JSON.stringify(s.subject)}`);
    if (shapes.has(s.name)) fail(`duplicate shape ${s.name}`);
    shapes.set(s.name, s);
  }
  if (!shapes.size) fail('no shapes declared');

  const rows = reg.measurement_types || [];
  if (!rows.length) fail('no measurement types declared');

  const seen = new Set();
  for (const m of rows) {
    const at = `measurement ${m.code}`;
    if (!CODE.test(m.code || '')) fail(`bad code: ${JSON.stringify(m.code)}`);
    if (seen.has(m.code)) fail(`duplicate code ${m.code}`);
    seen.add(m.code);
    if (!m.name) fail(`${at}: name is required`);
    if (!m.description) fail(`${at}: description is required`);
    if (!DATA_TYPES.has(m.data_type)) fail(`${at}: bad data_type ${JSON.stringify(m.data_type)}`);
    if (!m.category) fail(`${at}: category is required`);
    if (!SUBJECTS.has(m.subject)) fail(`${at}: bad subject ${JSON.stringify(m.subject)}`);

    const src = m.source || {};
    const shape = shapes.get(src.shape);
    if (!shape) fail(`${at}: unknown shape ${JSON.stringify(src.shape)}`);
    if (shape.subject !== m.subject) {
      fail(`${at}: declares subject '${m.subject}' but shape '${shape.name}' measures '${shape.subject}'`);
    }
    if (!src.value) fail(`${at}: source.value is required`);

    // Every field below names an entry in a Go whitelist. Which entries exist
    // is only checkable from Go (TestMeasurementRegistryCompiles builds every
    // plan), but the NAME SHAPE is checkable here, and that is what stops a row
    // carrying an expression, a fragment of SQL, or anything else that is not a
    // plain identifier from being generated, seeded and offered.
    for (const [field, value] of [
      ['source.value', src.value],
      ['source.transform', src.transform],
      ['source.row_filter', src.row_filter],
      ['source.order_by', src.order_by],
      ['source.measured_at', src.measured_at],
      ['source.via', src.via],
    ]) {
      // An omitted (or explicitly empty) optional field means "the shape's
      // default", which is a legal choice; only a value that is actually
      // present has to look like an identifier.
      if (value && !NAME.test(String(value))) {
        fail(`${at}: ${field} must name a whitelisted entry in measurement_shapes.go / ` +
          `measurement_registry.go, not ${JSON.stringify(value)} — nothing here may be an expression`);
      }
    }

    const allowed = m.allowed_rule_types || [];
    if (!allowed.length) fail(`${at}: allowed_rule_types is required`);
    for (const rt of allowed) {
      if (!RULE_TYPES.has(rt)) fail(`${at}: unknown rule type ${JSON.stringify(rt)}`);
      if (!COMPATIBLE[m.data_type].has(rt)) {
        fail(`${at}: rule type '${rt}' is not compatible with data type '${m.data_type}' — ` +
          'the measurement validator would refuse every rule authored with it');
      }
    }
    for (const op of m.valid_operators || []) {
      if (!OPERATORS.has(op)) fail(`${at}: unknown operator ${JSON.stringify(op)}`);
    }
    if ((m.valid_operators || []).length && !allowed.includes('threshold')) {
      fail(`${at}: declares valid_operators but does not allow threshold rules`);
    }
    if (m.data_type === 'enum' && !(m.enum_values || []).length) {
      fail(`${at}: data_type 'enum' needs enum_values — the rule builder offers them as the value set`);
    }
    if (m.data_type !== 'enum' && (m.enum_values || []).length) {
      fail(`${at}: enum_values on a non-enum data type`);
    }
    if (m.valid_range) {
      const { min, max } = m.valid_range;
      if (!Number.isInteger(min) || !Number.isInteger(max)) fail(`${at}: valid_range needs integer min and max`);
      if (min > max) fail(`${at}: valid_range min exceeds max`);
    }

    // The fact and finding shapes carry a bound parameter each. A row that
    // omits it would extract over every fact key, or count every producer's
    // findings — both silently wrong rather than loud.
    if (shape.name === 'fact' && !src.fact_key) fail(`${at}: the fact shape needs source.fact_key`);
    if (shape.name !== 'fact' && src.fact_key) fail(`${at}: fact_key on the '${shape.name}' shape`);
    if (shape.name === 'finding' && !src.assessed_by) {
      fail(`${at}: the finding shape needs source.assessed_by — without the producer gate an asset ` +
        'nothing has evaluated would count zero findings and read as compliant');
    }
    if (shape.name !== 'finding' && src.assessed_by) fail(`${at}: assessed_by on the '${shape.name}' shape`);
    if (shape.name !== 'finding' && src.via) fail(`${at}: via on the '${shape.name}' shape`);

    const keys = new Set();
    for (const ev of src.evidence || []) {
      const named = ['from', 'const', 'group'].filter((k) => ev[k] !== undefined);
      if (named.length !== 1) {
        fail(`${at}: each evidence entry needs exactly one of from/const/group, got [${named.join(', ')}]`);
      }
      // `from` and `group` both resolve to Go whitelists (a shape's selectables
      // and its evidence groups); `const` is literal metadata and may say
      // anything. `key` becomes a JSON object key on the finding.
      for (const [field, value] of [['from', ev.from], ['group', ev.group], ['key', ev.key]]) {
        if (value !== undefined && !NAME.test(String(value))) {
          fail(`${at}: evidence ${field} must be a plain identifier, not ${JSON.stringify(value)}`);
        }
      }
      if (ev.group === undefined) {
        if (!ev.key) fail(`${at}: evidence entry needs a key`);
        if (keys.has(ev.key)) fail(`${at}: duplicate evidence key ${JSON.stringify(ev.key)}`);
        keys.add(ev.key);
      }
    }
  }
  return { reg, rows, shapes };
}

// ---------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------

const goStr = (s) => JSON.stringify(s ?? '');

function goStrSlice(list) {
  if (!list || !list.length) return null;
  return `[]string{${list.map(goStr).join(', ')}}`;
}

function emitGo(rows) {
  const out = [];
  out.push('// Code generated by scripts/generate-measurement-types.mjs from');
  out.push('// standards/measurement-types.yaml. DO NOT EDIT.');
  out.push('');
  out.push('package services');
  out.push('');
  out.push('// measurementTypeRegistry is the measurement vocabulary: what a compliance');
  out.push('// control may measure, where the value comes from, and what travels with it.');
  out.push('// The same file generates the `measurement_types` rows seed.sql inserts, so the');
  out.push('// catalogue the rule builder offers and the extractor that serves it cannot');
  out.push('// disagree.');
  out.push('var measurementTypeRegistry = []MeasurementTypeDef{');
  for (const m of rows) {
    const src = m.source || {};
    out.push('\t{');
    out.push(`\t\tCode:        ${goStr(m.code)},`);
    out.push(`\t\tName:        ${goStr(m.name)},`);
    out.push(`\t\tDescription: ${goStr(oneLine(m.description))},`);
    out.push(`\t\tDataType:    ${goStr(m.data_type)},`);
    out.push(`\t\tCategory:    ${goStr(m.category)},`);
    if (m.units) out.push(`\t\tUnits:       ${goStr(m.units)},`);
    if (m.valid_range) {
      out.push(`\t\tValidRange:  &MeasurementRange{Min: ${m.valid_range.min}, Max: ${m.valid_range.max}},`);
    }
    const allowed = goStrSlice(m.allowed_rule_types);
    if (allowed) out.push(`\t\tAllowedRuleTypes: ${allowed},`);
    const enums = goStrSlice(m.enum_values);
    if (enums) out.push(`\t\tEnumValues:       ${enums},`);
    const ops = goStrSlice(m.valid_operators);
    if (ops) out.push(`\t\tValidOperators:   ${ops},`);
    out.push(`\t\tSubject:     ${goStr(m.subject)},`);
    out.push('\t\tSource: MeasurementSource{');
    out.push(`\t\t\tShape: ${goStr(src.shape)},`);
    out.push(`\t\t\tValue: ${goStr(src.value)},`);
    if (src.where) out.push(`\t\t\tWhere: ${goStr(oneLine(src.where))},`);
    if (src.subject_where) out.push(`\t\t\tSubjectWhere: ${goStr(oneLine(src.subject_where))},`);
    if (src.transform) out.push(`\t\t\tTransform: ${goStr(src.transform)},`);
    if (src.row_filter) out.push(`\t\t\tRowFilter: ${goStr(src.row_filter)},`);
    if (src.order_by) out.push(`\t\t\tOrderBy: ${goStr(src.order_by)},`);
    if (src.measured_at) out.push(`\t\t\tMeasuredAt: ${goStr(src.measured_at)},`);
    if (src.fact_key) out.push(`\t\t\tFactKey: ${goStr(src.fact_key)},`);
    if (src.assessed_by) out.push(`\t\t\tAssessedBy: ${goStr(src.assessed_by)},`);
    if (src.via) out.push(`\t\t\tVia: ${goStr(src.via)},`);
    if ((src.evidence || []).length) {
      out.push('\t\t\tEvidence: []EvidenceProjection{');
      for (const ev of src.evidence) {
        const parts = [];
        if (ev.key) parts.push(`Key: ${goStr(ev.key)}`);
        if (ev.from !== undefined) parts.push(`From: ${goStr(ev.from)}`);
        if (ev.const !== undefined) parts.push(`Const: ${goStr(String(ev.const))}`);
        if (ev.group !== undefined) parts.push(`Group: ${goStr(ev.group)}`);
        if (ev.always) parts.push('Always: true');
        out.push(`\t\t\t\t{${parts.join(', ')}},`);
      }
      out.push('\t\t\t},');
    }
    out.push('\t\t},');
    out.push('\t},');
  }
  out.push('}');
  out.push('');
  return gofmt(out.join('\n'));
}

// gofmt runs the emitted Go through the formatter rather than trying to
// reproduce its composite-literal alignment by hand. The alignment of a struct
// literal depends on the longest key in each contiguous run, and these rows
// have optional fields, so hand-padding would be wrong for some rows and CI's
// format check would fail on a generated file nobody may edit.
function gofmt(src) {
  try {
    return execFileSync('gofmt', { input: src, encoding: 'utf8' });
  } catch (e) {
    fail(`gofmt failed (it ships with the Go toolchain and must be on PATH): ${e.message}`);
    return src;
  }
}

// oneLine collapses a folded YAML scalar's newlines, which `>-` leaves as
// spaces already but `>` and hand-wrapped strings do not.
function oneLine(s) {
  return String(s ?? '').replace(/\s*\n\s*/g, ' ').trim();
}

// ---------------------------------------------------------------------------
// SQL
// ---------------------------------------------------------------------------

const sqlStr = (s) => `'${String(s).replace(/'/g, "''")}'`;
const sqlJSON = (v) => (v === null || v === undefined ? 'NULL' : `${sqlStr(JSON.stringify(v))}::jsonb`);

function emitSeedRegion(rows) {
  const lines = [];
  lines.push('-- The catalogue the rule builder offers and the extractor serves. Generated');
  lines.push('-- from standards/measurement-types.yaml, which also generates the Go registry');
  lines.push('-- (services/compliance-engine/internal/services/measurement_registry_gen.go),');
  lines.push('-- so a code offered here is always one the extractor implements.');
  lines.push('--');
  lines.push('-- ON CONFLICT DO UPDATE, not DO NOTHING: this is a catalogue, and an install');
  lines.push('-- that seeded it two releases ago must converge on the current text and value');
  lines.push('-- sets rather than keep the old ones forever. The row id is preserved, which');
  lines.push('-- is what control_measurements.measurement_type_id points at.');
  lines.push('--');
  lines.push('-- `extraction_query` is deliberately absent: ADR-0005 D5 drops that column');
  lines.push('-- rather than honouring it. SQL in a seeded row is an injection hazard and an');
  lines.push('-- upgrade hazard at once, and nothing ever executed it.');
  lines.push('INSERT INTO measurement_types (code, name, description, data_type, units, valid_range, allowed_rule_types, enum_values, valid_operators, category) VALUES');
  const values = rows.map((m) => {
    const cells = [
      sqlStr(m.code),
      sqlStr(m.name),
      sqlStr(oneLine(m.description)),
      sqlStr(m.data_type),
      m.units ? sqlStr(m.units) : 'NULL',
      m.valid_range ? sqlJSON({ min: m.valid_range.min, max: m.valid_range.max }) : 'NULL',
      sqlJSON(m.allowed_rule_types),
      (m.enum_values || []).length ? sqlJSON(m.enum_values) : 'NULL',
      (m.valid_operators || []).length ? sqlJSON(m.valid_operators) : 'NULL',
      sqlStr(m.category),
    ];
    return `(${cells.join(', ')})`;
  });
  lines.push(values.join(',\n'));
  lines.push('ON CONFLICT (code) DO UPDATE SET');
  lines.push('    name = EXCLUDED.name,');
  lines.push('    description = EXCLUDED.description,');
  lines.push('    data_type = EXCLUDED.data_type,');
  lines.push('    units = EXCLUDED.units,');
  lines.push('    valid_range = EXCLUDED.valid_range,');
  lines.push('    allowed_rule_types = EXCLUDED.allowed_rule_types,');
  lines.push('    enum_values = EXCLUDED.enum_values,');
  lines.push('    valid_operators = EXCLUDED.valid_operators,');
  lines.push('    category = EXCLUDED.category,');
  lines.push('    updated_at = NOW();');
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Region splicing (same shape as scripts/generate-permissions.mjs)
// ---------------------------------------------------------------------------

function spliceRegion(src, marker, body, commentPrefix) {
  const begin = `${commentPrefix} BEGIN GENERATED: ${marker} — from standards/measurement-types.yaml (make generate)`;
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
  const { rows, shapes } = load();

  const seedPath = path.join(root, 'scripts', 'database', 'seed.sql');
  const seed = spliceRegion(
    fs.readFileSync(seedPath, 'utf8'),
    'measurement type catalogue',
    emitSeedRegion(rows),
    '--',
  );

  const goPath = path.join(root, 'services', 'compliance-engine', 'internal', 'services',
    'measurement_registry_gen.go');

  const outputs = [[goPath, emitGo(rows)], [seedPath, seed]];

  if (checkOnly) {
    const stale = [];
    for (const [p, content] of outputs) {
      const current = fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '';
      if (current !== content) stale.push(path.relative(root, p));
    }
    if (stale.length) fail(`out of date — run \`make generate\`:\n  ${stale.join('\n  ')}`);
    console.log(`measurement-types check OK (${rows.length} types, ${shapes.size} shapes, ${outputs.length} artefacts)`);
    return;
  }

  for (const [p, content] of outputs) {
    await fs.ensureDir(path.dirname(p));
    await fs.writeFile(p, content);
    console.log(`Generated: ${path.relative(root, p)}`);
  }
  console.log(`  ${rows.length} measurement types over ${shapes.size} shapes`);
}

main().catch((e) => fail(e.stack || e.message));
