#!/usr/bin/env node
// ADR-0016: classify contract fields explicitly; a suffix does not imply polarity.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';

const ratingName = /(?:score|percent|confidence|severity|strength|security_level|risk_level|health_status)/;
const extraNames = new Set(['resource_efficiency', 'performance_metrics', 'security_posture', 'business_activity', 'cost_optimization', 'data_completeness']);
const escapePointer = (s) => String(s).replace(/~/g, '~0').replace(/\//g, '~1');

export function candidates(spec) {
  const found = new Map();
  function visit(value, parts) {
    if (!value || typeof value !== 'object') return;
    if (value.properties) {
      for (const [name, schema] of Object.entries(value.properties)) {
        if (ratingName.test(name) || extraNames.has(name)) {
          found.set('/' + [...parts, 'properties', name].map(escapePointer).join('/'), schema);
        }
      }
    }
    if (typeof value.name === 'string' && ratingName.test(value.name) && value.schema) {
      found.set('/' + [...parts, 'schema'].map(escapePointer).join('/'), value.schema);
    }
    for (const [key, child] of Object.entries(value)) visit(child, [...parts, key]);
  }
  visit(spec, []);
  return found;
}

export function requiredAt(spec, pointer) {
  const parts = pointer.slice(1).split('/').map(part => part.replace(/~1/g, '/').replace(/~0/g, '~'));
  const at = (keys) => keys.reduce((value, key) => value?.[key], spec);
  if (parts.at(-1) === 'schema') return Boolean(at(parts.slice(0, -1))?.required);
  return Boolean(at(parts.slice(0, -2))?.required?.includes(parts.at(-1)));
}

// Snapshot resolved wire constraints, including omission/default behavior. A
// reference is an indirection, not permission to hide a changed contract.
export function shape(schema, spec = {}, required = false) {
  const resolved = resolvedSchema(schema, spec);
  const contract = {
    type: resolved.type ?? 'unspecified',
    nullable: Boolean(resolved.nullable || (Array.isArray(resolved.type) && resolved.type.includes('null'))),
    required,
  };
  for (const field of ['minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'enum', 'default']) {
    if (Object.hasOwn(resolved, field)) contract[field] = resolved[field];
  }
  for (const field of ['items', 'additionalProperties']) {
    if (resolved[field] && typeof resolved[field] === 'object') contract[field] = shape(resolved[field], spec);
  }
  return contract;
}

export function canonicalEnums(definitions) {
  return {
    algorithm_strength: definitions.strength.map(row => row.value),
    algorithm_strength_filter: [...definitions.strength.map(row => row.value), 'unassessed'],
    risk_display: definitions.risk.map(row => row.label),
    severity: definitions.severity.map(row => row.value),
    control_severity: definitions.severity.filter(row => row.controlWeight > 0).map(row => row.value),
    health_with_history: [...definitions.health.map(row => row.value), 'unknown', 'critical'],
  };
}

function resolvedSchema(schema, spec, seen = new Set()) {
  if (!schema || typeof schema !== 'object') return {};
  if (schema.$ref) {
    if (!schema.$ref.startsWith('#/') || seen.has(schema.$ref)) throw new Error(`unsupported/cyclic rating reference ${schema.$ref}`);
    const next = new Set(seen).add(schema.$ref);
    const target = schema.$ref.slice(2).split('/').reduce((value, key) => value?.[key.replace(/~1/g, '/').replace(/~0/g, '~')], spec);
    if (!target) throw new Error(`missing rating reference ${schema.$ref}`);
    return { ...resolvedSchema(target, spec, next), ...Object.fromEntries(Object.entries(schema).filter(([key]) => key !== '$ref')) };
  }
  if (schema.allOf) return Object.assign({}, ...schema.allOf.map(part => resolvedSchema(part, spec, seen)), schema);
  return schema;
}

// Canonical enums are supplied by the same Go generator that produces the TS twins.
// Adapters/legacy contracts declare their vocabulary explicitly instead of being
// quietly lowercased (which would hide a wire compatibility change).
export function audit(specs, manifest, enums = {}) {
  const errors = [];
  const bindings = manifest.bindings ?? {};
  const concepts = manifest.concepts ?? {};
  const seen = new Set();
  if (manifest.version !== 1) errors.push('rating manifest version must be 1');
  for (const [name, concept] of Object.entries(concepts)) {
    for (const field of ['unit', 'direction', 'unknown', 'owner', 'types']) {
      if (!concept[field]) errors.push(`${name}: missing ${field}`);
    }
    if (!['higher_is_better', 'higher_is_worse', 'target_range', 'context_dependent', 'not_applicable'].includes(concept.direction)) {
      errors.push(`${name}: invalid direction`);
    }
  }
  for (const [file, spec] of Object.entries(specs)) {
    for (const [pointer, schema] of candidates(spec)) {
      const id = `${file}#${pointer}`;
      seen.add(id);
      const binding = bindings[id];
      if (!binding) { errors.push(`${id}: unregistered rating field`); continue; }
      const concept = concepts[binding.concept];
      if (!concept) { errors.push(`${id}: unknown concept ${binding.concept}`); continue; }
      if (!['implement', 'register_only', 'external'].includes(binding.delivery)) errors.push(`${id}: missing delivery classification`);
      let numeric;
      try {
        const contract = shape(schema, spec, requiredAt(spec, pointer));
        if (JSON.stringify(binding.contract) !== JSON.stringify(contract)) errors.push(`${id}: resolved contract type/nullability/requiredness/constraints changed; review binding`);
        const resolved = resolvedSchema(schema, spec);
        numeric = resolvedSchema(resolved.items ?? (typeof resolved.additionalProperties === 'object' ? resolved.additionalProperties : resolved), spec);
      } catch (error) { errors.push(`${id}: ${error.message}`); continue; }
      const types = (Array.isArray(numeric.type) ? numeric.type : [numeric.type]).filter(type => type !== 'null');
      if (!types.length || types.some(type => !concept.types?.includes(type))) errors.push(`${id}: schema type incompatible with ${binding.concept}`);
      const absentConstraints = [];
      if (concept.range) {
        if (concept.range[0] !== null && numeric.minimum === undefined) absentConstraints.push('minimum');
        if (concept.range[1] !== null && numeric.maximum === undefined) absentConstraints.push('maximum');
      }
      if ((concept.enum_source || concept.values) && !numeric.enum) absentConstraints.push('enum');
      if (absentConstraints.length && !binding.schema_exception) errors.push(`${id}: missing ${absentConstraints.join('/')} constraints; constrain schema or document a reviewed exception`);
      if (!absentConstraints.length && binding.schema_exception) errors.push(`${id}: stale schema exception`);
      if (concept.range) {
        const [min, max] = concept.range;
        if ((min !== null && numeric.minimum !== undefined && numeric.minimum < min) ||
            (max !== null && numeric.maximum !== undefined && numeric.maximum > max)) {
          errors.push(`${id}: schema bounds exceed ${binding.concept} range`);
        }
      }
      const allowed = binding.legacy_enum ?? (concept.enum_source ? enums[concept.enum_source] : concept.values);
      if (concept.enum_source && !allowed) errors.push(`${id}: canonical enum ${concept.enum_source} unavailable`);
      if (binding.legacy_enum && !binding.compatibility_reason) errors.push(`${id}: legacy enum requires a compatibility reason`);
      if (numeric.enum && allowed && numeric.enum.some(v => v !== null && !allowed.includes(v))) {
        errors.push(`${id}: enum violates ${binding.concept} vocabulary`);
      }
    }
  }
  if (seen.size === 0) errors.push('no rating fields scanned');
  for (const id of Object.keys(bindings)) if (!seen.has(id)) errors.push(`${id}: stale binding (field removed or scanner stopped seeing it)`);
  return errors;
}

export function readInputs(root) {
  const dir = path.join(root, 'api/openapi');
  const specs = Object.fromEntries(fs.readdirSync(dir).filter(f => f.endsWith('.yaml')).map(f => [f, YAML.parse(fs.readFileSync(path.join(dir, f), 'utf8'))]));
  const manifest = YAML.parse(fs.readFileSync(path.join(root, 'standards/rating-scales.yaml'), 'utf8'));
  return { specs, manifest };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const { specs, manifest } = readInputs(root);
  // Filled by the Go-owned ratings generator; never maintain another numeric ladder here.
  const definitions = JSON.parse(fs.readFileSync(path.join(root, 'standards/generated/rating-definitions.json'), 'utf8'));
  const errors = audit(specs, manifest, canonicalEnums(definitions));
  if (errors.length) { for (const error of errors) console.error(error); process.exitCode = 1; }
  else console.log(`Rating contracts: ${Object.keys(manifest.bindings).length} explicit bindings checked across ${Object.keys(specs).length} specs.`);
}
