import assert from 'node:assert/strict';
import fs from 'node:fs';
import { test } from 'node:test';
import { audit, candidates, shape, requiredAt, canonicalEnums } from './audit-rating-scales.mjs';

const concept = { types: ['number', 'integer'], unit: 'percent', direction: 'higher_is_worse', unknown: 'absent', owner: 'test', range: [0, 100] };
function fixture(schema = { type: 'number', minimum: 0, maximum: 100 }) {
  const specs = { 'sample.yaml': { components: { schemas: { Row: { properties: { high_risk_percent: schema } } } } } };
  const key = 'sample.yaml#/components/schemas/Row/properties/high_risk_percent';
  const manifest = { version: 1, concepts: { adverse_proportion: { ...concept } }, bindings: { [key]: { concept: 'adverse_proportion', delivery: 'implement', contract: shape(schema) } } };
  return { specs, manifest, key };
}

test('higher-is-worse percentage is legitimate; no suffix-based attainment rewrite', () => {
  const { specs, manifest } = fixture(); assert.deepEqual(audit(specs, manifest), []);
});
test('new field, stale field, changed unit range and type/nullability fail', () => {
  const { specs, manifest, key } = fixture();
  const props = specs['sample.yaml'].components.schemas.Row.properties;
  props.score = { type: 'number' };
  assert.match(audit(specs, manifest).join('\n'), /unregistered/);
  delete props.score;
  props.high_risk_percent.maximum = 101;
  assert.match(audit(specs, manifest).join('\n'), /bounds exceed/);
  props.high_risk_percent.maximum = 100;
  props.high_risk_percent.nullable = true;
  assert.match(audit(specs, manifest).join('\n'), /nullability\/requiredness\/constraints changed/);
  delete props.high_risk_percent;
  assert.ok(audit(specs, manifest).some(x => x.includes(key) && x.includes('stale')));
});
test('nested array fields, request parameters, bare score and resource efficiency are discovered', () => {
  const spec = { paths: { '/query': { get: { parameters: [{ name: 'risk_level', schema: { type: 'string' } }] } } }, components: { schemas: { Row: { properties: { rows: { type: 'array', items: { properties: { score: { type: 'number' }, resource_efficiency_score: { type: 'number' } } } }, health: { properties: { performance_metrics: { type: 'number' } } } } } } } };
  const fields = [...candidates(spec).keys()];
  assert.equal(fields.length, 4);
  assert.ok(fields.includes('/paths/~1query/get/parameters/0/schema'));
});
test('canonical severity rejects drift but allows an explicit subset and null', () => {
  const { specs, manifest, key } = fixture({ type: ['string', 'null'], enum: ['low', 'high', null] });
  manifest.concepts.adverse_proportion = { ...concept, types:['string'], range:undefined, enum_source: 'severity' };
  const enums = { severity: ['info', 'low', 'medium', 'high', 'critical'] };
  assert.deepEqual(audit(specs, manifest, enums), []);
  specs['sample.yaml'].components.schemas.Row.properties.high_risk_percent.enum.push('Med');
  assert.match(audit(specs, manifest, enums).join('\n'), /enum violates/);
  manifest.bindings[key].legacy_enum = ['low', 'high', 'Med'];
  manifest.bindings[key].contract=shape(specs['sample.yaml'].components.schemas.Row.properties.high_risk_percent);
  assert.match(audit(specs, manifest, enums).join('\n'), /compatibility reason/);
  manifest.bindings[key].compatibility_reason = 'Historical source payload, translated at boundary';
  assert.deepEqual(audit(specs, manifest, enums), []);
});
test('log vocabulary and signed change are distinct concepts; registration does not migrate them', () => {
  const { specs, manifest, key } = fixture({ type: 'number', minimum: -200, maximum: 300 });
  manifest.concepts.adverse_proportion = { ...concept, direction: 'context_dependent', range: [null, null] };
  manifest.bindings[key].delivery = 'register_only';
  assert.deepEqual(audit(specs, manifest), []);
  const log = fixture({ type: 'string', enum: ['debug', 'warn', 'error'] });
  log.manifest.concepts.adverse_proportion = { ...concept, types:['string'], range:undefined, values: ['debug', 'info', 'warn', 'error', 'critical'] };
  assert.deepEqual(audit(log.specs, log.manifest), []);
});
test('empty scanner and missing semantic metadata fail closed', () => {
  assert.match(audit({}, { version: 1 }).join('\n'), /no rating fields/);
  const { specs, manifest } = fixture(); delete manifest.concepts.adverse_proportion.direction;
  assert.match(audit(specs, manifest).join('\n'), /missing direction/);
});


test('referenced enums are checked and unresolved references fail closed', () => {
  const { specs, manifest, key } = fixture({type:'string'});
  const schema = {$ref: '#/components/schemas/Band'};
  specs['sample.yaml'].components.schemas.Row.properties.high_risk_percent=schema;
  const schemas = specs['sample.yaml'].components.schemas;
  schemas.Band = { type: 'string', enum: ['info', 'medium'] };
  manifest.bindings[key].contract=shape(schema,specs['sample.yaml']);
  manifest.concepts.adverse_proportion = { ...concept, types:['string'], range:undefined, enum_source: 'severity' };
  const enums = { severity: ['info', 'low', 'medium', 'high', 'critical'] };
  assert.deepEqual(audit(specs, manifest, enums), []);
  schemas.Band.enum.push('Med');
  assert.match(audit(specs, manifest, enums).join('\n'), /enum violates/);
  delete schemas.Band;
  assert.match(audit(specs, manifest, enums).join('\n'), /missing rating reference/);
});


test('audit and CI execute the contract checker and its mutation tests', () => {
  const make = fs.readFileSync(new URL('../Makefile', import.meta.url), 'utf8');
  const workflow = fs.readFileSync(new URL('../.github/workflows/standards.yml', import.meta.url), 'utf8');
  const wired = (text) => text.match(/^audit:.*\n((?:\t.*\n|\n)*)/m)?.[1].includes('node ./scripts/audit-rating-scales.mjs') ?? false;
  assert.equal(wired(make), true);
  assert.equal(wired(make.replace('node ./scripts/audit-rating-scales.mjs', 'true')), false);
  assert.match(workflow, /make rating-contract-test/);
  for (const trigger of ['api/openapi/**', 'shared/**', 'services/**', 'frontend-v2/src/**', 'admin-ui-v2/src/**', 'scripts/audit-rating-*.mjs']) {
    assert.equal(workflow.split(`'${trigger}'`).length - 1, 2, `${trigger} must trigger pushes and PRs`);
  }
  for (const artifact of ['standards/generated/rating-definitions.json', 'packages/primitives/src/ratings/definitions.gen.ts']) assert.ok(workflow.includes(artifact));
});


test('resolved type/nullability and required/default drift cannot hide behind a reference', () => {
  const {specs,manifest,key}=fixture({type:'number'});
  const spec=specs['sample.yaml']; const schema={$ref:'#/components/schemas/Score'};
  spec.components.schemas.Score={type:'number',minimum:0,maximum:100};
  spec.components.schemas.Row.properties.high_risk_percent=schema;
  manifest.bindings[key].contract=shape(schema,spec);
  assert.deepEqual(audit(specs,manifest),[]);
  for(const change of [{type:'string'},{nullable:true},{default:50}]) {
    const original={...spec.components.schemas.Score};Object.assign(spec.components.schemas.Score,change);
    assert.match(audit(specs,manifest).join('\n'),/contract.*changed/);
    spec.components.schemas.Score=original;
  }
  spec.components.schemas.Row.required=['high_risk_percent'];
  assert.equal(requiredAt(spec,key.split('#')[1]),true);
  assert.match(audit(specs,manifest).join('\n'),/requiredness/);
});
test('constraint deletion fails and existing omissions require explicit review', () => {
  const {specs,manifest,key}=fixture();const schema=specs['sample.yaml'].components.schemas.Row.properties.high_risk_percent;
  delete schema.maximum;
  assert.match(audit(specs,manifest).join('\n'),/constraints changed/);
  manifest.bindings[key].contract=shape(schema);
  assert.match(audit(specs,manifest).join('\n'),/missing maximum/);
  manifest.bindings[key].schema_exception='Legacy contract lacks an upper bound; concept documents intended range, runtime validation not asserted.';
  assert.deepEqual(audit(specs,manifest),[]);
  schema.maximum=100;manifest.bindings[key].contract=shape(schema);
  assert.match(audit(specs,manifest).join('\n'),/stale schema exception/);
  const categorical=fixture({type:'string',enum:['complete','partial']});
  assert.match(audit(categorical.specs,categorical.manifest).join('\n'),/schema type incompatible/);
});
test('enum constraint deletion is rejected even when the binding shape is refreshed', () => {
  const {specs,manifest,key}=fixture({type:'string',enum:['low','high']});
  manifest.concepts.adverse_proportion={...concept,range:undefined,types:['string'],enum_source:'severity'};
  const enums={severity:['info','low','medium','high','critical']};
  assert.deepEqual(audit(specs,manifest,enums),[]);
  const schema=specs['sample.yaml'].components.schemas.Row.properties.high_risk_percent;
  delete schema.enum;manifest.bindings[key].contract=shape(schema);
  assert.match(audit(specs,manifest,enums).join('\n'),/missing enum/);
});


test('external canonical enum follows generated strength while legacy labels stay separate', () => {
  const definitions = JSON.parse(fs.readFileSync(new URL('../standards/generated/rating-definitions.json', import.meta.url), 'utf8'));
  const enums = canonicalEnums(definitions);
  assert.deepEqual(enums.algorithm_strength, definitions.strength.map(row => row.value));
  assert.deepEqual(enums.algorithm_strength_filter, [...enums.algorithm_strength, 'unassessed']);
  const { specs, manifest, key } = fixture({ type: ['string', 'null'], enum: [...enums.algorithm_strength, null] });
  manifest.concepts.adverse_proportion = { ...concept, types: ['string'], range: undefined, enum_source: 'algorithm_strength' };
  assert.deepEqual(audit(specs, manifest, enums), []);
  for (const legacy of ['good', 'unknown']) {
    const schema = specs['sample.yaml'].components.schemas.Row.properties.high_risk_percent;
    schema.enum = [legacy, null];
    manifest.bindings[key].contract = shape(schema);
    assert.match(audit(specs, manifest, enums).join('\n'), /enum violates/);
  }
});
