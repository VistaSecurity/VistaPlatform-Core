// The generated production field table.
//
// `registry-fields.gen.ts` is emitted from Go's `catalog/registrycatalog` by
// `shared/query/catalog/registrycatalog/cmd/gen-ts-fields`, and `make audit`
// runs that command with --check. So the mirror can no longer drift from its
// source, and this file no longer has to stand in for that: what it asserts is
// the things a byte comparison cannot see — that the table is internally
// coherent, that the two catalogues agree where they are meant to and differ
// only where they mean to, and that the copies `targets.ts` and `catalog.ts`
// still hold match what Go publishes.
//
// This replaces `registry-fields.test.ts`, which asserted SEVEN differences
// between the two tables one by one. Six of them stand and are re-asserted
// here. The seventh — crypto_configuration's `signature` / `symmetric` / `hash`
// against §4.3's longer names — is closed: both catalogues now use the spec's
// names (workstream 0.8e), and the assertion below is that they agree rather
// than that they differ.

import { describe, expect, it } from 'vitest';

import type { FieldType } from './ast';
import { knownType, operatorsFor } from './catalog';
import {
  OPERATORS_BY_TYPE,
  REGISTRY_FIELDS_BY_TARGET,
  REGISTRY_TARGETS,
} from './registry-fields.gen';
import { TEST_FIELDS_BY_TARGET } from './test-fields';
import { IDENTIFIER_KINDS, TARGETS } from './targets';
import { RELATIONSHIP_TYPES } from './vocabulary';
import {
  FINDING_KIND_KEYS,
  FINDING_PRODUCER_KEYS,
  FINDING_SUBJECT_TYPES,
} from '../findings';

function names(
  table: Readonly<Record<string, readonly { name: string }[]>>,
  target: string,
): string[] {
  return (table[target] ?? []).map((f) => f.name).sort();
}

describe('the table is coherent', () => {
  it('has a field table for every target', () => {
    for (const t of TARGETS) {
      expect(REGISTRY_FIELDS_BY_TARGET[t.name], t.name).toBeDefined();
      expect((REGISTRY_FIELDS_BY_TARGET[t.name] ?? []).length, t.name).toBeGreaterThan(0);
    }
  });

  it('gives every field a usable type and a normalised version key', () => {
    for (const [target, fields] of Object.entries(REGISTRY_FIELDS_BY_TARGET)) {
      for (const f of fields) {
        expect(knownType(f.type), `${target}.${f.name} is ${JSON.stringify(f.type)}`).toBe(true);
        expect(operatorsFor(f.type).length).toBeGreaterThan(0);
        if (f.type === 'version') expect(f.accessor.sortColumn, `${target}.${f.name}`).toBeTruthy();
      }
    }
  });

  it('never publishes one field name twice on a target (§13 A1)', () => {
    for (const [target, fields] of Object.entries(REGISTRY_FIELDS_BY_TARGET)) {
      const list = fields.map((f) => f.name);
      expect(new Set(list).size, `${target} has a duplicate field name`).toBe(list.length);
    }
  });

  it('is sorted by name, as Go’s FirstClassFields returns it', () => {
    for (const [target, fields] of Object.entries(REGISTRY_FIELDS_BY_TARGET)) {
      const list = fields.map((f) => f.name);
      expect(list, target).toEqual([...list].sort());
    }
  });
});

describe('the copies the rest of the package holds', () => {
  it('targets.ts matches what Go publishes', () => {
    // `targets.ts` is shared by BOTH catalogues, because Go's two declare
    // identical target tables. That is a claim, and this is what checks it: a
    // target added, an alias changed or a `subs` list edited on the Go side
    // fails here rather than reaching a translator as a wrong join.
    expect([...TARGETS]).toEqual([...REGISTRY_TARGETS]);
  });

  it('the §4.4 operator matrix matches Go’s', () => {
    // catalog.ts implements the matrix rather than reading the generated
    // table — the validator asks four narrow questions of it, and a list of
    // operator strings is the wrong shape for those. So the table is the pin.
    // §4.4 written twice is §4.4 disagreeing with itself eventually.
    for (const [type, ops] of Object.entries(OPERATORS_BY_TYPE)) {
      expect(knownType(type as FieldType), type).toBe(true);
      expect(operatorsFor(type as FieldType), type).toEqual([...ops]);
    }
  });

  it('covers exactly the types the matrix knows', () => {
    // Enumerated rather than derived, so a type added to the FieldType union
    // and left out of one matrix fails here instead of silently resolving to
    // "no operators are legal".
    const every: FieldType[] = [
      'keyword', 'text', 'number', 'timestamp', 'boolean', 'inet',
      'class', 'band', 'version', 'uuid', 'keyword[]', 'json',
    ];
    expect(Object.keys(OPERATORS_BY_TYPE).sort()).toEqual([...every].sort());
    for (const t of every) expect(knownType(t), t).toBe(true);
    // The unresolved zero value is not a type and must never reach a
    // translator.
    expect(knownType('')).toBe(false);
    expect(OPERATORS_BY_TYPE['']).toBeUndefined();
  });
});

describe('the value sets that come from another generated registry', () => {
  // Emitted as references, not literals, so the two generated files cannot
  // disagree. The generator checks the values still match Go's registry before
  // emitting the reference; these assert the reference reached the right field.
  it('reads the finding vocabularies from @vistasecurity/primitives/findings', () => {
    const find = (name: string) => REGISTRY_FIELDS_BY_TARGET.finding.find((f) => f.name === name);
    expect(find('producer')?.enum).toEqual([...FINDING_PRODUCER_KEYS]);
    expect(find('kind')?.enum).toEqual([...FINDING_KIND_KEYS]);
    expect(find('subject_type')?.enum).toEqual([...FINDING_SUBJECT_TYPES]);
    expect(FINDING_PRODUCER_KEYS.length).toBeGreaterThan(0);
    expect(FINDING_KIND_KEYS.length).toBeGreaterThan(0);
  });

  it('reads identifier kinds and relationship types from their registries', () => {
    expect(REGISTRY_FIELDS_BY_TARGET.identifier.find((f) => f.name === 'kind')?.enum).toEqual([
      ...IDENTIFIER_KINDS,
    ]);
    expect(REGISTRY_FIELDS_BY_TARGET.relationship.find((f) => f.name === 'type')?.enum).toEqual([
      ...RELATIONSHIP_TYPES,
    ]);
  });
});

describe('the two catalogues: where they agree, and where they still differ', () => {
  it('agrees with the static table on crypto_configuration’s field names', () => {
    // The difference that used to be asserted here. §12 amendment 5 names
    // these; the static catalogue published the columns' short names, and no
    // conformance fixture writes any of the six — so the exemption list, which
    // only catches a case that RUNS, could never have noticed. Both sides now
    // use the spec's names, and this is the check that keeps them together.
    expect(names(REGISTRY_FIELDS_BY_TARGET, 'crypto_configuration')).toEqual(
      names(TEST_FIELDS_BY_TARGET, 'crypto_configuration'),
    );
    expect(names(REGISTRY_FIELDS_BY_TARGET, 'crypto_configuration')).toEqual(
      expect.arrayContaining(['signature_algorithm', 'symmetric_algorithm', 'hash_algorithm']),
    );
  });

  it('1. protocol carries the five OT values on BOTH sides now', () => {
    // It did not. The static list stopped at OPC_UA while `public.protocol_type`
    // had five more, so `protocol:S7` was an invalid field value in the spec
    // fixtures and a stored row in the database. Resolved in the registry's
    // favour: the static list gained them.
    const registry = REGISTRY_FIELDS_BY_TARGET.endpoint.find((f) => f.name === 'protocol');
    const test = TEST_FIELDS_BY_TARGET.endpoint.find((f) => f.name === 'protocol');
    for (const v of ['EtherNet_IP', 'BACnet', 'BACnet_SC', 'HART_IP', 'S7']) {
      expect(registry?.enum, `registry protocol has ${v}`).toContain(v);
      expect(test?.enum, `static protocol has ${v}`).toContain(v);
    }
    expect(registry?.enum).toEqual(test?.enum);
  });

  it('2. strength carries its closed value set on both sides', () => {
    // The static table published NO enum, so `strength:strng` validated against
    // the fixtures and returned no rows against the product.
    const registry = REGISTRY_FIELDS_BY_TARGET.crypto_configuration.find(
      (f) => f.name === 'strength',
    );
    const test = TEST_FIELDS_BY_TARGET.crypto_configuration.find((f) => f.name === 'strength');
    expect(registry?.enum).toEqual(['weak', 'acceptable', 'strong', 'recommended']);
    expect(test?.enum).toEqual(registry?.enum);
  });

  it('3. identifier.kind is the stored kinds on both sides, without the mac alias', () => {
    // `identifier:(kind:mac)` compares the column against "mac" and matches
    // nothing, forever and silently. `id.mac` is a PATH alias and stays one —
    // see the WRITABLE_IDENTIFIER_KINDS assertion in targets.
    const registry = REGISTRY_FIELDS_BY_TARGET.identifier.find((f) => f.name === 'kind');
    const test = TEST_FIELDS_BY_TARGET.identifier.find((f) => f.name === 'kind');
    expect(registry?.enum).toEqual([...IDENTIFIER_KINDS]);
    expect(registry?.enum).not.toContain('mac');
    expect(test?.enum).toEqual(registry?.enum);
  });

  it('4. relationship has first_seen and last_seen', () => {
    // The one NAME-level difference that remains, and it is the static table
    // being short rather than either side being wrong: no conformance fixture
    // writes either field, so adding them would change nothing the fixtures
    // prove. Recorded here so it cannot become invisible.
    expect(names(REGISTRY_FIELDS_BY_TARGET, 'relationship')).toEqual(
      expect.arrayContaining(['first_seen', 'last_seen']),
    );
    expect(names(TEST_FIELDS_BY_TARGET, 'relationship')).not.toContain('first_seen');
  });

  it('5. several fields carry the production catalogue’s description', () => {
    // Descriptions are autocomplete help text, not semantics: the production
    // catalogue carries them and the spec fixture does not, and no predicate
    // means anything different because of it. The remaining deliberate
    // difference.
    const proposedBy = REGISTRY_FIELDS_BY_TARGET.asset.find((f) => f.name === 'proposed_by');
    expect(proposedBy?.description).toContain('class_source_ref');
    const id = REGISTRY_FIELDS_BY_TARGET.asset.find((f) => f.name === 'id');
    expect(id?.description).toContain('id.any');
  });

  it('5b. observation.network.type is four values on both sides', () => {
    // §14 B1: the classifier copies the segment's `network_type` through and
    // the segment CHECK allows four. The static table said two, on the strength
    // of the field's NAME, which refused every cloud and vpn segment.
    const registry = REGISTRY_FIELDS_BY_TARGET.observation.find((f) => f.name === 'network.type');
    const test = TEST_FIELDS_BY_TARGET.observation.find((f) => f.name === 'network.type');
    expect(registry?.enum).toEqual(['private', 'public', 'vpn', 'cloud']);
    expect(new Set(test?.enum)).toEqual(new Set(registry?.enum));
  });

  it('5c. every shared first-class field agrees on TYPE and closed set', () => {
    // The sweep the numbered list above never did. It compared NAMES, so a
    // field present on both sides with a different type or a cut-down value set
    // passed — which is how `strength`, `protocol` and `identifier.kind` each
    // diverged without anything saying so. Names are not the contract; what a
    // predicate MEANS is.
    for (const [target, registryFields] of Object.entries(REGISTRY_FIELDS_BY_TARGET)) {
      const testFields = TEST_FIELDS_BY_TARGET[target];
      if (!testFields) continue;
      for (const rf of registryFields) {
        const tf = testFields.find((f) => f.name === rf.name);
        if (!tf) continue;
        expect(tf.type, `${target}.${rf.name} type`).toBe(rf.type);
        if (rf.enum === undefined && tf.enum === undefined) continue;
        expect(new Set(tf.enum ?? []), `${target}.${rf.name} value set`).toEqual(
          new Set(rf.enum ?? []),
        );
      }
    }
  });

  it('6. everything else is the same table', () => {
    // The targets whose field NAMES are identical in both. If one of these ever
    // diverges, it belongs above with a reason, not here.
    for (const target of [
      'asset', 'endpoint', 'certificate', 'crypto_configuration', 'finding',
      'software_install', 'observation', 'measurement',
    ]) {
      expect(names(REGISTRY_FIELDS_BY_TARGET, target), target).toEqual(
        names(TEST_FIELDS_BY_TARGET, target),
      );
    }
  });
});

describe('the closed value sets it mirrors from the schema', () => {
  // Every one of these is a Postgres enum type or a CHECK array. Go's
  // TestEnumsMatchSchema parses scripts/database/schema.sql and fails on any
  // difference in either direction, and this table is now generated FROM the Go
  // one — so the chain from schema.sql to the editor is unbroken. These pin the
  // values so that a change to one arrives here as a failing assertion with the
  // old value visible, rather than as a silent edit inside a generated file.
  const cases: [string, string, string[]][] = [
    ['asset', 'environment', ['production', 'staging', 'development', 'test']],
    ['asset', 'status', ['pending_approval', 'monitoring', 'denied', 'archived']],
    ['asset', 'ownership', ['internal', 'third_party', 'unknown']],
    ['asset', 'stale_status', ['active', 'stale', 'archived']],
    // Five, and the only one of these sets that is not four: `class_source_kind`
    // is the one column accepting `rule` (workstream 2.10b). The `source_kind`
    // sets on identifiers, relationships and facts stay at four.
    ['asset', 'source', ['measured', 'declared', 'imported', 'inferred', 'rule']],
    ['endpoint', 'transport', ['tcp', 'udp', 'none']],
    ['endpoint', 'status', ['active', 'stale', 'closed']],
    ['certificate', 'certificate_state', [
      'pre-activation', 'active', 'suspended', 'deactivated', 'revoked', 'expired', 'destroyed',
    ]],
    ['software_install', 'status', ['active', 'stale', 'removed']],
    ['relationship', 'status', ['pending', 'active', 'rejected', 'stale']],
    ['finding', 'detection_state', ['ACTIVE', 'INACTIVE', 'ARCHIVED']],
    ['finding', 'workflow_status', ['NEW', 'NOTIFIED', 'RESOLVED', 'SUPPRESSED']],
    // Four, not two: the classifier copies the matching SEGMENT's
    // `network_type` through, so the segment column's CHECK is its range.
    // Written as {private, public} from the field's NAME until validating
    // auto-approval rules for real refused every cloud and vpn segment.
    ['observation', 'network.type', ['private', 'public', 'vpn', 'cloud']],
    ['observation', 'network.ownership', ['internal', 'third_party', 'unknown']],
  ];
  for (const [target, field, values] of cases) {
    it(`${target}.${field}`, () => {
      const f = REGISTRY_FIELDS_BY_TARGET[target].find((x) => x.name === field);
      expect(f?.enum).toEqual(values);
    });
  }

  it('applies the ::text cast to every closed set', () => {
    // Required for a Postgres ENUM — neither lower() nor a text comparison
    // exists for one, and a value outside the type raises "invalid input value
    // for enum" at query time, an error where the honest answer is "no rows".
    // A no-op on a text column with a CHECK, so it is applied to both rather
    // than tracked per column.
    for (const [target, fields] of Object.entries(REGISTRY_FIELDS_BY_TARGET)) {
      for (const f of fields) {
        if (f.enum === undefined || f.accessor.kind !== 'column') continue;
        expect(f.accessor.cast, `${target}.${f.name}`).toBe('text');
      }
    }
  });
});
