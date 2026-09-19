// The static field table, pinned to §4.3 by name — and the targets, which both
// catalogues share.
//
// `test-fields.ts` is hand-mirrored from Go's `catalog/testcatalog`, and what
// keeps it honest is the conformance suite: 228 fixtures resolve against it, so
// any column renamed, retyped or dropped shows up there case by case. What the
// fixtures do NOT prove is the reverse — a field §4.3 lists that nobody
// happened to write a fixture for could quietly go missing, or one nobody asked
// for could quietly be added. So the names are pinned here.

import { describe, expect, it } from 'vitest';

import { ASSET_CLASSES, ASSET_CLASS_KEYS } from '../assets';
import { knownType, operatorsFor } from './catalog';
import {
  COLLECTOR_MINTED_KINDS,
  IDENTIFIER_ANY_KIND,
  IDENTIFIER_KINDS,
  IDENTIFIER_KIND_ALIASES,
  NAMESPACES_BY_TARGET,
  TARGETS,
  USER_ENTERABLE_IDENTIFIER_KINDS,
  WRITABLE_IDENTIFIER_KINDS,
} from './targets';
import { TEST_FIELDS_BY_TARGET } from './test-fields';

/** §4.1's target list, in the spec's own order. */
const SPEC_TARGETS = [
  'asset',
  'endpoint',
  'certificate',
  'crypto_configuration',
  'finding',
  'software_install',
  'relationship',
  'observation',
  'measurement',
];

/** §4.3's field names, per target, as the STATIC catalogue spells them. */
const SPEC_FIELDS: Record<string, string[]> = {
  asset: [
    'class',
    'display_name', 'hostname', 'description',
    'primary_address',
    'environment',
    'business_unit', 'owner_email', 'support_group', 'site', 'region', 'zone',
    'status', 'ownership', 'stale_status', 'identity_status', 'source', 'proposed_by',
    'risk', 'risk_score', 'risk_assessed_by',
    'confidence_score', 'class_confidence',
    'first_seen', 'last_seen', 'created_at', 'updated_at',
    'segment_id', 'location_id', 'id',
  ],
  endpoint: [
    'address', 'fqdn', 'port', 'transport', 'protocol', 'service_name',
    // `bound_local` is three-valued and NULL matches neither comparison, which
    // is what makes `= false` mean "measured, and exposed to the network"
    // rather than "not known to be loopback" (QUERY_LANGUAGE §4.3).
    'service_version', 'status', 'bound_local', 'sni', 'alpn',
    'last_seen', 'last_scanned', 'id',
  ],
  certificate: [
    'subject_dn', 'issuer_dn', 'fingerprint_sha256', 'key_algorithm', 'signature_alg',
    'certificate_state', 'key_size', 'not_before', 'not_after', 'self_signed', 'id',
  ],
  // §12 contradiction 5: §4.3 gave this target no table. The three algorithm
  // fields carry §12 amendment 5's names in BOTH catalogues — they were short
  // here until workstream 0.8e, which is a disagreement no fixture could have
  // caught. `registry-fields.gen.test.ts` now asserts the two agree.
  crypto_configuration: [
    'protocol', 'protocol_version', 'cipher_suite', 'key_exchange', 'signature_algorithm',
    'symmetric_algorithm', 'hash_algorithm', 'key_size', 'risk_score', 'risk', 'strength',
    'algorithm.deprecated', 'first_seen', 'last_seen', 'id',
  ],
  finding: [
    'producer', 'kind', 'subject_type', 'detection_state', 'workflow_status',
    'severity', 'score', 'summary', 'first_seen', 'last_seen', 'id',
  ],
  software_install: [
    'name', 'vendor', 'version', 'cpe', 'purl', 'install_path', 'status',
    'first_seen', 'last_seen', 'id',
  ],
  relationship: ['type', 'status', 'source', 'confidence', 'id'],
  observation: [
    'source', 'kind', 'confidence', 'class', 'hostname', 'address',
    'network.ownership', 'network.type', 'network.segment_id', 'first_seen',
  ],
  measurement: ['value'],
  identifier: [
    'kind', 'value', 'scope', 'confidence', 'source_kind', 'first_seen', 'last_seen', 'id',
  ],
};

describe('the targets of §4.1', () => {
  it('are all present, and nothing else is', () => {
    const names = TARGETS.map((t) => t.name);
    for (const t of SPEC_TARGETS) expect(names, `§4.1 lists ${t}`).toContain(t);
    // `identifier` is the one extra: §3 lists it as a sub-predicate collection,
    // so its inner predicate needs a target to resolve against.
    expect([...names].sort()).toEqual([...SPEC_TARGETS, 'identifier'].sort());
  });

  it('mark the two table-less ones as in-memory', () => {
    // §4.1: an observation is evaluated by the identification engine and a
    // measurement by the extractor; neither has a table, and the server's
    // translator refuses them rather than inventing one.
    for (const t of TARGETS) {
      const shouldBeInMemory = t.name === 'observation' || t.name === 'measurement';
      expect(t.inMemory === true, t.name).toBe(shouldBeInMemory);
      expect(t.table === '', t.name).toBe(shouldBeInMemory);
    }
  });

  it('make only asset-shaped rows traversable and free-textable', () => {
    // §5.6: edges join assets. §5.4: free text is a substring search over an
    // asset's name, hostname, identifiers and tags — no other target has that
    // column set, so a free-text term there is untranslatable rather than
    // silently narrowed.
    expect(TARGETS.filter((t) => t.traversable).map((t) => t.name)).toEqual(['asset']);
    expect(TARGETS.filter((t) => t.freeTextable).map((t) => t.name)).toEqual(['asset']);
  });
});

describe('the namespaces of §4.2', () => {
  it('resolve only on asset-shaped targets', () => {
    expect(NAMESPACES_BY_TARGET.asset).toEqual(['attr', 'fact', 'id', 'tag']);
    expect(NAMESPACES_BY_TARGET.observation).toEqual(['attr', 'fact', 'id', 'tag']);
    expect(NAMESPACES_BY_TARGET.measurement).toEqual(['fact']);
    expect(NAMESPACES_BY_TARGET.endpoint).toBeUndefined();
    expect(NAMESPACES_BY_TARGET.certificate).toBeUndefined();
  });
});

describe('the identifier registry (ADR-0002 D3)', () => {
  // The kinds are hand-mirrored from standards/asset-classes.yaml, which
  // generates them for Go and not for TypeScript. The one generated TypeScript
  // artefact that does carry kinds is every class's `identifierPrecedence`, so
  // that is what they are cross-checked against — in both directions, so a kind
  // added to the YAML and not here fails.
  const fromClasses = new Set<string>();
  for (const key of ASSET_CLASS_KEYS) {
    for (const k of ASSET_CLASSES[key].identifierPrecedence) fromClasses.add(k);
  }

  it('matches the kinds the generated class taxonomy uses', () => {
    // Declarations are issued by the confirmation operation for any class;
    // they are not a class-specific matching rule for collected evidence.
    expect([...IDENTIFIER_KINDS].sort()).toEqual([...fromClasses, 'declaration_id'].sort());
  });

  it('separates the stored kinds from the spellings id.<kind> accepts', () => {
    // §12 amendment 4: the §3 cheat sheet writes `id.mac`, ADR-0002 D3 names
    // the kind `mac_address`, and both resolve — but only `mac_address` ever
    // reaches the column.
    expect(IDENTIFIER_KINDS).not.toContain('mac');
    expect(WRITABLE_IDENTIFIER_KINDS).toContain('mac');
    expect(IDENTIFIER_KIND_ALIASES.mac).toBe('mac_address');
  });

  it('keeps the any-kind pseudo-kind out of the real ones (§13 A1)', () => {
    expect(IDENTIFIER_KINDS).not.toContain(IDENTIFIER_ANY_KIND);
    expect(WRITABLE_IDENTIFIER_KINDS).not.toContain(IDENTIFIER_ANY_KIND);
  });

  // gate1 C11. The asset form kept its own hand-written copy of "the kinds a
  // person may type", under the same NAME as the query language's writable set
  // — one including `mac`, the other which must never include it. The form's
  // list is derived from these two now.
  it('names every collector-minted kind as a real kind', () => {
    for (const k of COLLECTOR_MINTED_KINDS) {
      expect(IDENTIFIER_KINDS, `${k} is not a kind`).toContain(k);
    }
  });

  it('derives the user-enterable kinds as the registry minus the collector-minted ones', () => {
    expect([...USER_ENTERABLE_IDENTIFIER_KINDS])
      .toEqual(IDENTIFIER_KINDS.filter((k) => !COLLECTOR_MINTED_KINDS.includes(k)));
    for (const k of COLLECTOR_MINTED_KINDS) {
      expect(USER_ENTERABLE_IDENTIFIER_KINDS, `a person must not be able to claim ${k}`).not.toContain(k);
    }
  });

  it('keeps the user-enterable kinds distinct from the query language’s writable set', () => {
    // The other polarity of the same confusion: an alias is a spelling, not a
    // kind, and a form that offered `mac` would write a value the column can
    // never hold.
    expect(USER_ENTERABLE_IDENTIFIER_KINDS).not.toContain('mac');
    expect(USER_ENTERABLE_IDENTIFIER_KINDS.length).toBeLessThan(WRITABLE_IDENTIFIER_KINDS.length);
  });
});

describe('the static first-class fields', () => {
  for (const [target, expected] of Object.entries(SPEC_FIELDS)) {
    it(`${target} has exactly the fields the spec names`, () => {
      const actual = (TEST_FIELDS_BY_TARGET[target] ?? []).map((f) => f.name);
      expect([...actual].sort()).toEqual([...expected].sort());
    });
  }

  it('gives every field a type the §4.4 matrix covers', () => {
    // An unresolved or unknown type must never reach a translator; the
    // validator reports one as `untranslatable`, and a field that can only ever
    // be untranslatable is a catalogue bug, not a user error.
    for (const [target, fields] of Object.entries(TEST_FIELDS_BY_TARGET)) {
      for (const f of fields) {
        expect(knownType(f.type), `${target}.${f.name} is ${JSON.stringify(f.type)}`).toBe(true);
        expect(operatorsFor(f.type).length).toBeGreaterThan(1);
      }
    }
  });

  it('never publishes one field name twice on a target (§13 A1)', () => {
    for (const [target, fields] of Object.entries(TEST_FIELDS_BY_TARGET)) {
      const names = fields.map((f) => f.name);
      expect(new Set(names).size, `${target} has a duplicate field name`).toBe(names.length);
    }
  });

  it('gives every version field a normalised sort key (§5.5)', () => {
    // A lexical fallback is forbidden outright, so a version field without a
    // sort column can only ever be untranslatable.
    for (const [target, fields] of Object.entries(TEST_FIELDS_BY_TARGET)) {
      for (const f of fields) {
        if (f.type !== 'version') continue;
        expect(f.accessor.sortColumn, `${target}.${f.name}`).toBeTruthy();
      }
    }
  });

  it('gives risk its coverage column and severity none (§5.2)', () => {
    // `risk:not_assessed` is a question about coverage, and only a band field
    // that records who assessed it can answer it. `findings.severity` carries a
    // stored label instead, and reports unknown_value for not_assessed.
    const risk = TEST_FIELDS_BY_TARGET.asset.find((f) => f.name === 'risk');
    expect(risk?.accessor.assessedBy).toBe('risk_assessed_by');
    const severity = TEST_FIELDS_BY_TARGET.finding.find((f) => f.name === 'severity');
    expect(severity?.accessor.assessedBy).toBeUndefined();
    expect(severity?.accessor.labelColumn).toBe('severity');
  });

  it('closes the environment enum (§12 A1)', () => {
    // It used to be open here, because §8's scope mapping and §9 example 18
    // wrote `prod`. §12 amendment 1 settled that the other way, and
    // `assets.environment` IS the Postgres type: a row holding `prod` cannot
    // exist, so an open set turns a typo into an empty result.
    const env = TEST_FIELDS_BY_TARGET.asset.find((f) => f.name === 'environment');
    expect(env?.enum).toEqual(['production', 'staging', 'development', 'test']);
    expect(env?.accessor.cast).toBe('text');
  });

  it('identifier.kind is the STORED kinds, with no mac alias', () => {
    // It used to carry `mac`, and that was one of the places the two catalogues
    // differed. `identifier:(kind:mac)` compares the column against "mac" and
    // matches nothing, for ever and silently — so the alias belongs to the PATH
    // (`id.mac`), which rewrites to `mac_address` before any column sees it,
    // and never to the value set.
    const kind = TEST_FIELDS_BY_TARGET.identifier.find((f) => f.name === 'kind');
    expect(kind?.enum).not.toContain('mac');
    expect(kind?.enum).toContain('mac_address');
  });
});
