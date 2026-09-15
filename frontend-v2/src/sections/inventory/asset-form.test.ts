// The registry-driven asset form (ADR-0006 D8).
//
// The property that matters is that nothing about the form enumerates a class or
// an attribute: adding a class to `standards/asset-classes.yaml` must add its
// fields to this form without a page edit. So the tests walk the GENERATED
// registry rather than restating a list — a test that restated one would pass
// forever while the form drifted away from the taxonomy.
import { describe, expect, it } from 'vitest';
import { ASSET_CLASSES, ASSET_CLASS_KEYS, ATTRIBUTE_SCHEMAS } from '@vistasecurity/primitives/assets';
import {
  COLLECTOR_MINTED_KINDS, IDENTIFIER_KINDS, USER_ENTERABLE_IDENTIFIER_KINDS,
  WRITABLE_IDENTIFIER_KINDS as QUERY_WRITABLE_KINDS,
} from '@vistasecurity/primitives/query';
import {
  FORM_IDENTIFIER_KINDS, IDENTIFIER_KIND_LABEL, attributesToValues, buildAttributes,
  flattenClassTree, humaniseAttribute, isServiceBranch,
} from './class-picker';
import { validateAssetForm } from './asset-form-modal';

describe('flattenClassTree', () => {
  it('offers EVERY platform class, exactly once', () => {
    const flat = flattenClassTree();
    expect(flat.map((f) => f.key).sort()).toEqual([...ASSET_CLASS_KEYS].sort());
  });

  it('records the depth so the picker can indent the tree', () => {
    const flat = flattenClassTree();
    const server = flat.find((f) => f.key === 'server')!;
    const hardware = flat.find((f) => f.key === 'hardware')!;
    expect(hardware.depth).toBe(0);
    // hardware → computer → server
    expect(server.depth).toBe(2);
  });

  it('lists a parent before its children', () => {
    const order = flattenClassTree().map((f) => f.key);
    for (const key of ASSET_CLASS_KEYS) {
      const parent = ASSET_CLASSES[key].parent;
      if (parent) expect(order.indexOf(parent)).toBeLessThan(order.indexOf(key));
    }
  });
});

describe('isServiceBranch', () => {
  it('is true for the service classes, derived from the class PATH', () => {
    // Derived rather than listed, so a subclass added under `service` later
    // inherits the display-name requirement instead of silently escaping it.
    expect(isServiceBranch('service')).toBe(true);
    expect(isServiceBranch('business_service')).toBe(true);
    expect(isServiceBranch('technical_service')).toBe(true);
  });

  it('is false for everything else, including an unknown class', () => {
    expect(isServiceBranch('server')).toBe(false);
    expect(isServiceBranch('object_storage')).toBe(false);
    expect(isServiceBranch('tenant_custom_thing')).toBe(false);
    expect(isServiceBranch(null)).toBe(false);
  });
});

describe('validateAssetForm — the identity floor', () => {
  const ok = { classKey: 'server', displayName: '', identifiers: [{ kind: 'hostname', value: 'web-01' }], metadataError: null };

  it('accepts a class plus at least one identifier', () => {
    expect(validateAssetForm(ok)).toBeNull();
  });

  it('requires a class first — it decides every other field', () => {
    expect(validateAssetForm({ ...ok, classKey: '' })).toMatch(/class/i);
  });

  it('REFUSES an asset with no identifier at all', () => {
    // ADR-0002's floor. An asset nothing can be recognised by can never be
    // matched to a later sighting, so it becomes a duplicate on the next scan —
    // which is the exact problem the identification engine exists to solve.
    expect(validateAssetForm({ ...ok, identifiers: [] })).toMatch(/identifier/i);
    expect(validateAssetForm({ ...ok, identifiers: [{ kind: 'hostname', value: '   ' }] })).toMatch(/identifier/i);
  });

  it('requires a NAME for a service instead of an identifier', () => {
    // A service identifies by (tenant, class, name): it has no address or serial
    // to be known by, which is the one legitimate exception to the floor.
    const service = { classKey: 'business_service', displayName: '', identifiers: [], metadataError: null };
    expect(validateAssetForm(service)).toMatch(/name/i);
    expect(validateAssetForm({ ...service, displayName: 'Payroll' })).toBeNull();
  });

  it('surfaces a metadata JSON error', () => {
    expect(validateAssetForm({ ...ok, metadataError: 'Invalid JSON' })).toBe('Invalid JSON');
  });
});

describe('buildAttributes — coercion into the typed bag', () => {
  it('coerces by the DECLARED type, not by what the string looks like', () => {
    const out = buildAttributes('server', { operating_system: 'Ubuntu', cpu_count: '8', memory_mb: '16384' });
    expect(out).toEqual({ operating_system: 'Ubuntu', cpu_count: 8, memory_mb: 16384 });
    expect(typeof out.cpu_count).toBe('number');
  });

  it('OMITS a blank field rather than sending an empty string', () => {
    // "The operator left it blank" and "the operator set it to empty" are
    // different facts, and the second is never what anyone meant.
    expect(buildAttributes('server', { operating_system: '', model: '   ' })).toEqual({});
  });

  it('omits a number that does not parse rather than sending NaN', () => {
    // JSON renders NaN as null, and the schema would then reject the write with
    // a message about a type nobody typed.
    expect(buildAttributes('server', { cpu_count: 'lots' })).toEqual({});
  });

  it('drops anything the class does not declare', () => {
    // `additionalProperties: false` — an attribute nothing declared is a
    // collection bug, not a bonus, and the server would reject the write.
    expect(buildAttributes('server', { not_a_real_attribute: 'x' })).toEqual({});
  });

  it('returns {} for an unknown class rather than throwing', () => {
    expect(buildAttributes('tenant_custom_thing', { anything: 'x' })).toEqual({});
  });

  it('round-trips through attributesToValues', () => {
    const original = { operating_system: 'Ubuntu', cpu_count: 8 };
    expect(buildAttributes('server', attributesToValues(original))).toEqual(original);
  });

  it('accepts every declared attribute of every class', () => {
    // The real property: the form can express whatever the registry declares.
    // If a new attribute type were added to the YAML and not handled here, this
    // is what would catch it.
    for (const key of ASSET_CLASS_KEYS) {
      const props = ATTRIBUTE_SCHEMAS[key]?.properties ?? {};
      for (const [name, prop] of Object.entries(props)) {
        const sample = prop.enum?.[0]
          ?? (prop.type === 'integer' || prop.type === 'number' ? '1'
            : prop.type === 'boolean' ? 'true'
              : prop.type === 'array' ? 'a, b'
                : 'x');
        const out = buildAttributes(key, { [name]: sample });
        expect(Object.keys(out)).toEqual([name]);
      }
    }
  });
});

describe('attributesToValues', () => {
  it('stringifies numbers and joins arrays for the form inputs', () => {
    expect(attributesToValues({ cpu_count: 8, tags: ['a', 'b'] })).toEqual({ cpu_count: '8', tags: 'a, b' });
  });

  it('skips nulls and copes with a non-object', () => {
    expect(attributesToValues({ model: null })).toEqual({});
    expect(attributesToValues(null)).toEqual({});
    expect(attributesToValues(['a'])).toEqual({});
  });
});

describe('the identifier kinds the form offers', () => {
  it('excludes the kinds a COLLECTOR mints', () => {
    // `agent_id` and `cloud_resource_id` mean "this is the thing that agent or
    // resource is". Letting an operator type one lets them claim an identity the
    // platform assigns, which is how two real assets get merged by hand.
    expect(FORM_IDENTIFIER_KINDS).not.toContain('agent_id');
    expect(FORM_IDENTIFIER_KINDS).not.toContain('cloud_resource_id');
  });

  it('offers the ones a person can actually know', () => {
    for (const kind of ['hostname', 'fqdn', 'ip_address', 'mac_address', 'serial_number']) {
      expect(FORM_IDENTIFIER_KINDS).toContain(kind);
    }
  });

  // gate1 C11. The form's list was hand-written under the name
  // `WRITABLE_IDENTIFIER_KINDS`, which is ALSO a primitives export meaning
  // something else entirely — every spelling the QUERY language accepts,
  // aliases included. Two constants, one name, opposite jobs. Both directions
  // are pinned here so neither can drift from the registry unnoticed.
  it('is EXACTLY the registry’s kinds minus the collector-minted ones', () => {
    expect([...FORM_IDENTIFIER_KINDS]).toEqual([...USER_ENTERABLE_IDENTIFIER_KINDS]);
    expect([...FORM_IDENTIFIER_KINDS].sort())
      .toEqual([...IDENTIFIER_KINDS].filter((k) => !COLLECTOR_MINTED_KINDS.includes(k)).sort());
  });

  it('offers every registry kind that is not collector-minted (the other polarity)', () => {
    for (const kind of IDENTIFIER_KINDS) {
      if (COLLECTOR_MINTED_KINDS.includes(kind)) continue;
      expect(FORM_IDENTIFIER_KINDS, `the form cannot enter the ${kind} identifier`).toContain(kind);
    }
  });

  it('is NOT the query language’s writable set, which includes aliases', () => {
    // `mac` is a spelling the query language accepts; it is not a kind the
    // column may hold, so it must never reach this dropdown.
    expect(QUERY_WRITABLE_KINDS).toContain('mac');
    expect(FORM_IDENTIFIER_KINDS).not.toContain('mac');
  });

  it('has a human label for every kind it offers', () => {
    for (const kind of FORM_IDENTIFIER_KINDS) {
      expect(IDENTIFIER_KIND_LABEL[kind], `no label for the ${kind} identifier`).toBeTruthy();
    }
  });

  it('lists them in the registry’s precedence order, strongest first', () => {
    const precedence = IDENTIFIER_KINDS.filter((k) => !COLLECTOR_MINTED_KINDS.includes(k));
    expect([...FORM_IDENTIFIER_KINDS]).toEqual([...precedence]);
  });
});

describe('humaniseAttribute', () => {
  it.each([
    ['operating_system', 'Operating system'],
    ['os_version', 'OS version'],
    ['account_id', 'Account ID'],
  ])('renders %s as %s', (input, expected) => {
    expect(humaniseAttribute(input)).toBe(expected);
  });
});
