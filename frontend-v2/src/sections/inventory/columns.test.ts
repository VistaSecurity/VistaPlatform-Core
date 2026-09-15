// The per-class column registry (ADR-0006 D2).
//
// The registry is DERIVED from the generated attribute schemas, and the point of
// these tests is that it stays derived: a hand-written table would pass a test
// that restated it, and would then rot the first time a class was added to the
// YAML. Every assertion below is about behaviour the derivation must have for
// ANY class, checked against a few real ones.
import { describe, expect, it } from 'vitest';
import { ASSET_CLASS_KEYS, ATTRIBUTE_SCHEMAS } from '@vistasecurity/primitives/assets';
import {
  BASE_COLUMNS, MAX_CLASS_COLUMNS, classColumns, classesWithAttributes,
  columnsForClass, gridTemplate, humanise,
} from './columns';
import type { AssetLike } from './asset-shape';

describe('classColumns', () => {
  it('gives a server its most identifying attributes first', () => {
    const cols = classColumns('server');
    expect(cols.map((c) => c.attribute)).toEqual(['operating_system', 'os_version', 'model']);
  });

  it('gives a cloud resource a different set, because the class declares different things', () => {
    const bucket = classColumns('object_storage').map((c) => c.attribute);
    expect(bucket).not.toContain('operating_system');
    expect(bucket.length).toBeGreaterThan(0);
  });

  it('never exceeds the table’s budget', () => {
    for (const key of ASSET_CLASS_KEYS) {
      expect(classColumns(key).length).toBeLessThanOrEqual(MAX_CLASS_COLUMNS);
    }
  });

  it('only ever names attributes the class actually declares', () => {
    // The guard against a ranked name outliving the schema that had it: a
    // column reading an attribute nothing declares renders an empty cell for
    // every row, forever, with nothing failing.
    for (const key of ASSET_CLASS_KEYS) {
      const declared = Object.keys(ATTRIBUTE_SCHEMAS[key]?.properties ?? {});
      for (const col of classColumns(key)) {
        expect(declared).toContain(col.attribute);
      }
    }
  });

  it('returns [] for an unknown class rather than throwing', () => {
    // A tenant subclass this build has never seen. Base columns only is correct
    // and not empty.
    expect(classColumns('tenant_custom_thing')).toEqual([]);
  });

  it('covers every class that has attributes at all', () => {
    const withAttrs = classesWithAttributes();
    expect(withAttrs.length).toBeGreaterThan(20); // anchor: an empty list would make this vacuous
    for (const key of withAttrs) {
      expect(classColumns(key).length).toBeGreaterThan(0);
    }
  });
});

describe('columnsForClass', () => {
  it('falls back to base columns plus Segment when NO class is selected', () => {
    // The most useful thing to say about a heterogeneous list. There is no
    // attribute set to draw from, so inventing one would mean empty cells.
    const keys = columnsForClass(undefined).map((c) => c.key);
    expect(keys).toContain('class');
    expect(keys).toContain('segment');
    expect(keys.some((k) => k.startsWith('attr.'))).toBe(false);
  });

  it('gives a PARENT class its own (shared) attributes, not its children’s', () => {
    // `hardware` contributes vendor/model/asset_tag and nothing class-specific,
    // which is right: a list mixing servers and switches has no common OS
    // column to show.
    const keys = columnsForClass('hardware').map((c) => c.attribute).filter(Boolean);
    expect(keys).not.toContain('operating_system');
    expect(keys).toContain('vendor');
  });

  it('adds the class columns when a leaf class is selected', () => {
    const keys = columnsForClass('server').map((c) => c.key);
    expect(keys).toContain('attr.operating_system');
    expect(keys).toContain('address');
  });

  it('always keeps the Address column, whatever the class', () => {
    // The primary-endpoint cell is the one thing every row needs, and it is the
    // cell the primary-endpoint rule governs.
    for (const key of ['server', 'switch', 'object_storage', 'business_service'] as const) {
      expect(columnsForClass(key).map((c) => c.key)).toContain('address');
    }
  });
});

describe('cell values', () => {
  const server: AssetLike = {
    class_key: 'server',
    environment: 'production',
    endpoints: [{ id: 'e', address: '192.0.2.10', port: 443 }],
    attributes: { operating_system: 'Ubuntu' },
  };

  it('reads the class label, the primary endpoint and the attribute', () => {
    const cols = columnsForClass('server');
    const by = (k: string) => cols.find((c) => c.key === k)!;
    expect(by('class').value(server)).toBe('Server');
    expect(by('address').value(server)).toBe('192.0.2.10:443');
    expect(by('attr.operating_system').value(server)).toBe('Ubuntu');
  });

  it('returns EMPTY, not a placeholder, for an asset with no endpoint', () => {
    // The row renders the em dash; the registry returns the absence. Keeping
    // that split means the rule is testable without a DOM.
    const bucket: AssetLike = { class_key: 'object_storage', endpoints: [] };
    expect(columnsForClass('object_storage').find((c) => c.key === 'address')!.value(bucket)).toBe('');
  });

  it('produces a grid track for every column plus the chip and the name', () => {
    const cols = columnsForClass('server');
    expect(gridTemplate(cols).split(' ').length).toBe(cols.length + 2);
  });
});

describe('humanise', () => {
  it.each([
    ['operating_system', 'Operating system'],
    ['os_version', 'OS version'],
    ['cpu_count', 'CPU count'],
    ['memory_mb', 'Memory MB'],
    ['account_id', 'Account ID'],
    ['vendor', 'Vendor'],
  ])('renders %s as %s', (input, expected) => {
    expect(humanise(input)).toBe(expected);
  });
});

describe('base columns', () => {
  it('are the ones every class has', () => {
    expect(BASE_COLUMNS.map((c) => c.key)).toEqual(['class', 'address', 'environment', 'owner', 'last_seen']);
  });
});
