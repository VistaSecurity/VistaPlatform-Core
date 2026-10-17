import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { OBJECT_KIND_LABELS, OBJECT_KINDS } from './index';

// Read the YAML (the source of truth), not the Go file, so this fails if either
// generated mirror drifts from the registry.
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../../..');
const reg = parse(fs.readFileSync(path.join(root, 'standards', 'vocabulary.yaml'), 'utf8')) as {
  reserved: { key: string }[];
  objects: { key: string }[];
};
const expected: string[] = [
  ...['asset', 'endpoint'].filter((k) => reg.reserved.some((r) => r.key === k)),
  ...reg.objects.map((o) => o.key),
];

describe('OBJECT_KINDS', () => {
  it('equals the vocabulary registry, in order', () => {
    expect([...OBJECT_KINDS]).toEqual(expected);
  });

  it('has a label row for every kind and honours ui_label_override', () => {
    expect(Object.keys(OBJECT_KIND_LABELS).sort()).toEqual([...OBJECT_KINDS].sort());
    expect(OBJECT_KIND_LABELS.platform.label).toBe('Platform');
    expect(OBJECT_KIND_LABELS.platform.uiLabel).toBe('Platform (OS)');
    expect(OBJECT_KIND_LABELS.provider.uiLabel).toBe('Circuit Provider');
    expect(OBJECT_KIND_LABELS.rack.uiLabel).toBe('Rack');
  });

  it('matches the Go constants', () => {
    const go = fs.readFileSync(path.join(root, 'shared', 'dcim', 'objectkind_gen.go'), 'utf8');
    const goKinds = [...go.matchAll(/^\tObjectKind\w+\s+ObjectKind = "([a-z0-9_]+)"/gm)].map((m) => m[1]);
    expect(goKinds).toEqual([...OBJECT_KINDS]);
  });
});
