// The TypeScript attribute schemas against the Go ones.
//
// Both files are emitted by scripts/generate-asset-classes.mjs from the same
// YAML, and `make audit` runs it with --check, so neither can drift from the
// registry. What --check cannot see is the two EMITTERS disagreeing: it
// compares each output against its own renderer, so a bug in the TypeScript
// renderer — an attribute dropped, an enum truncated, an inherited property not
// merged — would produce a file that is stale in no way it can detect, and the
// query editor would then have a vocabulary the server does not.
//
// So this reads the Go artefact and compares content, the same way
// `query/conformance.test.ts` reads the Go fixture rather than a copy of it.

/// <reference types="node" />
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { ASSET_CLASS_KEYS } from './classes.gen';
import { ATTRIBUTE_SCHEMAS, attributeSchema } from './attribute-schemas.gen';

interface GoSchemaFile {
  schemas: Record<
    string,
    {
      type: string;
      additionalProperties: boolean;
      properties: Record<string, Record<string, unknown>>;
    }
  >;
}

const here = dirname(fileURLToPath(import.meta.url));
const goPath = resolve(here, '../../../../shared/assetclass/attribute_schemas_gen.json');
const go = JSON.parse(readFileSync(goPath, 'utf8')) as GoSchemaFile;

describe('the generated attribute schemas match the Go mirror', () => {
  it('covers exactly the same classes', () => {
    expect(Object.keys(ATTRIBUTE_SCHEMAS).sort()).toEqual(Object.keys(go.schemas).sort());
    // …and every class in the generated taxonomy has one, so a class cannot
    // appear in the picker with no attribute schema behind it.
    expect(Object.keys(ATTRIBUTE_SCHEMAS).sort()).toEqual([...ASSET_CLASS_KEYS].sort());
  });

  it('declares the same effective properties for every class', () => {
    for (const key of ASSET_CLASS_KEYS) {
      const ts = ATTRIBUTE_SCHEMAS[key];
      const want = go.schemas[key];
      expect(ts.type, key).toBe('object');
      expect(ts.additionalProperties, key).toBe(false);
      expect(want.type, key).toBe('object');
      expect(want.additionalProperties, key).toBe(false);
      // The merge is what matters: a child's schema is its own properties over
      // every ancestor's, so `server` must carry `vendor` from `hardware`.
      expect(Object.keys(ts.properties).sort(), key).toEqual(
        Object.keys(want.properties).sort(),
      );
      for (const [name, def] of Object.entries(ts.properties)) {
        const wantDef = want.properties[name];
        expect(def.type, `${key}.${name}.type`).toBe(wantDef.type);
        expect(def.description, `${key}.${name}.description`).toBe(wantDef.description);
        expect(def.enum, `${key}.${name}.enum`).toEqual(wantDef.enum);
        expect(def.items, `${key}.${name}.items`).toEqual(wantDef.items);
      }
    }
  });

  it('merges an ancestor’s attributes into a leaf', () => {
    // A worked instance of the rule above, so a merge that silently stopped
    // happening fails with something readable rather than a 49-class diff.
    expect(Object.keys(ATTRIBUTE_SCHEMAS.server.properties)).toContain('vendor');
    expect(Object.keys(ATTRIBUTE_SCHEMAS.server.properties)).toContain('cpu_count');
  });

  it('looks a class up by key and reports an unknown one as undefined', () => {
    expect(attributeSchema('server')).toBe(ATTRIBUTE_SCHEMAS.server);
    // A tenant leaf subclass is runtime data and is deliberately not here.
    expect(attributeSchema('acme_edge_router')).toBeUndefined();
    // Not an inherited Object.prototype member, either.
    expect(attributeSchema('constructor')).toBeUndefined();
  });
});
