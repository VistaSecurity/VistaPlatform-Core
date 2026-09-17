import { RISK_BANDS } from '../ratings';
// The production catalogue: the generated registries over the production field
// table.
//
// This is the one the query editor and the facet rail use — the mirror of Go's
// `catalog/registrycatalog`. Every part of its vocabulary is now generated:
//
//   first-class  ← `registry-fields.gen.ts`, emitted from that package's
//                  exported `AllTargets()` / `FirstClassFields()` by
//                  `shared/query/catalog/registrycatalog/cmd/gen-ts-fields`
//   class keys   ← `@vistasecurity/primitives/assets` (ASSET_CLASSES),
//                  generated from standards/asset-classes.yaml
//   attr keys    ← `@vistasecurity/primitives/assets` (ATTRIBUTE_SCHEMAS),
//                  generated from the same YAML's per-class attribute_schema
//   fact keys    ← `@vistasecurity/primitives/facts` (FACT_KEY_DEFS),
//                  generated from standards/fact-keys.yaml
//   finding      ← `@vistasecurity/primitives/findings`, generated from
//   vocabularies   standards/findings-registry.yaml
//
// The resolution rules are `base-catalog.ts`, shared with the static catalogue
// the conformance suite holds to Go's behaviour case by case.
//
// The `attr.` namespace used to be EMPTY here, because nothing generated the
// class attribute schemas for TypeScript, and an app had to hand the catalogue
// a vocabulary it had assembled from somewhere else. That gap is closed
// (workstream 0.8e). `RegistryCatalogOptions.attributeKeys` survives as an
// override layered on top, not as the only way in.

import type { FieldType } from './ast';
import type { BandLadder, ClassInfo, FieldInfo } from './catalog';
import type { CatalogVocabulary, NamespaceKey } from './base-catalog';
import { BaseCatalog } from './base-catalog';
import { REGISTRY_FIELDS_BY_TARGET } from './registry-fields.gen';
import { ASSET_CLASSES, ASSET_CLASS_KEYS, ATTRIBUTE_SCHEMAS } from '../assets';
import { FACT_KEY_DEFS, FACT_KEY_ORDER } from '../facts';
import type { FactValueType } from '../facts';

/** What a caller may supply beyond the generated registries. */
export interface RegistryCatalogOptions {
  /**
   * Extra class attribute keys, layered over the generated vocabulary and
   * winning where the names collide.
   *
   * The generated schemas cover every attribute the platform taxonomy declares
   * (ADR-0002 D2), so this is no longer how an app gets an `attr.` vocabulary —
   * it is for a test that wants a specific shape, and for an attribute a build
   * knows about before the registry does.
   */
  attributeKeys?: Readonly<Record<string, NamespaceKey>>;
  /**
   * Tenant leaf subclasses (ADR-0002 D2), which are runtime data rather than
   * generated: `{ key, path }` with the path rooted in a platform class. A
   * tenant subclass is matched by its parent's subtree term either way (§5.3),
   * so supplying them only affects whether the exact key resolves and whether
   * autocomplete offers it.
   */
  tenantClasses?: readonly ClassInfo[];
}

/**
 * Maps a registry's declared value type onto a query field type. It is the same
 * mapping the Go catalogue applies to both `attr.` and `fact.` keys.
 *
 * Two rows are the ones worth arguing about.
 *
 * **string → keyword, not text.** `:` on keyword is case-insensitive equality;
 * on text it is substring. Every string in these registries is a short
 * structured value a collector wrote — a region, a model, an image id, an OS
 * name — and a facet chip built from `attr.provider` has to mean equality or it
 * is not a facet. `~ "regex"` and `attr.model:Cat*` remain available for
 * partial matching.
 *
 * **array/object → json, not keyword[].** The accessor for a jsonb value
 * yields its raw TEXT, so `keyword[]` would generate `unnest(text)` and
 * `array_length(text)` — errors from Postgres, not answers. `keyword[]` is for
 * a real `text[]` COLUMN (assets.risk_assessed_by, asset_endpoints.sni), and
 * those are first-class fields, not registry keys. A json field accepts no
 * operator: `exists(fact.<key>)` is the only honest question about one.
 *
 * A type the mapping does not cover is left OUT of the vocabulary entirely, so
 * the key reports unknown_key rather than acquiring a type by default.
 */
function registryFieldType(t: FactValueType | string): FieldType | null {
  switch (t) {
    case 'string':
      return 'keyword';
    case 'integer':
    case 'number':
      return 'number';
    case 'boolean':
      return 'boolean';
    case 'date':
      return 'timestamp';
    case 'array':
    case 'object':
      return 'json';
    default:
      return null;
  }
}

/** Exposed so a caller supplying extra attribute keys can use the same mapping. */
export { registryFieldType };

function buildFactKeys(): Readonly<Record<string, NamespaceKey>> {
  const out: Record<string, NamespaceKey> = {};
  for (const key of FACT_KEY_ORDER) {
    const def = FACT_KEY_DEFS[key];
    const type = registryFieldType(def.type);
    if (type === null) continue;
    out[key] = {
      type,
      ...(def.enum === undefined ? {} : { enum: [...def.enum] }),
      description: def.description,
    };
  }
  return out;
}

function sameValues(a: readonly string[] | undefined, b: readonly string[] | undefined): boolean {
  const x = a ?? [];
  const y = b ?? [];
  return x.length === y.length && x.every((v, i) => v === y[i]);
}

/**
 * Folds every class's effective attribute schema into ONE `attr.` namespace —
 * the port of Go's `buildAttributeFields`.
 *
 * §4.2 makes the namespace flat and global: `attr.model` is one field, not one
 * per class, because a query is a predicate over `assets`, whose `attributes`
 * jsonb holds whichever class's keys the row carries. A per-class vocabulary
 * would make `class:hardware and attr.model:X` legal while `attr.model:X` alone
 * was not.
 *
 * Two classes declaring one name with two types is a registry bug with no
 * correct runtime behaviour — typing one class's data by another class's schema
 * is the silent wrong answer, and dropping the attribute makes the vocabulary
 * change shape on an unreviewed YAML edit. Go panics; the generator now refuses
 * to emit it at all, so this throw is a backstop rather than the guard.
 *
 * Where several classes declare an attribute and describe it DIFFERENTLY, the
 * description is dropped: showing one class's wording as if it were the field's
 * is a small lie in a tooltip, and showing none is not.
 */
function buildAttrKeys(): Readonly<Record<string, NamespaceKey>> {
  const out: Record<string, NamespaceKey> = {};
  const owner: Record<string, string> = {};
  const disagreed = new Set<string>();

  for (const cls of ASSET_CLASS_KEYS) {
    const props = ATTRIBUTE_SCHEMAS[cls].properties;
    for (const name of Object.keys(props).sort()) {
      const p = props[name];
      const type = registryFieldType(p.type);
      if (type === null) continue;
      const key = name.toLowerCase();
      const entry: NamespaceKey = {
        type,
        ...(p.enum === undefined ? {} : { enum: [...p.enum] }),
        description: p.description,
      };
      const prev = out[key];
      if (prev === undefined) {
        out[key] = entry;
        owner[key] = cls;
        continue;
      }
      if (prev.type !== entry.type || !sameValues(prev.enum, entry.enum)) {
        throw new Error(
          `query/registry-catalog: class attribute "${key}" is declared as ${prev.type} by ` +
            `"${owner[key]}" and as ${entry.type} by "${cls}"; one name cannot be two fields`,
        );
      }
      if (prev.description !== entry.description) disagreed.add(key);
    }
  }
  for (const key of disagreed) delete out[key].description;
  return out;
}

/**
 * The generated attribute vocabulary, folded once. The schemas are immutable
 * for the life of the process, and a catalogue is cheap enough to build per
 * render only if this is not redone each time.
 */
let attrKeysCache: Readonly<Record<string, NamespaceKey>> | undefined;

function generatedAttrKeys(): Readonly<Record<string, NamespaceKey>> {
  attrKeysCache ??= buildAttrKeys();
  return attrKeysCache;
}

function buildClasses(tenantClasses: readonly ClassInfo[]): readonly ClassInfo[] {
  const out: ClassInfo[] = ASSET_CLASS_KEYS.map((key) => ({
    key,
    path: ASSET_CLASSES[key].path,
  }));
  return [...out, ...tenantClasses];
}

/** The production catalogue over the generated registries. */
export class RegistryCatalog extends BaseCatalog {
  private readonly vocab: CatalogVocabulary;

  constructor(opts: RegistryCatalogOptions = {}) {
    super();
    this.vocab = {
      attrKeys:
        opts.attributeKeys === undefined
          ? generatedAttrKeys()
          : { ...generatedAttrKeys(), ...opts.attributeKeys },
      factKeys: buildFactKeys(),
      classes: buildClasses(opts.tenantClasses ?? []),
    };
  }

  protected vocabulary(): CatalogVocabulary {
    return this.vocab;
  }

  protected firstClassFields(target: string): readonly FieldInfo[] {
    return REGISTRY_FIELDS_BY_TARGET[target] ?? [];
  }

  /**
   * Lists every class key, so an unknown one gets a "did you mean". This is the
   * optional `Catalog.classKeys` extension; the static test catalogue
   * deliberately does not implement it, because Go's `testcatalog` does not
   * either and the fixtures are held to that behaviour.
   */
  classKeys(): string[] {
    return this.vocab.classes.map((c) => c.key);
  }
}

/** Returns the production catalogue. */
export function newRegistryCatalog(opts: RegistryCatalogOptions = {}): RegistryCatalog {
  return new RegistryCatalog(opts);
}

/**
 * The CVSS-anchored risk/severity ladder (§5.5) — the CVSS v3.1/v4.0
 * qualitative ratings ×10, which is what `models.RiskBands` holds server-side.
 *
 * The server generates every band predicate from its own copy; this one exists
 * so the editor can validate `risk >= high` and offer the rungs by name without
 * a round trip. They must agree — badges at >= 60 while facets used >= 70 is
 * the drift the single-ladder rule exists to make impossible — so if the
 * server's ladder ever changes, this changes with it.
 */
export const CVSS_LADDER: BandLadder = {
  bands: () => RISK_BANDS.map(({ label, min }) => ({ label, min })),
};
