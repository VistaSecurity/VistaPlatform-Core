// The resolution machinery both catalogues share.
//
// The first-class half is `fields.ts` and is identical in the two; what differs
// is the namespace vocabulary — the static sample in `test-catalog.ts`, the
// generated registries in `registry-catalog.ts`. So the resolution rules live
// here once, and a subclass supplies only the vocabulary.

import type { Accessor, FieldRef, FieldType, Namespace } from './ast';
import { asNamespace } from './ast';
import type { Catalog, ClassInfo, FieldInfo, ResolveResult, Target } from './catalog';
import {
  IDENTIFIER_ANY_KIND,
  IDENTIFIER_KIND_ALIASES,
  NAMESPACES_BY_TARGET,
  TARGETS,
  WRITABLE_IDENTIFIER_KINDS,
} from './targets';
import type { Relationship } from './vocabulary';
import { RELATIONSHIPS } from './vocabulary';

/** One entry of a namespace's key vocabulary. */
export interface NamespaceKey {
  type: FieldType;
  enum?: string[];
  description?: string;
}

/**
 * The vocabulary a concrete catalogue supplies: the `attr.` and `fact.` keys it
 * knows, and the class tree it resolves `class:` against.
 */
export interface CatalogVocabulary {
  /** Class attribute keys (ADR-0002 D2), by key. */
  attrKeys: Readonly<Record<string, NamespaceKey>>;
  /** Registered fact keys (standards/fact-keys.yaml), by key. */
  factKeys: Readonly<Record<string, NamespaceKey>>;
  /** Every class, key and materialised path (§5.3). */
  classes: readonly ClassInfo[];
}

/**
 * Resolution over a first-class field table plus a namespace vocabulary, both
 * supplied by the concrete catalogue.
 *
 * The two catalogues differ in BOTH — `test-fields.ts` against the generated
 * `registry-fields.gen.ts`, a static sample against the generated registries —
 * so neither is shared here. What is shared is the resolution: which namespaces a
 * target carries, that a bare `id` is the row's uuid, how an alias maps to a
 * stored kind, and that a tag key is free-form.
 */
export abstract class BaseCatalog implements Catalog {
  protected abstract vocabulary(): CatalogVocabulary;

  /** The target's first-class fields, without the namespaces. */
  protected abstract firstClassFields(target: string): readonly FieldInfo[];

  targets(): Target[] {
    return [...TARGETS];
  }

  relationshipNames(): readonly Relationship[] {
    return RELATIONSHIPS;
  }

  enumValues(field: FieldRef): string[] | null {
    if (field.enum === undefined || field.enum.length === 0) return null;
    return field.enum;
  }

  /**
   * A class is nameable by its key or by its full path, because §9 example 3
   * writes `class:hardware.computer.server` while example 14 writes
   * `class=hypervisor`.
   */
  classExists(key: string): ClassInfo | null {
    const lower = key.toLowerCase();
    for (const ci of this.vocabulary().classes) {
      if (ci.key.toLowerCase() === lower || ci.path.toLowerCase() === lower) return ci;
    }
    return null;
  }

  /**
   * Namespaced entries are appended so autocomplete and the unknown_field
   * suggestion see the whole vocabulary.
   */
  fields(target: string): FieldInfo[] {
    const name = target.toLowerCase();
    const base = this.firstClassFields(name);
    const namespaces = NAMESPACES_BY_TARGET[name] ?? [];
    if (namespaces.length === 0) return [...base];
    const vocab = this.vocabulary();
    const out: FieldInfo[] = [...base];
    if (namespaces.includes('attr')) {
      for (const k of Object.keys(vocab.attrKeys).sort()) {
        out.push(namespacedField('attr', k, vocab.attrKeys[k]));
      }
    }
    if (namespaces.includes('fact')) {
      for (const k of Object.keys(vocab.factKeys).sort()) {
        out.push(namespacedField('fact', k, vocab.factKeys[k]));
      }
    }
    if (namespaces.includes('id')) {
      for (const k of WRITABLE_IDENTIFIER_KINDS) {
        out.push({
          name: 'id.' + k,
          type: 'keyword',
          // The written kind, not the stored one: this list is for names and
          // suggestions, and `resolve` is what maps an alias to its column key.
          accessor: { kind: 'identifier', column: 'value', key: k },
        });
      }
      // The any-kind form is `id.any`, NOT a second entry named `id`: a bare
      // `id` is the row's uuid column, and publishing two fields under one name
      // made autocomplete and the "did you mean" suggestion both wrong about
      // which one a user would get (§13 A1).
      out.push({
        name: 'id.' + IDENTIFIER_ANY_KIND,
        type: 'keyword',
        accessor: { kind: 'identifier_any', column: 'value' },
        description: 'an identifier of any kind with this value',
      });
    }
    if (namespaces.includes('tag')) {
      out.push({
        name: 'tag',
        type: 'text',
        accessor: { kind: 'tag_any', jsonColumn: 'tags' },
        description: 'any tag key or value',
      });
    }
    return out;
  }

  resolve(target: string, path: string[]): ResolveResult {
    const name = target.toLowerCase();
    const tgt = TARGETS.find((t) => t.name.toLowerCase() === name);
    if (tgt === undefined) {
      return { ok: false, error: { target: name, path, namespace: '', reason: 'unknown_target' } };
    }
    if (path.length === 0) {
      return { ok: false, error: { target: name, path, namespace: '', reason: 'unknown_field' } };
    }

    // A bare `id` is the ROW's uuid on every target, never the identifier
    // namespace (§13 A1). Taking the namespace branch first made `assets.id` —
    // a first-class uuid column §4.3 lists — unreachable, and published two
    // different fields under one name. The any-kind form is `id.any`.
    if (path.length === 1 && path[0].toLowerCase() === 'id') {
      return this.resolveFirstClass(tgt.name, path);
    }
    const ns = asNamespace(path[0]);
    if (ns !== null && ns !== '' && (NAMESPACES_BY_TARGET[tgt.name] ?? []).includes(ns)) {
      return this.resolveNamespaced(tgt.name, ns, path);
    }
    return this.resolveFirstClass(tgt.name, path);
  }

  /** Resolves a path against the target's own column catalogue. */
  private resolveFirstClass(target: string, path: string[]): ResolveResult {
    const name = path.join('.').toLowerCase();
    for (const f of this.firstClassFields(target)) {
      if (f.name.toLowerCase() === name) {
        return { ok: true, field: buildFieldRef(path, f, '', f.name) };
      }
    }
    return { ok: false, error: { target, path, namespace: '', reason: 'unknown_field' } };
  }

  /** Resolves `attr.` / `fact.` / `id.` / `tag.` paths and the bare `tag` form. */
  private resolveNamespaced(target: string, ns: Namespace, path: string[]): ResolveResult {
    const key = path.slice(1).join('.');
    if (key === '') {
      // Bare `id` never reaches here — it is the row's uuid (§13 A1).
      if (ns === 'tag') {
        return {
          ok: true,
          field: buildFieldRef(
            path,
            { name: 'tag', type: 'text', accessor: { kind: 'tag_any', jsonColumn: 'tags' } },
            ns,
            '',
          ),
        };
      }
      return { ok: false, error: { target, path, namespace: ns, reason: 'empty_key' } };
    }

    const lower = key.toLowerCase();
    const vocab = this.vocabulary();

    if (ns === 'attr') {
      const info = vocab.attrKeys[lower];
      if (info === undefined) {
        return { ok: false, error: { target, path, namespace: ns, reason: 'unknown_key' } };
      }
      return { ok: true, field: buildFieldRef(path, namespacedField('attr', lower, info), ns, lower) };
    }
    if (ns === 'fact') {
      const info = vocab.factKeys[lower];
      if (info === undefined) {
        return { ok: false, error: { target, path, namespace: ns, reason: 'unknown_key' } };
      }
      return { ok: true, field: buildFieldRef(path, namespacedField('fact', lower, info), ns, lower) };
    }
    if (ns === 'id') {
      if (lower === IDENTIFIER_ANY_KIND) {
        // `id.any:"aa:bb:…"` is "an identifier of any kind with this value" —
        // what the §3 cheat sheet used to spell `id:"…"`, before that collided
        // with the row's own uuid (§13 A1).
        return {
          ok: true,
          field: buildFieldRef(
            path,
            {
              name: 'id.any',
              type: 'keyword',
              accessor: { kind: 'identifier_any', column: 'value' },
            },
            ns,
            '',
          ),
        };
      }
      if (!WRITABLE_IDENTIFIER_KINDS.some((k) => k.toLowerCase() === lower)) {
        return { ok: false, error: { target, path, namespace: ns, reason: 'unknown_key' } };
      }
      const stored = IDENTIFIER_KIND_ALIASES[lower] ?? lower;
      return {
        ok: true,
        field: buildFieldRef(
          path,
          {
            name: 'id.' + lower,
            type: 'keyword',
            accessor: { kind: 'identifier', column: 'value', key: stored },
          },
          ns,
          stored,
        ),
      };
    }
    // tag: any tenant key resolves; tags are free-form by design.
    return {
      ok: true,
      field: buildFieldRef(
        path,
        {
          name: 'tag.' + key,
          type: 'keyword',
          accessor: { kind: 'jsonb', jsonColumn: 'tags', key },
        },
        ns,
        key,
      ),
    };
  }
}

function namespacedField(ns: 'attr' | 'fact', key: string, info: NamespaceKey): FieldInfo {
  const accessor: Accessor =
    ns === 'attr'
      ? { kind: 'jsonb', jsonColumn: 'attributes', key }
      : { kind: 'fact', column: 'value', key };
  return {
    name: ns + '.' + key,
    type: info.type,
    accessor,
    ...(info.enum === undefined ? {} : { enum: info.enum }),
    ...(info.description === undefined ? {} : { description: info.description }),
  };
}

/** Builds the resolved reference the validator hands a translator. */
function buildFieldRef(
  path: string[],
  info: FieldInfo,
  ns: Namespace,
  key: string,
): FieldRef {
  return {
    segments: path,
    quoted: path.map(() => false),
    text: path.join('.'),
    namespace: ns,
    key,
    type: info.type,
    accessor: info.accessor,
    ...(info.enum === undefined ? {} : { enum: info.enum }),
    resolved: true,
    span: { start: 0, end: 0 },
  };
}
