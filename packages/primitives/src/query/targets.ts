// The query targets (§4.1) and the identifier registry (ADR-0002 D3).
//
// These are the parts both catalogues share verbatim. The FIELD tables do not:
// `test-fields.ts` mirrors Go's `catalog/testcatalog` and the generated
// `registry-fields.gen.ts` mirrors `catalog/registrycatalog`, and the two
// genuinely disagree — the Go side keeps an exemption list for the eight
// conformance cases where they reach different answers. Sharing one table here
// would have papered over that.
//
// TARGETS below is shared because Go's two catalogues declare identical target
// tables, which is a claim rather than a coincidence:
// `registry-fields.gen.test.ts` pins this copy against the generated
// `REGISTRY_TARGETS`, so a target that changes on the Go side fails here.

import type { Target } from './catalog';

/** §4.1's targets, with the physical shape a translator joins. */
export const TARGETS: readonly Target[] = [
  {
    name: 'asset',
    table: 'assets',
    alias: 'a',
    idColumn: 'id',
    subs: ['endpoint', 'software', 'finding', 'cert', 'crypto', 'identifier', 'relationship'],
    traversable: true,
    freeTextable: true,
  },
  {
    name: 'endpoint',
    table: 'asset_endpoints',
    alias: 'e',
    idColumn: 'id',
    assetIdColumn: 'asset_id',
    subs: ['asset', 'crypto', 'cert'],
    traversable: false,
    freeTextable: false,
  },
  {
    name: 'certificate',
    table: 'certificates',
    alias: 'c',
    idColumn: 'id',
    subs: ['asset'],
    traversable: false,
    freeTextable: false,
  },
  {
    name: 'crypto_configuration',
    table: 'crypto_implementations',
    alias: 'ci',
    idColumn: 'id',
    subs: ['asset', 'cert'],
    traversable: false,
    freeTextable: false,
  },
  {
    name: 'finding',
    table: 'findings',
    alias: 'f',
    idColumn: 'id',
    subs: ['asset'],
    traversable: false,
    freeTextable: false,
  },
  {
    name: 'software_install',
    table: 'software_installs',
    alias: 'si',
    idColumn: 'id',
    assetIdColumn: 'asset_id',
    subs: ['asset'],
    traversable: false,
    freeTextable: false,
  },
  {
    name: 'identifier',
    table: 'asset_identifiers',
    alias: 'ai',
    idColumn: 'id',
    assetIdColumn: 'asset_id',
    subs: ['asset'],
    traversable: false,
    freeTextable: false,
  },
  {
    // An edge has two ends, so "the asset of a relationship" is ambiguous;
    // there is no `asset:(…)` shape from here rather than an invented one.
    name: 'relationship',
    table: 'asset_relationships',
    alias: 'r',
    idColumn: 'id',
    subs: [],
    traversable: false,
    freeTextable: false,
  },
  {
    // §4.1, §8: the in-flight discovery an approval rule sees. No table — the
    // identification engine holds it in memory, so a predicate over it is
    // evaluated there and the SQL translator refuses it rather than inventing a
    // table.
    name: 'observation',
    table: '',
    alias: 'o',
    idColumn: '',
    subs: [],
    traversable: false,
    freeTextable: false,
    inMemory: true,
  },
  {
    // §12 amendment 3: §8 reserves `value` for a measurement's extracted
    // scalar, and a predicate needs a target to resolve against. Table-less for
    // the same reason as observation.
    name: 'measurement',
    table: '',
    alias: 'm',
    idColumn: '',
    subs: [],
    traversable: false,
    freeTextable: false,
    inMemory: true,
  },
];

/**
 * Which of the four namespaces resolve on a target (§4.2). Only an asset-shaped
 * row carries class attributes, facts, identifiers and tags; a measurement
 * predicate reads facts and nothing else (§8).
 */
export const NAMESPACES_BY_TARGET: Readonly<
  Record<string, readonly ('attr' | 'fact' | 'id' | 'tag')[]>
> = {
  asset: ['attr', 'fact', 'id', 'tag'],
  observation: ['attr', 'fact', 'id', 'tag'],
  measurement: ['fact'],
};

/**
 * The ADR-0002 D3 identifier registry, in default precedence order — the STORED
 * kinds, which is what the `identifier` target's `kind` column may hold.
 *
 * Hand-mirrored from `standards/asset-classes.yaml` (`identifier_kinds`), which
 * generates `shared/assetclass.IdentifierKinds` for Go but nothing for
 * TypeScript. `test-fields.test.ts` cross-checks it against the one generated
 * TypeScript artefact that does carry kinds — every class's
 * `identifierPrecedence` in `@vistasecurity/primitives/assets` — in both
 * directions, so a kind added to the YAML and not here fails.
 */
export const IDENTIFIER_KINDS: readonly string[] = [
  'agent_id',
  'cloud_resource_id',
  'serial_number',
  'cmdb_sys_id',
  'ssh_host_key_fingerprint',
  'mac_address',
  'fqdn',
  'hostname',
  'ip_address',
  // Tenth kind (ADR-0002 D3 erratum, phase 1): declared service classes
  // identify by name, scoped by class key.
  'name',
];

/**
 * The kinds a COLLECTOR mints, which a person must never type.
 *
 * Both mean "this is the thing that agent / that cloud resource is", and the
 * platform is the only party that can know it. An operator who can type one can
 * claim an identity the platform assigns — which is how two real assets get
 * merged into one by hand, with no proposal and nothing to review.
 */
export const COLLECTOR_MINTED_KINDS: readonly string[] = ['agent_id', 'cloud_resource_id'];

/**
 * The kinds a person may enter, and the only ones an editor may retire: every
 * registry kind except the collector-minted ones.
 *
 * DERIVED, so a kind added to `standards/asset-classes.yaml` reaches the form
 * without a page edit — and so a kind that must not be typed has to be named as
 * collector-minted rather than merely left off a hand-written list.
 */
export const USER_ENTERABLE_IDENTIFIER_KINDS: readonly string[] =
  IDENTIFIER_KINDS.filter((k) => !COLLECTOR_MINTED_KINDS.includes(k));

/**
 * Maps a written identifier kind to the STORED one. §12 amendment 4: the §3
 * cheat sheet writes `id.mac`, ADR-0002 D3 names the kind `mac_address`, and
 * both resolve — but only `mac_address` ever reaches the column, because that
 * is what is in it.
 */
export const IDENTIFIER_KIND_ALIASES: Readonly<Record<string, string>> = { mac: 'mac_address' };

/**
 * Every spelling `id.<kind>` accepts: the registry's kinds plus the aliases.
 * Distinct from IDENTIFIER_KINDS, which is what the `identifier.kind` COLUMN
 * may hold — `identifier:(kind:mac)` would compare the column against "mac" and
 * match nothing, forever and silently.
 */
export const WRITABLE_IDENTIFIER_KINDS: readonly string[] = [
  ...IDENTIFIER_KINDS,
  ...Object.keys(IDENTIFIER_KIND_ALIASES),
].sort();

/**
 * The pseudo-kind matching an identifier of ANY kind (§13 A1). It cannot
 * collide with a real kind: "any" is not one of them.
 */
export const IDENTIFIER_ANY_KIND = 'any';
