#!/usr/bin/env node
// Generates every asset-class artefact from standards/asset-classes.yaml
// (ADR-0002 D2; BUILD_PLAN workstream 0.1).
//
// The class taxonomy is consumed by SQL (the seeded `asset_classes` rows), Go
// (ingest, the identification engine, the CMDB sync), TypeScript (facets, the
// per-class column/form registry) and the OpenAPI contract. Hand-maintaining
// the same 49-row tree in four languages is exactly how the permission
// catalogue drifted before scripts/generate-permissions.mjs existed, so it is
// generated from one file from the start.
//
// Outputs:
//   scripts/database/seed.sql                            (1 generated region)
//   scripts/database/seed-asset-classes.sql              (whole file)
//   shared/assetclass/classes_gen.go                     (whole file)
//   shared/assetclass/attribute_schemas_gen.json         (whole file)
//   packages/primitives/src/assets/classes.gen.ts        (whole file)
//   packages/primitives/src/assets/attribute-schemas.gen.ts  (whole file)
//   api/openapi/inventory-service.openapi.yaml           (1 generated region)
//
// Run via `make generate`; `make audit` runs `--check` and fails on drift.
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

const KEY = /^[a-z][a-z0-9_]*$/;
const ATTR = /^[a-z][a-z0-9_]*$/;
const ICON = /^[A-Z][A-Za-z0-9]*$/;

// Attribute names that belong to asset_identifiers, not to assets.attributes.
// An identifier is stored once, unique across assets, with its own source,
// confidence and first/last-seen (ADR-0002 D3). Declaring the same value as a
// class attribute gives it a second home in a jsonb blob with no rule for
// which one wins — which is the reconciliation bug of ADR-0002 D4 built in at
// the schema level. The nine identifier kinds are rejected by name, and so are
// the spellings that mean the same thing: `resource_id` shipped in the first
// draft of the registry and is exactly `cloud_resource_id`.
//
// This list is names, not concepts: `account_id` is NOT here, because a cloud
// account is context (ADR-0002 D2 names it as a cloud_resource attribute) and
// is not an identifier kind.
const RESERVED_ATTRIBUTE_NAMES = new Set([
  // the ten kinds themselves
  'agent_id', 'cloud_resource_id', 'serial_number', 'cmdb_sys_id',
  'ssh_host_key_fingerprint', 'mac_address', 'fqdn', 'hostname', 'ip_address',
  'name',
  // spellings of the same thing
  'resource_id', 'cloud_instance_id', 'serial', 'sys_id', 'ssh_host_key',
  'mac', 'macs', 'mac_addresses', 'fqdns', 'hostnames', 'ip', 'ips',
  'ip_addresses', 'display_name', 'service_name',
]);

function fail(msg) {
  console.error(`asset-classes: ${msg}`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Load + validate
// ---------------------------------------------------------------------------

function load() {
  const registryPath = path.join(root, 'standards', 'asset-classes.yaml');
  const reg = yaml.parse(fs.readFileSync(registryPath, 'utf8'));

  const identifierKinds = reg.identifier_kinds || [];
  const cyclonedxTypes = reg.cyclonedx_types || [];
  const legacyTypes = reg.legacy_asset_types || [];
  const attrTypes = reg.attribute_types || [];
  for (const [name, list] of Object.entries({
    identifier_kinds: identifierKinds,
    cyclonedx_types: cyclonedxTypes,
    legacy_asset_types: legacyTypes,
    attribute_types: attrTypes,
  })) {
    if (!Array.isArray(list) || list.length === 0) fail(`${name}: must be a non-empty list`);
    if (new Set(list).size !== list.length) fail(`${name}: duplicate entries`);
  }

  const classes = reg.classes || [];
  if (!classes.length) fail('no classes defined');

  const byKey = new Map();
  for (const c of classes) {
    if (!KEY.test(c.key || '')) fail(`bad class key: ${JSON.stringify(c.key)}`);
    if (byKey.has(c.key)) fail(`duplicate class key: ${c.key}`);
    if (!c.label) fail(`${c.key}: label required`);
    if (!c.description) fail(`${c.key}: description required`);
    if (!ICON.test(c.icon || '')) {
      fail(`${c.key}: icon must be a PascalCase lucide-react export name, got ${JSON.stringify(c.icon)}`);
    }
    if (!cyclonedxTypes.includes(c.cyclonedx_type)) {
      fail(`${c.key}: invalid cyclonedx_type: ${c.cyclonedx_type}`);
    }
    if (!legacyTypes.includes(c.legacy_asset_type)) {
      fail(`${c.key}: invalid legacy_asset_type: ${c.legacy_asset_type}`);
    }
    if (c.cmdb_ci_type !== null && c.cmdb_ci_type !== undefined) {
      if (typeof c.cmdb_ci_type !== 'string' || !c.cmdb_ci_type.trim()) {
        fail(`${c.key}: cmdb_ci_type must be a non-empty string or null`);
      }
    }
    if (!('identifier_precedence' in c) || !Array.isArray(c.identifier_precedence)) {
      fail(`${c.key}: identifier_precedence must be a list (empty means dependent identity)`);
    }
    const seenKind = new Set();
    for (const kind of c.identifier_precedence) {
      if (!identifierKinds.includes(kind)) fail(`${c.key}: unknown identifier kind: ${kind}`);
      if (seenKind.has(kind)) fail(`${c.key}: identifier kind listed twice: ${kind}`);
      seenKind.add(kind);
    }
    validateSchema(c, attrTypes);
    byKey.set(c.key, c);
  }

  // Parents must exist, must not be self, and the chain must terminate.
  for (const c of classes) {
    const parent = c.parent ?? null;
    if (parent === null) continue;
    if (typeof parent !== 'string') fail(`${c.key}: parent must be a class key or null`);
    if (parent === c.key) fail(`${c.key}: is its own parent`);
    if (!byKey.has(parent)) fail(`${c.key}: parent ${parent} is not a declared class`);
  }

  // Derive paths; a cycle shows up as a walk that never reaches a root.
  const pathOf = new Map();
  for (const c of classes) {
    const chain = [];
    const seen = new Set();
    let cur = c;
    while (cur) {
      if (seen.has(cur.key)) fail(`cycle in the class tree at ${cur.key}`);
      seen.add(cur.key);
      chain.unshift(cur.key);
      cur = cur.parent ? byKey.get(cur.parent) : null;
    }
    pathOf.set(c.key, chain.join('.'));
  }

  // A parent must be declared before its children so every consumer can build
  // the tree in one pass (and so the SQL insert order is FK-safe if 0.2 adds a
  // self-referencing foreign key).
  const declared = new Set();
  for (const c of classes) {
    if (c.parent && !declared.has(c.parent)) {
      fail(`${c.key}: declared before its parent ${c.parent}`);
    }
    declared.add(c.key);
  }

  // Effective attribute schemas: own properties merged over every ancestor's.
  // A child redeclaring an ancestor's property is a mistake, not an override —
  // the two would disagree about the type of one jsonb key.
  const effective = new Map();
  for (const c of classes) {
    const props = {};
    const owner = {};
    const chain = pathOf.get(c.key).split('.');
    for (const key of chain) {
      const anc = byKey.get(key);
      for (const [name, def] of Object.entries(anc.attribute_schema.properties || {})) {
        if (name in props) {
          fail(`${key}: attribute "${name}" redeclares the one inherited from ${owner[name]}`);
        }
        props[name] = def;
        owner[name] = key;
      }
    }
    effective.set(c.key, {
      type: 'object',
      additionalProperties: false,
      properties: props,
    });
  }

  // One attribute NAME is one query field. §4.2 makes `attr.` flat and global —
  // `attr.model` is one field, not one per class — because a query is a
  // predicate over `assets`, whose `attributes` jsonb holds whichever class's
  // keys the row carries. So two unrelated classes declaring one name with two
  // types would be one field with two types, and both catalogues that fold this
  // namespace (shared/query/catalog/registrycatalog and the TypeScript
  // RegistryCatalog) have no correct behaviour available: typing one class's
  // data by another class's schema is the silent wrong answer, and dropping the
  // attribute makes the vocabulary change shape on an unreviewed YAML edit.
  //
  // The Go catalogue therefore PANICS, saying "a registry bug that
  // `make generate` should never emit and `make audit` would catch". This is
  // what makes that sentence true.
  const attrOwner = new Map();
  for (const c of classes) {
    for (const [name, def] of Object.entries(effective.get(c.key).properties)) {
      const sig = JSON.stringify({ type: def.type, enum: def.enum ?? null, items: def.items ?? null });
      const prev = attrOwner.get(name);
      if (prev === undefined) {
        attrOwner.set(name, { cls: c.key, sig });
        continue;
      }
      if (prev.sig !== sig) {
        fail(
          `attribute "${name}" is declared as ${prev.sig} by "${prev.cls}" and as ${sig} by ` +
          `"${c.key}"; one attribute name is one query field (attr.${name}), so it cannot be two`,
        );
      }
    }
  }

  const rows = classes.map((c) => ({
    key: c.key,
    parent: c.parent ?? '',
    path: pathOf.get(c.key),
    label: c.label,
    description: c.description.trim().replace(/\s+/g, ' '),
    icon: c.icon,
    cmdbCIType: c.cmdb_ci_type ?? '',
    cyclonedxType: c.cyclonedx_type,
    identifierPrecedence: c.identifier_precedence,
    legacyAssetType: c.legacy_asset_type,
    schema: effective.get(c.key),
  }));

  return { reg, rows, identifierKinds, cyclonedxTypes, legacyTypes };
}

function validateSchema(c, attrTypes) {
  const s = c.attribute_schema;
  if (!s || typeof s !== 'object') fail(`${c.key}: attribute_schema required`);
  if (s.type !== 'object') fail(`${c.key}: attribute_schema.type must be "object"`);
  if (!s.properties || typeof s.properties !== 'object') {
    fail(`${c.key}: attribute_schema.properties must be a map (use {} for none)`);
  }
  for (const [name, def] of Object.entries(s.properties)) {
    if (!ATTR.test(name)) fail(`${c.key}: bad attribute name: ${name}`);
    if (RESERVED_ATTRIBUTE_NAMES.has(name)) {
      fail(
        `${c.key}.${name}: reserved — that value is an identifier, not a class attribute. ` +
        'Identifiers live in asset_identifiers under one of the nine kinds of ADR-0002 D3.',
      );
    }
    if (!attrTypes.includes(def?.type)) fail(`${c.key}.${name}: invalid type: ${def?.type}`);
    if (!def.description) fail(`${c.key}.${name}: description required`);
    if (def.type === 'array') {
      if (!def.items || !attrTypes.includes(def.items.type)) {
        fail(`${c.key}.${name}: array attributes need items.type`);
      }
    }
    if (def.enum !== undefined) {
      if (!Array.isArray(def.enum) || !def.enum.length) fail(`${c.key}.${name}: enum must be a non-empty list`);
      if (def.type !== 'string') fail(`${c.key}.${name}: enum is only supported on string attributes`);
    }
  }
}

// ---------------------------------------------------------------------------
// Icon check — the icon must be a real export of the lucide-react the UIs use.
//
// lucide-react lives in the root node_modules (both frontends declare it), not
// in scripts/, so this is live wherever the workspace has been installed. When
// it is not resolvable the check says so LOUDLY rather than passing quietly: a
// guard that cannot fail is worse than no guard. The always-live consumer-side
// version of this assertion is frontend-v2/src/app/asset-class-icons.test.ts,
// which imports lucide-react directly.
// ---------------------------------------------------------------------------

function lucideIconNames() {
  const candidates = [
    path.join(root, 'node_modules', 'lucide-react', 'dist', 'lucide-react.d.ts'),
    path.join(root, 'frontend-v2', 'node_modules', 'lucide-react', 'dist', 'lucide-react.d.ts'),
    path.join(root, 'admin-ui-v2', 'node_modules', 'lucide-react', 'dist', 'lucide-react.d.ts'),
  ];
  for (const p of candidates) {
    if (!fs.existsSync(p)) continue;
    const src = fs.readFileSync(p, 'utf8');
    // The typings end in one `export { A, B as BIcon, ... }` statement, which
    // is the authoritative list: it carries the deprecated aliases too, so
    // parsing `declare const` instead would reject names that really do
    // resolve at runtime.
    const block = /^export \{([^}]*)\};/m.exec(src);
    if (!block) fail(`${path.relative(root, p)} has no trailing export statement — the typings shape changed`);
    const names = new Set();
    for (const entry of block[1].split(',')) {
      const m = /(?:\bas\s+)?([A-Za-z0-9_$]+)\s*$/.exec(entry.trim());
      if (m) names.add(m[1]);
    }
    if (names.size < 500) fail(`${path.relative(root, p)} parsed to ${names.size} icons — the typings shape changed`);
    return { names, from: path.relative(root, p) };
  }
  return null;
}

function checkIcons(rows) {
  const lucide = lucideIconNames();
  if (!lucide) {
    console.warn(
      'asset-classes: WARNING — lucide-react is not installed, so icon names were NOT verified.\n' +
      '  Run `npm install` at the repo root to make this check live.',
    );
    return 'unverified';
  }
  const bad = rows.filter((r) => !lucide.names.has(r.icon));
  if (bad.length) {
    fail(
      `icon(s) not exported by lucide-react (${lucide.from}):\n  ` +
      bad.map((r) => `${r.key}: ${r.icon}`).join('\n  '),
    );
  }
  return `verified against ${lucide.from}`;
}

// ---------------------------------------------------------------------------
// Emitters
// ---------------------------------------------------------------------------

const HEADER_LINES = [
  'Code generated by scripts/generate-asset-classes.mjs from',
  'standards/asset-classes.yaml. DO NOT EDIT — edit the YAML and run',
  '`make generate`.',
];

function sqlStr(s) {
  return `'${String(s).replace(/'/g, "''")}'`;
}

function sqlTextArray(values) {
  if (!values.length) return `ARRAY[]::text[]`;
  return `ARRAY[${values.map(sqlStr).join(', ')}]::text[]`;
}

function sqlNullable(s) {
  return s ? sqlStr(s) : 'NULL';
}

// The upsert itself, with no file header. Emitted TWICE: as the body of the
// standalone scripts/database/seed-asset-classes.sql, and as the generated
// region spliced into scripts/database/seed.sql (which is the copy that
// actually runs — see emitSQL's header for why both exist).
function emitClassUpsert(rows) {
  const values = rows.map((r) => {
    const schema = JSON.stringify(r.schema);
    return `    (NULL, ${sqlStr(r.key)}, ${sqlNullable(r.parent)}, ${sqlStr(r.path)},
     ${sqlStr(r.label)}, ${sqlStr(r.description)}, ${sqlStr(r.icon)},
     ${sqlStr(schema)}::jsonb, ${sqlTextArray(r.identifierPrecedence)},
     ${sqlNullable(r.cmdbCIType)}, ${sqlStr(r.cyclonedxType)}, true)`;
  });

  return `INSERT INTO public.asset_classes (
    tenant_id, key, parent_key, path,
    label, description, icon,
    attribute_schema, identifier_precedence,
    cmdb_ci_type, cyclonedx_type, is_fixed
) VALUES
${values.join(',\n')}
ON CONFLICT (key) WHERE tenant_id IS NULL DO UPDATE SET
    parent_key            = EXCLUDED.parent_key,
    path                  = EXCLUDED.path,
    label                 = EXCLUDED.label,
    description           = EXCLUDED.description,
    icon                  = EXCLUDED.icon,
    attribute_schema      = EXCLUDED.attribute_schema,
    identifier_precedence = EXCLUDED.identifier_precedence,
    cmdb_ci_type          = EXCLUDED.cmdb_ci_type,
    cyclonedx_type        = EXCLUDED.cyclonedx_type,
    is_fixed              = true;`;
}

function emitSQL(rows) {
  return `-- ${HEADER_LINES.join('\n-- ')}
--
-- Platform (tenant_id IS NULL) rows of public.asset_classes — the fixed class
-- hierarchy of ADR-0002 D2. Tenant leaf subclasses are runtime rows with
-- tenant_id set and is_fixed = false; this file never touches them.
--
-- THIS FILE IS NOT THE COPY THAT RUNS. The same upsert is spliced into the
-- "platform asset classes" generated region of scripts/database/seed.sql, and
-- that is what both compose (02-seed.sql) and the chart's seed-data Job apply.
-- It has to be inline there: the chart hands psql a ConfigMap key, so a
-- \\i include of a second file would resolve to nothing. This standalone file
-- is kept as the generator's readable output and as the drift anchor — the
-- --check run compares BOTH, so the spliced region cannot quietly diverge from
-- the YAML.
--
-- What the asset_classes table (schema.sql, BUILD_PLAN workstream 0.2)
-- provides for the statement below:
--
--   1. a default for asset_classes.id (gen_random_uuid()), since the insert
--      does not supply one;
--   2. the partial unique index the ON CONFLICT target infers:
--        CREATE UNIQUE INDEX IF NOT EXISTS asset_classes_platform_key_uniq
--            ON public.asset_classes (key) WHERE tenant_id IS NULL;
--
-- Re-appliable by construction: the upsert restates every generated column, so
-- re-running it after a taxonomy change reconciles existing rows rather than
-- erroring (CLAUDE.md's schema idempotency invariants).

${emitClassUpsert(rows)}
`;
}

function goName(key) {
  return key.split('_').map((p) => p[0].toUpperCase() + p.slice(1)).join('');
}

function goStr(s) {
  return JSON.stringify(String(s ?? ''));
}

// An empty precedence list is a STATEMENT — "this class has no independent
// identity" (ADR-0002 D3) — so it is emitted as an empty slice, never nil. The
// seed SQL writes ARRAY[]::text[] and the TS writes [], and a nil here would
// have marshalled the same fact as JSON `null` in Go alone: three mirrors of
// one registry disagreeing about the value the ADR gives meaning to.
function goStrSlice(values) {
  if (!values.length) return '[]string{}';
  return `[]string{${values.map(goStr).join(', ')}}`;
}

function emitGo(rows, identifierKinds, cyclonedxTypes, legacyTypes) {
  const width = Math.max(...rows.map((r) => goName(r.key).length)) + 1;
  const consts = rows
    .map((r) => `\tKey${goName(r.key)}${' '.repeat(width - goName(r.key).length)}Key = ${goStr(r.key)}`)
    .join('\n');

  const entries = rows.map((r) => `	{
		Key:                  ${goStr(r.key)},
		Parent:               ${goStr(r.parent)},
		Path:                 ${goStr(r.path)},
		Label:                ${goStr(r.label)},
		Icon:                 ${goStr(r.icon)},
		CMDBCIType:           ${goStr(r.cmdbCIType)},
		CycloneDXType:        ${goStr(r.cyclonedxType)},
		IdentifierPrecedence: ${goStrSlice(r.identifierPrecedence)},
		LegacyAssetType:      ${goStr(r.legacyAssetType)},
	},`).join('\n');

  return `// ${HEADER_LINES.join('\n// ')}
package assetclass

import "strings"

// Key is an asset class key. It is an alias rather than a defined type so the
// constants below drop straight into the string columns and JSON fields that
// carry a class ("assets.class_key", the OpenAPI AssetClassKey enum, the
// asset_classes registry rows) with no conversion at every call site.
type Key = string

// Class keys. The top level is fixed (ADR-0002 D2); tenants may add leaf
// subclasses at runtime, which never appear here.
const (
${consts}
)

// IdentifierKinds is the allowed set of identifier kinds, in the default
// precedence order of ADR-0002 D3. A class may drop and reorder kinds; it may
// not invent one.
var IdentifierKinds = ${goStrSlice(identifierKinds)}

// CycloneDXTypes is the allowed set of Class.CycloneDXType values. "service" is
// not a CycloneDX component type — a class carrying it is emitted into the
// CycloneDX "services" array rather than "components".
var CycloneDXTypes = ${goStrSlice(cyclonedxTypes)}

// LegacyAssetTypes is the allowed set of Class.LegacyAssetType values: the four
// values of the public.asset_type enum this taxonomy replaces.
var LegacyAssetTypes = ${goStrSlice(legacyTypes)}

// Class is one node of the fixed class hierarchy.
type Class struct {
	// Key is the stable identifier, unique across the platform hierarchy.
	Key Key \`json:"key"\`
	// Parent is the parent class key, empty for a top-level class.
	Parent Key \`json:"parent,omitempty"\`
	// Path is the materialised dot-separated ancestor chain ending in Key,
	// e.g. "hardware.computer.server". Prefix matching on Path is how a facet
	// selects a whole branch.
	Path string \`json:"path"\`
	// Label is the human-facing name.
	Label string \`json:"label"\`
	// Icon is a lucide-react export name (PascalCase).
	Icon string \`json:"icon"\`
	// CMDBCIType is the default ServiceNow class for the CMDB sync. Empty
	// means no confident default: resolve to the nearest ancestor that has
	// one, or let the sync profile map it. Empty is deliberately not the same
	// as a guess.
	CMDBCIType string \`json:"cmdb_ci_type,omitempty"\`
	// CycloneDXType is the component type used when the class is emitted into
	// an xBOM.
	CycloneDXType string \`json:"cyclonedx_type"\`
	// IdentifierPrecedence is the ordered subset of IdentifierKinds the
	// identification engine tries for this class, highest confidence first.
	// Empty means the class has no independent identity and is matched by
	// dependent identity instead (ADR-0002 D3) — an empty slice, never nil,
	// so the fact marshals as [] here exactly as it does in the TS mirror and
	// the seeded ARRAY[]::text[].
	IdentifierPrecedence []string \`json:"identifier_precedence"\`
	// LegacyAssetType maps the class onto the public.asset_type enum value the
	// pre-ADR-0002 model used. Reference only.
	LegacyAssetType string \`json:"legacy_asset_type"\`
}

// All is the fixed class hierarchy, in registry order. A parent always
// precedes its children.
var All = []Class{
${entries}
}

var byKey = func() map[string]Class {
	m := make(map[string]Class, len(All))
	for _, c := range All {
		m[c.Key] = c
	}
	return m
}()

// Get returns the class with this key. The second result is false for an
// unknown key and for tenant subclasses, which are runtime rows and are not
// part of the generated hierarchy.
func Get(key string) (Class, bool) {
	c, ok := byKey[key]
	return c, ok
}

// IsAncestor reports whether ancestor is key itself or one of its ancestors.
// It is the Path prefix test the facets use, done on whole segments so
// "hardware" never matches a hypothetical "hardware_x".
func IsAncestor(ancestor, key string) bool {
	if ancestor == "" || key == "" {
		return false
	}
	if ancestor == key {
		_, ok := byKey[key]
		return ok
	}
	c, ok := byKey[key]
	if !ok {
		return false
	}
	a, ok := byKey[ancestor]
	if !ok {
		return false
	}
	return strings.HasPrefix(c.Path, a.Path+".")
}

// Children returns the direct children of a class, in registry order. A leaf
// class returns an empty slice, as does an unknown key.
func Children(key string) []Class {
	out := make([]Class, 0, 4)
	for _, c := range All {
		if c.Parent == key && c.Parent != "" {
			out = append(out, c)
		}
	}
	return out
}

// Roots returns the top-level classes, in registry order.
func Roots() []Class {
	out := make([]Class, 0, 8)
	for _, c := range All {
		if c.Parent == "" {
			out = append(out, c)
		}
	}
	return out
}
`;
}

function emitSchemasJSON(rows) {
  const obj = {
    _comment: HEADER_LINES.join(' '),
    schemas: Object.fromEntries(rows.map((r) => [r.key, r.schema])),
  };
  return JSON.stringify(obj, null, 2) + '\n';
}

function tsStr(s) {
  return JSON.stringify(String(s ?? ''));
}

// emitAttributeSchemasTS is the TypeScript mirror of emitSchemasJSON: the same
// effective per-class schemas, typed.
//
// Go reads the JSON through shared/assetclass.Attributes; TypeScript imports
// this. Both feed the same thing — the flat, global `attr.` namespace of
// QUERY_LANGUAGE §4.2 — and until this file existed the TypeScript catalogue
// had no attribute vocabulary at all, so every `attr.<name>` reported
// unknown_field and an app had to hand the catalogue a list it had assembled
// somewhere else.
function emitAttributeSchemasTS(rows, attrTypes) {
  const union = attrTypes.map(tsStr).join(' | ');

  const prop = (def, indent) => {
    const pad = ' '.repeat(indent);
    const parts = [`${pad}type: ${tsStr(def.type)},`];
    parts.push(`${pad}description: ${tsStr(def.description)},`);
    if (def.enum !== undefined) {
      parts.push(`${pad}enum: [${def.enum.map(tsStr).join(', ')}],`);
    }
    if (def.items !== undefined) {
      parts.push(`${pad}items: { type: ${tsStr(def.items.type)} },`);
    }
    return parts.join('\n');
  };

  const entries = rows.map((r) => {
    const names = Object.keys(r.schema.properties);
    if (names.length === 0) {
      return `  ${tsStr(r.key)}: { type: 'object', additionalProperties: false, properties: {} },`;
    }
    const props = names
      .map((n) => `      ${tsStr(n)}: {\n${prop(r.schema.properties[n], 8)}\n      },`)
      .join('\n');
    return [
      `  ${tsStr(r.key)}: {`,
      `    type: 'object',`,
      `    additionalProperties: false,`,
      `    properties: {`,
      props,
      `    },`,
      `  },`,
    ].join('\n');
  }).join('\n');

  return `// ${HEADER_LINES.join('\n// ')}
//
// The EFFECTIVE attribute schema of every class — its own properties merged
// over every ancestor's — which is the same content as the Go mirror
// \`shared/assetclass/attribute_schemas_gen.json\`, typed.
//
// This is the vocabulary behind \`attr.<name>\` in the query language (§4.2).
// That namespace is flat and global: \`attr.model\` is ONE field, not one per
// class, because a query is a predicate over \`assets\` and its \`attributes\`
// jsonb holds whichever class's keys the row carries. The generator therefore
// refuses to emit two classes declaring one name with two types.

import type { AssetClassKey } from './classes.gen';

/** The value types a class attribute may declare. */
export type AssetAttributeType = ${union};

/** One class-specific attribute: a JSON-schema property restricted to the
 *  shapes the registry allows. */
export interface AssetAttributeProperty {
  type: AssetAttributeType;
  description: string;
  /** Closed value set. Only a string attribute may declare one. */
  enum?: readonly string[];
  /** The element type of an array attribute. */
  items?: { type: AssetAttributeType };
}

/** A class's effective attribute schema. \`additionalProperties\` is always
 *  false — an attribute nothing declared is a collection bug, not a bonus. */
export interface AssetAttributeSchema {
  type: 'object';
  additionalProperties: false;
  properties: Readonly<Record<string, AssetAttributeProperty>>;
}

export const ATTRIBUTE_SCHEMAS: Readonly<Record<AssetClassKey, AssetAttributeSchema>> = {
${entries}
};

/** A class's effective attribute schema, or undefined for a key the platform
 *  taxonomy does not define (a tenant leaf subclass is runtime data). */
export function attributeSchema(key: string): AssetAttributeSchema | undefined {
  return Object.prototype.hasOwnProperty.call(ATTRIBUTE_SCHEMAS, key)
    ? ATTRIBUTE_SCHEMAS[key as AssetClassKey]
    : undefined;
}
`;
}

function emitTS(rows, identifierKinds) {
  const union = rows.map((r) => `  | ${tsStr(r.key)}`).join('\n');
  const records = rows.map((r) => `  ${tsStr(r.key)}: {
    key: ${tsStr(r.key)},
    parent: ${r.parent ? tsStr(r.parent) : 'null'},
    path: ${tsStr(r.path)},
    label: ${tsStr(r.label)},
    description: ${tsStr(r.description)},
    icon: ${tsStr(r.icon)},
    cmdbCiType: ${r.cmdbCIType ? tsStr(r.cmdbCIType) : 'null'},
    cyclonedxType: ${tsStr(r.cyclonedxType)},
    identifierPrecedence: [${r.identifierPrecedence.map(tsStr).join(', ')}],
    legacyAssetType: ${tsStr(r.legacyAssetType)},
  },`).join('\n');

  const childrenOf = new Map();
  for (const r of rows) {
    if (!childrenOf.has(r.parent)) childrenOf.set(r.parent, []);
    childrenOf.get(r.parent).push(r.key);
  }
  const node = (key, indent) => {
    const kids = childrenOf.get(key) || [];
    const pad = '  '.repeat(indent);
    if (!kids.length) return `${pad}{ key: ${tsStr(key)}, children: [] },`;
    return [
      `${pad}{`,
      `${pad}  key: ${tsStr(key)},`,
      `${pad}  children: [`,
      ...kids.map((k) => node(k, indent + 2)),
      `${pad}  ],`,
      `${pad}},`,
    ].join('\n');
  };
  const tree = (childrenOf.get('') || []).map((k) => node(k, 1)).join('\n');

  return `// ${HEADER_LINES.join('\n// ')}
//
// The asset class taxonomy for the TypeScript side — facets, the class picker,
// and the per-class column/form registry import it as
// \`@vistasecurity/primitives/assets\`. The Go mirror is shared/assetclass; the
// DB mirror is the asset_classes table. All three come from the same YAML.

export const ASSET_IDENTIFIER_KINDS = [${identifierKinds.map(tsStr).join(', ')}] as const;

/** Every platform class key. Tenant leaf subclasses are runtime data and are
 *  deliberately NOT in this union — they are typed as \`string\`. */
export type AssetClassKey =
${union};

/** A CycloneDX component type, or "service" for classes emitted into the
 *  CycloneDX \`services\` array rather than \`components\`. */
export type AssetClassCycloneDXType = ${[...new Set(rows.map((r) => r.cyclonedxType))].sort().map(tsStr).join(' | ')};

export interface AssetClass {
  key: AssetClassKey;
  /** Parent class key; null for a top-level class. */
  parent: AssetClassKey | null;
  /** Materialised dot-separated ancestor chain, e.g. "hardware.computer.server". */
  path: string;
  label: string;
  description: string;
  /** lucide-react export name. */
  icon: string;
  /** Default ServiceNow class for the CMDB sync; null means no confident
   *  default (resolve to the nearest mapped ancestor). */
  cmdbCiType: string | null;
  cyclonedxType: AssetClassCycloneDXType;
  /** Ordered identifier kinds the identification engine tries, best first.
   *  Empty means dependent identity (ADR-0002 D3). */
  identifierPrecedence: string[];
  /** The public.asset_type enum value this class maps onto. Reference only. */
  legacyAssetType: string;
}

export const ASSET_CLASSES: Record<AssetClassKey, AssetClass> = {
${records}
};

/** Every class key in registry order — a parent always precedes its children. */
export const ASSET_CLASS_KEYS = Object.keys(ASSET_CLASSES) as AssetClassKey[];

export interface AssetClassNode {
  key: AssetClassKey;
  children: AssetClassNode[];
}

/** The class hierarchy, for facet rails and the class picker. Look labels and
 *  icons up in ASSET_CLASSES rather than duplicating them here. */
export const CLASS_TREE: AssetClassNode[] = [
${tree}
];
`;
}

function emitOpenAPIRegion(rows) {
  const lines = [
    '    AssetClassKey:',
    '      type: string',
    "      description: 'Asset class key from the fixed platform taxonomy (ADR-0002 D2, standards/asset-classes.yaml). Tenant leaf subclasses are runtime rows and are NOT members of this enum.'",
    '      enum:',
    ...rows.map((r) => `      - ${r.key}`),
  ];
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Region splicing (same shape as scripts/generate-permissions.mjs)
// ---------------------------------------------------------------------------

function spliceRegion(src, marker, body, commentPrefix) {
  const begin = `${commentPrefix} BEGIN GENERATED: ${marker} — from standards/asset-classes.yaml (make generate)`;
  const end = `${commentPrefix} END GENERATED: ${marker}`;
  const bi = src.indexOf(begin);
  const ei = src.indexOf(end);
  if (bi === -1 || ei === -1 || ei < bi) {
    fail(`region markers for "${marker}" not found (or out of order) — expected:\n  ${begin}\n  ${end}`);
  }
  return `${src.slice(0, bi + begin.length)}\n${body}\n${src.slice(ei)}`;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

async function main() {
  const checkOnly = process.argv.includes('--check');
  const { reg, rows, identifierKinds, cyclonedxTypes, legacyTypes } = load();
  const iconStatus = checkIcons(rows);

  const specPath = path.join(root, 'api', 'openapi', 'inventory-service.openapi.yaml');
  const spec = spliceRegion(
    fs.readFileSync(specPath, 'utf8'),
    'asset class keys',
    emitOpenAPIRegion(rows),
    '    #',
  );

  // The copy that actually runs. seed.sql is applied as 02-seed.sql in compose
  // and from a ConfigMap by the chart's seed-data Job, neither of which can
  // resolve a `\i` include — so the upsert is spliced in rather than sourced.
  const seedPath = path.join(root, 'scripts', 'database', 'seed.sql');
  const seed = spliceRegion(
    fs.readFileSync(seedPath, 'utf8'),
    'platform asset classes',
    emitClassUpsert(rows),
    '--',
  );

  const outputs = [
    [seedPath, seed],
    [path.join(root, 'scripts', 'database', 'seed-asset-classes.sql'), emitSQL(rows)],
    [path.join(root, 'shared', 'assetclass', 'classes_gen.go'),
      emitGo(rows, identifierKinds, cyclonedxTypes, legacyTypes)],
    [path.join(root, 'shared', 'assetclass', 'attribute_schemas_gen.json'), emitSchemasJSON(rows)],
    [path.join(root, 'packages', 'primitives', 'src', 'assets', 'classes.gen.ts'), emitTS(rows, identifierKinds)],
    [path.join(root, 'packages', 'primitives', 'src', 'assets', 'attribute-schemas.gen.ts'),
      emitAttributeSchemasTS(rows, reg.attribute_types)],
    [specPath, spec],
  ];

  if (checkOnly) {
    const stale = [];
    for (const [p, content] of outputs) {
      const current = fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '';
      if (current !== content) stale.push(path.relative(root, p));
    }
    if (stale.length) {
      fail(`out of date — run \`make generate\`:\n  ${stale.join('\n  ')}`);
    }
    console.log(`asset-classes check OK (${rows.length} classes, ${outputs.length} artefacts, icons ${iconStatus})`);
    return;
  }

  for (const [p, content] of outputs) {
    await fs.ensureDir(path.dirname(p));
    await fs.writeFile(p, content);
    console.log(`Generated: ${path.relative(root, p)}`);
  }
  console.log(`  ${rows.length} classes, icons ${iconStatus}`);
}

main().catch((e) => fail(e.stack || e.message));
