#!/usr/bin/env node
// Generates the Go connector registry from standards/connectors.yaml
// (asset-inventory ADR-0004 D5). Output:
//   shared/connectors/registry_gen.go
// Run via `make generate`; `make audit` fails on drift (--check mode).
//
// Also generates the TypeScript mirror both UIs read:
//   packages/primitives/src/connectors/registry.gen.ts
//
// --check additionally asserts that every `live` and `registered` connector key
// still appears in the CHECK constraint that carries it in
// scripts/database/schema.sql (platform_integrations.integration_type,
// cmdb_sync_profiles.platform_type or connector_connections.connector_key).
// The CHECKs stay hand-maintained in this phase — generating them is a later
// workstream — so this assertion is the only thing keeping the registry and
// the schema from drifting apart silently.
//
// `registered` is checked exactly as hard as `live`: the difference between
// the two is whether an implementation DISPATCHES on the key, not whether the
// database accepts it. Both kinds of row can exist, so both keys must be in a
// CHECK.
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';
import { goConst, goConstBlock, goStr, fail as sharedFail } from './lib/registry-codegen.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

const DIRECTIONS = ['pull', 'push', 'both'];

// live       — an implementation dispatches on this key (and
//              shared/connectors/implementations.go names the package).
// registered — the schema accepts the key but nothing dispatches on it.
// planned    — declared here only; no CHECK carries it.
const STATUSES = ['live', 'registered', 'planned'];

// Statuses whose key must appear in a schema.sql CHECK constraint.
const STATUSES_IN_SCHEMA = ['live', 'registered'];

// Where a live connector key must appear in schema.sql, keyed by the
// schema_source value in the YAML.
const CHECK_CONSTRAINTS = {
  platform_integrations: {
    constraint: 'valid_integration_type',
    column: 'platform_integrations.integration_type',
  },
  cmdb_sync_profiles: {
    constraint: 'valid_cmdb_platform_type',
    column: 'cmdb_sync_profiles.platform_type',
  },
  connector_connections: {
    constraint: 'valid_connector_key',
    column: 'connector_connections.connector_key',
  },
};

const fail = (msg) => sharedFail('connectors', msg);

function validate(registry) {
  const kinds = registry.kinds || [];
  if (!kinds.length) fail('no kinds defined');
  const kindSet = new Set(kinds);
  if (kindSet.size !== kinds.length) fail('duplicate entry in kinds');
  for (const k of kinds) {
    if (!/^[a-z0-9_]+$/.test(k)) fail(`bad kind: ${k}`);
  }

  const connectors = registry.connectors || [];
  if (!connectors.length) fail('no connectors defined');

  const seen = new Set();
  const usedKinds = new Set();

  for (const c of connectors) {
    if (!c.key || !/^[a-z0-9_]+$/.test(c.key)) fail(`bad connector key: ${c.key}`);
    if (seen.has(c.key)) fail(`duplicate connector key: ${c.key}`);
    seen.add(c.key);

    if (!c.label) fail(`${c.key}: label required`);
    if (!c.description) fail(`${c.key}: description required`);
    if (!kindSet.has(c.kind)) fail(`${c.key}: invalid kind: ${c.kind}`);
    usedKinds.add(c.kind);
    if (!DIRECTIONS.includes(c.direction)) fail(`${c.key}: invalid direction: ${c.direction}`);
    if (!STATUSES.includes(c.status)) fail(`${c.key}: invalid status: ${c.status}`);

    if (!Array.isArray(c.produces_classes)) {
      fail(`${c.key}: produces_classes must be a list (use [] for a connector that creates no assets)`);
    }
    const seenClasses = new Set();
    for (const cls of c.produces_classes) {
      // Class keys are plain strings here: standards/asset-classes.yaml owns
      // the class tree, and this registry deliberately does not depend on it.
      if (typeof cls !== 'string' || !/^[a-z0-9_]+$/.test(cls)) {
        fail(`${c.key}: bad class key: ${cls}`);
      }
      if (seenClasses.has(cls)) fail(`${c.key}: duplicate class key: ${cls}`);
      seenClasses.add(cls);
    }
    // A push-only connector is a sink. Claiming to produce assets in a
    // direction it never reads is a contradiction that would mislead anything
    // building an intake map from this registry.
    if (c.direction === 'push' && c.produces_classes.length) {
      fail(`${c.key}: direction is push but it claims to produce classes`);
    }

    if (STATUSES_IN_SCHEMA.includes(c.status)) {
      if (!CHECK_CONSTRAINTS[c.schema_source]) {
        fail(`${c.key}: ${c.status} connectors need schema_source (one of ${Object.keys(CHECK_CONSTRAINTS).join(', ')})`);
      }
    } else if (c.schema_source) {
      fail(`${c.key}: schema_source is only meaningful for live and registered connectors`);
    }

    // `feature` is an entitlement key (a billable_items key). It is optional:
    // absent means the connector is Core. The EDITION is deliberately not
    // restated here — shared/entitlements.EditionFor owns that, and a second
    // copy is a second opinion.
    if (c.feature !== undefined) {
      if (typeof c.feature !== 'string' || !/^[a-z0-9_]+$/.test(c.feature)) {
        fail(`${c.key}: bad feature key: ${c.feature}`);
      }
    }
  }

  for (const k of kinds) {
    if (!usedKinds.has(k)) fail(`kind '${k}' is declared but no connector uses it`);
  }
}

// Extracts the string literals from one CHECK constraint in schema.sql.
function checkConstraintValues(schema, constraintName) {
  const marker = `CONSTRAINT ${constraintName} CHECK`;
  const start = schema.indexOf(marker);
  if (start === -1) {
    fail(`constraint ${constraintName} not found in scripts/database/schema.sql — ` +
      'if it was renamed or dropped, update CHECK_CONSTRAINTS in this generator');
  }
  // Walk to the end of the CHECK's balanced parentheses so a constraint that
  // grows a nested expression cannot silently truncate the extracted list.
  const open = schema.indexOf('(', start + marker.length - 'CHECK'.length);
  if (open === -1) fail(`constraint ${constraintName}: no opening parenthesis`);
  let depth = 0;
  let end = -1;
  for (let i = open; i < schema.length; i++) {
    if (schema[i] === '(') depth++;
    else if (schema[i] === ')') {
      depth--;
      if (depth === 0) {
        end = i;
        break;
      }
    }
  }
  if (end === -1) fail(`constraint ${constraintName}: unbalanced parentheses`);
  const body = schema.slice(open, end + 1);
  const values = [...body.matchAll(/'([^']+)'::character varying/g)].map((m) => m[1]);
  if (!values.length) {
    fail(`constraint ${constraintName}: no values extracted — the CHECK's shape changed, ` +
      'so this audit would pass vacuously; fix the extractor rather than deleting it');
  }
  return new Set(values);
}

async function auditAgainstSchema(registry) {
  const schemaPath = path.resolve(root, 'scripts', 'database', 'schema.sql');
  const schema = await fs.readFile(schemaPath, 'utf8');

  const cache = {};
  const problems = [];
  for (const c of registry.connectors) {
    if (!STATUSES_IN_SCHEMA.includes(c.status)) continue;
    const target = CHECK_CONSTRAINTS[c.schema_source];
    cache[c.schema_source] ??= checkConstraintValues(schema, target.constraint);
    if (!cache[c.schema_source].has(c.key)) {
      problems.push(
        `  ${c.key}: declared ${c.status} with schema_source '${c.schema_source}' but ` +
        `'${c.key}' is not in ${target.column}'s CHECK (${target.constraint})`);
    }
  }
  if (problems.length) {
    fail(
      'live/registered connectors missing from the schema.sql CHECK constraints:\n' +
      problems.join('\n') +
      '\nAdd the key to the CHECK in a schema change, or mark the connector planned. ' +
      'Do not edit the CHECK as a side effect of a registry edit.');
  }
  const counts = Object.entries(cache).map(([k, v]) => `${k}=${v.size}`).join(', ');
  return counts;
}

function renderGo(registry) {
  const connectors = registry.connectors;

  const keyConsts = goConstBlock(
    connectors.map((c) => ({ name: `Connector${goConst(c.key)}`, value: goStr(c.key) })));

  const kindConsts = goConstBlock(
    registry.kinds.map((k) => ({ name: `Kind${goConst(k)}`, value: goStr(k) })));

  const entries = connectors
    .map((c) => {
      const classes = c.produces_classes.map((cls) => goStr(cls)).join(', ');
      const classLiteral = classes ? `[]string{${classes}}` : 'nil';
      // One line per value so gofmt's alignment block is never broken by a
      // nested literal; names padded to the longest (ProducesClasses).
      return `	{
		Key:             ${goStr(c.key)},
		Label:           ${goStr(c.label)},
		Kind:            ${goStr(c.kind)},
		Direction:       ${goStr(c.direction)},
		ProducesClasses: ${classLiteral},
		Status:          ${goStr(c.status)},
		SchemaSource:    ${goStr(c.schema_source ?? '')},
		Feature:         ${goStr(c.feature ?? '')},
		Description:     ${goStr(c.description.trim())},
	},`;
    })
    .join('\n');

  return `// Code generated by scripts/generate-connectors.mjs from
// standards/connectors.yaml. DO NOT EDIT — edit the YAML and run
// \`make generate\`.

// Package connectors is the generated registry of external systems the
// platform integrates with (asset-inventory ADR-0004 D5). It replaces the
// knowledge that is currently spread across two CHECK constraints in
// schema.sql, which carry a list of names and nothing else: no kind, no
// direction, no notion of what an integration produces.
//
// In this phase the CHECKs remain the enforcement point for writes and stay
// hand-maintained; \`make audit\` asserts that every live connector here still
// appears in the CHECK that carries it, so the two cannot drift apart.
package connectors

// Connector keys.
const (
${keyConsts}
)

// Connector kinds.
const (
${kindConsts}
)

// Direction values.
const (
	DirectionPull = "pull"
	DirectionPush = "push"
	DirectionBoth = "both"
)

// Status values.
//
// The three answer different questions and must not be collapsed:
//
//	StatusLive       an implementation dispatches on this key. [Implementation]
//	                 names the package, and the registry test fails if it does
//	                 not exist.
//	StatusRegistered the schema accepts the key — a row may carry it — but
//	                 nothing dispatches on it. A catalogue shows it; a UI must
//	                 not offer it as addable.
//	StatusPlanned    declared here only. No CHECK carries it, so the database
//	                 would reject a row.
const (
	StatusLive       = "live"
	StatusRegistered = "registered"
	StatusPlanned    = "planned"
)

// Connector is one external system the platform can integrate with.
type Connector struct {
	Key       string \`json:"key"\`
	Label     string \`json:"label"\`
	Kind      string \`json:"kind"\`
	Direction string \`json:"direction"\`
	// ProducesClasses are asset-class keys this connector can create assets
	// for, as plain strings: standards/asset-classes.yaml owns the class tree.
	// Empty for connectors that produce no assets, such as notification sinks.
	ProducesClasses []string \`json:"produces_classes,omitempty"\`
	Status          string   \`json:"status"\`
	// SchemaSource names the CHECK constraint carrying this key while the
	// CHECKs remain hand-maintained. Empty for planned connectors.
	SchemaSource string \`json:"schema_source,omitempty"\`
	// Feature is the entitlement key (a billable_items key) this connector is
	// gated on, or empty for a Core connector. The EDITION is deliberately not
	// stored here: shared/entitlements.EditionFor(Feature) is the single source
	// for that, and a second copy is a second opinion.
	Feature     string \`json:"feature,omitempty"\`
	Description string \`json:"description"\`
}

// All is the generated connector list, in YAML order.
var All = []Connector{
${entries}
}

// Kinds is the connector-kind vocabulary, in YAML order.
var Kinds = []string{${registry.kinds.map((k) => goStr(k)).join(', ')}}

var byKey = func() map[string]Connector {
	m := make(map[string]Connector, len(All))
	for _, c := range All {
		m[c.Key] = c
	}
	return m
}()

// Get returns the registry entry for a connector key. The second result is
// false when the key is not registered.
func Get(key string) (Connector, bool) {
	c, ok := byKey[key]
	return c, ok
}

// IsLive reports whether a connector is shipped and reachable — that is,
// whether something in this tree dispatches on the key. A registered or
// planned connector appears in the catalogue so a tenant can see it is coming;
// it is NOT dispatchable, and a caller that treats "in the registry" as "I can
// run this" is the bug this distinction exists to prevent.
func IsLive(key string) bool {
	c, ok := Get(key)
	return ok && c.Status == StatusLive
}

// IsRegistered reports whether the schema accepts this key but nothing
// implements it. Such a connector must be shown as "not yet available", never
// offered as addable.
func IsRegistered(key string) bool {
	c, ok := Get(key)
	return ok && c.Status == StatusRegistered
}

// FeatureFor returns the entitlement key gating a connector, or "" when it is
// Core (free in every edition). The second result is false for an unregistered
// key, which callers must treat as "do not dispatch" rather than as Core.
func FeatureFor(key string) (string, bool) {
	c, ok := Get(key)
	if !ok {
		return "", false
	}
	return c.Feature, true
}

// ByKind returns the connectors of one kind, in registry order.
func ByKind(kind string) []Connector {
	var out []Connector
	for _, c := range All {
		if c.Kind == kind {
			out = append(out, c)
		}
	}
	return out
}
`;
}


// Display labels for the kind vocabulary. They live here rather than in the
// YAML because they are presentation, and a registry that carries its own
// English is a registry two teams edit for two reasons.
const KIND_LABELS = {
  cloud: 'Cloud',
  cmdb: 'CMDB / ITSM',
  network_source_of_truth: 'Network source of truth',
  itsm: 'ITSM',
  siem: 'SIEM',
  notification: 'Notifications',
  edr_mdm: 'EDR / MDM',
  sbom_source: 'Software & SBOM',
  secrets_store: 'Secrets stores',
};

// --- TypeScript mirror -----------------------------------------------------
//
// Both UIs read the registry so the Integrations page is DRIVEN by it rather
// than by a hand-kept list beside it. The hand-kept list is what this replaces:
// the CMDB platform labels lived in a `PLATFORM_LABEL` object in the modal file
// and had to be edited whenever the registry changed, which is a drift the
// build could not see.
const tsStr = (v) => JSON.stringify(String(v ?? ''));

function renderTs(registry) {
  const connectors = registry.connectors;

  const entries = connectors
    .map((c) => {
      const lines = [
        `  {`,
        `    key: ${tsStr(c.key)},`,
        `    label: ${tsStr(c.label)},`,
        `    kind: ${tsStr(c.kind)},`,
        `    direction: ${tsStr(c.direction)},`,
        `    producesClasses: [${c.produces_classes.map((x) => tsStr(x)).join(', ')}],`,
        `    status: ${tsStr(c.status)},`,
      ];
      if (c.feature) lines.push(`    feature: ${tsStr(c.feature)},`);
      lines.push(`    description: ${tsStr(c.description.trim())},`);
      lines.push('  },');
      return lines.join('\n');
    })
    .join('\n');

  return `// Code generated by scripts/generate-connectors.mjs from
// standards/connectors.yaml. DO NOT EDIT — edit the YAML and run
// \`make generate\`.
//
// The connector registry for the TypeScript side — frontend-v2 imports it as
// \`@vistasecurity/primitives/connectors\`. The Go mirror is
// shared/connectors/registry_gen.go; both come from the same YAML, and
// \`make audit\` fails if either drifts.

/** The kinds of external system the platform integrates with (ADR-0004 D5). */
export type ConnectorKind =
${registry.kinds.map((k) => `  | ${tsStr(k)}`).join('\n')};

/** Which way data flows. */
export type ConnectorDirection = 'pull' | 'push' | 'both';

/**
 * How far along a connector is. The three are answers to different questions
 * and a UI must not collapse them:
 *
 *  - \`live\`       — an implementation dispatches on this key. Addable.
 *  - \`registered\` — the schema accepts the key but nothing implements it.
 *                   Show it, say "not yet available", do NOT make it selectable.
 *  - \`planned\`    — declared in the registry only. Same UI treatment as
 *                   registered; the difference is a database one.
 */
export type ConnectorStatus = 'live' | 'registered' | 'planned';

/** Every registered connector key. */
export type ConnectorKey =
${connectors.map((c) => `  | ${tsStr(c.key)}`).join('\n')};

export interface ConnectorDef {
  key: ConnectorKey;
  label: string;
  kind: ConnectorKind;
  direction: ConnectorDirection;
  /** Asset-class keys this connector can create assets for. */
  producesClasses: readonly string[];
  status: ConnectorStatus;
  /**
   * Entitlement key (a billable_items key) this connector is gated on.
   * Absent means Core — free in every edition.
   */
  feature?: string;
  description: string;
}

/** Every connector, in registry order. */
export const CONNECTORS: readonly ConnectorDef[] = [
${entries}
];

/** The connector-kind vocabulary, in registry order. */
export const CONNECTOR_KINDS: readonly ConnectorKind[] = [
${registry.kinds.map((k) => `  ${tsStr(k)},`).join('\n')}
];

/** Human labels for each kind, for section headings. */
export const CONNECTOR_KIND_LABEL: Record<ConnectorKind, string> = {
${registry.kinds.map((k) => `  ${tsStr(k)}: ${tsStr(KIND_LABELS[k] ?? k)},`).join('\n')}
};

const byKey = new Map(CONNECTORS.map((c) => [c.key, c]));

/** Look up one connector. Returns undefined for an unregistered key. */
export function getConnector(key: string): ConnectorDef | undefined {
  return byKey.get(key as ConnectorKey);
}

/**
 * Connectors of one kind, in registry order. Returns a new array each call so
 * a caller cannot reorder the registry in place.
 */
export function connectorsByKind(kind: ConnectorKind): ConnectorDef[] {
  return CONNECTORS.filter((c) => c.kind === kind);
}

/**
 * The kinds that actually have connectors, in registry order — what a grouped
 * catalogue iterates. A kind with no connectors is impossible today (the
 * generator refuses one), but a UI that assumed so would break on the day one
 * is added ahead of its first connector.
 */
export function populatedKinds(): ConnectorKind[] {
  return CONNECTOR_KINDS.filter((k) => CONNECTORS.some((c) => c.kind === k));
}

/**
 * Whether a connector may be added by a tenant right now.
 *
 * \`live\` is necessary but not sufficient: a gated connector also needs its
 * entitlement. Passing \`features\` as the resolved feature map keeps the two
 * halves of that question in one place, so a page cannot check one and forget
 * the other — which is how a paid connector came to be offered on Core.
 */
export function isAddable(c: ConnectorDef, features: Record<string, boolean>): boolean {
  if (c.status !== 'live') return false;
  if (!c.feature) return true;
  return features[c.feature] === true;
}

/**
 * Why a connector is not addable, for the UI to render. Null when it IS
 * addable. \`upgrade\` means "your edition/plan does not include this";
 * \`unavailable\` means "we have not built it yet" — different sentences, and
 * showing an upgrade prompt for something nobody can buy yet is the worse of
 * the two mistakes.
 */
export function unavailableReason(
  c: ConnectorDef,
  features: Record<string, boolean>,
): 'upgrade' | 'unavailable' | null {
  if (c.status !== 'live') return 'unavailable';
  if (c.feature && features[c.feature] !== true) return 'upgrade';
  return null;
}
`;
}

async function main() {
  const checkOnly = process.argv.includes('--check');
  const registryPath = path.resolve(root, 'standards', 'connectors.yaml');

  const registry = yaml.parse(await fs.readFile(registryPath, 'utf8'));
  validate(registry);

  const outputs = [
    [path.resolve(root, 'shared', 'connectors', 'registry_gen.go'), renderGo(registry)],
    [
      path.resolve(root, 'packages', 'primitives', 'src', 'connectors', 'registry.gen.ts'),
      renderTs(registry),
    ],
  ];

  const live = registry.connectors.filter((c) => c.status === 'live').length;
  const registered = registry.connectors.filter((c) => c.status === 'registered').length;

  if (checkOnly) {
    for (const [outPath, want] of outputs) {
      const current = (await fs.pathExists(outPath)) ? await fs.readFile(outPath, 'utf8') : '';
      if (current !== want) {
        fail(`${path.relative(root, outPath)} is out of date — run \`make generate\``);
      }
    }
    const counts = await auditAgainstSchema(registry);
    console.log(
      `connectors check OK (${registry.connectors.length} connectors, ${live} live, ` +
      `${registered} registered; schema CHECK values: ${counts})`);
    return;
  }

  for (const [outPath, content] of outputs) {
    await fs.ensureDir(path.dirname(outPath));
    await fs.writeFile(outPath, content);
    console.log(
      `Generated: ${path.relative(root, outPath)} ` +
      `(${registry.connectors.length} connectors, ${live} live, ${registered} registered)`);
  }
}

main().catch((e) => fail(e.message));
