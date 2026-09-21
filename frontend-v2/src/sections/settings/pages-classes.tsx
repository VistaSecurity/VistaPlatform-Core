// Settings → Policies → Classes, and → Identification rules (ADR-0006 D7).
//
// Both are READ-ONLY in phase 1, and both are read from the generated registry
// rather than from an endpoint: the taxonomy is fixed (`standards/asset-classes.yaml`
// → `@vistasecurity/primitives/assets`), and the client already ships it because
// the facet rail, the class picker and the column registry all need it. Fetching
// a copy of a constant over HTTP would add a loading state to a page that cannot
// fail and a second version of a list that must not disagree with itself.
//
// Tenant SUBCLASS authoring (ADR-0002) and editable identifier precedence land
// in phase 2; this page is where they will land, which is why it exists now
// rather than after them — a user needs to be able to see the rules that are
// deciding what their inventory looks like.
import { useMemo, useState } from 'react';
import {
  ASSET_CLASSES, ATTRIBUTE_SCHEMAS, CLASS_TREE,
  type AssetClassKey, type AssetClassNode,
} from '@vistasecurity/primitives/assets';
import { Icon } from '../../components/ui';
import { classIcon } from '../inventory/asset-shape';
import { SPage, SCard } from './kit';
import { AutoAcceptCard } from './auto-accept-card';
import type { SettingsNavItem } from './nav';

type Meta = SettingsNavItem & { section?: string };

function humanise(name: string): string {
  const words = name.split('_');
  const head = words[0] === 'os' || words[0] === 'cpu' || words[0] === 'ip'
    ? words[0].toUpperCase()
    : words[0].charAt(0).toUpperCase() + words[0].slice(1);
  return [head, ...words.slice(1).map((w) => (w === 'id' ? 'ID' : w === 'mb' ? 'MB' : w))].join(' ');
}

/** The attributes a class declares ITSELF, i.e. the ones not inherited. The
 *  generated schema is the EFFECTIVE one (its own merged over every ancestor's),
 *  so the difference against the parent is what tells a reader what this class
 *  adds — which is the question the tree answers. */
export function ownAttributes(key: AssetClassKey): string[] {
  const own = Object.keys(ATTRIBUTE_SCHEMAS[key]?.properties ?? {});
  const parent = ASSET_CLASSES[key]?.parent;
  if (!parent) return own;
  const inherited = new Set(Object.keys(ATTRIBUTE_SCHEMAS[parent]?.properties ?? {}));
  return own.filter((a) => !inherited.has(a));
}

function ClassRow({ node, depth }: { node: AssetClassNode; depth: number }) {
  const cls = ASSET_CLASSES[node.key];
  const [open, setOpen] = useState(depth === 0);
  const own = useMemo(() => ownAttributes(node.key), [node.key]);
  const effective = Object.keys(ATTRIBUTE_SCHEMAS[node.key]?.properties ?? {});
  const inheritedCount = effective.length - own.length;
  const hasChildren = node.children.length > 0;

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, padding: '8px 0', paddingLeft: depth * 18, borderBottom: '1px solid var(--app-border)' }}>
        <button
          onClick={() => setOpen((o) => !o)}
          disabled={!hasChildren}
          aria-label={hasChildren ? (open ? `Collapse ${cls.label}` : `Expand ${cls.label}`) : undefined}
          style={{ width: 16, height: 18, border: 'none', background: 'transparent', color: 'var(--app-t3)', cursor: hasChildren ? 'pointer' : 'default', padding: 0, flex: 'none', visibility: hasChildren ? 'visible' : 'hidden' }}
        >
          <Icon name={open ? 'chevron-down' : 'chevron-right'} size={12} />
        </button>
        <Icon name={classIcon(cls.key)} size={14} style={{ color: 'var(--app-t3)', flex: 'none', marginTop: 1 }} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--app-t1)' }}>{cls.label}</span>
            <span className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>{cls.key}</span>
            <span style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>CycloneDX: {cls.cyclonedxType}</span>
            {cls.cmdbCiType && <span style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>ServiceNow: {cls.cmdbCiType}</span>}
          </div>
          <div style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 2, lineHeight: 1.5 }}>{cls.description}</div>
          {own.length > 0 && (
            <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginTop: 6 }}>
              {own.map((a) => (
                <span
                  key={a}
                  title={ATTRIBUTE_SCHEMAS[node.key].properties[a].description}
                  className="mono"
                  style={{ fontSize: 10.5, color: 'var(--app-t2)', background: 'var(--app-panel2)', border: '1px solid var(--app-border2)', borderRadius: 40, padding: '1px 8px' }}
                >
                  {humanise(a)}
                </span>
              ))}
              {inheritedCount > 0 && (
                <span style={{ fontSize: 10.5, color: 'var(--app-t3)', alignSelf: 'center' }} title="Attributes this class inherits from its parents">
                  + {inheritedCount} inherited
                </span>
              )}
            </div>
          )}
        </div>
      </div>
      {open && node.children.map((c) => <ClassRow key={c.key} node={c} depth={depth + 1} />)}
    </div>
  );
}

export function ClassesPage({ meta }: { meta: Meta }) {
  const total = Object.keys(ASSET_CLASSES).length;
  return (
    <SPage eyebrow={meta.section ?? 'Policies'} title={meta.label} job={meta.job} maxWidth={1000}>
      <SCard>
        <div style={{ fontSize: 12.5, color: 'var(--app-t3)', lineHeight: 1.65, marginBottom: 14 }}>
          Every asset has exactly one class, and the class decides which attributes the asset can carry, how it is exported to a CBOM, and which CMDB type it maps to. The {total} classes below are the platform taxonomy — fixed, so that a query written in one tenant means the same thing in another.
          <br />
          <strong style={{ color: 'var(--app-t2)' }}>Read-only in this release.</strong> Adding your own subclasses, with their own attributes, is coming.
        </div>
        <div>
          {CLASS_TREE.map((n) => <ClassRow key={n.key} node={n} depth={0} />)}
        </div>
      </SCard>
    </SPage>
  );
}

// ------------------------------------------------- identification rules --

/**
 * What each identifier kind is WORTH — not what order it is tried in.
 *
 * The order is a property of the CLASS, not of the kind: the registry gives
 * every class its own `identifier_precedence`, and `hardware` starts at
 * `serial_number` while `computer` starts at `agent_id`. A single ladder shown
 * here would be a second copy of an ordering this page does not own, and it was
 * one: it claimed `agent_id` was first for everything, which is not true of any
 * class that cannot run an agent.
 *
 * `scoped` mirrors `Kind.AcceptsScope` in `shared/identity`: a scope means
 * something for exactly four kinds — the segment for `hostname` and
 * `ip_address`, the class key for `name`, the sync profile for `cmdb_sys_id`.
 * The other six are globally unique by construction and the engine REJECTS a
 * scope on one, because a scope nobody asked for splits the uniqueness key.
 */
export const IDENTIFIER_KIND_NOTES: Readonly<Record<string, { label: string; scoped: boolean; why: string }>> = {
  agent_id: { label: 'Agent ID', scoped: false, why: 'Minted by the platform when an agent enrols. Names exactly one installation.' },
  sensor_id: { label: 'Sensor ID', scoped: false, why: 'A sensor installation’s own identifier, issued at enrollment. Distinct from a device agent’s Agent ID — a single host can carry both.' },
  cloud_resource_id: { label: 'Cloud resource ID', scoped: false, why: 'The provider’s own ARN/ID. Unique by construction, and stable across restarts and address changes.' },
  serial_number: { label: 'Serial number', scoped: false, why: 'Burned in by the manufacturer. Survives reimaging, renaming and re-addressing.' },
  cmdb_sys_id: { label: 'CMDB sys_id', scoped: true, why: 'The connected CMDB’s own key. Scoped to the sync profile it came from, because two CMDBs can issue the same sys_id.' },
  ssh_host_key_fingerprint: { label: 'SSH host key', scoped: false, why: 'The host’s own key. Changes only when the host is rebuilt — which is itself worth knowing.' },
  mac_address: { label: 'MAC address', scoped: false, why: 'Unique per interface. Weaker than a serial: virtual machines and containers can be given one.' },
  fqdn: { label: 'FQDN', scoped: false, why: 'A fully-qualified name. Unique across the tenant on its own, because the domain is part of it.' },
  hostname: { label: 'Hostname', scoped: true, why: 'A short name, unique only inside a segment. Two segments can each have a “db01”.' },
  ip_address: { label: 'IP address', scoped: true, why: 'Weakest: addresses are reassigned. Matched inside a segment, never across the tenant.' },
  name: { label: 'Name', scoped: true, why: 'For declared services, which have no address or serial. Scoped by class key.' },
};

/**
 * The order the engine resolves a sighting of this class in, read from the
 * generated registry rather than restated here.
 *
 * An empty list is a real answer, not a missing one: the YAML defines it as a
 * class with no independent identity at all, which refuses every observation of
 * itself. No shipped class is empty today, so the branch is there for the day
 * one is rather than because one already is. An unknown class — a tenant
 * subclass this build predates — also returns empty, and the page says which of
 * the two it is looking at.
 */
export function precedenceForClass(classKey: string): string[] {
  return [...(ASSET_CLASSES[classKey as AssetClassKey]?.identifierPrecedence ?? [])];
}

/** Every kind that appears in any class's precedence, so the page can say what
 *  it has no note for instead of rendering a bare key. */
export function kindsInUse(): string[] {
  const seen = new Set<string>();
  for (const key of Object.keys(ASSET_CLASSES) as AssetClassKey[]) {
    for (const kind of ASSET_CLASSES[key].identifierPrecedence) seen.add(kind);
  }
  return [...seen];
}

const DEFAULT_RULES_CLASS: AssetClassKey = 'server';

export function IdentificationRulesPage({ meta }: { meta: Meta }) {
  const [classKey, setClassKey] = useState<string>(DEFAULT_RULES_CLASS);
  const options = useMemo(() => flattenTree(CLASS_TREE, 0), []);
  const order = precedenceForClass(classKey);
  const cls = ASSET_CLASSES[classKey as AssetClassKey];

  return (
    <SPage eyebrow={meta.section ?? 'Policies'} title={meta.label} job={meta.job} maxWidth={1000}>
      <SCard>
        <div style={{ fontSize: 12.5, color: 'var(--app-t3)', lineHeight: 1.65, marginBottom: 16 }}>
          When something is discovered, the platform has to decide whether it is a thing it already knows about or a new one. It decides by identifier, strongest first: the first identifier that matches an existing asset wins, and nothing matching means a new asset.
          <br />
          This is why a host seen by a sensor, pulled from your CMDB and typed in by hand becomes <em>one</em> asset rather than three — and why, when the evidence is ambiguous, you get a merge proposal in Discovery → Approvals instead of a silent guess.
          <br />
          The order is <strong style={{ color: 'var(--app-t2)' }}>per class</strong>: a server can be known by the agent installed on it, and a printer cannot. Pick a class to see the order used for it.
          <br />
          The order itself is <strong style={{ color: 'var(--app-t2)' }}>read-only in this release</strong>; editing it per class arrives in a later one. What a merge proposal is scored on, and whether a high enough score may settle one without you, is the card below.
        </div>

        <label style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 14 }}>
          <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)', flex: 'none' }}>Class</span>
          <select
            aria-label="Class"
            value={classKey}
            onChange={(e) => setClassKey(e.target.value)}
            style={{ height: 31, padding: '0 9px', borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12.5, minWidth: 260 }}
          >
            {options.map(({ key, depth }) => (
              <option key={key} value={key}>
                {'  '.repeat(depth)}{depth > 0 ? '└ ' : ''}{ASSET_CLASSES[key].label}
              </option>
            ))}
          </select>
          {cls && <span className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>{cls.path}</span>}
        </label>

        {order.length === 0 ? (
          <div style={{ fontSize: 12.5, color: 'var(--app-t3)', lineHeight: 1.6, padding: '10px 0' }}>
            {cls
              ? `${cls.label} has no independent identity: nothing can name one on its own, so an observation of one is never resolved into an asset by itself.`
              : 'This class is not in the taxonomy this build ships, so its order cannot be shown here.'}
          </div>
        ) : (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: '28px minmax(0,190px) 96px minmax(0,1fr)', gap: 10, padding: '0 0 6px' }}>
              <span className="eyebrow-app">#</span>
              <span className="eyebrow-app">Identifier</span>
              <span className="eyebrow-app">Uniqueness</span>
              <span className="eyebrow-app">Why it sits here</span>
            </div>
            {order.map((kind, i) => {
              const note = IDENTIFIER_KIND_NOTES[kind];
              const scoped = note?.scoped ?? false;
              return (
                <div key={kind} style={{ display: 'grid', gridTemplateColumns: '28px minmax(0,190px) 96px minmax(0,1fr)', gap: 10, alignItems: 'start', padding: '9px 0', borderTop: '1px solid var(--app-border)' }}>
                  <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{i + 1}</span>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>{note?.label ?? kind}</div>
                    <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>{kind}</div>
                  </div>
                  <span
                    title={scoped
                      ? 'Matched inside its scope — the network segment, the class, or the CMDB sync profile. An unsegmented tenant uses one tenant-wide default scope.'
                      : 'Unique across the whole tenant on its own.'}
                    style={{ fontSize: 10.5, fontWeight: 600, alignSelf: 'start', color: scoped ? 'var(--warn)' : 'var(--ok)', background: `color-mix(in srgb, ${scoped ? 'var(--warn)' : 'var(--ok)'} 11%, transparent)`, borderRadius: 40, padding: '2px 8px', justifySelf: 'start' }}
                  >
                    {scoped ? 'Scoped' : 'Global'}
                  </span>
                  <span style={{ fontSize: 12, color: 'var(--app-t3)', lineHeight: 1.55 }}>
                    {note?.why ?? 'No description for this identifier kind in this release.'}
                  </span>
                </div>
              );
            })}
          </>
        )}
      </SCard>

      {/* The auto-accept threshold. Below the order, because it only matters
          once you understand what the order could not settle. */}
      <AutoAcceptCard />
    </SPage>
  );
}

/** Flattens the class tree into `[{ key, depth }]` for the indented select. */
function flattenTree(nodes: readonly AssetClassNode[], depth: number): { key: AssetClassKey; depth: number }[] {
  const out: { key: AssetClassKey; depth: number }[] = [];
  for (const n of nodes) {
    out.push({ key: n.key, depth });
    out.push(...flattenTree(n.children, depth + 1));
  }
  return out;
}
