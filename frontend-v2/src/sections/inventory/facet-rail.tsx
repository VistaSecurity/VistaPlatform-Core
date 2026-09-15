// The Inventory facet rail — a builder for the query string.
//
// ADR-0006 D2. Every control here does one thing: rewrite `?query=`. There is no
// second filter state, which is deliberate — the page used to hold `fEnv`,
// `fRisk` and `fStrength` in component state while the URL held only the lens,
// so a filtered view could not be shared, bookmarked or saved.
//
// The class facet is hierarchical (pick "Hardware" or drill to "Server") because
// the taxonomy is a tree and `class:hardware` matches the whole subtree, which
// is what makes one faceted list able to replace the twelve near-identical pages
// a lens-per-class would have needed.
import { useEffect, useMemo, useState } from 'react';
import { ASSET_CLASSES, CLASS_TREE, type AssetClassKey, type AssetClassNode } from '@vistasecurity/primitives/assets';
import { Icon } from '../../components/ui';
import {
  FACET_LABEL, PROVENANCE_LABEL, PROVENANCE_VALUES, RISK_BANDS, RISK_BAND_LABEL,
  STATUS_LABEL, STATUS_VALUES, cycleFindings, facetCount, setFacetClass, toggleFacetValue,
  type FacetKey, type FacetState,
} from './facet-query';
import { type FacetLevel, bucketMap, type FacetBuckets, type FacetData } from './asset-queries';

export interface FacetValue { value: string; count?: number; label?: string }

/**
 * What a bucket facet should show — the THIRD state is the point.
 *
 * `empty` is a sentence about the tenant's data ("No sites recorded."), and a
 * failed request is not evidence for it. A level that did not answer says so
 * and offers a retry; it never speaks for the data it could not read.
 *
 * A failed level still lists whatever the QUERY selects, so a filter can be
 * cleared from the rail even while its counts are unavailable.
 */
export function bucketFacetView(
  buckets: { value: string; count: number; label?: string }[],
  selected: readonly string[],
  failed: boolean,
  empty: string,
): { kind: 'values' | 'failed'; values: FacetValue[] } | { kind: 'empty'; message: string } {
  const seen = new Set(buckets.map((b) => b.value));
  const values: FacetValue[] = [
    ...buckets,
    ...selected.filter((v) => !seen.has(v)).map((v) => ({ value: v, count: failed ? undefined : 0 })),
  ];
  if (failed) return { kind: 'failed', values };
  if (values.length === 0) return { kind: 'empty', message: empty };
  return { kind: 'values', values };
}

/**
 * The count to show beside a class — the server's own subtree total.
 *
 * Buckets are keyed by the class PATH, not the key: the facet's `value` is what
 * a QUERY TERM matches on, and `class:` compares a prefix of the path. Looking
 * them up by key would have found nothing for every class below the top level
 * and quietly shown a tree of zeroes.
 *
 * The rollup is the SERVER's and is not repeated here. `classFacets` expands
 * each row's `class_path` into every one of its ancestors, so an asset at
 * `hardware.computer.server` is already counted under `hardware` and
 * `hardware.computer` as well as under itself — and summing the children again
 * on this side counted it once per level (40 servers rendered as
 * "Hardware 120 / Computer 80 / Server 40"). One implementation of the taxonomy
 * arithmetic, and it is the one that can see a tenant subclass this build's
 * generated tree has never heard of.
 */
export function subtreeCount(node: AssetClassNode, counts: Record<string, number>): number {
  const path = ASSET_CLASSES[node.key]?.path ?? node.key;
  return counts[path] ?? 0;
}

/** The path of ancestor keys down to a class, for auto-expanding the tree to
 *  whatever the query selected. */
export function ancestorsOf(classKey: string): string[] {
  const cls = ASSET_CLASSES[classKey as AssetClassKey];
  if (!cls) return [];
  return cls.path.split('.').slice(0, -1);
}

function ClassNode({ node, depth, counts, countsFailed, selected, expanded, onToggleExpand, onPick }: {
  node: AssetClassNode;
  depth: number;
  counts: Record<string, number>;
  /** The class level did not answer — show no number rather than a zero. */
  countsFailed?: boolean;
  selected?: string;
  expanded: Set<string>;
  onToggleExpand: (key: string) => void;
  onPick: (key: string) => void;
}) {
  const cls = ASSET_CLASSES[node.key];
  const count = subtreeCount(node, counts);
  const isSelected = selected === node.key;
  const open = expanded.has(node.key);
  const hasChildren = node.children.length > 0;
  return (
    <div>
      <div
        className="row-hover"
        style={{
          display: 'flex', alignItems: 'center', gap: 5, borderRadius: 7,
          paddingLeft: 4 + depth * 11,
          background: isSelected ? 'color-mix(in srgb, var(--accent) 13%, transparent)' : 'transparent',
        }}
      >
        <button
          aria-label={hasChildren ? (open ? `Collapse ${cls?.label ?? node.key}` : `Expand ${cls?.label ?? node.key}`) : undefined}
          disabled={!hasChildren}
          onClick={() => onToggleExpand(node.key)}
          style={{ width: 15, height: 22, border: 'none', background: 'transparent', cursor: hasChildren ? 'pointer' : 'default', color: 'var(--app-t3)', padding: 0, flex: 'none', visibility: hasChildren ? 'visible' : 'hidden' }}
        >
          <Icon name={open ? 'chevron-down' : 'chevron-right'} size={12} />
        </button>
        <button
          onClick={() => onPick(node.key)}
          title={cls?.description}
          style={{
            display: 'flex', alignItems: 'center', gap: 7, flex: 1, minWidth: 0,
            padding: '4px 6px 4px 0', border: 'none', background: 'transparent', cursor: 'pointer',
            textAlign: 'left', color: isSelected ? 'var(--accent)' : 'var(--app-t1)',
            fontSize: 12, fontWeight: isSelected ? 600 : 500,
          }}
        >
          <span style={{ flex: 1, minWidth: 0, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {cls?.label ?? node.key}
          </span>
          {/* A count of 0 is a real answer (nothing of this class), and showing
              it is how a user learns the taxonomy has a slot they are not
              filling. It is muted, not hidden. */}
          <span className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', opacity: count > 0 ? 1 : 0.45, flex: 'none' }}>{countsFailed ? '—' : count}</span>
        </button>
      </div>
      {open && hasChildren && node.children.map((child) => (
        <ClassNode key={child.key} node={child} depth={depth + 1} counts={counts} countsFailed={countsFailed} selected={selected} expanded={expanded} onToggleExpand={onToggleExpand} onPick={onPick} />
      ))}
    </div>
  );
}

function Section({ label, children, count }: { label: string; children: React.ReactNode; count?: number }) {
  const [open, setOpen] = useState(true);
  return (
    <div style={{ borderTop: '1px solid var(--app-border)', padding: '9px 12px 10px' }}>
      <button
        onClick={() => setOpen((o) => !o)}
        style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%', border: 'none', background: 'transparent', cursor: 'pointer', padding: 0, marginBottom: open ? 7 : 0, color: 'var(--app-t2)' }}
      >
        <Icon name={open ? 'chevron-down' : 'chevron-right'} size={11} />
        <span className="eyebrow-app" style={{ flex: 1, textAlign: 'left' }}>{label}</span>
        {count ? <span className="mono" style={{ fontSize: 10, color: 'var(--accent)' }}>{count}</span> : null}
      </button>
      {open && children}
    </div>
  );
}

function CheckRow({ label, value, count, checked, onToggle }: {
  label: string; value: string; count?: number; checked: boolean; onToggle: () => void;
}) {
  return (
    <label
      title={value}
      style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '3px 2px', cursor: 'pointer', fontSize: 12, color: checked ? 'var(--app-t1)' : 'var(--app-t2)' }}
    >
      <input type="checkbox" checked={checked} onChange={onToggle} aria-label={label} style={{ accentColor: 'var(--accent)', width: 13, height: 13 }} />
      <span style={{ flex: 1, minWidth: 0, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontWeight: checked ? 600 : 400 }}>{label}</span>
      {count !== undefined && (
        <span className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', opacity: count > 0 ? 1 : 0.45 }}>{count}</span>
      )}
    </label>
  );
}

/**
 * A multi-select facet whose values come from the SERVER's buckets, not from a
 * hardcoded list. Site, owner, business unit and segment are all tenant data;
 * enumerating them here would show a list nobody in this tenant uses and hide
 * the one they do.
 */
/** "Couldn't load" + a retry, for one level. Never an empty-fact sentence. */
function LevelFailed({ onRetry }: { onRetry?: () => void }) {
  return (
    <div data-testid="facet-level-failed" style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11.5, color: 'var(--warn-strong)' }}>
      <Icon name="alert-triangle" size={11} />
      <span style={{ flex: 1 }}>Couldn’t load these counts.</span>
      {onRetry && (
        <button className="ui-btn ghost" onClick={onRetry} style={{ height: 21, padding: '0 6px', fontSize: 11 }}>Retry</button>
      )}
    </div>
  );
}

function BucketFacet({ facetKey, facets, buckets, failed, onChange, onRetry, labelOf, empty }: {
  facetKey: Exclude<FacetKey, 'class' | 'findings'>;
  facets: FacetState;
  buckets: { value: string; count: number; label?: string }[];
  failed: boolean;
  onChange: (next: FacetState) => void;
  onRetry?: () => void;
  labelOf?: (v: string) => string;
  empty?: string;
}) {
  const selected = facets[facetKey] as string[];
  // A value the query selects but the current buckets do not contain must still
  // be shown and un-checkable-off, or a filter would become impossible to
  // clear from the rail the moment it narrowed the result set to nothing.
  const view = useMemo(
    () => bucketFacetView(buckets, selected, failed, empty ?? 'Nothing recorded yet.'),
    [buckets, selected, failed, empty],
  );
  const values = useMemo(() => (view.kind === 'empty' ? [] : view.values), [view]);
  const counts = useMemo(() => Object.fromEntries(values.map((b) => [b.value, b.count])), [values]);
  return (
    <Section label={FACET_LABEL[facetKey]} count={selected.length}>
      {view.kind === 'empty' ? (
        <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{view.message}</div>
      ) : (
        <>
          {values.length > 0 && (
            <div style={{ maxHeight: 190, overflowY: 'auto' }}>
              {values.map((b) => (
                <CheckRow
                  key={b.value}
                  value={b.value}
                  // `label` is what the rail shows a person; `value` is what the
                  // query term matches. They differ wherever the stored value is
                  // an id or a path, and the server sends both.
                  label={labelOf ? labelOf(b.value) : (b.label ?? b.value)}
                  count={counts[b.value]}
                  checked={selected.includes(b.value)}
                  onToggle={() => onChange(toggleFacetValue(facets, facetKey, b.value))}
                />
              ))}
            </div>
          )}
          {view.kind === 'failed' && <LevelFailed onRetry={onRetry} />}
        </>
      )}
    </Section>
  );
}

/**
 * The levels the rail asks the server to count, in the server's own names.
 *
 * They are NOT the rail's facet keys: the rail calls them `owner` and
 * `provenance` because that is what a person calls them, and the API calls them
 * `owner_email` and `source` because that is what the columns are. The mapping
 * lives here, once, rather than in each call site.
 */
export const FACET_LEVEL_FOR: Readonly<Record<string, FacetLevel>> = {
  class: 'class',
  status: 'status',
  environment: 'environment',
  site: 'site',
  segment: 'segment',
  owner: 'owner_email',
  business_unit: 'business_unit',
  tag: 'tag',
  risk: 'risk',
  provenance: 'source',
  findings: 'has_findings',
};
export const FACET_LEVELS = Object.values(FACET_LEVEL_FOR);

/** The buckets for one of the rail's facets, looked up by the SERVER's name for
 *  it. */
function bucketsFor(buckets: FacetBuckets | undefined, facetKey: string): { value: string; count: number; label?: string }[] {
  return buckets?.[FACET_LEVEL_FOR[facetKey] ?? facetKey] ?? [];
}

/** Did the level behind one of the rail's facets fail to answer? */
export function levelFailed(data: FacetData | undefined, facetKey: string): boolean {
  return data?.failed.includes(FACET_LEVEL_FOR[facetKey] ?? facetKey) ?? false;
}

export function FacetRail({ facets, data, extra, unparsed = false, onChange, onClear, onRetry }: {
  facets: FacetState;
  data: FacetData | undefined;
  /** Terms only the editor can express, so the rail can say they are there. */
  extra: string[];
  /** The typed query does not parse. The rail cannot preserve text it could not
   *  read, so its controls are disabled rather than silently destructive. */
  unparsed?: boolean;
  onChange: (next: FacetState) => void;
  onClear: () => void;
  /** Re-ask the server for the counts, for a level that did not answer. */
  onRetry?: () => void;
}) {
  const buckets = data?.buckets;
  const classCounts = useMemo(() => bucketMap(bucketsFor(buckets, 'class')), [buckets]);
  // The top level starts open; a selected class opens its ancestry too, so a
  // shared link opens showing WHERE its class sits in the tree rather than
  // hiding the selection inside a collapsed branch.
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set(CLASS_TREE.map((n) => n.key)));

  const selectedClass = facets.class;
  useEffect(() => {
    if (!selectedClass) return;
    setExpanded((prev) => {
      const missing = ancestorsOf(selectedClass).filter((a) => !prev.has(a));
      if (missing.length === 0) return prev;
      const next = new Set(prev);
      for (const a of missing) next.add(a);
      return next;
    });
  }, [selectedClass]);

  const toggleExpand = (key: string) => setExpanded((prev) => {
    const next = new Set(prev);
    if (next.has(key)) next.delete(key); else next.add(key);
    return next;
  });

  const active = facetCount(facets);

  return (
    <aside
      aria-label="Inventory filters"
      style={{ width: 236, flex: 'none', display: 'flex', flexDirection: 'column', minHeight: 0, overflowY: 'auto', borderRight: '1px solid var(--app-border)' }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '11px 12px 9px' }}>
        <Icon name="list-filter" size={14} style={{ color: 'var(--accent)' }} />
        <span style={{ fontSize: 12.5, fontWeight: 700, color: 'var(--app-t1)', flex: 1 }}>Filters</span>
        {active > 0 && (
          <button className="ui-btn ghost" onClick={onClear} style={{ height: 24, padding: '0 7px', fontSize: 11.5 }}>
            <Icon name="x" size={11} />Clear
          </button>
        )}
      </div>

      {extra.length > 0 && !unparsed && (
        // The honest note. A hand-written traversal cannot be shown as a
        // checkbox; saying so is better than dropping it on the next click or
        // pretending the checkboxes describe the whole query.
        <div style={{ margin: '0 12px 9px', padding: '7px 9px', borderRadius: 9, border: '1px solid color-mix(in srgb, var(--accent) 35%, transparent)', background: 'color-mix(in srgb, var(--accent) 8%, transparent)', fontSize: 11.5, color: 'var(--app-t2)' }}>
          <Icon name="info" size={11} style={{ color: 'var(--accent)', marginRight: 5, verticalAlign: -1 }} />
          {extra.length} term{extra.length === 1 ? '' : 's'} in this query {extra.length === 1 ? 'has' : 'have'} no filter control — edit {extra.length === 1 ? 'it' : 'them'} in the query box above. {extra.length === 1 ? 'It is' : 'They are'} kept when you change a filter.
        </div>
      )}

      {unparsed && (
        // The rail cannot preserve text it could not read: `queryToFacets`
        // returns no `extra` for a query that did not parse, so one checkbox
        // click used to overwrite whatever was typed with the rail's own
        // (empty) state. Disabled and explained beats silently destructive.
        <div
          data-testid="facet-rail-unparsed"
          style={{ margin: '0 12px 9px', padding: '7px 9px', borderRadius: 9, border: '1px solid color-mix(in srgb, var(--warn) 40%, transparent)', background: 'color-mix(in srgb, var(--warn) 9%, transparent)', fontSize: 11.5, color: 'var(--app-t2)', lineHeight: 1.5 }}
        >
          <Icon name="alert-triangle" size={11} style={{ color: 'var(--warn-strong)', marginRight: 5, verticalAlign: -1 }} />
          This query doesn’t parse, so the filters are switched off — using one would replace what you typed. Fix the query above to use the facets.
        </div>
      )}

      {/* A disabled fieldset disables every control inside it, which is the one
          way to switch the whole rail off without hiding what it says. */}
      <fieldset disabled={unparsed} style={{ border: 'none', padding: 0, margin: 0, minWidth: 0, opacity: unparsed ? 0.55 : 1 }}>

      <Section label={FACET_LABEL.class} count={facets.class ? 1 : 0}>
        <div style={{ maxHeight: 300, overflowY: 'auto' }}>
          {CLASS_TREE.map((node) => (
            <ClassNode
              key={node.key}
              node={node}
              depth={0}
              counts={classCounts}
              countsFailed={levelFailed(data, 'class')}
              selected={facets.class}
              expanded={expanded}
              onToggleExpand={toggleExpand}
              onPick={(key) => onChange(setFacetClass(facets, key))}
            />
          ))}
        </div>
        {/* The tree itself is the generated registry, so it still renders and
            still filters; only the counts are missing, and a zero beside every
            class would read as "you have none of these". */}
        {levelFailed(data, 'class') && <LevelFailed onRetry={onRetry} />}
      </Section>

      <Section label={FACET_LABEL.risk} count={facets.risk.length}>
        {RISK_BANDS.map((band) => (
          <CheckRow
            key={band}
            value={band}
            label={RISK_BAND_LABEL[band]}
            count={bucketMap(bucketsFor(buckets, 'risk'))[band]}
            checked={facets.risk.includes(band)}
            onToggle={() => onChange(toggleFacetValue(facets, 'risk', band))}
          />
        ))}
        {facets.risk.includes('not_assessed') && (
          <div style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 5, lineHeight: 1.45 }}>
            “Not assessed” is the absence of a score, not a low one — no producer has evaluated these assets.
          </div>
        )}
        {levelFailed(data, 'risk') && <LevelFailed onRetry={onRetry} />}
      </Section>

      <Section label={FACET_LABEL.status} count={facets.status.length}>
        {STATUS_VALUES.map((v) => (
          <CheckRow
            key={v}
            value={v}
            label={STATUS_LABEL[v]}
            count={bucketMap(bucketsFor(buckets, 'status'))[v]}
            checked={facets.status.includes(v)}
            onToggle={() => onChange(toggleFacetValue(facets, 'status', v))}
          />
        ))}
        {levelFailed(data, 'status') && <LevelFailed onRetry={onRetry} />}
      </Section>

      <Section label={FACET_LABEL.provenance} count={facets.provenance.length}>
        {PROVENANCE_VALUES.map((v) => (
          <CheckRow
            key={v}
            value={v}
            label={PROVENANCE_LABEL[v]}
            count={bucketMap(bucketsFor(buckets, 'provenance'))[v]}
            checked={facets.provenance.includes(v)}
            onToggle={() => onChange(toggleFacetValue(facets, 'provenance', v))}
          />
        ))}
        {levelFailed(data, 'provenance') && <LevelFailed onRetry={onRetry} />}
      </Section>

      <BucketFacet facetKey="environment" facets={facets} buckets={bucketsFor(buckets, 'environment')} failed={levelFailed(data, 'environment')} onChange={onChange} onRetry={onRetry} empty="No environment set on any asset." />
      <BucketFacet facetKey="site" facets={facets} buckets={bucketsFor(buckets, 'site')} failed={levelFailed(data, 'site')} onChange={onChange} onRetry={onRetry} empty="No sites recorded." />
      <BucketFacet facetKey="segment" facets={facets} buckets={bucketsFor(buckets, 'segment')} failed={levelFailed(data, 'segment')} onChange={onChange} onRetry={onRetry} empty="No network segments defined." />
      <BucketFacet facetKey="owner" facets={facets} buckets={bucketsFor(buckets, 'owner')} failed={levelFailed(data, 'owner')} onChange={onChange} onRetry={onRetry} empty="No owner recorded." />
      <BucketFacet facetKey="business_unit" facets={facets} buckets={bucketsFor(buckets, 'business_unit')} failed={levelFailed(data, 'business_unit')} onChange={onChange} onRetry={onRetry} empty="No business unit recorded." />
      <BucketFacet facetKey="tag" facets={facets} buckets={bucketsFor(buckets, 'tag')} failed={levelFailed(data, 'tag')} onChange={onChange} onRetry={onRetry} empty="No tags on any asset." />

      {/* Restored at workstream 3.1. The control writes OPEN_FINDINGS and the
          server's has_findings level counts by compiling that same string, so
          the checkbox and its number are one predicate. */}
      <Section label={FACET_LABEL.findings} count={facets.findings === undefined ? 0 : 1}>
        <button
          onClick={() => onChange(cycleFindings(facets))}
          className="ui-btn"
          style={{ width: '100%', height: 28, fontSize: 12, justifyContent: 'flex-start' }}
        >
          <Icon name={facets.findings === true ? 'circle-check' : facets.findings === false ? 'circle-slash' : 'circle-dashed'} size={12} />
          {facets.findings === true ? 'Has open findings' : facets.findings === false ? 'No open findings' : 'Any'}
        </button>
        <div style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 5, lineHeight: 1.45 }}>
          “No open findings” means producers looked and found nothing. For assets nobody has looked at, use Risk → Not assessed.
        </div>
      </Section>

      </fieldset>
    </aside>
  );
}
