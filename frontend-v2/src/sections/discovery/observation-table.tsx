// Discovery → Observations: the review table. One line per observation
// — host and its services, the network's NAME, the source's NAME, when it was
// last seen, what it needs — expanding to all of its evidence beside a plain
// "What this needs". Rows, not cards: the page exists to be scanned.
import { useState, type CSSProperties, type MouseEvent } from 'react';
import { Link } from 'react-router';
import { Icon, Pill } from '../../components/ui';
import { SEGMENTS_SETTINGS_PATH } from '../settings/auto-scan-not-scanned';
import { relTime } from './kit';
import { ObservationActions } from './observation-actions';
import { CollectorReachability, ObservationDetails, enrichmentExplanation } from './observation-details';
import {
  EXPLANATIONS, evidenceEndpoints, hostLabel, isSelectable, linkLabel, needsLabel, networkLabel, observationAddress,
  serviceChips, serviceLabel, stableIdentifierNote, type DecisionAction, type Observation,
} from './observation-review';
import { useObservation, type ObservationListQuery } from './queries';

export type SortKey = NonNullable<ObservationListQuery['sort']>;

/** A row a bulk decision failed on: why, in the row's own words. */
export interface RowFailure { message: string; code?: string; status: number }

const reasons: Record<string, string> = {
  insufficient_identity_evidence: 'Evidence does not yet establish a distinct device.',
  unverified_relayed_advertisement: 'The advertisement could not be tied directly to its originating device.',
  dynamic_address_without_device_binding: 'This changing address has no contemporaneous device binding.',
  network_scope_unresolved: 'The observation could not be placed in a specific network.',
  no_device_or_address_binding: 'A name was observed without a confirmed device or address binding.',
  authoritative_identifier: 'An authoritative source identified this entity.',
  direct_scoped_interface: 'A device interface was directly observed within its network.',
  direct_scoped_address: 'A network entity was directly observed at this address.',
  declared_service: 'An operator declared this service.',
  // D1/D8: promotion is the only step that consumes the tenant's asset
  // allowance, so an exhausted allowance stops the item becoming established
  // WITHOUT throwing the evidence away. Saying both halves is the point.
  asset_allowance_exhausted: 'Direct evidence was found, but the asset allowance is exhausted; the item stays provisional.',
};

/** Decisions apply to these states — the same rule the card list had — and to
 *  supporting evidence whose endpoints were held off its asset (platform
 *  ADR-0003 D2): linking it to that asset is what attaches them. */
const decidable = (o: Pick<Observation, 'state' | 'evidence_held'>) =>
  o.state === 'unresolved' || o.state === 'expired' || o.state === 'dismissed' || (o.state === 'linked' && o.evidence_held);

const visuallyHidden: CSSProperties = {
  position: 'absolute', width: 1, height: 1, padding: 0, margin: -1, overflow: 'hidden', clip: 'rect(0,0,0,0)', whiteSpace: 'nowrap', border: 0,
};
const th: CSSProperties = { textAlign: 'left', padding: '0 12px', height: 'var(--tbl-head-h, 36px)', borderBottom: '1px solid var(--app-border2)', whiteSpace: 'nowrap' };
const td: CSSProperties = { padding: '8px 12px', borderBottom: '1px solid var(--app-border)', verticalAlign: 'top', fontSize: 12.5, color: 'var(--app-t2)' };
const stop = (e: MouseEvent) => e.stopPropagation();
const fullTime = (iso: string) => new Date(iso).toLocaleString();

const needsColor: Record<Observation['needs'], string> = {
  ready_to_confirm: 'var(--ok)',
  link_existing: 'var(--ok)',
  needs_review: 'var(--warn-strong)',
  needs_network: 'var(--info)',
  needs_sensor: 'var(--info)',
  likely_noise: 'var(--app-t3)',
  none: 'var(--app-t2)',
};

function SortHeader({ label, sortKey, sort, onSort }: { label: string; sortKey: 'host' | 'network' | 'needs' | 'last_seen'; sort: SortKey; onSort: (s: SortKey) => void }) {
  const active = sortKey === 'last_seen' ? sort.startsWith('last_seen') : sort === sortKey;
  const ariaSort = !active ? 'none' : sort === 'last_seen_desc' ? 'descending' : 'ascending';
  const next: SortKey = sortKey === 'last_seen' ? (sort === 'last_seen_desc' ? 'last_seen_asc' : 'last_seen_desc') : sortKey;
  return <th scope="col" aria-sort={ariaSort} style={th}>
    <button type="button" className="eyebrow-app" onClick={() => onSort(next)}
      style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: 4, color: active ? 'var(--app-t1)' : undefined }}>
      {label}
      {active && <Icon name={ariaSort === 'descending' ? 'chevron-down' : 'chevron-up'} size={12} />}
    </button>
  </th>;
}

export function ObservationTable({ rows, pinned = [], loading, canDecide, selectable, selected, onToggle, onToggleAll, sort, onSort, failures, expandFirst, skeletonRows = 6 }: {
  rows: Observation[];
  /** Rows a bulk decision failed on that the refreshed page no longer holds. */
  pinned?: Observation[];
  loading: boolean;
  /** The viewer holds assets.update. Without it the table is read-only. */
  canDecide: boolean;
  /** Checkboxes are offered (not in the single-observation view). */
  selectable: boolean;
  selected: ReadonlySet<string>;
  onToggle: (id: string) => void;
  onToggleAll: (ids: string[], on: boolean) => void;
  sort: SortKey;
  onSort: (s: SortKey) => void;
  failures: ReadonlyMap<string, RowFailure>;
  /** Open the first row (the `?observation_id=` view). */
  expandFirst?: boolean;
  skeletonRows?: number;
}) {
  const checkboxes = canDecide && selectable;
  const pageIds = rows.filter(isSelectable).map((r) => r.id);
  const onPage = pageIds.filter((id) => selected.has(id)).length;
  const cols = 5 + (checkboxes ? 1 : 0) + (canDecide ? 1 : 0);
  return <div className="panel" style={{ overflowX: 'auto', borderRadius: 14 }}>
    <table aria-label="Observations" aria-busy={loading} style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--row-fs, 13px)' }}>
      <thead>
        <tr>
          {checkboxes && <th scope="col" style={{ ...th, width: 36 }}>
            <input
              type="checkbox" aria-label="Select every observation on this page"
              disabled={pageIds.length === 0}
              checked={pageIds.length > 0 && onPage === pageIds.length}
              ref={(el) => { if (el) el.indeterminate = onPage > 0 && onPage < pageIds.length; }}
              onChange={(e) => onToggleAll(pageIds, e.target.checked)}
            />
          </th>}
          <SortHeader label="Host" sortKey="host" sort={sort} onSort={onSort} />
          <SortHeader label="Network" sortKey="network" sort={sort} onSort={onSort} />
          <th scope="col" style={th}><span className="eyebrow-app">Source</span></th>
          <SortHeader label="Last seen" sortKey="last_seen" sort={sort} onSort={onSort} />
          <SortHeader label="Needs" sortKey="needs" sort={sort} onSort={onSort} />
          {canDecide && <th scope="col" style={th}><span style={visuallyHidden}>Actions</span></th>}
        </tr>
      </thead>
      <tbody>
        {loading && rows.length === 0
          ? Array.from({ length: skeletonRows }, (_, i) => <tr key={i} data-skeleton aria-hidden="true">
            <td colSpan={cols} style={td}><div style={{ height: 14, borderRadius: 6, background: 'var(--app-panel2)', width: `${60 + ((i * 13) % 35)}%` }} /></td>
          </tr>)
          : <>
            {pinned.map((o) => <ObservationRow key={`pinned-${o.id}`} o={o} canDecide={canDecide} checkboxes={checkboxes} pinned failure={failures.get(o.id)} cols={cols} selected={false} onToggle={onToggle} />)}
            {rows.map((o, i) => <ObservationRow key={o.id} o={o} canDecide={canDecide} checkboxes={checkboxes} failure={failures.get(o.id)} cols={cols}
              selected={selected.has(o.id)} onToggle={onToggle} defaultExpanded={expandFirst && i === 0} />)}
          </>}
      </tbody>
    </table>
  </div>;
}

function ObservationRow({ o, canDecide, checkboxes, selected, onToggle, failure, cols, defaultExpanded = false, pinned = false }: {
  o: Observation; canDecide: boolean; checkboxes: boolean; selected: boolean; onToggle: (id: string) => void;
  failure?: RowFailure; cols: number; defaultExpanded?: boolean; pinned?: boolean;
}) {
  const [expanded, setExpanded] = useState(defaultExpanded);
  // Bumped by the row's Confirm/Dismiss buttons: remounts the decision form
  // opened on that action, with its reason prefilled.
  const [decision, setDecision] = useState<{ action: DecisionAction; n: number } | null>(null);
  const open = (action: DecisionAction) => { setExpanded(true); setDecision((d) => ({ action, n: (d?.n ?? 0) + 1 })); };
  const host = hostLabel(o);
  const chips = serviceChips(o);
  const panelID = `observation-${pinned ? 'pinned-' : ''}${o.id}`;
  return <>
    <tr className="row-hover" data-observation={o.id} onClick={() => setExpanded((e) => !e)} style={{ cursor: 'pointer', background: failure ? 'color-mix(in srgb, var(--danger) 6%, transparent)' : undefined }}>
      {checkboxes && <td style={td} onClick={stop}>
        {!pinned && isSelectable(o) && <input type="checkbox" aria-label={`Select ${host.primary}`} checked={selected} onChange={() => onToggle(o.id)} />}
      </td>}
      <td style={{ ...td, color: 'var(--app-t1)' }}>
        <button
          type="button" aria-expanded={expanded} aria-controls={panelID}
          onClick={(e) => { e.stopPropagation(); setExpanded(!expanded); }}
          style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer', color: 'inherit', font: 'inherit', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 6, textAlign: 'left' }}
        >
          <Icon name={expanded ? 'chevron-down' : 'chevron-right'} size={14} />
          <span>{host.primary}</span>
        </button>
        {host.secondary && <span className="mono" style={{ marginLeft: 8, fontSize: 11.5, color: 'var(--app-t3)' }}>{host.secondary}</span>}
        {chips.length > 0 && <span style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4, paddingLeft: 20 }}>
          {chips.map((c) => <span key={c} className="mono" style={{ fontSize: 11, padding: '1px 6px', borderRadius: 6, border: '1px solid var(--app-border2)', color: 'var(--app-t2)' }}>{c}</span>)}
        </span>}
        {failure && <p data-row-failure style={{ margin: '6px 0 0 20px', color: 'var(--danger-text)', fontSize: 12 }}>{failure.message}</p>}
      </td>
      <td style={td}>{networkLabel(o)}</td>
      <td style={td}>{o.source_name}</td>
      <td style={td}><time dateTime={o.last_seen_at} title={fullTime(o.last_seen_at)}>{relTime(o.last_seen_at)}</time></td>
      <td style={td}><Pill color={o.state === 'unresolved' ? needsColor[o.needs] : 'var(--app-t2)'}>{needsLabel(o)}</Pill></td>
      {canDecide && <td style={{ ...td, whiteSpace: 'nowrap', textAlign: 'right' }} onClick={stop}>
        {!pinned && decidable(o) && <RowActions o={o} open={open} expand={() => setExpanded(true)} />}
      </td>}
    </tr>
    <tr id={panelID} hidden={!expanded}>
      <td colSpan={cols} style={{ ...td, background: 'var(--app-panel2)', padding: '14px 20px' }}>
        {expanded && <ObservationExpanded o={o} decision={decision} />}
      </td>
    </tr>
  </>;
}

/** The collapsed row's primary action (from the server's suggestion) and Dismiss. */
function RowActions({ o, open, expand }: { o: Observation; open: (a: DecisionAction) => void; expand: () => void }) {
  const unresolved = o.state === 'unresolved';
  const primary = !unresolved ? null
    : o.suggested_action === 'confirm' ? <button type="button" className="ui-btn sm accent" onClick={() => open('confirm')}>Confirm…</button>
    : o.suggested_action === 'link' ? <button type="button" className="ui-btn sm accent" onClick={() => open('link')}>{linkLabel(o)}…</button>
    : o.suggested_action === 'add_network' ? <Link className="ui-btn sm" to={SEGMENTS_SETTINGS_PATH}>Add network</Link>
    : o.suggested_action === 'sensor_options' ? <button type="button" className="ui-btn sm" onClick={expand}>See options</button>
    : null;
  if (o.state === 'linked' && o.evidence_held) {
    // Supporting evidence: already on its asset, its endpoints are not. The
    // one decision left is attaching them.
    return <button type="button" className="ui-btn sm" onClick={() => open('link')}>Attach endpoints…</button>;
  }
  return <span style={{ display: 'inline-flex', gap: 6 }}>
    {primary}
    {o.state !== 'dismissed' && <button type="button" className="ui-btn sm" onClick={() => open('dismiss')}>Dismiss…</button>}
  </span>;
}

function ObservationExpanded({ o: listed, decision }: { o: Observation; decision: { action: DecisionAction; n: number } | null }) {
  // The list row already carries everything the evidence column shows; the
  // detail read adds enrichment attempts and retained evidence.
  const detail = useObservation(listed.id);
  const o = detail.data ?? listed;
  const endpoints = evidenceEndpoints(o);
  const explanation = EXPLANATIONS[o.explanation_code];
  const stable = o.explanation_code === 'dynamic_address_answered' ? stableIdentifierNote(o) : null;
  const address = observationAddress(o);
  return <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 24, color: 'var(--app-t1)' }}>
    <section aria-label="Evidence">
      <h4 style={{ margin: '0 0 8px', fontSize: 13 }}>Evidence</h4>
      <dl style={{ display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: '4px 12px', margin: 0, fontSize: 12 }}>
        {o.summary.map((s, i) => <div key={`${s.kind}:${i}`} style={{ display: 'contents' }}><dt style={{ color: 'var(--app-t3)' }}>{s.label}</dt><dd style={{ margin: 0, overflowWrap: 'anywhere' }} className="mono">{s.value}</dd></div>)}
        {o.summary.length === 0 && <><dt style={{ color: 'var(--app-t3)' }}>Identifiers</dt><dd style={{ margin: 0 }}>No usable identifiers recorded.</dd></>}
        <dt style={{ color: 'var(--app-t3)' }}>Network</dt><dd style={{ margin: 0 }}>{networkLabel(o)}</dd>
        <dt style={{ color: 'var(--app-t3)' }}>Source</dt><dd style={{ margin: 0 }}>{o.source_name}{o.collector_version ? ` · ${o.collector_version}` : ''}</dd>
        <dt style={{ color: 'var(--app-t3)' }}>First observed</dt><dd style={{ margin: 0 }}>{fullTime(o.first_seen_at)}</dd>
        <dt style={{ color: 'var(--app-t3)' }}>Last observed</dt><dd style={{ margin: 0 }}>{fullTime(o.last_seen_at)} · {o.occurrence_count} sighting{o.occurrence_count === 1 ? '' : 's'}</dd>
        <dt style={{ color: 'var(--app-t3)' }}>Enrichment</dt><dd style={{ margin: 0 }}>{o.enrichment_state}{o.enrichment_reason ? ` — ${enrichmentExplanation(o.enrichment_reason)}` : ''}</dd>
      </dl>
      <h5 style={{ margin: '12px 0 4px', fontSize: 12 }}>Endpoints</h5>
      {endpoints.length === 0 ? <p style={{ margin: 0, fontSize: 12 }}>No endpoints were seen.</p>
        : <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12 }}>{endpoints.map((e, i) => <li key={i} className="mono">
          {e.address || e.fqdn || 'No address'}{e.port > 0 ? `:${e.port}` : ''} · {serviceLabel(e)}{e.transport ? ` · ${e.transport}` : ''}{e.service ? ` · ${e.service}` : ''}
        </li>)}</ul>}
      {o.collector && <CollectorReachability collector={o.collector} />}
      {/* A provisional item and a linked asset are the same kind of link to two
          different things, so only one is shown. `unresolved` WITH an asset is
          exactly the provisional shape (#1898 D2): the observation keeps working
          — enrichment still runs on it — while the asset it created waits for
          something to corroborate it. */}
      {o.asset_id && (o.state === 'unresolved'
        ? <p style={{ fontSize: 12 }}>Provisional inventory item: <Link to={`/inventory/assets/${o.asset_id}`}>Open provisional item</Link></p>
        : <p style={{ fontSize: 12 }}><Link to={`/inventory/assets/${o.asset_id}`}>Open linked asset</Link></p>)}
      {o.proposal_id && <p style={{ fontSize: 12 }}><Link to="/discovery/approvals">Review identity conflict</Link></p>}
      {detail.isPending && <p role="status" style={{ fontSize: 12 }}>Loading details…</p>}
      {detail.isError && <p role="alert" style={{ fontSize: 12 }}>Couldn’t load details. <button type="button" className="ui-btn sm" onClick={() => { void detail.refetch(); }}>Retry</button></p>}
      {detail.data && <ObservationDetails observation={detail.data} />}
    </section>
    <section aria-label="What this needs">
      <h4 style={{ margin: '0 0 8px', fontSize: 13 }}>What this needs</h4>
      <p style={{ margin: '0 0 6px', fontSize: 12.5 }}>{explanation.why}</p>
      {explanation.fix && <p style={{ margin: '0 0 6px', fontSize: 12.5 }}>{explanation.fix}</p>}
      {stable && <p style={{ margin: '0 0 6px', fontSize: 12.5 }}>{stable}</p>}
      {o.needs === 'needs_network' && <p style={{ fontSize: 12.5 }}>
        <Link to={SEGMENTS_SETTINGS_PATH}>Add a network segment</Link>{address ? <> that covers <span className="mono">{address}</span></> : null} in Settings → Network Segments.
      </p>}
      {o.needs === 'needs_sensor' && <p style={{ fontSize: 12.5 }}>
        <Link to="/discovery/sensors">Install a sensor on that network</Link> from Sensors &amp; Agents — or link this to an asset you already have, or dismiss it.
      </p>}
      {/* D2: a plain shortcut to the network's addressing setting and nothing
          else. No review date, no reminder, no expiry: the owner ruled those
          out, because networks do not change like that and every asset is
          already re-checked daily. */}
      {o.explanation_code === 'dynamic_address_answered' && <p style={{ fontSize: 12.5 }}>
        <Link to={SEGMENTS_SETTINGS_PATH}>Treat this network as stable…</Link>{' '}
        If addresses on {o.network_name ? <strong>{o.network_name}</strong> : 'this network'} do not move, set its DHCP to off in Network Segments. Future scans can then create and approve assets there directly, because an address does identify a device where addresses do not move.
      </p>}
      {o.admission_reasons.length > 0 && <>
        <h5 style={{ margin: '12px 0 4px', fontSize: 12 }}>Why it was kept</h5>
        <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12 }}>{o.admission_reasons.map((r) => <li key={r}>{reasons[r] ?? r.replace(/_/g, ' ')}</li>)}</ul>
      </>}
      {decidable(o) && <ObservationActions key={decision?.n ?? 0} id={o.id} observation={o} initialAction={decision?.action ?? null} />}
    </section>
  </div>;
}
