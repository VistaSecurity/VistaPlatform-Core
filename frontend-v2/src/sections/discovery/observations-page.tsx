import { useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { PROVISIONAL_INVENTORY_HREF } from '../inventory/facet-query';
import { ObservationActions } from './observation-actions';
import { CollectorReachability, ObservationDetails, enrichmentExplanation } from './observation-details';

type Observation = inventoryComponents['schemas']['IdentityObservation'];
type State = Observation['state'] | 'all';
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

export function IdentityCoverage() {
  const q = useQuery({ queryKey: ['identity-summary'], queryFn: async () => {
    const { data, response } = await clients.inventory.GET('/identity/summary');
    if (!response.ok || !data) throw new Error('Unable to load identity coverage');
    return data;
  }});
  if (q.isPending) return <p role="status">Loading identity coverage…</p>;
  if (q.isError) return <p role="alert">Identity coverage unavailable. <button className="ui-btn sm" onClick={() => { void q.refetch(); }}>Retry</button></p>;
  const d = q.data;
  return <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', padding: '10px 26px', fontSize: 12 }}>
    <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
      <strong>Monitored inventory:</strong>
      <span>{d.established} established</span><span>{d.operator_confirmed} operator-confirmed</span>
      <span title="These records have not had their identity established by the evidence checks. This does not describe their age or security posture.">{d.legacy} not evaluated</span>
    </div>
    {d.admission_mode === 'disabled' && <span>Identity assessment is not activated. <Link to="/settings/sensor-config">Configure discovery</Link></span>}
    {d.admission_mode === 'observe' && <span>Identity assessment is observing evidence; inventory identities are not being established.</span>}
    {d.admission_mode === 'paused' && <span>Identity assessment and enrichment are paused.</span>}
    <Link to="/discovery/observations">{d.unresolved} unresolved observations</Link>
    <Link to="/discovery/approvals">{d.conflicted} assets with identity conflicts</Link>
    {/* The inventory page's ONE filter is the query string (`?query=`), which is
        what the facet rail writes and what a saved view stores. The predicate
        itself is derived from the rail's own writer — see
        PROVISIONAL_INVENTORY_HREF for why a bare `identity_status:provisional`
        would land on an empty list. */}
    <Link to={PROVISIONAL_INVENTORY_HREF}>{d.provisional} provisional items</Link>
  </div>;
}

function ObservationEvidence({ observation: o, detail }: { observation: Observation; detail: boolean }) {
  const raw = o.evidence.identifiers;
  const identifiers = Array.isArray(raw) ? raw.filter((v): v is Record<string, unknown> => typeof v === 'object' && v !== null) : [];
  const name = identifiers.find((i) => i.kind === 'hostname' || i.kind === 'fqdn')?.value;
  return <article style={{ padding: 16, borderBottom: '1px solid var(--app-border)' }}>
    <h3 style={{ fontSize: 14, margin: '0 0 8px' }}>{typeof name === 'string' ? name : 'Device observation'} <small>· {o.state}</small></h3>
    {o.admission_reasons.map((r) => <p key={r}>{reasons[r] ?? r.replace(/_/g, ' ')}</p>)}
    <dl style={{ fontSize: 12 }}>
      <dt>Source</dt><dd>{o.source_ref} · {o.source_kind}{o.collector_version ? ` · ${o.collector_version}` : ''}</dd>
      <dt>Network</dt><dd>{o.network_scope || 'Not established'}</dd>
      <dt>First observed</dt><dd>{new Date(o.first_seen_at).toLocaleString()}</dd>
      <dt>Last observed</dt><dd>{new Date(o.last_seen_at).toLocaleString()} · {o.occurrence_count} sighting{o.occurrence_count === 1 ? '' : 's'}</dd>
      <dt>Enrichment</dt><dd>{o.enrichment_state}{o.enrichment_reason ? ` — ${enrichmentExplanation(o.enrichment_reason)}` : ''}</dd>
    </dl>
    {o.collector && <CollectorReachability collector={o.collector} />}
    <details><summary>Observed identifiers</summary>
      {identifiers.length === 0 ? <p>No usable identifiers recorded.</p> : <ul>{identifiers.map((i, n) => <li key={n}>{String(i.kind ?? '')}: {String(i.value ?? '')}{i.scope ? ` (${String(i.scope)})` : ''}</li>)}</ul>}
    </details>
    {!detail && <p><Link to={`/discovery/observations?observation_id=${o.id}`}>Open observation details</Link></p>}
    {detail && <ObservationDetails observation={o} />}
    {/* A provisional item and a linked asset are the same kind of link to two
        different things, so only one is shown. `unresolved` WITH an asset is
        exactly the provisional shape (#1898 D2): the observation keeps working
        — enrichment still runs on it — while the asset it created waits for
        something to corroborate it. */}
    {o.asset_id && (o.state === 'unresolved'
      ? <p>Provisional inventory item: <Link to={`/inventory/assets/${o.asset_id}`}>Open provisional item</Link></p>
      : <Link to={`/inventory/assets/${o.asset_id}`}>Open linked asset</Link>)}
    {o.proposal_id && <Link to="/discovery/approvals">Review identity conflict</Link>}
    {(o.state === 'unresolved' || o.state === 'expired' || o.state === 'dismissed') && <ObservationActions id={o.id} />}
  </article>;
}

export function ObservationsPage() {
  const [params] = useSearchParams();
  const assetID = params.get('asset_id') ?? undefined;
  const observationID = params.get('observation_id') ?? undefined;
  const [state, setState] = useState<State>(assetID ? 'all' : 'unresolved');
  const [page, setPage] = useState(1);
  const q = useQuery({ queryKey: ['identity-observations', state, page, assetID, observationID], queryFn: async () => {
    if (observationID) {
      const { data, response } = await clients.inventory.GET('/discovery/observations/{id}', { params: { path: { id: observationID } } });
      if (!response.ok || !data) throw new Error('Unable to load observation');
      return { observations: [data], total: 1 };
    }
    const { data, response } = await clients.inventory.GET('/discovery/observations', { params: { query: { state, page, page_size: 50, asset_id: assetID } } });
    if (!response.ok || !data) throw new Error('Unable to load observations');
    return data;
  }});
  return <section style={{ padding: 26 }}>
    <h1>Discovery observations</h1>
    {observationID && <p>Identity evidence was retained for resolution. <Link to="/discovery/observations">View all observations</Link></p>}
    {assetID && <p>Showing evidence linked to this asset. <Link to={`/inventory/assets/${assetID}`}>Back to asset</Link></p>}
    <p>Evidence awaiting identification is retained here. An observation is not necessarily a distinct device.</p>
    <IdentityCoverage />
    {!observationID && <label>Show <select className="ui-input" style={{ width: 200 }} aria-label="Observation state" value={state} onChange={(e) => { setState(e.target.value as State); setPage(1); }}>
      {(['unresolved', 'conflict', 'linked', 'dismissed', 'expired', 'all'] as const).map((s) => <option key={s} value={s}>{s}</option>)}
    </select></label>}
    {q.isPending && <p role="status">Loading observations…</p>}
    {q.isError && <p role="alert">Unable to load observations. <button className="ui-btn" onClick={() => { void q.refetch(); }}>Retry</button></p>}
    {q.data && <>
      {q.data.observations.length === 0 ? <p>No observations in this view. Unresolved observations leave the active view after 30 days without a sighting.</p> : q.data.observations.map((o) => <ObservationEvidence key={o.id} observation={o} detail={!!observationID} />)}
      {!observationID && <div style={{ display: 'flex', gap: 12, marginTop: 16 }}>
        <button className="ui-btn" disabled={page === 1} onClick={() => setPage(page - 1)}>Previous</button>
        <span>Page {page} · {q.data.total} observations</span>
        <button className="ui-btn" disabled={page * 50 >= q.data.total} onClick={() => setPage(page + 1)}>Next</button>
      </div>}
    </>}
  </section>;
}
