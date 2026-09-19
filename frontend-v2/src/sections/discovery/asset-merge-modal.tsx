import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { Modal, ModalField, ModalSelect } from '../../components/ui';
import { clients } from '../../lib/clients';
import { errorMessage, useAssetsQuery, type MergeCandidate, type MergeProposal } from '../inventory/asset-queries';
import { candidateName } from './merge-proposal-row';

type Preview = inventoryComponents['schemas']['AssetMergePreview'];
type Selection = inventoryComponents['schemas']['AssetMergeSelection'];

export function mergeChoices(proposal: MergeProposal): MergeCandidate[] {
  const choices = [...(proposal.observation ? [proposal.observation] : []), ...proposal.candidates];
  return choices.filter((c, index) => !c.deleted && c.asset_status !== 'archived' && c.asset_status !== 'denied' && choices.findIndex((other) => other.asset_id === c.asset_id) === index);
}
function displayValue(value: unknown): string {
  if (value == null || value === '') return 'Not set';
  return typeof value === 'string' ? value : JSON.stringify(value);
}
function fieldLabel(field: string): string { return field.replace(/_/g, ' '); }

const childLabels: Record<string, string> = {
  asset_endpoints: 'Network endpoints', asset_identifiers: 'Identity identifiers', asset_management: 'Management connections',
  asset_credentials: 'Credential references', asset_facts: 'Collected facts', asset_history: 'Audit history',
  software_installs: 'Software installations', producer_assessments: 'Assessment coverage', asset_relationships: 'Relationships',
  crypto_implementations: 'Crypto configurations', crypto_implementation_certificates: 'Certificate attachments',
  crypto_implementation_algorithms: 'Algorithm assessments', implementation_keys: 'Key attachments', implementation_libraries: 'Library attachments',
  identity_observations: 'Discovery observations', identity_observation_payloads: 'Retained discovery evidence',
  identity_observation_receipts: 'Observation deliveries', identity_observation_management: 'Retained management details',
  identity_observation_host_inventories: 'Retained host inventories', asset_merge_management_history: 'Historical management profiles',
  sensor_discoveries: 'Discovery results', sensors: 'Sensors and agents', tickets: 'Tickets', external_connections: 'Observed connections',
};
function record(value: unknown): Record<string, unknown> { return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}; }
function EvidenceSummary({ evidence }: { evidence: Preview['evidence'] }) {
  if (!evidence.length) return <p>No additional proposal evidence was recorded.</p>;
  return <ul>{evidence.map((entry, index) => {
    const candidates = Array.isArray(entry.candidates) ? entry.candidates.map(record) : [];
    return <li key={index}>
      <p>{typeof entry.reason === 'string' ? entry.reason : 'Identity reconciliation question'}<br />
        Source: {displayValue(entry.source_kind ?? entry.source)} · Proposed: {displayValue(entry.proposed_at)}
      </p>
      {candidates.map((candidate, i) => {
        const identifiers = Array.isArray(candidate.matched_identifiers) ? candidate.matched_identifiers.map(record) : [];
        return <div key={i}><strong>{displayValue(candidate.display_name ?? candidate.hostname ?? candidate.asset_id)}</strong>
          <ul>{identifiers.map((identifier, j) => <li key={j}>{fieldLabel(String(identifier.kind ?? 'identifier'))}: {displayValue(identifier.value)}{identifier.scope ? ` · scope ${displayValue(identifier.scope)}` : ''}</li>)}</ul>
        </div>;
      })}
    </li>;
  })}</ul>;
}

/** Selection and preview are separate steps; neither similarity nor a group
 * membership selects sources on the operator's behalf. */
export function AssetMergeModal({ proposal, initialAssets = [], onClose }: { proposal?: MergeProposal; initialAssets?: MergeCandidate[]; onClose: () => void }) {
  const cache = useQueryClient();
  const [added, setAdded] = useState<MergeCandidate[]>(initialAssets);
  const [search, setSearch] = useState('');
  const [searchPage, setSearchPage] = useState(1);
  const [addID, setAddID] = useState('');
  const matches = useAssetsQuery(`(status:monitoring OR status:pending_approval)${search.trim() ? ` AND ${JSON.stringify(search.trim())}` : ''}`, searchPage, !proposal);
  const choices = proposal ? mergeChoices(proposal) : added;
  const [survivor, setSurvivor] = useState('');
  const [sources, setSources] = useState<string[]>([]);
  const [resolutions, setResolutions] = useState<Record<string, string>>({});
  const [reason, setReason] = useState('');
  const [preview, setPreview] = useState<Preview>();
  const [previewKey, setPreviewKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [stale, setStale] = useState(false);
  const selection: Selection = { source_asset_ids: sources, survivor_asset_id: survivor, field_resolutions: resolutions };
  const key = JSON.stringify(selection);
  const selectionValid = !!survivor && sources.length > 0 && sources.length <= 20 && !sources.includes(survivor);
  const current = !!preview && previewKey === key && !stale;
  const unresolved = preview?.conflicts.some((conflict) => conflict.requires_resolution && !resolutions[conflict.field]);
  const name = (id: string) => {
    const currentAsset = preview?.assets.find((a) => a.asset_id === id);
    if (currentAsset) return currentAsset.display_name || currentAsset.hostname || id;
    const asset = choices.find((c) => c.asset_id === id);
    return asset ? candidateName(asset) : id;
  };

  async function loadPreview() {
    setBusy(true); setError(''); setStale(true);
    try {
      const { data, error: failure } = proposal ? await clients.inventory.POST('/approvals/merge-proposals/{id}/preview', {
        params: { path: { id: proposal.id } }, body: selection,
      }) : await clients.inventory.POST('/infrastructure-assets/merge/preview', { body: selection });
      if (failure || !data?.preview) throw new Error(errorMessage(failure) ?? 'Could not load the merge preview.');
      setPreview(data.preview); setPreviewKey(key); setStale(false);
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not load the merge preview.'); }
    finally { setBusy(false); }
  }
  async function merge() {
    if (!preview || !current || unresolved || reason.trim().length < 3) return;
    setBusy(true); setError('');
    try {
      const body = { ...selection, revision: preview.revision, reason: reason.trim() };
      const { error: failure, response } = proposal ? await clients.inventory.POST('/approvals/merge-proposals/{id}/merge', {
        params: { path: { id: proposal.id } }, body,
      }) : await clients.inventory.POST('/infrastructure-assets/merge', { body });
      if (response.status === 409) {
        setStale(true); setError('The assets or evidence changed. Refresh the preview and review it before merging.'); return;
      }
      if (failure) throw new Error(errorMessage(failure) ?? 'Could not merge the selected assets.');
      // A merge changes asset children, findings, topology and dashboard totals.
      // Invalidate all read models so an already-open detail panel cannot keep
      // showing associations on the archived source.
      await cache.invalidateQueries();
      onClose();
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not merge the selected assets.'); }
    finally { setBusy(false); }
  }
  function changeSelection(nextSurvivor: string, nextSources: string[]) {
    setSurvivor(nextSurvivor); setSources(nextSources); setResolutions({}); setPreview(undefined); setError('');
  }
  return (
    <Modal open onClose={onClose} dismissible={!busy} size="lg" icon="git-merge" eyebrow="Identity decision" title="Review asset merge"
      description="Choose exactly which records represent the same asset. The surviving asset keeps its identity."
      footerNote="Merged records remain in audit history with a link to the survivor. Merge undo is not available."
      primary={<button className="ui-btn accent" disabled={busy || !current || !!unresolved || reason.trim().length < 3} onClick={() => { void merge(); }}>Merge selected assets</button>}
      secondary={<button className="ui-btn" disabled={busy} onClick={onClose}>Cancel</button>}>
      <fieldset disabled={busy} style={{ border: 0, padding: 0, margin: 0 }}>
        {!proposal && <div style={{ marginBottom: 14 }}>
          <ModalField label="Find another asset"><input className="ui-input" aria-label="Find another asset" value={search} onChange={(e) => { setSearch(e.target.value); setSearchPage(1); setAddID(''); }} /></ModalField>
          {matches.isError && <p role="alert">Could not load assets. <button onClick={() => { void matches.refetch(); }}>Retry</button></p>}
          {matches.isPending && <p role="status">Loading assets…</p>}
          <ModalSelect aria-label="Asset to add" value={addID} onChange={(e) => setAddID(e.target.value)}>
            <option value="">Choose another record to compare</option>
            {matches.data?.assets.filter((a) => !choices.some((c) => c.asset_id === a.id)).map((a) => <option key={a.id} value={a.id}>{a.display_name || a.hostname || a.id} · {a.id.slice(0, 8)}</option>)}
          </ModalSelect>
          <button className="ui-btn sm" disabled={!addID || added.length >= 21} onClick={() => {
            const a = matches.data?.assets.find((entry) => entry.id === addID);
            if (a) setAdded((previous) => [...previous, { asset_id: a.id, display_name: a.display_name, hostname: a.hostname, class_key: a.class_key, asset_status: a.asset_status, score: 0, deleted: false, matched_identifiers: [] }]);
            setAddID('');
          }}>Add record</button>
          <button className="ui-btn sm" disabled={searchPage <= 1} onClick={() => { setSearchPage(searchPage - 1); setAddID(''); }}>Previous</button>
          <span> Page {searchPage} </span>
          <button className="ui-btn sm" disabled={!matches.data || searchPage * matches.data.pageSize >= matches.data.total} onClick={() => { setSearchPage(searchPage + 1); setAddID(''); }}>Next</button>
        </div>}
        <ModalField label="Surviving asset">
          <ModalSelect aria-label="Surviving asset" value={survivor} onChange={(e) => changeSelection(e.target.value, sources.filter((id) => id !== e.target.value))}>
            <option value="">Choose the record to keep</option>
            {choices.map((c) => <option key={c.asset_id} value={c.asset_id}>{candidateName(c)} · {c.asset_id.slice(0, 8)}</option>)}
          </ModalSelect>
        </ModalField>
        <fieldset style={{ border: '1px solid var(--app-border2)', borderRadius: 8, marginBottom: 12 }}>
          <legend>Records to merge into the survivor</legend>
          {choices.filter((c) => c.asset_id !== survivor).map((c) => (
            <label key={c.asset_id} style={{ display: 'block', padding: 5 }}>
              <input type="checkbox" checked={sources.includes(c.asset_id)} aria-label={`Merge ${candidateName(c)}`} onChange={(e) => changeSelection(survivor, e.target.checked ? [...sources, c.asset_id] : sources.filter((id) => id !== c.asset_id))} />{' '}
              {candidateName(c)} <span className="mono">{c.asset_id.slice(0, 8)}</span>
            </label>
          ))}
        </fieldset>
        <button className="ui-btn" disabled={!selectionValid || busy} onClick={() => { void loadPreview(); }}>{preview ? 'Refresh preview' : 'Preview selected merge'}</button>
        {error && <p role="alert" style={{ color: 'var(--danger-text)' }}>{error}</p>}
        {busy && <p role="status">Checking the selected assets…</p>}
        {preview && <div style={{ marginTop: 14 }}>
          {!current && <p role="status">Review a refreshed preview before merging.</p>}
          <p><strong>{name(preview.survivor_asset_id)}</strong> survives. {preview.source_asset_ids.map(name).join(', ')} will be archived with redirects.</p>
          <p>Populated survivor fields are preserved unless you select another value. Missing fields are filled from compatible evidence.</p>
          {preview.conflicts.map((conflict) => (
            <ModalField key={conflict.field} label={fieldLabel(conflict.field)} hint={conflict.requires_resolution ? 'Conflicting declared values require an explicit choice.' : 'Choose another value only if it should replace the default.'}>
              <ModalSelect aria-label={`Resolve ${fieldLabel(conflict.field)}`} value={resolutions[conflict.field] ?? ''} onChange={(e) => setResolutions((previous) => {
                const next = { ...previous }; if (e.target.value) next[conflict.field] = e.target.value; else delete next[conflict.field]; return next;
              })}>
                <option value="">{conflict.requires_resolution ? 'Choose a value' : 'Keep the proposed value'}</option>
                {conflict.values.map((v) => <option key={v.asset_id} value={v.asset_id}>{name(v.asset_id)}: {displayValue(v.value)}{v.declared ? ' (declared)' : ''}</option>)}
              </ModalSelect>
            </ModalField>
          ))}
          <details><summary>Resulting fields</summary><dl>{Object.entries(preview.selected_fields).map(([field, value]) => <div key={field}><dt>{fieldLabel(field)}</dt><dd>{displayValue(value)}</dd></div>)}</dl></details>
          <details><summary>Affected records</summary><ul>{preview.children.filter((c) => c.count > 0).map((c) => <li key={c.table}>{childLabels[c.table] ?? fieldLabel(c.table)}: {c.count}</li>)}</ul></details>
          <details><summary>Current identity evidence</summary><EvidenceSummary evidence={preview.evidence} /></details>
        </div>}
        <ModalField label="Reason for merging" hint="Recorded with your identity and field choices in the merge history.">
          <textarea className="ui-input" aria-label="Reason for merging" maxLength={2000} value={reason} onChange={(e) => setReason(e.target.value)} rows={3} style={{ width: '100%' }} />
        </ModalField>
      </fieldset>
    </Modal>
  );
}
