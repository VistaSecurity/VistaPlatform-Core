import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { useAssetsQuery } from '../inventory/asset-queries';
import { assetIdentity, primaryAddressPort } from '../inventory/asset-shape';

type Action = 'confirm' | 'link' | 'dismiss';

export function ObservationActions({ id }: { id: string }) {
  return <PermissionGate permission={TENANT_PERMISSIONS.assets.update}><DecisionForm id={id} /></PermissionGate>;
}

function DecisionForm({ id }: { id: string }) {
  const [action, setAction] = useState<Action | null>(null);
  const [reason, setReason] = useState('');
  const [name, setName] = useState('');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [assetID, setAssetID] = useState('');
  const cache = useQueryClient();
  const candidates = useAssetsQuery(`(status:monitoring OR status:pending_approval)${search.trim() ? ` AND ${JSON.stringify(search.trim())}` : ''}`, page, action === 'link');
  const mutation = useMutation({ mutationFn: async () => {
    const body = { reason: reason.trim(), ...(name.trim() ? { name: name.trim() } : {}), ...(assetID ? { asset_id: assetID } : {}) };
    const params = { path: { id } };
    const result = action === 'confirm' ? await clients.inventory.POST('/discovery/observations/{id}/confirm', { params, body })
      : action === 'link' ? await clients.inventory.POST('/discovery/observations/{id}/link', { params, body: { ...body, asset_id: assetID } })
      : await clients.inventory.POST('/discovery/observations/{id}/dismiss', { params, body });
    if (!result.response.ok) {
      throw new Error(result.response.status === 409 ? 'This observation changed or has conflicting ownership. Refresh it and review the current evidence.'
        : result.response.status === 402 ? 'The asset allowance has been reached. This observation is still saved; you can link it to an existing asset.'
        : 'The decision could not be saved. Try again.');
    }
  }, onSuccess: async () => {
    setAction(null); setReason('');
    await Promise.all([
      cache.invalidateQueries({ queryKey: ['identity-observations'] }),
      cache.invalidateQueries({ queryKey: ['identity-summary'] }),
      cache.invalidateQueries({ queryKey: ['inventory'] }),
      cache.invalidateQueries({ queryKey: ['discovery', 'pending-assets'] }),
    ]);
  }});
  if (!action) return <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
    <button className="ui-btn sm" onClick={() => setAction('confirm')}>Confirm identity</button>
    <button className="ui-btn sm" onClick={() => setAction('link')}>Link to an asset</button>
    <button className="ui-btn sm" onClick={() => setAction('dismiss')}>Dismiss</button>
  </div>;
  return <form style={{ marginTop: 12, display: 'grid', gap: 10, maxWidth: 600 }} onSubmit={(e) => { e.preventDefault(); mutation.mutate(); }}>
    <p>{action === 'confirm' ? 'Confirm that this evidence represents a distinct asset. The asset will still require monitoring approval.' : action === 'link' ? 'Select the existing asset this evidence belongs to. Its monitoring approval and observation time will be preserved.' : 'Remove this observation from active work. This does not mean it represents a different device.'}</p>
    {action === 'confirm' && <label>Display name (optional)<input className="ui-input" value={name} maxLength={255} onChange={(e) => setName(e.target.value)} /></label>}
    {action === 'link' && <>
      <label>Find an asset<input className="ui-input" value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); setAssetID(''); }} /></label>
      {candidates.isError && <p role="alert">Unable to load assets. <button type="button" onClick={() => { void candidates.refetch(); }}>Retry</button></p>}
      {candidates.isPending && <p role="status">Loading assets…</p>}
      <label>Asset<select className="ui-input" value={assetID} required onChange={(e) => setAssetID(e.target.value)}>
        <option value="">Choose an asset</option>
        {candidates.data?.assets.map((asset) => <option key={asset.id} value={asset.id}>{assetIdentity(asset).primary} · {primaryAddressPort(asset) || 'No address'} · {asset.id.slice(0, 8)}</option>)}
      </select></label>
      <div><button type="button" disabled={page === 1} onClick={() => { setPage(page - 1); setAssetID(''); }}>Previous</button> Page {page} <button type="button" disabled={!candidates.data || page * candidates.data.pageSize >= candidates.data.total} onClick={() => { setPage(page + 1); setAssetID(''); }}>Next</button></div>
    </>}
    <label>Reason<textarea className="ui-input" value={reason} required maxLength={2000} onChange={(e) => setReason(e.target.value)} /></label>
    {mutation.isError && <p role="alert">{mutation.error.message} <button type="button" onClick={() => { void cache.invalidateQueries({ queryKey: ['identity-observations'] }); }}>Refresh evidence</button></p>}
    <div style={{ display: 'flex', gap: 8 }}>
      <button className="ui-btn" type="submit" disabled={mutation.isPending || !reason.trim() || (action === 'link' && !assetID)}>{mutation.isPending ? 'Saving…' : 'Save decision'}</button>
      <button className="ui-btn" type="button" disabled={mutation.isPending} onClick={() => { setAction(null); mutation.reset(); }}>Cancel</button>
    </div>
  </form>;
}
