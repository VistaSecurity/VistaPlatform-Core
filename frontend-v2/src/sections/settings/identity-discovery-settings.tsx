import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { SCard, SSection } from './kit';

type Settings = inventoryComponents['schemas']['IdentityDiscoverySettings'];
type Update = inventoryComponents['schemas']['IdentityDiscoverySettingsUpdate'];
const key = ['settings', 'identity-discovery'];
const modes: Record<Settings['mode'], string> = {
  disabled: 'Not activated', observe: 'Observe evidence', enforce: 'Identify before adding to Inventory', paused: 'Paused — retain incoming evidence',
};
const lines = (value: string) => [...new Set(value.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean))];
async function readSettings() {
  const { data, response } = await clients.inventory.GET('/settings/identity-discovery');
  if (!response.ok || !data) throw new Error('Unable to load identity discovery settings.');
  return data;
}

export function IdentityDiscoverySettings() {
  const query = useQuery({ queryKey: key, queryFn: readSettings });
  return <SSection title="Trustworthy discovery" desc="Keep unresolved evidence in Discovery until it identifies an asset. Identity, monitoring approval, device type, and assessment remain separate decisions.">
    <SCard>
      {query.isPending && <p role="status">Loading identity discovery settings…</p>}
      {query.isError && <p role="alert">Unable to load identity discovery settings. <button className="ui-btn sm" onClick={() => { void query.refetch(); }}>Retry settings</button></p>}
      {query.data && <IdentityDiscoveryForm current={query.data} />}
    </SCard>
  </SSection>;
}

function IdentityDiscoveryForm({ current }: { current: Settings }) {
  const cache = useQueryClient();
  const [settings, setSettings] = useState(current);
  const [mode, setMode] = useState(settings.mode);
  const [enabled, setEnabled] = useState(settings.enrichment.enabled);
  const [excluded, setExcluded] = useState(settings.enrichment.excluded_cidrs.join('\n'));
  const [sensitive, setSensitive] = useState(settings.enrichment.sensitive_asset_ids.join('\n'));
  const [reason, setReason] = useState('');
  const [writeStale, setStale] = useState(false);
  const stale = writeStale || current.version > settings.version;
  function reset(data: Settings) {
    setSettings(data); setMode(data.mode); setEnabled(data.enrichment.enabled);
    setExcluded(data.enrichment.excluded_cidrs.join('\n')); setSensitive(data.enrichment.sensitive_asset_ids.join('\n'));
    setReason(''); setStale(false);
  }
  const reload = useMutation({ mutationFn: () => cache.fetchQuery({ queryKey: key, queryFn: readSettings, staleTime: 0 }), onSuccess: reset });
  const payload: Update = { mode, enrichment: { enabled, excluded_cidrs: lines(excluded), sensitive_asset_ids: lines(sensitive) }, reason: reason.trim(), version: settings.version };
  const tooMany = payload.enrichment.excluded_cidrs.length > settings.limits.max_excluded_cidrs || payload.enrichment.sensitive_asset_ids.length > settings.limits.max_sensitive_asset_ids;
  const validMode = !enabled || mode === 'enforce' || mode === 'paused';
  const dirty = mode !== settings.mode || enabled !== settings.enrichment.enabled || excluded !== settings.enrichment.excluded_cidrs.join('\n') || sensitive !== settings.enrichment.sensitive_asset_ids.join('\n');
  const reasonTooShort = reason.trim().length < 3;
  const save = useMutation({ mutationFn: async () => {
    const { data, error, response } = await clients.inventory.PUT('/settings/identity-discovery', { body: payload });
    if (!response.ok || !data) {
      if (response.status === 409 && error?.error === 'stale_version') {
        setStale(true);
        throw new Error('These settings changed. Reload the saved settings, then review and apply your changes again.');
      }
      throw new Error(typeof error?.message === 'string' ? error.message : 'Unable to save identity discovery settings. Review the values and try again.');
    }
    return data;
  }, onSuccess: async (data) => {
    cache.setQueryData(key, data);
    reset(data);
    await cache.invalidateQueries({ queryKey: ['identity-observations'] });
  }});
  return <>
    <p>Current policy: <strong>{modes[current.mode]}</strong>.</p>
    <dl>
      <dt>Automatic enrichment</dt><dd>{current.enrichment.enabled ? (current.mode === 'paused' ? 'Enabled, paused with admission' : 'Enabled') : 'Disabled'}</dd>
      <dt>Saved network exclusions</dt><dd>{current.enrichment.excluded_cidrs.join(', ') || 'None'}</dd>
      <dt>Saved sensitive assets</dt><dd style={{ overflowWrap: 'anywhere' }}>{current.enrichment.sensitive_asset_ids.join(', ') || 'None'}</dd>
    </dl>
    <p>Existing records stay visible as “Identity not evaluated”. New qualifying evidence can establish their identity in place. Unresolved observations do not count toward the asset allowance.</p>
    {!settings.capabilities.admission && <p role="status">This release has not enabled identity admission. Activation becomes available after the complete discovery capability is deployed.</p>}
    {settings.activated_at && <p>Activated {new Date(settings.activated_at).toLocaleString()}. You can pause processing while retaining incoming evidence.</p>}
    <PermissionGate permission={TENANT_PERMISSIONS.settings.update} fallback={<p>You can view this policy. Changing it requires settings update permission.</p>}>
      <form style={{ display: 'grid', gap: 12, maxWidth: 680 }} onSubmit={(e) => { e.preventDefault(); if (!stale && !tooMany && validMode && reason.trim().length >= 3) save.mutate(); }}>
        <fieldset disabled={save.isPending || stale} style={{ display: 'grid', gap: 12, border: 0, padding: 0, margin: 0 }}>
          <label>Identity admission<select className="ui-input" aria-label="Identity admission" value={mode} onChange={(e) => setMode(e.target.value as Settings['mode'])}>
            {(Object.keys(modes) as Settings['mode'][]).map((m) => <option key={m} value={m} disabled={((m === 'disabled' || m === 'observe') && !!settings.activated_at) || ((m === 'enforce' || m === 'observe' || (m === 'paused' && !settings.activated_at)) && !settings.capabilities.admission)}>{modes[m]}</option>)}
          </select></label>
          <p style={{ margin: 0, fontSize: 12 }}>{mode === 'observe' ? 'Observe mode records evidence while keeping the existing admission behavior. Use it only before activation.' : mode === 'paused' ? 'Pause stops new admission and enrichment. Incoming evidence is still retained for later processing.' : mode === 'enforce' ? 'Weak evidence remains unresolved; qualifying evidence can establish an asset. Monitoring approval rules still apply.' : 'Existing admission behavior continues until activation.'}</p>
          <label><input type="checkbox" checked={enabled} disabled={!settings.capabilities.enrichment && !enabled} onChange={(e) => setEnabled(e.target.checked)} /> Automatically enrich identity evidence</label>
          <p style={{ margin: 0, fontSize: 12 }}>Uses configured sources first, then permitted DNS and targeted TLS/SSH checks. Active probes also follow the scanning policy below. Local names require a suitable collector in the observed network.</p>
          {!settings.capabilities.enrichment && <p>Automatic identity enrichment is unavailable in this release.</p>}
          <label>Excluded networks<textarea className="ui-input" rows={3} value={excluded} onChange={(e) => setExcluded(e.target.value)} placeholder="192.168.20.0/24" /></label>
          <p style={{ margin: 0, fontSize: 12 }}>One CIDR per line, up to {settings.limits.max_excluded_cidrs}. These exclusions further restrict authorized networks.</p>
          <label>Sensitive asset IDs<textarea className="ui-input" rows={3} value={sensitive} onChange={(e) => setSensitive(e.target.value)} /></label>
          <p style={{ margin: 0, fontSize: 12 }}>One asset ID per line, up to {settings.limits.max_sensitive_asset_ids}. Copy the ID from its asset URL. Automatic enrichment skips these assets; only assets in this tenant are accepted.</p>
          <label>Reason for change<textarea className="ui-input" required minLength={3} maxLength={settings.limits.max_reason_length} aria-describedby="identity-policy-reason-help" value={reason} onChange={(e) => setReason(e.target.value)} /></label>
          <p id="identity-policy-reason-help" role={dirty && reasonTooShort ? 'alert' : undefined} style={{ margin: 0, fontSize: 12 }}>
            Required for the audit history. Enter at least 3 characters before saving.
          </p>
        </fieldset>
        {tooMany && <p role="alert">Reduce the exclusions or sensitive asset list to the displayed limits.</p>}
        {!validMode && <p role="alert">Automatic enrichment requires active identity admission. Pausing preserves the setting without running enrichment.</p>}
        {save.isError && <p role="alert">{save.error.message}</p>}
        {stale && <p role="alert">A newer policy is available. Your draft has been preserved; reload the saved settings before making another change.</p>}
        {reload.isError && <p role="alert">{reload.error.message}</p>}
        {stale && <button type="button" className="ui-btn" disabled={reload.isPending} onClick={() => reload.mutate()}>Reload saved settings</button>}
        <button className="ui-btn accent" type="submit" title={dirty && reasonTooShort ? 'Enter a reason of at least 3 characters to save' : undefined} disabled={!dirty || stale || save.isPending || tooMany || !validMode || reasonTooShort}>{save.isPending ? 'Saving…' : 'Save identity policy'}</button>
      </form>
    </PermissionGate>
  </>;
}
