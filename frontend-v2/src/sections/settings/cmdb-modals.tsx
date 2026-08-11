// Settings · Integrations — CMDB sync profile modals. Surfaces the
// existing inventory-service CMDB backend (ServiceNow / Device42 / SolarWinds /
// Oomnitza): create/edit a profile, delete it, and view its recent sync jobs.
// The four `*_config` fields are opaque JSON on the wire; here we build the
// connection + sync configs from structured forms. Field/CI-type mapping use
// backend defaults in v1 (no UI yet).
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import { SToggle, STag, StateNote, relTime, GREEN, AMBER, RED } from './kit';

export type CMDBProfile = inventoryComponents['schemas']['CMDBSyncProfile'];
type CMDBJob = inventoryComponents['schemas']['CMDBSyncJob'];

interface PlatformSpec {
  value: string;
  label: string;
  auth: string[];
  urlLabel: string;
  urlPlaceholder: string;
}

export const CMDB_PLATFORMS: PlatformSpec[] = [
  { value: 'servicenow', label: 'ServiceNow', auth: ['basic', 'api_token', 'oauth2'], urlLabel: 'Instance URL', urlPlaceholder: 'https://acme.service-now.com' },
  { value: 'device42', label: 'Device42', auth: ['api_token', 'basic'], urlLabel: 'Base URL', urlPlaceholder: 'https://device42.example.com' },
  { value: 'solarwinds', label: 'SolarWinds', auth: ['basic', 'api_token'], urlLabel: 'Base URL', urlPlaceholder: 'https://solarwinds.example.com' },
  { value: 'oomnitza', label: 'Oomnitza', auth: ['api_token', 'basic'], urlLabel: 'Base URL', urlPlaceholder: 'https://acme.oomnitza.com' },
];

export const PLATFORM_LABEL: Record<string, string> = Object.fromEntries(CMDB_PLATFORMS.map((p) => [p.value, p.label]));

const AUTH_LABEL: Record<string, string> = { basic: 'Username & password', api_token: 'API token', oauth2: 'OAuth2 client credentials' };
const SCHEDULES = ['manual', 'hourly', 'daily', 'weekly'];
const CONFLICT = [
  { value: 'source_wins', label: 'Platform wins (overwrite CMDB)' },
  { value: 'target_wins', label: 'CMDB wins (keep their value)' },
  { value: 'skip', label: 'Skip conflicts' },
];

interface ConnForm {
  base_url: string;
  auth_type: string;
  username: string;
  password: string;
  api_token: string;
  client_id: string;
  client_secret: string;
}
interface SyncForm {
  schedule: string;
  conflict_resolution: string;
  batch_size: number;
  include_crypto_summary: boolean;
}

function asRecord(v: unknown): Record<string, unknown> {
  return v && typeof v === 'object' ? (v as Record<string, unknown>) : {};
}
function str(v: unknown): string {
  return v === null || v === undefined ? '' : String(v);
}

export function jobTone(status?: string): string {
  const s = (status || '').toLowerCase();
  if (s === 'completed' || s === 'success') return GREEN;
  if (s === 'failed') return RED;
  if (s === 'partial') return AMBER;
  return 'var(--app-t3)'; // pending / running
}

export function CmdbProfileModal({ profile, open, onClose }: { profile: CMDBProfile | null; open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const isEdit = !!profile;
  const conn0 = asRecord(profile?.connection_config);
  const sync0 = asRecord(profile?.sync_config);

  const [name, setName] = useState(profile?.name ?? '');
  const [platform, setPlatform] = useState(profile?.platform_type ?? CMDB_PLATFORMS[0].value);
  const [enabled, setEnabled] = useState(profile?.is_enabled ?? true);
  const [conn, setConn] = useState<ConnForm>({
    base_url: str(conn0.base_url || conn0.instance_url),
    auth_type: str(conn0.auth_type) || 'api_token',
    username: str(conn0.username),
    password: str(conn0.password),
    api_token: str(conn0.api_token),
    client_id: str(conn0.client_id),
    client_secret: str(conn0.client_secret),
  });
  const [sync, setSync] = useState<SyncForm>({
    schedule: str(sync0.schedule) || 'manual',
    conflict_resolution: str(sync0.conflict_resolution) || 'source_wins',
    batch_size: typeof sync0.batch_size === 'number' ? (sync0.batch_size as number) : 100,
    include_crypto_summary: Boolean(sync0.include_crypto_summary),
  });

  const spec = CMDB_PLATFORMS.find((p) => p.value === platform) ?? CMDB_PLATFORMS[0];
  const authOptions = spec.auth;
  // Keep auth_type valid when the platform changes.
  const authType = authOptions.includes(conn.auth_type) ? conn.auth_type : authOptions[0];

  const valid = name.trim() !== '' && conn.base_url.trim() !== '' &&
    (authType === 'basic' ? conn.username && conn.password : authType === 'oauth2' ? conn.client_id && conn.client_secret : conn.api_token);

  const save = useMutation({
    mutationFn: async () => {
      const connection_config: Record<string, unknown> = { base_url: conn.base_url.trim(), auth_type: authType };
      if (platform === 'servicenow') connection_config.instance_url = conn.base_url.trim();
      if (authType === 'basic') {
        connection_config.username = conn.username;
        connection_config.password = conn.password;
      } else if (authType === 'oauth2') {
        connection_config.client_id = conn.client_id;
        connection_config.client_secret = conn.client_secret;
      } else {
        connection_config.api_token = conn.api_token;
      }
      const body = {
        name: name.trim(),
        platform_type: platform,
        is_enabled: enabled,
        connection_config,
        sync_config: { schedule: sync.schedule, conflict_resolution: sync.conflict_resolution, batch_size: Number(sync.batch_size) || 100, include_crypto_summary: sync.include_crypto_summary },
      };
      const res = isEdit
        ? await clients.inventory.PUT('/cmdb/profiles/{id}', { params: { path: { id: profile!.id } }, body })
        : await clients.inventory.POST('/cmdb/profiles', { body });
      if (res.error || !res.response.ok) throw new Error('Failed to save the CMDB profile');
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['settings', 'cmdb-profiles'] });
      toast.success(isEdit ? 'CMDB profile updated' : 'CMDB profile created');
      onClose();
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Save failed'),
  });

  return (
    <Modal
      open={open}
      onClose={save.isPending ? undefined : onClose}
      dismissible={!save.isPending}
      size="lg"
      tone="accent"
      icon="plug"
      eyebrow="Settings · Integrations · CMDB"
      title={isEdit ? `Edit ${profile!.name}` : 'New CMDB sync'}
      description="Connect a CMDB/ITSM platform. After saving, use Test to verify the connection and Sync to push your inventory."
      primary={<button className="ui-btn accent" disabled={!valid || save.isPending} onClick={() => save.mutate()}>{save.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Create'}</button>}
      secondary={<button className="ui-btn" onClick={onClose} disabled={save.isPending}>Cancel</button>}
      footerNote={save.isError ? <span style={{ color: 'var(--danger-text)' }}>{(save.error as Error).message}</span> : (isEdit ? <span style={{ color: 'var(--app-t3)' }}>Re-enter credentials if you change auth — they overwrite the stored config.</span> : undefined)}
    >
      <ModalField label="Name">
        <ModalInput data-autofocus value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Production ServiceNow" />
      </ModalField>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
        <ModalField label="Platform">
          <ModalSelect value={platform} onChange={(e) => setPlatform(e.target.value)}>
            {CMDB_PLATFORMS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
          </ModalSelect>
        </ModalField>
        <ModalField label="Authentication">
          <ModalSelect value={authType} onChange={(e) => setConn((c) => ({ ...c, auth_type: e.target.value }))}>
            {authOptions.map((a) => <option key={a} value={a}>{AUTH_LABEL[a] ?? a}</option>)}
          </ModalSelect>
        </ModalField>
      </div>
      <ModalField label={spec.urlLabel}>
        <ModalInput value={conn.base_url} onChange={(e) => setConn((c) => ({ ...c, base_url: e.target.value }))} placeholder={spec.urlPlaceholder} />
      </ModalField>

      {authType === 'basic' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <ModalField label="Username"><ModalInput value={conn.username} onChange={(e) => setConn((c) => ({ ...c, username: e.target.value }))} /></ModalField>
          <ModalField label="Password"><ModalInput type="password" value={conn.password} onChange={(e) => setConn((c) => ({ ...c, password: e.target.value }))} /></ModalField>
        </div>
      )}
      {authType === 'api_token' && (
        <ModalField label="API token"><ModalInput type="password" value={conn.api_token} onChange={(e) => setConn((c) => ({ ...c, api_token: e.target.value }))} /></ModalField>
      )}
      {authType === 'oauth2' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <ModalField label="Client ID"><ModalInput value={conn.client_id} onChange={(e) => setConn((c) => ({ ...c, client_id: e.target.value }))} /></ModalField>
          <ModalField label="Client secret"><ModalInput type="password" value={conn.client_secret} onChange={(e) => setConn((c) => ({ ...c, client_secret: e.target.value }))} /></ModalField>
        </div>
      )}

      <div style={{ height: 1, background: 'var(--app-border)', margin: '6px 0 14px' }} />

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
        <ModalField label="Sync schedule">
          <ModalSelect value={sync.schedule} onChange={(e) => setSync((s) => ({ ...s, schedule: e.target.value }))}>
            {SCHEDULES.map((s) => <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>)}
          </ModalSelect>
        </ModalField>
        <ModalField label="On conflict">
          <ModalSelect value={sync.conflict_resolution} onChange={(e) => setSync((s) => ({ ...s, conflict_resolution: e.target.value }))}>
            {CONFLICT.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
          </ModalSelect>
        </ModalField>
      </div>
      <label style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 4 }}>
        <SToggle on={enabled} onChange={setEnabled} />
        <span style={{ fontSize: 12.5, color: 'var(--app-t2)' }}>Enabled — include this profile in scheduled syncs</span>
      </label>
      <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, marginTop: 10 }}>
        <SToggle on={sync.include_crypto_summary} onChange={(v) => setSync((s) => ({ ...s, include_crypto_summary: v }))} />
        <span style={{ fontSize: 12.5, color: 'var(--app-t2)' }}>
          Include cryptographic summary
          <span style={{ display: 'block', fontSize: 11, color: 'var(--app-t3)', marginTop: 2 }}>
            Append a plain-language crypto-posture summary (algorithms, PQC status) to each asset's description in the CMDB. Works on any platform.
          </span>
        </span>
      </label>
    </Modal>
  );
}

export function CmdbDeleteModal({ profile, open, onClose }: { profile: CMDBProfile; open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const del = useMutation({
    mutationFn: async () => {
      const { error, response } = await clients.inventory.DELETE('/cmdb/profiles/{id}', { params: { path: { id: profile.id } } });
      if (error || !response.ok) throw new Error('Failed to delete the profile');
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['settings', 'cmdb-profiles'] });
      toast.success('CMDB profile deleted');
      onClose();
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Delete failed'),
  });
  return (
    <Modal
      open={open} onClose={del.isPending ? undefined : onClose} dismissible={!del.isPending}
      size="sm" tone="danger" icon="alert-triangle" eyebrow="Settings · Integrations · CMDB"
      title={`Delete ${profile.name}?`}
      description="The sync profile and its configuration are removed. Items already pushed to your CMDB are not affected."
      primary={<button className="ui-btn danger" disabled={del.isPending} onClick={() => del.mutate()}>{del.isPending ? 'Deleting…' : 'Delete'}</button>}
      secondary={<button className="ui-btn" onClick={onClose} disabled={del.isPending}>Cancel</button>}
    />
  );
}

export function CmdbJobsModal({ profile, open, onClose }: { profile: CMDBProfile; open: boolean; onClose: () => void }) {
  const jobsQ = useQuery({
    queryKey: ['settings', 'cmdb-jobs', profile.id],
    enabled: open,
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/cmdb/profiles/{id}/jobs', { params: { path: { id: profile.id } } });
      if (error || !data) throw new Error('Failed to load sync history');
      return data.jobs ?? [];
    },
  });
  const jobs = jobsQ.data ?? [];
  return (
    <Modal
      open={open} onClose={onClose} size="lg" tone="accent" icon="history"
      eyebrow="Settings · Integrations · CMDB" title={`Sync history — ${profile.name}`}
      description="Recent sync runs for this profile."
      primary={<button className="ui-btn accent" onClick={onClose}>Close</button>}
    >
      {jobsQ.isError ? (
        <StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load history" message="The sync-job history failed to load." />
      ) : jobsQ.isLoading ? (
        <StateNote icon="loader" tone="var(--app-t3)" title="Loading…" message="Fetching sync runs." />
      ) : jobs.length === 0 ? (
        <StateNote icon="history" tone="var(--app-t3)" title="No syncs yet" message="Run a sync from the connection card to populate this history." />
      ) : (
        <div className="panel" style={{ borderRadius: 12, overflow: 'auto', maxHeight: 320 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ position: 'sticky', top: 0, background: 'var(--app-panel)' }}>
                <th style={th}>When</th><th style={th}>Trigger</th><th style={th}>Status</th>
                <th style={th}>Pushed</th><th style={th}>Reconciled</th><th style={th}>Failed</th><th style={th}>Skipped</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((j: CMDBJob) => (
                <tr key={j.id} style={{ borderTop: '1px solid var(--app-border)' }}>
                  <td style={td}>{relTime(j.completed_at ?? j.started_at ?? j.created_at)}</td>
                  <td style={td}>{j.trigger_type}</td>
                  <td style={td}><STag color={jobTone(j.status)}>{j.status}</STag></td>
                  <td style={td}>{j.items_pushed}</td>
                  <td style={td}>{j.items_reconciled}</td>
                  <td style={{ ...td, color: j.items_failed ? 'var(--danger)' : undefined }}>{j.items_failed}</td>
                  <td style={td}>{j.items_skipped}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Modal>
  );
}

const th: React.CSSProperties = { textAlign: 'left', padding: '7px 10px', fontSize: 10.5, textTransform: 'uppercase', letterSpacing: 0.4, color: 'var(--app-t3)', fontWeight: 600 };
const td: React.CSSProperties = { padding: '6px 10px', color: 'var(--app-t1)', whiteSpace: 'nowrap' };
