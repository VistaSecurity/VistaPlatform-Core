// Settings · Integrations — CMDB sync profile modals. Surfaces the
// existing inventory-service CMDB backend (ServiceNow / Device42 / SolarWinds /
// Oomnitza): create/edit a profile, delete it, and view its recent sync jobs.
// The four `*_config` fields are opaque JSON on the wire; here we build the
// connection + sync configs from structured forms. Field/CI-type mapping use
// backend defaults in v1 (no UI yet).
//
// Credentials are write-only: the API never returns a password, API token or
// client secret, only has_password / has_api_token / has_client_secret. The edit
// form therefore starts those fields blank, and a blank field on save keeps the
// stored secret (the server merges it back in).
//
// Which way data moves comes from the connector registry (CONNECTORS, generated
// from standards/connectors.yaml) — the same answer the server enforces. A
// pull-only platform (SolarWinds) is never offered Sync, batch size or the
// crypto summary, all of which are push-only concepts.
//
// There is no conflict-resolution choice any more. The form offered "Platform
// wins / CMDB wins / Skip conflicts" and nothing read it: every connector
// upserts, and honouring the other two needs per-vendor field comparison.
import { Fragment, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { CONNECTORS } from '@vistasecurity/primitives/connectors';
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
  // ServiceNow's REST APIs take Basic or an OAuth access token; the "API
  // token" this used to offer was sent as a bearer token ServiceNow never
  // issued (integrations review M16), and the API now refuses it.
  { value: 'servicenow', label: 'ServiceNow', auth: ['basic', 'oauth2'], urlLabel: 'Instance URL', urlPlaceholder: 'https://acme.service-now.com' },
  { value: 'device42', label: 'Device42', auth: ['basic'], urlLabel: 'Base URL', urlPlaceholder: 'https://device42.example.com' },
  { value: 'solarwinds', label: 'SolarWinds', auth: ['basic'], urlLabel: 'Base URL', urlPlaceholder: 'https://solarwinds.example.com' },
  { value: 'oomnitza', label: 'Oomnitza', auth: ['api_token', 'basic'], urlLabel: 'Base URL', urlPlaceholder: 'https://acme.oomnitza.com' },
];

export const PLATFORM_LABEL: Record<string, string> = Object.fromEntries(CMDB_PLATFORMS.map((p) => [p.value, p.label]));

const AUTH_LABEL: Record<string, string> = { basic: 'Username & password', api_token: 'API token', oauth2: 'OAuth2 client credentials' };
const SCHEDULES = ['manual', 'hourly', 'daily', 'weekly'];
const DEFAULT_BATCH = 100;
const MAX_BATCH = 1000;

/** The platform's registry direction: 'push', 'pull', 'both', or undefined. */
export function cmdbDirection(platform: string): string | undefined {
  return CONNECTORS.find((c) => c.key === platform && c.kind === 'cmdb')?.direction;
}
/** Whether Vista may write to this platform (Sync). */
export function canPushTo(platform: string): boolean {
  const d = cmdbDirection(platform);
  return d === 'push' || d === 'both';
}
/** Whether Vista may read this platform's inventory (Pull). */
export function canPullFrom(platform: string): boolean {
  const d = cmdbDirection(platform);
  return d === 'pull' || d === 'both';
}

/** What a scheduled run of this platform does, in words. */
function scheduleMeaning(platform: string): string {
  const push = canPushTo(platform), pull = canPullFrom(platform);
  if (push && pull) return 'A scheduled run pulls the CMDB\'s inventory into Vista, then pushes your approved inventory to it.';
  if (pull) return 'A scheduled run pulls the CMDB\'s inventory into Vista. Vista never writes to this platform.';
  return 'A scheduled run pushes your approved inventory to the CMDB.';
}

interface ConnForm {
  base_url: string;
  auth_type: string;
  username: string;
  password: string;
  api_token: string;
  client_id: string;
  client_secret: string;
  allow_private_endpoint: boolean;
  ca_bundle_pem: string;
}
interface SyncForm {
  schedule: string;
  batch_size: string;
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

/** The server's `{ error }` message from an openapi-fetch error body, if any. */
export function serverError(error: unknown): string | undefined {
  const msg = (error as { error?: unknown } | undefined)?.error;
  return typeof msg === 'string' && msg.trim() !== '' ? msg : undefined;
}

export function CmdbProfileModal({ profile, open, onClose }: { profile: CMDBProfile | null; open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const isEdit = !!profile;
  const conn0 = asRecord(profile?.connection_config);
  const sync0 = asRecord(profile?.sync_config);
  // Which secrets the server already holds (edit only). A stored secret may be
  // left blank on save — the server keeps it.
  const stored = {
    password: !!profile?.has_password,
    api_token: !!profile?.has_api_token,
    client_secret: !!profile?.has_client_secret,
  };

  const [name, setName] = useState(profile?.name ?? '');
  const [platform, setPlatform] = useState(profile?.platform_type ?? CMDB_PLATFORMS[0].value);
  const [enabled, setEnabled] = useState(profile?.is_enabled ?? true);
  const [conn, setConn] = useState<ConnForm>({
    base_url: str(conn0.base_url || conn0.instance_url),
    auth_type: str(conn0.auth_type) || 'api_token',
    username: str(conn0.username),
    // Never pre-filled: the API does not return secret values.
    password: '',
    api_token: '',
    client_id: str(conn0.client_id),
    client_secret: '',
    allow_private_endpoint: conn0.allow_private_endpoint === true,
    ca_bundle_pem: str(conn0.ca_bundle_pem),
  });
  const [sync, setSync] = useState<SyncForm>({
    schedule: str(sync0.schedule) || 'manual',
    batch_size: String(typeof sync0.batch_size === 'number' && sync0.batch_size > 0 ? sync0.batch_size : DEFAULT_BATCH),
    include_crypto_summary: Boolean(sync0.include_crypto_summary),
  });

  const spec = CMDB_PLATFORMS.find((p) => p.value === platform) ?? CMDB_PLATFORMS[0];
  const authOptions = spec.auth;
  // Keep auth_type valid when the platform changes.
  const authType = authOptions.includes(conn.auth_type) ? conn.auth_type : authOptions[0];

  const pushes = canPushTo(platform);
  const batch = Number(sync.batch_size);
  const batchValid = !pushes || (Number.isInteger(batch) && batch >= 1 && batch <= MAX_BATCH);

  const has = (field: 'password' | 'api_token' | 'client_secret') => conn[field] !== '' || stored[field];
  const valid = name.trim() !== '' && conn.base_url.trim() !== '' && batchValid &&
    (authType === 'basic' ? conn.username && has('password') : authType === 'oauth2' ? conn.client_id && has('client_secret') : has('api_token'));
  const keepHint = (field: 'password' | 'api_token' | 'client_secret') =>
    stored[field] ? 'Leave blank to keep the current secret' : undefined;

  const save = useMutation({
    mutationFn: async () => {
      const connection_config: Record<string, unknown> = {
        base_url: conn.base_url.trim(),
        auth_type: authType,
        // Egress (non-secret): reach a CMDB on the tenant's own network, and
        // trust an internal CA. Validated on save; the server says why if not.
        allow_private_endpoint: conn.allow_private_endpoint,
        ca_bundle_pem: conn.ca_bundle_pem.trim(),
      };
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
        sync_config: pushes
          ? { schedule: sync.schedule, batch_size: batch, include_crypto_summary: sync.include_crypto_summary }
          : { schedule: sync.schedule },
      };
      const res = isEdit
        ? await clients.inventory.PUT('/cmdb/profiles/{id}', { params: { path: { id: profile.id } }, body })
        : await clients.inventory.POST('/cmdb/profiles', { body });
      // Show the server's reason (duplicate name, unknown platform, …) rather
      // than a generic failure.
      if (res.error || !res.response.ok) throw new Error(serverError(res.error) ?? 'Failed to save the CMDB profile');
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['settings', 'cmdb-profiles'] });
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
      title={isEdit ? `Edit ${profile.name}` : 'New CMDB sync'}
      description={pushes
        ? 'Connect a CMDB/ITSM platform. After saving, use Test to verify the connection, then Sync to push your inventory or Pull to import the CMDB\'s.'
        : 'Connect a CMDB/ITSM platform. After saving, use Test to verify the connection and Pull to import its inventory. This platform is pull-only: Vista never writes to it.'}
      primary={<button className="ui-btn accent" disabled={!valid || save.isPending} onClick={() => save.mutate()}>{save.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Create'}</button>}
      secondary={<button className="ui-btn" onClick={onClose} disabled={save.isPending}>Cancel</button>}
      footerNote={save.isError ? <span style={{ color: 'var(--danger-text)' }}>{save.error.message}</span> : (isEdit ? <span style={{ color: 'var(--app-t3)' }}>Stored secrets are never shown. Leave a secret blank to keep the current one, or type a new one to replace it.</span> : undefined)}
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
          <ModalField label="Password"><ModalInput type="password" value={conn.password} placeholder={keepHint('password')} onChange={(e) => setConn((c) => ({ ...c, password: e.target.value }))} /></ModalField>
        </div>
      )}
      {authType === 'api_token' && (
        <ModalField label="API token"><ModalInput type="password" value={conn.api_token} placeholder={keepHint('api_token')} onChange={(e) => setConn((c) => ({ ...c, api_token: e.target.value }))} /></ModalField>
      )}
      {authType === 'oauth2' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <ModalField label="Client ID"><ModalInput value={conn.client_id} onChange={(e) => setConn((c) => ({ ...c, client_id: e.target.value }))} /></ModalField>
          <ModalField label="Client secret"><ModalInput type="password" value={conn.client_secret} placeholder={keepHint('client_secret')} onChange={(e) => setConn((c) => ({ ...c, client_secret: e.target.value }))} /></ModalField>
        </div>
      )}

      <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, marginTop: 4 }}>
        <SToggle on={conn.allow_private_endpoint} onChange={(v) => setConn((c) => ({ ...c, allow_private_endpoint: v }))} />
        <span style={{ fontSize: 12.5, color: 'var(--app-t2)' }}>
          CMDB is on our own network
          <span style={{ display: 'block', fontSize: 11, color: 'var(--app-t3)', marginTop: 2 }}>
            Required for a CMDB on a private (10.x, 172.16–31.x, 192.168.x) address — the usual case for an on-premises SolarWinds or Device42. Loopback and cloud metadata addresses are never reachable, whatever this is set to.
          </span>
        </span>
      </label>
      <ModalField
        label="CA bundle (PEM)"
        hint="Optional. For a CMDB whose HTTPS certificate your own CA issued: paste that CA's certificate (or chain). It is trusted in addition to the public roots — certificate checking is never switched off. Never paste a private key here."
      >
        <textarea
          value={conn.ca_bundle_pem}
          rows={3}
          placeholder="-----BEGIN CERTIFICATE-----"
          onChange={(e) => setConn((c) => ({ ...c, ca_bundle_pem: e.target.value }))}
          className="mono"
          spellCheck={false}
          aria-label="CA bundle (PEM)"
          style={{ width: '100%', padding: '9px 12px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 11.5, outline: 'none', resize: 'vertical' }}
        />
      </ModalField>

      <div style={{ height: 1, background: 'var(--app-border)', margin: '6px 0 14px' }} />

      <div style={{ display: 'grid', gridTemplateColumns: pushes ? '1fr 1fr' : '1fr', gap: 8 }}>
        <ModalField label="Schedule" hint={scheduleMeaning(platform)}>
          <ModalSelect aria-label="Schedule" value={sync.schedule} onChange={(e) => setSync((s) => ({ ...s, schedule: e.target.value }))}>
            {SCHEDULES.map((s) => <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>)}
          </ModalSelect>
        </ModalField>
        {pushes && (
          <ModalField label="Push batch size" hint={`CIs sent per batch, 1–${MAX_BATCH}. Each batch is recorded before the next is sent.`}>
            <ModalInput aria-label="Push batch size" type="number" min={1} max={MAX_BATCH} step={1} value={sync.batch_size}
              onChange={(e) => setSync((s) => ({ ...s, batch_size: e.target.value }))} />
          </ModalField>
        )}
      </div>
      <label style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 4 }}>
        <SToggle on={enabled} onChange={setEnabled} />
        <span style={{ fontSize: 12.5, color: 'var(--app-t2)' }}>Enabled — while off, nothing runs: no scheduled runs, no Sync, no Pull</span>
      </label>
      {pushes && (
        <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, marginTop: 10 }}>
          <SToggle on={sync.include_crypto_summary} onChange={(v) => setSync((s) => ({ ...s, include_crypto_summary: v }))} />
          <span style={{ fontSize: 12.5, color: 'var(--app-t2)' }}>
            Include cryptographic summary
            <span style={{ display: 'block', fontSize: 11, color: 'var(--app-t3)', marginTop: 2 }}>
              Append a plain-language crypto-posture summary (algorithms, PQC status) to each asset's description in the CMDB.
            </span>
          </span>
        </label>
      )}
    </Modal>
  );
}

export function CmdbDeleteModal({ profile, open, onClose }: { profile: CMDBProfile; open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const del = useMutation({
    mutationFn: async () => {
      const { error, response } = await clients.inventory.DELETE('/cmdb/profiles/{id}', { params: { path: { id: profile.id } } });
      if (error || !response.ok) throw new Error(serverError(error) ?? 'Failed to delete the profile');
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['settings', 'cmdb-profiles'] });
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

/** A job's summary, as the engine writes it (ee/cmdbsync completeSyncJob). */
interface JobSummary {
  direction?: string;
  created?: number;
  updated?: number;
  unresolved?: number;
  errors?: { local_id?: string; external_id?: string; error: string }[];
  errors_total?: number;
  errors_omitted?: number;
}

/** The job-level failure message (error_log), when the whole run failed. */
function jobFailure(j: CMDBJob): string | undefined {
  const log: unknown = j.error_log;
  if (!Array.isArray(log)) return undefined;
  const first = log.find((e) => e && typeof e === 'object' && typeof (e as { error?: unknown }).error === 'string') as { error: string } | undefined;
  return first?.error;
}

export function CmdbJobsModal({ profile, open, onClose }: { profile: CMDBProfile; open: boolean; onClose: () => void }) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const jobsQ = useQuery({
    queryKey: ['settings', 'cmdb-jobs', profile.id],
    enabled: open,
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/cmdb/profiles/{id}/jobs', { params: { path: { id: profile.id } } });
      if (error || !data) throw new Error(serverError(error) ?? 'Failed to load sync history');
      return data.jobs ?? [];
    },
  });
  const jobs = jobsQ.data ?? [];
  return (
    <Modal
      open={open} onClose={onClose} size="lg" tone="accent" icon="history"
      eyebrow="Settings · Integrations · CMDB" title={`Sync history — ${profile.name}`}
      description="Recent runs for this profile — manual and scheduled, pushes and pulls. Select a run with errors to see what the CMDB refused."
      primary={<button className="ui-btn accent" onClick={onClose}>Close</button>}
    >
      {jobsQ.isError ? (
        <StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load history" message={jobsQ.error.message} />
      ) : jobsQ.isLoading ? (
        <StateNote icon="loader" tone="var(--app-t3)" title="Loading…" message="Fetching sync runs." />
      ) : jobs.length === 0 ? (
        <StateNote icon="history" tone="var(--app-t3)" title="No runs yet" message="Run a sync or a pull from the connection card, or set a schedule, to populate this history." />
      ) : (
        <div className="panel" style={{ borderRadius: 12, overflow: 'auto', maxHeight: 360 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ position: 'sticky', top: 0, background: 'var(--app-panel)' }}>
                <th style={th}>When</th><th style={th}>Run</th><th style={th}>Status</th>
                <th style={th}>Created</th><th style={th}>Updated / matched</th><th style={th}>Failed</th><th style={th}>Skipped</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((j: CMDBJob) => {
                // Created / updated come from the run summary. They split what
                // items_pushed aggregates, so a run that keeps reporting new CIs
                // for inventory you already synced is visible rather than hidden
                // behind one "pushed" total. For a pull, "matched" is records
                // already in Vista.
                const sum = (j.summary ?? {}) as JobSummary;
                const pull = sum.direction === 'pull';
                const itemErrors = sum.errors ?? [];
                const failure = jobFailure(j);
                const hasDetail = itemErrors.length > 0 || !!failure;
                const isOpen = expanded === j.id;
                return (
                  <Fragment key={j.id}>
                    <tr
                      style={{ borderTop: '1px solid var(--app-border)', cursor: hasDetail ? 'pointer' : undefined }}
                      onClick={hasDetail ? () => setExpanded(isOpen ? null : j.id) : undefined}
                      aria-expanded={hasDetail ? isOpen : undefined}
                    >
                      <td style={td}>{relTime(j.completed_at ?? j.started_at ?? j.created_at)}</td>
                      <td style={td}>{pull ? 'Pull' : 'Push'} · {j.trigger_type}</td>
                      <td style={td}><STag color={jobTone(j.status)}>{j.status}</STag></td>
                      <td style={td}>{sum.created ?? j.items_pushed}</td>
                      <td style={td}>{pull ? j.items_skipped : (sum.updated ?? 0)}</td>
                      <td style={{ ...td, color: j.items_failed ? 'var(--danger)' : undefined }}>{j.items_failed}{hasDetail ? (isOpen ? ' ▾' : ' ▸') : ''}</td>
                      <td style={td}>{pull ? (sum.unresolved ? `${sum.unresolved} unresolved` : 0) : j.items_skipped}</td>
                    </tr>
                    {isOpen && (
                      <tr>
                        <td colSpan={7} style={{ padding: '6px 10px 10px', background: 'var(--app-panel2)' }}>
                          {failure && <div style={{ color: 'var(--danger-text)', fontSize: 11.5, whiteSpace: 'normal', marginBottom: itemErrors.length ? 6 : 0 }}>{failure}</div>}
                          {itemErrors.length > 0 && (
                            <ul style={{ margin: 0, paddingLeft: 16, fontSize: 11.5, color: 'var(--app-t2)', whiteSpace: 'normal' }}>
                              {itemErrors.map((e, i) => (
                                <li key={i}><span className="mono" style={{ color: 'var(--app-t3)' }}>{e.local_id ?? e.external_id ?? '—'}</span>: {e.error}</li>
                              ))}
                            </ul>
                          )}
                          {(sum.errors_omitted ?? 0) > 0 && (
                            <div style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 4 }}>…and {sum.errors_omitted} more (of {sum.errors_total}).</div>
                          )}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Modal>
  );
}

const th: React.CSSProperties = { textAlign: 'left', padding: '7px 10px', fontSize: 10.5, textTransform: 'uppercase', letterSpacing: 0.4, color: 'var(--app-t3)', fontWeight: 600 };
const td: React.CSSProperties = { padding: '6px 10px', color: 'var(--app-t1)', whiteSpace: 'nowrap' };
