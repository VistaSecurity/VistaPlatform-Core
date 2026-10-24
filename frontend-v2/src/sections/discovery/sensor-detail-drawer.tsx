// Sensor detail drawer — opened by clicking a sensor row in sensors-page.
// Rendered on the shared runtime frame (runtime-drawer.tsx), so its header, tab
// order, Health opening block, job history and restart control are the same as
// the discovery agent's:
//   Overview · Discoveries · Health · Jobs · Logs · Settings
// All data comes from the typed sensor-manager client. queries.ts is shared /
// off-limits, so every query/mutation hook this panel needs lives locally here.
//
// Real-field discipline (see ## sensor feature work): the Health tab OMITS
// cpu_usage_percent (a goroutine-ratio estimate) and errors_count (hardcoded 0)
// even though they're in the schema — they'd mislead. The command-type picker
// excludes set_log_level / trigger_scan (no-ops). Platform/in-cluster sensors
// send no health/commands/config/cert telemetry, so they show only Overview +
// Discoveries.
import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { sensorManagerComponents } from '@vistasecurity/api-contract';
import { PermissionGate, TENANT_PERMISSIONS, usePermissions } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { Icon, MetaRow, SectionLabel, Pill, Modal, ModalField } from '../../components/ui';
import { DTable, CellMono, CellTxt, Note, sensorOnline, relTime } from './kit';
import { summariseHostObservations } from './host-observations';
import { SettingsPanel } from './settings-panel';
import { useSensorConfig, useSensorConfigHistory, useSaveSensorConfig } from './sensor-config-queries';
import { ConfigHistorySection } from './config-history';
import type { SettingValue } from './agent-config';
import {
  RuntimeDrawer, ConnectionHealth, JobHistoryList, MetricCard, PayloadBlock, DetailRow, RestartControl,
  ManagedHereNote, Muted, fmtTs, LogExportPanel, type LogExportState, type RecentJob, type RuntimeTabKey,
} from './runtime-drawer';
// useDiscoveryCounts is the one hook this drawer borrows from the shared
// queries.ts (everything else lives locally per the note above) — it's a
// cheap bulk id→count fetch already shared by sensors-page.tsx and
// command-center.tsx, and duplicating it here would mean a second cache entry
// for the same data.
import { useDiscoveryCounts } from './queries';
import { unwrap } from '../../lib/api-result';

type Sensor = sensorManagerComponents['schemas']['Sensor'];
type HealthMetrics = sensorManagerComponents['schemas']['SensorHealthMetrics'];
type SensorDiscovery = sensorManagerComponents['schemas']['SensorDiscovery'];
type SensorCertificate = sensorManagerComponents['schemas']['SensorCertificateResponse'];
type SensorCommand = sensorManagerComponents['schemas']['SensorCommand'];

// sensorHostAssetHref is the "Host" row's link target: the inventory asset
// for the host THIS sensor runs on, once its own self-report has resolved
// one (asset-inventory decision 9). null — and the row is omitted — for an
// older sensor build that never sent a `host` block, or before its first
// self-observation has landed.
export function sensorHostAssetHref(sensor: Pick<Sensor, 'asset_id'>): string | null {
  const id = sensor.asset_id;
  if (!id) return null;
  return `/inventory/assets/${id}`;
}

// ---- formatters -----------------------------------------------------------
function fmtUptime(sec?: number | null): string {
  if (sec == null) return '—';
  const s = Math.max(0, Math.floor(sec));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function fmtBytes(bytes?: number | null): string {
  if (bytes == null) return '—';
  const mb = bytes / (1024 * 1024);
  if (mb >= 1024) return `${(mb / 1024).toFixed(1)} GB`;
  return `${mb.toFixed(0)} MB`;
}

function fmtNum(n?: number | null): string {
  return n == null ? '—' : n.toLocaleString();
}

// Compact label for a reporting interval (seconds) → "30s" / "5m" / "1h".
function fmtIntervalSecs(sec?: number | null): string {
  if (sec == null) return '—';
  if (sec % 3600 === 0) return `${sec / 3600}h`;
  if (sec % 60 === 0) return `${sec / 60}m`;
  return `${sec}s`;
}

// Fixed menu of reporting-interval presets (seconds) — mirrors the backend
// models.AllowedReportingIntervals; the server rejects anything outside this set.
const REPORTING_INTERVAL_PRESETS: { value: number; label: string }[] = [
  { value: 30, label: '30 seconds' },
  { value: 60, label: '1 minute' },
  { value: 300, label: '5 minutes' },
  { value: 900, label: '15 minutes' },
  { value: 1800, label: '30 minutes' },
  { value: 3600, label: '1 hour' },
  { value: 7200, label: '2 hours' },
  { value: 14400, label: '4 hours' },
  { value: 28800, label: '8 hours' },
  { value: 43200, label: '12 hours' },
  { value: 86400, label: '24 hours' },
];

// ---- platform-sensor detection --------------------------------------------
// Platform/in-cluster sensors don't emit health/commands/config/cert telemetry,
// so those tabs would be empty. Match the admin handler's signature plus the
// tenant-side hints (system/platform tags, platform-* types).
function isPlatformSensorOf(s?: Sensor | null): boolean {
  if (!s) return false;
  const t = (s.sensor_type || '').toLowerCase();
  const p = (s.profile || '').toLowerCase();
  const plat = (s.platform || '').toLowerCase();
  const tags = (s.tags ?? []).map((x) => x.toLowerCase());
  if (plat.includes('platform') || t.includes('platform') || p.includes('platform')) return true;
  if (t === 'platform-discovery' || t === 'platform-device-agent') return true;
  if (tags.includes('system') || tags.includes('platform')) return true;
  return false;
}

// ---- local queries (queries.ts is off-limits) -----------------------------
function useSensorDetail(sensorId: string) {
  return useQuery({
    queryKey: ['discovery', 'sensor-detail', sensorId],
    queryFn: async () => {
      const { data, error } = await clients.sensors.GET('/sensors/{sensor_id}', { params: { path: { sensor_id: sensorId } } });
      if (error || !data) throw new Error('Failed to load sensor');
      return data;
    },
  });
}

function useSensorHealth(sensorId: string, enabled: boolean) {
  return useQuery({
    queryKey: ['discovery', 'sensor-health', sensorId],
    enabled,
    queryFn: async () => {
      const { data, error, response } = await clients.sensors.GET('/sensors/{sensor_id}/health', { params: { path: { sensor_id: sensorId } } });
      if (response.status === 404) return null; // no metrics yet
      if (error || !data) throw new Error('Failed to load health metrics');
      return data;
    },
  });
}

function useSensorHealthHistory(sensorId: string, since: string, enabled: boolean) {
  return useQuery({
    queryKey: ['discovery', 'sensor-health-history', sensorId, since],
    enabled,
    queryFn: async () => {
      const { data, error } = await clients.sensors.GET('/sensors/{sensor_id}/health/history', {
        params: { path: { sensor_id: sensorId }, query: { since, limit: 100 } },
      });
      if (error || !data) throw new Error('Failed to load health history');
      return data.metrics ?? [];
    },
  });
}

function useSensorDiscoveries(sensorId: string, limit: number, enabled: boolean) {
  return useQuery({
    queryKey: ['discovery', 'sensor-discoveries', sensorId, limit],
    enabled,
    queryFn: async () => {
      const { data, error } = await clients.sensors.GET('/sensors/{sensor_id}/discoveries', {
        params: { path: { sensor_id: sensorId }, query: { limit } },
      });
      if (error || !data) throw new Error('Failed to load discoveries');
      return data.discoveries ?? [];
    },
  });
}

function useSensorCertificate(sensorId: string, enabled: boolean) {
  return useQuery({
    queryKey: ['discovery', 'sensor-certificate', sensorId],
    enabled,
    queryFn: async () => {
      const { data, error, response } = await clients.sensors.GET('/sensors/{sensor_id}/certificate', { params: { path: { sensor_id: sensorId } } });
      if (response.status === 404) return null; // no cert — sensor may not have registered
      if (error || !data) throw new Error('Failed to load certificate');
      return data;
    },
  });
}

function useSensorCommands(sensorId: string, enabled: boolean) {
  return useQuery({
    queryKey: ['discovery', 'sensor-commands', sensorId],
    enabled,
    refetchInterval: 5000, // commands move through their lifecycle server-side
    queryFn: async () => {
      const { data, error } = await clients.sensors.GET('/sensors/{sensor_id}/commands', { params: { path: { sensor_id: sensorId } } });
      if (error || !data) throw new Error('Failed to load commands');
      return data.commands ?? [];
    },
  });
}

// ---------------------------------------------------------------------------
const SENSOR_TABS: readonly RuntimeTabKey[] = ['overview', 'discoveries', 'health', 'jobs', 'logs', 'settings'];
// Platform sensors send no health/commands/config/cert telemetry.
const PLATFORM_SENSOR_TABS: readonly RuntimeTabKey[] = ['overview', 'discoveries'];

export function SensorDetailDrawer({ sensor: row, onClose }: { sensor: Sensor; onClose: () => void }) {
  // Refetch the full sensor for fresh/complete fields (available_interfaces,
  // air_gapped, network_interfaces). Fall back to the list row while loading.
  const detailQ = useSensorDetail(row.id);
  const sensor = detailQ.data ?? row;
  const isPlatform = isPlatformSensorOf(sensor);
  const tabs = isPlatform ? PLATFORM_SENSOR_TABS : SENSOR_TABS;

  const [tab, setTab] = useState<RuntimeTabKey>('overview');
  const on = sensorOnline(sensor.status, sensor.last_heartbeat);

  return (
    <RuntimeDrawer
      icon="radar"
      eyebrow={isPlatform ? 'Platform sensor' : (sensor.sensor_type || sensor.profile || 'Sensor')}
      name={sensor.name}
      online={on}
      status={sensor.status}
      badges={<>
        {sensor.version && <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>v{sensor.version}</span>}
        {sensor.air_gapped && <Pill color="var(--app-t3)" style={{ fontSize: 10.5 }}>air-gapped</Pill>}
        {sensor.ip_address && <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{sensor.ip_address}</span>}
      </>}
      tabs={tabs}
      tab={tab}
      onTab={setTab}
      onClose={onClose}
    >
      {tab === 'overview' && <OverviewTab sensor={sensor} isPlatform={isPlatform} />}
      {tab === 'discoveries' && <DiscoveriesTab sensorId={sensor.id} />}
      {tab === 'health' && !isPlatform && <HealthTab sensor={sensor} />}
      {tab === 'jobs' && !isPlatform && <JobsTab sensorId={sensor.id} />}
      {tab === 'logs' && !isPlatform && <LogsTab sensorId={sensor.id} />}
      {tab === 'settings' && !isPlatform && <SettingsTab sensor={sensor} />}
    </RuntimeDrawer>
  );
}

// ==== Tab 1 — Overview =====================================================
function OverviewTab({ sensor, isPlatform }: { sensor: Sensor; isPlatform: boolean }) {
  const on = sensorOnline(sensor.status, sensor.last_heartbeat);
  // Uptime from latest health (skip for platform sensors — no telemetry).
  const healthQ = useSensorHealth(sensor.id, !isPlatform);
  const uptime = healthQ.data ? fmtUptime(healthQ.data.uptime_seconds) : '—';

  return (
    <>
      <SectionLabel icon="info">Summary</SectionLabel>
      <MetaRow k="Status" v={(sensor.status || 'unknown').replace('_', ' ')} />
      {/* "Last heartbeat" while online; flips to "Last seen X ago" once the
          sensor goes offline (the reaper sets that after missed heartbeats). */}
      <MetaRow k={on ? 'Last heartbeat' : 'Last seen'} v={relTime(sensor.last_heartbeat)} />
      {!isPlatform && <MetaRow k="Reporting interval" v={fmtIntervalSecs(sensor.reporting_interval)} />}
      <MetaRow k="Version" v={sensor.version ? 'v' + sensor.version : null} mono />
      <MetaRow k="IP address" v={sensor.ip_address} mono />
      {/* The asset for the HOST THIS SENSOR RUNS ON, once its own self-report
          has resolved one (asset-inventory decision 9) — absent for an older
          sensor build or before its first self-observation lands. */}
      {sensorHostAssetHref(sensor) && (
        <MetaRow
          k="Host"
          v={<Link to={sensorHostAssetHref(sensor)!} style={{ color: 'var(--accent)', fontWeight: 600 }}>View asset</Link>}
          title="The inventory asset for the host this sensor runs on"
        />
      )}
      {/* Only worth listing when the host has more than the primary — on a
          single-homed box the list would just repeat the row above. */}
      {(sensor.addresses?.length ?? 0) > 1 && (
        <div style={{ padding: '8px 0', borderBottom: '1px solid var(--app-border)' }}>
          <div style={{ fontSize: 11, color: 'var(--app-t3)', marginBottom: 5 }}>All addresses</div>
          {sensor.addresses!.map((a) => (
            <div key={`${a.interface_name}-${a.address}`} style={{ display: 'flex', justifyContent: 'space-between', gap: 10, padding: '2px 0' }}>
              <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t2)' }}>
                {a.address}{a.prefix_length ? `/${a.prefix_length}` : ''}
              </span>
              <span style={{ fontSize: 11, color: 'var(--app-t3)', whiteSpace: 'nowrap' }}>
                {a.interface_name}{a.is_primary ? ' · primary' : ''}
              </span>
            </div>
          ))}
        </div>
      )}
      <MetaRow k="Deployment" v={sensor.air_gapped ? 'Air-gapped' : 'Connected'} />
      {!isPlatform && <MetaRow k="Uptime" v={uptime} />}
      <MetaRow k="Monitored interfaces" v={(sensor.network_interfaces ?? []).join(', ') || 'none'} mono />
      {sensor.description && <MetaRow k="Description" v={sensor.description} />}
      {(sensor.tags?.length ?? 0) > 0 && (
        <div style={{ padding: '8px 0', borderBottom: '1px solid var(--app-border)', display: 'flex', gap: 5, flexWrap: 'wrap' }}>
          {sensor.tags!.map((tag) => <span key={tag} className="mono" style={{ fontSize: 11, color: 'var(--app-t2)', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', borderRadius: 6, padding: '2px 7px' }}>{tag}</span>)}
        </div>
      )}

      {!isPlatform && <CertificateCard sensorId={sensor.id} sensorName={sensor.name} />}
    </>
  );
}

// ---- Certificate status card ----------------------------------------------
function certStatus(cert: SensorCertificate): { label: string; color: string } {
  if (cert.is_revoked) return { label: 'Revoked', color: 'var(--danger)' };
  if (cert.is_expired) return { label: 'Expired', color: 'var(--danger)' };
  if (cert.days_until_expiry < 30) return { label: 'Expiring soon', color: 'var(--warn)' };
  return { label: 'Active', color: 'var(--ok)' };
}

function CertificateCard({ sensorId, sensorName }: { sensorId: string; sensorName: string }) {
  const certQ = useSensorCertificate(sensorId, true);
  const [revokeOpen, setRevokeOpen] = useState(false);

  const download = (pem: string) => {
    const blob = new Blob([pem], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${sensorName}-certificate.pem`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <SectionLabel icon="shield">Certificate</SectionLabel>
      {certQ.isLoading ? (
        <div style={{ fontSize: 12, color: 'var(--app-t3)', padding: '6px 0' }}>Loading certificate…</div>
      ) : certQ.isError ? (
        <div style={{ fontSize: 12, color: 'var(--danger-text)', padding: '6px 0' }}>Couldn't load the certificate.</div>
      ) : !certQ.data ? (
        <div style={{ fontSize: 12, color: 'var(--app-t3)', padding: '6px 0' }}>No certificate (sensor may not have registered yet).</div>
      ) : (() => {
        const cert = certQ.data;
        const st = certStatus(cert);
        return (
          <div className="panel" style={{ borderRadius: 12, padding: '14px 16px', marginTop: 6 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10 }}>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12.5, fontWeight: 600, color: st.color }}>
                <span style={{ width: 7, height: 7, borderRadius: 50, background: st.color }} />{st.label}
              </span>
              <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{cert.days_until_expiry}d left</span>
            </div>
            <MetaRow k="Serial" v={cert.serial_number} mono />
            <MetaRow k="Issued" v={fmtTs(cert.issued_at).slice(0, 10)} mono />
            <MetaRow k="Expires" v={fmtTs(cert.expires_at).slice(0, 10)} mono />
            {cert.revocation_reason && <MetaRow k="Revocation reason" v={cert.revocation_reason} />}
            <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
              <button className="ui-btn sm" onClick={() => download(cert.certificate_pem)} disabled={!cert.certificate_pem}>
                <Icon name="download" size={13} />Download
              </button>
              <PermissionGate permission={TENANT_PERMISSIONS.sensors.manage}>
                {!cert.is_revoked && (
                  <button className="ui-btn sm ghost" style={{ color: 'var(--danger-text)' }} onClick={() => setRevokeOpen(true)}>
                    <Icon name="x-circle" size={13} />Revoke
                  </button>
                )}
              </PermissionGate>
            </div>
          </div>
        );
      })()}

      <RevokeCertModal open={revokeOpen} sensorId={sensorId} onClose={() => setRevokeOpen(false)} />
    </>
  );
}

function RevokeCertModal({ open, sensorId, onClose }: { open: boolean; sensorId: string; onClose: () => void }) {
  const qc = useQueryClient();
  const [reason, setReason] = useState('');

  const revoke = useMutation({
    mutationFn: async () => {
      unwrap(await clients.sensors.POST('/sensors/{sensor_id}/certificates/revoke', {
        params: { path: { sensor_id: sensorId } },
        body: { reason: reason.trim() },
      }), 'Failed to revoke certificate');
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['discovery', 'sensor-certificate', sensorId] });
      setReason('');
      onClose();
    },
  });

  return (
    <Modal
      open={open}
      onClose={revoke.isPending ? undefined : onClose}
      dismissible={!revoke.isPending}
      size="sm"
      tone="danger"
      icon="x-circle"
      eyebrow="Certificate"
      title="Revoke certificate"
      description="Revoking immediately invalidates the sensor's certificate. A reason is required."
      primary={
        <button className="ui-btn" style={{ background: 'var(--danger)', color: '#fff', borderColor: 'var(--danger)' }} disabled={!reason.trim() || revoke.isPending} onClick={() => revoke.mutate()}>
          {revoke.isPending ? 'Revoking…' : 'Revoke'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={revoke.isPending}>Cancel</button>}
      footerNote={revoke.isError ? <span style={{ color: 'var(--danger-text)' }}>{revoke.error.message}</span> : undefined}
    >
      <ModalField label="Reason" hint="e.g. compromised, rotated, manual.">
        <textarea
          data-autofocus
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          rows={3}
          placeholder="Why is this certificate being revoked?"
          style={{ width: '100%', padding: '9px 11px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12.5, outline: 'none', resize: 'vertical', lineHeight: 1.5 }}
        />
      </ModalField>
    </Modal>
  );
}

// ==== Tab 2 — Discoveries ==================================================
const DISCOVERY_COLS = [
  { label: 'Protocol', w: '1fr' },
  { label: 'Destination', w: '1.3fr' },
  { label: 'Port', w: '70px', align: 'right' as const },
  { label: 'Confidence', w: '90px', align: 'right' as const },
  { label: 'Timestamp', w: '1.3fr', align: 'right' as const },
];

function DiscoveriesTab({ sensorId }: { sensorId: string }) {
  const [limit, setLimit] = useState(50);
  const q = useSensorDiscoveries(sensorId, limit, true);
  const rows = q.data ?? [];

  return (
    <div style={{ marginTop: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 12 }}>
        <span style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>{q.isLoading ? 'Loading…' : `${rows.length} discoveries`}</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <select value={limit} onChange={(e) => setLimit(Number(e.target.value))} style={{ height: 30, padding: '0 8px', borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12, cursor: 'pointer' }}>
            <option value={20}>20</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
          </select>
          <button className="ui-btn sm ghost" onClick={() => q.refetch()} title="Refresh"><Icon name="history" size={13} /></button>
        </div>
      </div>
      {q.isError ? (
        <Note panel icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load discoveries" message={q.error instanceof Error ? q.error.message : 'Request failed'} />
      ) : q.isLoading ? (
        <Note panel icon="loader" tone="var(--app-t3)" title="Loading discoveries…" message=" " />
      ) : rows.length === 0 ? (
        <Note panel icon="radar" tone="var(--app-t3)" title="No discoveries" message="This sensor hasn't reported any discoveries yet." />
      ) : (
        <DTable
          cols={DISCOVERY_COLS}
          rows={rows}
          rowKey={(d: SensorDiscovery) => d.id}
          render={(d: SensorDiscovery) => (
            <>
              <CellTxt v={d.protocol} />
              <CellMono v={d.dest_ip} />
              <CellMono right v={d.port} />
              <CellMono right v={`${(d.confidence * 100).toFixed(0)}%`} />
              <CellMono right v={fmtTs(d.timestamp)} c="var(--app-t3)" />
            </>
          )}
        />
      )}
    </div>
  );
}

// ==== Tab 3 — Health =======================================================
const HISTORY_RANGES: { key: string; label: string; ms: number }[] = [
  { key: '1h', label: '1h', ms: 3600_000 },
  { key: '24h', label: '24h', ms: 86_400_000 },
  { key: '7d', label: '7d', ms: 7 * 86_400_000 },
];

const HISTORY_COLS = [
  { label: 'Time', w: '1.3fr' },
  { label: 'Memory', w: '1fr', align: 'right' as const },
  { label: 'Packets', w: '1fr', align: 'right' as const },
  { label: 'Discoveries', w: '1fr', align: 'right' as const },
  { label: 'Uptime', w: '1fr', align: 'right' as const },
];

function HealthTab({ sensor }: { sensor: Sensor }) {
  const sensorId = sensor.id;
  const healthQ = useSensorHealth(sensorId, true);
  const configQ = useSensorConfig(sensorId);
  // Cumulative discoveries for this sensor — the fleet row on Sensors & Agents
  // shows this same number as "Assets found". h.discoveries_made below is only
  // the latest heartbeat's PER-INTERVAL count, so labeling it as if cumulative
  // read as "Discoveries made: 0/1" beside a fleet row saying "4429" (M-8).
  const countsQ = useDiscoveryCounts();
  const totalDiscoveries = countsQ.data?.[sensorId];
  const [range, setRange] = useState('24h');
  const since = useMemo(() => {
    const r = HISTORY_RANGES.find((x) => x.key === range) ?? HISTORY_RANGES[1];
    return new Date(Date.now() - r.ms).toISOString();
  }, [range]);
  const histQ = useSensorHealthHistory(sensorId, since, true);
  const hist = histQ.data ?? [];

  // Passive host observations over the selected range. Null when no heartbeat
  // in the range reported the counters — an older sensor build, or host
  // observation switched off — in which case the whole block is omitted rather
  // than shown as zeroes: "not running" and "running and seeing nothing" must
  // not look the same.
  // Depends on histQ.data rather than the `hist` local: `?? []` builds a fresh
  // array every render, so memoising on it would recompute every time.
  const hostObs = useMemo(() => summariseHostObservations(histQ.data ?? []), [histQ.data]);
  const rangeLabel = HISTORY_RANGES.find((r) => r.key === range)?.label ?? '24h';

  return (
    <div>
      <ConnectionHealth
        noun="sensor"
        online={sensorOnline(sensor.status, sensor.last_heartbeat)}
        lastHeartbeat={sensor.last_heartbeat}
        version={sensor.version}
        configStatus={configQ.data?.status}
        configLoading={configQ.isLoading}
      />
      <SectionLabel icon="activity">Current</SectionLabel>
      {healthQ.isLoading ? (
        <div style={{ fontSize: 12, color: 'var(--app-t3)', padding: '6px 0' }}>Loading health…</div>
      ) : healthQ.isError ? (
        <div style={{ fontSize: 12, color: 'var(--danger-text)', padding: '6px 0' }}>Couldn't load health metrics.</div>
      ) : !healthQ.data ? (
        <div style={{ fontSize: 12, color: 'var(--app-t3)', padding: '6px 0' }}>No health metrics reported yet.</div>
      ) : (() => {
        const h = healthQ.data;
        return (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginTop: 6 }}>
              <MetricCard icon="clock" label="Uptime" value={fmtUptime(h.uptime_seconds)} />
              <MetricCard icon="database" label="Memory" value={fmtBytes(h.memory_usage_bytes)} />
              <MetricCard icon="radar" label="Packets captured" value={fmtNum(h.packets_captured)} />
              <MetricCard icon="search" label="Discoveries (last interval)" value={fmtNum(h.discoveries_made)} />
              <MetricCard icon="layers" label="Discoveries (total)" value={countsQ.isLoading ? '…' : fmtNum(totalDiscoveries)} />
            </div>
            <div style={{ fontSize: 10.5, color: 'var(--app-t3)', marginTop: 8 }}>as of {fmtTs(h.recorded_at)}</div>
          </>
        );
      })()}

      {hostObs && (
        <>
          <div style={{ margin: '20px 0 0' }}>
            <SectionLabel icon="radar">Host observations</SectionLabel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10, marginTop: 6 }}>
            {/* The counters are cumulative, so this is a DIFFERENCE across the
                range — and "since restart" when a restart inside the range makes
                the range's own figure unknowable. See host-observations.ts. */}
            <MetricCard
              icon="radar"
              label={hostObs.sinceRestart ? 'Hosts seen (since restart)' : `Hosts seen (${rangeLabel})`}
              value={fmtNum(hostObs.emitted)}
            />
            <MetricCard
              icon="alert-triangle"
              label={hostObs.sinceRestart ? 'Shed (since restart)' : `Shed (${rangeLabel})`}
              value={fmtNum(hostObs.dropped)}
            />
            <MetricCard icon="layers" label="Accumulating now" value={fmtNum(hostObs.pending)} />
          </div>
          <div style={{ fontSize: 10.5, color: 'var(--app-t3)', marginTop: 8 }}>
            Devices seen on the wire without connecting to them. Each becomes a pending asset in Approvals.
            {hostObs.dropped > 0 && ' Shed observations mean this segment is busier than the sensor is sized for.'}
          </div>
        </>
      )}

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, margin: '20px 0 8px' }}>
        <div className="eyebrow-app" style={{ display: 'flex', alignItems: 'center', gap: 7 }}><Icon name="activity" size={13} style={{ color: 'var(--accent)' }} />History</div>
        <div style={{ display: 'flex', gap: 4 }}>
          {HISTORY_RANGES.map((r) => (
            <button key={r.key} onClick={() => setRange(r.key)} className="ui-btn sm" style={{ background: range === r.key ? 'var(--app-panel2)' : 'transparent', color: range === r.key ? 'var(--app-t1)' : 'var(--app-t3)' }}>{r.label}</button>
          ))}
        </div>
      </div>
      {histQ.isError ? (
        <Note panel icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load history" message={histQ.error instanceof Error ? histQ.error.message : 'Request failed'} />
      ) : histQ.isLoading ? (
        <Note panel icon="loader" tone="var(--app-t3)" title="Loading history…" message=" " />
      ) : hist.length === 0 ? (
        <Note panel icon="activity" tone="var(--app-t3)" title="No history" message="No health metrics in this range." />
      ) : (
        <DTable
          cols={HISTORY_COLS}
          rows={hist}
          rowKey={(m: HealthMetrics) => m.id}
          render={(m: HealthMetrics) => (
            <>
              <CellMono v={fmtTs(m.recorded_at)} c="var(--app-t3)" />
              <CellMono right v={fmtBytes(m.memory_usage_bytes)} />
              <CellMono right v={fmtNum(m.packets_captured)} />
              <CellMono right v={fmtNum(m.discoveries_made)} />
              <CellMono right v={fmtUptime(m.uptime_seconds)} />
            </>
          )}
        />
      )}
    </div>
  );
}

// ==== Tab — Settings =========================================================
function SettingsTab({ sensor }: { sensor: Sensor }) {
  return (
    <div style={{ marginTop: 4 }}>
      {/* Managed settings first: they are what an operator came here to change,
          and they are the half that survives a restart of the sensor. The NIC
          picker, the sensor's own record and the restart control follow. */}
      <SensorSettingsSection sensor={sensor} />
      <ConfigSection sensor={sensor} />
      <SensorRestartSection sensorId={sensor.id} />
    </div>
  );
}

// Restart is a command to a sensor. sensors.update, not .manage: sensor-manager
// gates POST /sensors/:id/commands on SensorsUpdate, and a control the server
// would accept from a role must not be hidden from it.
function SensorRestartSection({ sensorId }: { sensorId: string }) {
  const qc = useQueryClient();
  const restart = useMutation({
    mutationFn: async () => {
      unwrap(await clients.sensors.POST('/sensors/{sensor_id}/commands', {
        params: { path: { sensor_id: sensorId } },
        body: { command_type: 'restart', payload: {} },
      }), 'Could not request a restart');
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['discovery', 'sensor-commands', sensorId] }),
  });
  return (
    <PermissionGate permission={TENANT_PERMISSIONS.sensors.update}>
      <RestartControl
        noun="sensor"
        caveat="The sensor exits at its next check-in and its process supervisor (systemd, Docker or Kubernetes) starts it again. A sensor launched by hand will stop instead of restarting."
        pending={restart.isPending}
        onConfirm={() => restart.mutate()}
        successNote={restart.isSuccess ? 'Requested. The restart shows in the Jobs tab once the sensor picks it up.' : undefined}
        error={restart.isError ? restart.error.message : null}
      />
    </PermissionGate>
  );
}

// ---- Control-plane-managed settings -------------------------------
function SensorSettingsSection({ sensor }: { sensor: Sensor }) {
  // Not destructured: relationships-tab.tsx records that destructuring the
  // permission hook's methods trips.
  const canEdit = usePermissions().hasPermission(TENANT_PERMISSIONS.sensors.update);
  const q = useSensorConfig(sensor.id);
  const save = useSaveSensorConfig(sensor.id);
  // Fetched only once opened: a drawer somebody glances at should not query an
  // audit table.
  const [historyOpen, setHistoryOpen] = useState(false);
  const history = useSensorConfigHistory(sensor.id, historyOpen);

  if (q.isLoading) return <Muted>Loading settings…</Muted>;
  if (q.isError || !q.data) return <Muted danger>Couldn't load this sensor's settings.</Muted>;

  return (
    <>
      <SettingsPanel
        settings={q.data.settings}
        status={q.data.status}
        version={q.data.version}
        scope="device"
        canEdit={canEdit}
        saving={save.isPending}
        save={(values: Record<string, SettingValue>, confirmed: boolean) => save.mutateAsync({ values, confirmed })}
      />
      <ManagedHereNote noun="sensor" canEdit={canEdit} />
      <ConfigHistorySection
        changes={history.data}
        isLoading={history.isLoading}
        isError={history.isError}
        onOpen={() => setHistoryOpen(true)}
      />
    </>
  );
}

// ---- Configuration --------------------------------------------------------
function ConfigSection({ sensor }: { sensor: Sensor }) {
  const qc = useQueryClient();
  const sensorId = sensor.id;

  const available = useMemo(() => sensor.available_interfaces ?? [], [sensor.available_interfaces]);
  const monitored = useMemo(() => sensor.network_interfaces ?? [], [sensor.network_interfaces]);

  // NIC selection is STAGED locally and applied with an explicit "Save NICs"
  // button — selecting a checkbox queues nothing until Save, so the user knows
  // a command is being sent to the sensor. `extraIfaces` holds names added by
  // hand that the host hasn't reported.
  const [extraIfaces, setExtraIfaces] = useState<string[]>([]);
  const [selected, setSelected] = useState<string[]>(monitored);
  const [addName, setAddName] = useState('');
  const [airGapped, setAirGapped] = useState(sensor.air_gapped);
  const [description, setDescription] = useState(sensor.description ?? '');
  const [tags, setTags] = useState((sensor.tags ?? []).join(', '));
  const [reportingInterval, setReportingInterval] = useState<number | null>(sensor.reporting_interval ?? null);

  // Re-sync the staged selection whenever the sensor data refreshes.
  useEffect(() => { setSelected(sensor.network_interfaces ?? []); setExtraIfaces([]); }, [sensor.network_interfaces]);
  useEffect(() => { setReportingInterval(sensor.reporting_interval ?? null); }, [sensor.reporting_interval]);

  const allIfaces = useMemo(() => Array.from(new Set([...available, ...monitored, ...extraIfaces])), [available, monitored, extraIfaces]);

  const invalidateSensor = () => {
    void qc.invalidateQueries({ queryKey: ['discovery', 'sensor-detail', sensorId] });
    void qc.invalidateQueries({ queryKey: ['discovery', 'sensors'] });
  };

  const toggleLocal = (iface: string) =>
    setSelected((s) => s.includes(iface) ? s.filter((x) => x !== iface) : [...s, iface]);

  const addByName = () => {
    const n = addName.trim();
    if (!n) return;
    if (!allIfaces.includes(n)) setExtraIfaces((e) => [...e, n]);
    setSelected((s) => s.includes(n) ? s : [...s, n]);
    setAddName('');
  };

  // Diff the staged selection against the sensor's current monitored set.
  const monitoredSet = useMemo(() => new Set(monitored), [monitored]);
  const selectedSet = useMemo(() => new Set(selected), [selected]);
  const toAdd = selected.filter((i) => !monitoredSet.has(i));
  const toRemove = monitored.filter((i) => !selectedSet.has(i));
  const nicsDirty = toAdd.length > 0 || toRemove.length > 0;

  const saveNics = useMutation({
    mutationFn: async () => {
      unwrap(await clients.sensors.PUT('/sensors/{sensor_id}/interfaces', {
        params: { path: { sensor_id: sensorId } },
        body: { add: toAdd, remove: toRemove },
      }), 'Failed to update interfaces');
    },
    onSuccess: () => {
      invalidateSensor();
      void qc.invalidateQueries({ queryKey: ['discovery', 'sensor-commands', sensorId] });
    },
  });

  const detect = useMutation({
    mutationFn: async () => {
      unwrap(await clients.sensors.POST('/sensors/{sensor_id}/commands', {
        params: { path: { sensor_id: sensorId } },
        body: { command_type: 'list_interfaces', payload: {} },
      }), 'Failed to queue detect command');
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['discovery', 'sensor-commands', sensorId] }),
  });

  const saveConfig = useMutation({
    mutationFn: async () => {
      const tagList = tags.split(',').map((t) => t.trim()).filter(Boolean);
      unwrap(await clients.sensors.PUT('/sensors/{sensor_id}/config', {
        params: { path: { sensor_id: sensorId } },
        body: { air_gapped: airGapped, description, tags: tagList },
      }), 'Failed to save configuration');
    },
    onSuccess: () => invalidateSensor(),
  });

  // Reporting interval has its own apply action (like Save NICs): it queues an
  // update_config command the sensor applies + reports back on its next check-in.
  const saveInterval = useMutation({
    mutationFn: async () => {
      if (reportingInterval == null) throw new Error('Pick an interval');
      unwrap(await clients.sensors.PUT('/sensors/{sensor_id}/config', {
        params: { path: { sensor_id: sensorId } },
        body: { reporting_interval: reportingInterval },
      }), 'Failed to update reporting interval');
    },
    onSuccess: () => {
      invalidateSensor();
      void qc.invalidateQueries({ queryKey: ['discovery', 'sensor-commands', sensorId] });
    },
  });
  const intervalDirty = reportingInterval !== (sensor.reporting_interval ?? null);

  const configDirty = airGapped !== sensor.air_gapped || description !== (sensor.description ?? '') || tags !== (sensor.tags ?? []).join(', ');

  // sensors.update, not .manage: sensor-manager gates PUT
  // /sensors/:id/interfaces and PUT /sensors/:id/config on SensorsUpdate.
  // sensors.manage guards only certificate regeneration/revocation.
  return (
    <PermissionGate permission={TENANT_PERMISSIONS.sensors.update} fallback={<div style={{ fontSize: 12, color: 'var(--app-t3)', padding: '12px 0' }}>You don't have permission to manage this sensor's configuration.</div>}>
      <SectionLabel icon="sliders-horizontal">Network interfaces</SectionLabel>
      <div style={{ fontSize: 10.5, color: 'var(--app-t3)', margin: '2px 0 4px' }}>Select the interfaces the sensor should monitor, then Save interfaces to send the change.</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
        {allIfaces.length === 0 && <div style={{ fontSize: 12, color: 'var(--app-t3)', padding: '6px 0' }}>No interfaces detected yet. Run "Detect" or add one by name.</div>}
        {allIfaces.map((iface) => {
          const isSelected = selected.includes(iface);
          const notDetected = !available.includes(iface);
          return (
            <label key={iface} style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '7px 0', borderBottom: '1px solid var(--app-border)', cursor: 'pointer' }}>
              <input type="checkbox" checked={isSelected} onChange={() => toggleLocal(iface)} />
              <span className="mono" style={{ fontSize: 12.5, color: 'var(--app-t1)', wordBreak: 'break-all' }}>{iface}</span>
              {notDetected && <span style={{ fontSize: 10.5, color: 'var(--warn)', flex: 'none' }}>not detected on host</span>}
            </label>
          );
        })}
      </div>
      <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
        <input value={addName} onChange={(e) => setAddName(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addByName(); } }} placeholder="add by name (e.g. eth0)" className="mono" style={{ flex: 1, minWidth: 0, height: 32, padding: '0 10px', borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12.5, outline: 'none' }} />
        <button className="ui-btn sm" disabled={!addName.trim()} onClick={addByName}><Icon name="plus" size={13} />Add</button>
        <button className="ui-btn sm ghost" disabled={detect.isPending} onClick={() => detect.mutate()} title="Queue a list_interfaces command (the result appears in the Jobs tab)"><Icon name="history" size={13} />Detect</button>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 12 }}>
        <button className="ui-btn accent sm" disabled={!nicsDirty || saveNics.isPending} onClick={() => saveNics.mutate()} style={{ opacity: !nicsDirty || saveNics.isPending ? 0.6 : 1 }}>
          <Icon name="check" size={13} />{saveNics.isPending ? 'Saving…' : 'Save interfaces'}
        </button>
        {nicsDirty && <span style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>Queues an update command — the sensor applies it on its next check-in.</span>}
        {saveNics.isError && <span style={{ fontSize: 11, color: 'var(--danger-text)' }}>{saveNics.error.message}</span>}
        {saveNics.isSuccess && !nicsDirty && <span style={{ fontSize: 11, color: 'var(--ok)' }}>Queued.</span>}
      </div>
      {detect.isSuccess && <div style={{ fontSize: 10.5, color: 'var(--app-t3)', marginTop: 6 }}>Detect queued — the result appears in the Jobs tab.</div>}

      <SectionLabel icon="settings">Settings</SectionLabel>
      <label style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '8px 0', borderBottom: '1px solid var(--app-border)', cursor: 'pointer' }}>
        <input type="checkbox" checked={airGapped} onChange={(e) => setAirGapped(e.target.checked)} />
        <span style={{ fontSize: 12.5, color: 'var(--app-t1)' }}>Air-gapped</span>
        <span style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>Sensor does not check in / heartbeat / stream discoveries.</span>
      </label>
      <div style={{ marginTop: 12 }}>
        <div style={{ fontSize: 12, color: 'var(--app-t3)', marginBottom: 5 }}>Description</div>
        <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} placeholder="Short description" style={{ width: '100%', padding: '8px 11px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12.5, outline: 'none', resize: 'vertical', lineHeight: 1.5 }} />
      </div>
      <div style={{ marginTop: 12 }}>
        <div style={{ fontSize: 12, color: 'var(--app-t3)', marginBottom: 5 }}>Tags <span style={{ fontSize: 10.5 }}>(comma-separated)</span></div>
        <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="prod, datacenter-east" style={{ width: '100%', height: 32, padding: '0 11px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12.5, outline: 'none' }} />
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 12 }}>
        <button className="ui-btn accent sm" disabled={!configDirty || saveConfig.isPending} onClick={() => saveConfig.mutate()} style={{ opacity: !configDirty || saveConfig.isPending ? 0.6 : 1 }}>
          <Icon name="check" size={13} />{saveConfig.isPending ? 'Saving…' : 'Save'}
        </button>
        {saveConfig.isError && <span style={{ fontSize: 11, color: 'var(--danger-text)' }}>{saveConfig.error.message}</span>}
        {saveConfig.isSuccess && !configDirty && <span style={{ fontSize: 11, color: 'var(--ok)' }}>Saved.</span>}
      </div>

      <SectionLabel icon="history">Reporting interval</SectionLabel>
      <div style={{ fontSize: 10.5, color: 'var(--app-t3)', margin: '2px 0 6px' }}>How often the sensor sends discovered data to the platform. Applied via a command on the sensor's next check-in.</div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <select
          value={reportingInterval ?? ''}
          onChange={(e) => setReportingInterval(e.target.value ? Number(e.target.value) : null)}
          style={{ flex: 1, minWidth: 0, height: 32, padding: '0 10px', borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12.5, outline: 'none' }}
        >
          {reportingInterval == null && <option value="">— not reported yet —</option>}
          {REPORTING_INTERVAL_PRESETS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
        </select>
        <button className="ui-btn accent sm" disabled={!intervalDirty || reportingInterval == null || saveInterval.isPending} onClick={() => saveInterval.mutate()} style={{ opacity: !intervalDirty || reportingInterval == null || saveInterval.isPending ? 0.6 : 1 }}>
          <Icon name="check" size={13} />{saveInterval.isPending ? 'Applying…' : 'Apply'}
        </button>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 8 }}>
        {intervalDirty && reportingInterval != null && <span style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>Queues a command — the sensor applies it on its next check-in.</span>}
        {saveInterval.isError && <span style={{ fontSize: 11, color: 'var(--danger-text)' }}>{saveInterval.error.message}</span>}
        {saveInterval.isSuccess && !intervalDirty && <span style={{ fontSize: 11, color: 'var(--ok)' }}>Queued — applies on next check-in.</span>}
      </div>
    </PermissionGate>
  );
}

// ==== Tab — Jobs ============================================================
// Everything the platform has asked this sensor to do — operator commands and
// the discovery jobs handed to it — newest first, last 10, one line each.
//
// Only these command types are real, sensor-handled actions an operator would
// send by hand. set_log_level and trigger_scan are no-ops / misleading, so they
// are excluded; restart and export_logs have their own controls (Settings and
// Logs), so they are not repeated here.
const COMMAND_TYPES = ['clear_cache', 'list_interfaces', 'update_interfaces', 'update_config'];

const COMMAND_LABELS: Record<string, string> = {
  restart: 'Restart',
  clear_cache: 'Clear cache',
  update_interfaces: 'Update interfaces',
  list_interfaces: 'Detect interfaces',
  export_logs: 'Export logs',
  update_config: 'Update configuration',
  set_log_level: 'Set log level',
  trigger_scan: 'Trigger scan',
  discovery_job: 'Discovery job',
  cancel_discovery_job: 'Cancel discovery job',
  resolve_identity_dns: 'Identity DNS lookup',
};

export function commandLabel(type?: string | null): string {
  if (!type) return 'Command';
  return COMMAND_LABELS[type] ?? type.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase());
}

function sensorCommandRow(cmd: SensorCommand): RecentJob {
  return {
    id: cmd.id,
    title: commandLabel(cmd.command_type),
    status: cmd.status,
    createdAt: cmd.created_at,
    error: cmd.error_message,
  };
}

function SensorCommandDetail({ cmd }: { cmd: SensorCommand }) {
  // Exported log lines are shown in the Logs tab, not as a JSON array here.
  const response = cmd.command_type === 'export_logs' && cmd.response_data
    ? { line_count: (cmd.response_data as { line_count?: number }).line_count, lines: 'shown in the Logs tab' }
    : cmd.response_data;
  return (
    <>
      <DetailRow k="Command" v={cmd.command_type} mono />
      <DetailRow k="Sent" v={fmtTs(cmd.created_at)} mono />
      <DetailRow k="Delivered" v={cmd.delivered_at ? fmtTs(cmd.delivered_at) : null} mono />
      <DetailRow k="Acknowledged" v={cmd.acknowledged_at ? fmtTs(cmd.acknowledged_at) : null} mono />
      <DetailRow k={(cmd.status || '').toLowerCase() === 'failed' ? 'Failed' : 'Completed'} v={cmd.completed_at ? fmtTs(cmd.completed_at) : null} mono />
      <PayloadBlock label="Payload" value={cmd.payload} />
      <PayloadBlock label="Response" value={response} />
    </>
  );
}

function JobsTab({ sensorId }: { sensorId: string }) {
  const q = useSensorCommands(sensorId, true);
  const commands = q.data ?? [];
  const byId = new Map(commands.map((c) => [c.id, c]));
  return (
    <>
      <SendCommandSection sensorId={sensorId} />
      <JobHistoryList
        jobs={commands.map(sensorCommandRow)}
        isLoading={q.isLoading}
        isError={q.isError}
        emptyText="No jobs have been sent to this sensor."
        renderDetail={(id) => <SensorCommandDetail cmd={byId.get(id)!} />}
      />
    </>
  );
}

function SendCommandSection({ sensorId }: { sensorId: string }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [commandType, setCommandType] = useState(COMMAND_TYPES[0]);
  const [payloadText, setPayloadText] = useState('{}');
  const [payloadErr, setPayloadErr] = useState<string | null>(null);

  const send = useMutation({
    mutationFn: async () => {
      let payload: Record<string, unknown> = {};
      try {
        payload = payloadText.trim() ? JSON.parse(payloadText) : {};
      } catch {
        throw new Error('Payload is not valid JSON');
      }
      unwrap(await clients.sensors.POST('/sensors/{sensor_id}/commands', {
        params: { path: { sensor_id: sensorId } },
        body: { command_type: commandType, payload },
      }), 'Failed to queue command');
    },
    onSuccess: () => {
      setPayloadText('{}');
      void qc.invalidateQueries({ queryKey: ['discovery', 'sensor-commands', sensorId] });
    },
  });

  const validatePayload = (text: string) => {
    setPayloadText(text);
    if (!text.trim()) { setPayloadErr(null); return; }
    try { JSON.parse(text); setPayloadErr(null); } catch { setPayloadErr('Invalid JSON'); }
  };

  // sensors.update: POST /sensors/:id/commands is gated on SensorsUpdate. No
  // fallback text: a viewer still has the history below, and a line saying what
  // they cannot do is noise above it.
  return (
    <PermissionGate permission={TENANT_PERMISSIONS.sensors.update}>
      <div style={{ marginTop: 14 }}>
        {!open ? (
          <button className="ui-btn sm ghost" onClick={() => setOpen(true)}>
            <Icon name="terminal" size={13} />Send a command
          </button>
        ) : (
          <div className="panel" style={{ borderRadius: 10, padding: '12px 13px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <select aria-label="Command" value={commandType} onChange={(e) => setCommandType(e.target.value)} style={{ flex: 1, minWidth: 0, height: 32, padding: '0 8px', borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12.5, cursor: 'pointer' }}>
                {COMMAND_TYPES.map((t) => <option key={t} value={t}>{commandLabel(t)}</option>)}
              </select>
              <button className="ui-btn sm ghost" onClick={() => setOpen(false)} title="Close"><Icon name="x" size={13} /></button>
            </div>
            <div style={{ marginTop: 8 }}>
              <div style={{ fontSize: 11, color: 'var(--app-t3)', marginBottom: 5 }}>Payload (JSON, optional)</div>
              <textarea value={payloadText} onChange={(e) => validatePayload(e.target.value)} rows={2} className="mono" style={{ width: '100%', padding: '8px 11px', borderRadius: 9, border: `1px solid ${payloadErr ? 'var(--danger)' : 'var(--app-border2)'}`, background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12, outline: 'none', resize: 'vertical', lineHeight: 1.5 }} />
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 8 }}>
              <button className="ui-btn accent sm" disabled={!!payloadErr || send.isPending} onClick={() => send.mutate()} style={{ opacity: !!payloadErr || send.isPending ? 0.6 : 1 }}>
                <Icon name="send" size={13} />{send.isPending ? 'Queuing…' : 'Send'}
              </button>
              {payloadErr && <span style={{ fontSize: 11, color: 'var(--danger-text)' }}>{payloadErr}</span>}
              {send.isError && <span style={{ fontSize: 11, color: 'var(--danger-text)' }}>{send.error.message}</span>}
              {send.isSuccess && <span style={{ fontSize: 11, color: 'var(--ok)' }}>Queued — it runs at the sensor's next check-in.</span>}
            </div>
          </div>
        )}
      </div>
    </PermissionGate>
  );
}

// ==== Tab — Logs ============================================================
// The sensor keeps its recent log lines in memory and returns them in reply to
// an export_logs command. This tab sends that command and shows the newest
// reply as text — the lines used to arrive as a JSON array inside the command
// history.

export function latestLogExport(commands: SensorCommand[]): SensorCommand | undefined {
  // The list is newest first; the first export_logs is the latest request.
  return commands.find((c) => c.command_type === 'export_logs');
}

export function logLinesOf(cmd: SensorCommand | undefined): string[] | null {
  const lines = (cmd?.response_data as { lines?: unknown } | null | undefined)?.lines;
  return Array.isArray(lines) ? lines.map((l) => String(l)) : null;
}

function LogsTab({ sensorId }: { sensorId: string }) {
  const qc = useQueryClient();
  const q = useSensorCommands(sensorId, true);
  const canRequest = usePermissions().hasPermission(TENANT_PERMISSIONS.sensors.update);
  const [lineCount, setLineCount] = useState(200);
  const latest = latestLogExport(q.data ?? []);
  const lines = logLinesOf(latest);
  const settled = ['completed', 'failed', 'error', 'success', 'expired'].includes((latest?.status || '').toLowerCase());

  const request = useMutation({
    mutationFn: async () => {
      unwrap(await clients.sensors.POST('/sensors/{sensor_id}/commands', {
        params: { path: { sensor_id: sensorId } },
        body: { command_type: 'export_logs', payload: { lines: lineCount } },
      }), 'Could not request the logs');
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['discovery', 'sensor-commands', sensorId] }),
  });

  const state: LogExportState = q.isError
    ? { kind: 'error', message: "Couldn't load the logs." }
    : q.isLoading
      ? { kind: 'loading' }
      : !latest
        ? { kind: 'none' }
        : !settled
          ? { kind: 'waiting', requestedAt: latest.created_at }
          : latest.error_message || !lines
            ? { kind: 'failed', message: latest.error_message || 'The sensor replied without log lines.' }
            : { kind: 'ready', lines, receivedAt: latest.completed_at ?? latest.acknowledged_at };

  return (
    <LogExportPanel
      noun="sensor"
      state={state}
      canRequest={canRequest}
      lineCount={lineCount}
      onLineCount={setLineCount}
      onFetch={() => request.mutate()}
      fetching={request.isPending}
      fetchError={request.isError ? request.error.message : null}
    />
  );
}
