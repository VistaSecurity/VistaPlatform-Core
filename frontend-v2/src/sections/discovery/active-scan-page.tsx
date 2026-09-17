import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Link } from 'react-router';
import { clients } from '../../lib/clients';
import { Icon } from '../../components/ui';
import { DTable, CellMono, CellTxt, PageWrap, queryNote, relTime } from './kit';
import { useSensors, useUnscannedAssets } from './queries';
import { assetIdentity, classLabel, primaryAddressPort } from '../inventory/asset-shape';
import { describeScanResult, runFromOptions, scanRequestBody } from './active-scan-run-from';
import { ActiveScanJobsPanel, type SkippedAsset, type StartedScan } from './active-scan-jobs-panel';

// Discovery → Active Scan () — coverage surface for the active inventory:
// monitoring assets that have never been actively scanned. Run a TLS probe per asset (or
// all at once); the scan approves + dispatches, and results flow back through the discovery
// pipeline to catalog/verify their crypto. Pending assets are handled in Approvals;
// just-imported assets get a scan prompt in the import wizard.
//
// "Run from" chooses the executor: Auto sends each asset to the tenant
// sensor that observed it (else one on its segment, else the platform),
// Platform sensor runs everything from the cluster, or one named tenant sensor
// runs everything. The permission is the same assets.update for all three —
// the permission follows the action, not the executor.

const COLS = [
  { label: 'Asset', w: '1.4fr' },
  { label: 'Address', w: '1fr' },
  { label: 'Class', w: '1fr' },
  { label: 'Segment', w: '1fr' },
  { label: 'Status', w: '120px' },
  { label: 'Last seen', w: '100px' },
  { label: '', w: '120px', align: 'right' as const },
];

export function ActiveScanPage() {
  const q = useUnscannedAssets();
  const sensorsQ = useSensors();
  const qc = useQueryClient();
  const assets = q.data ?? [];

  const runFrom = runFromOptions(sensorsQ.data, { loading: sensorsQ.isLoading, error: sensorsQ.isError });
  const [picked, setPicked] = useState<string | null>(null);
  const [started, setStarted] = useState<StartedScan[]>([]);
  const [skipped, setSkipped] = useState<SkippedAsset[]>([]);
  // What the operator picked, as long as it is still on offer; otherwise the
  // fleet's default (Auto once sensors have loaded, Platform until then, or
  // after a chosen sensor was deleted). Derived rather than synced in an
  // effect, so there is no render where the select and the request disagree.
  const choice = picked !== null && runFrom.options.some((o) => o.value === picked) ? picked : runFrom.defaultValue;

  const scan = useMutation({
    mutationFn: async (ids: string[]) => {
      const { data, error, response } = await clients.inventory.POST('/infrastructure-assets/scan', { body: scanRequestBody(ids, choice) });
      if (error || !data) {
        const detail = (error as { error?: string } | undefined)?.error;
        throw new Error(detail ?? `Failed to scan asset${ids.length === 1 ? '' : 's'} (${response.status})`);
      }
      return data;
    },
    onSuccess: (r) => {
      const d = describeScanResult(r);
      if (d.tone === 'success') toast.success(d.text);
      else if (d.tone === 'warning') toast(d.text, { icon: '⚠️' });
      else toast.error(d.text);
      // The page's own job feedback: every job this scan started, newest
      // first, polled while it runs. The toast fades; this does not.
      const at = new Date().toISOString();
      setStarted((prev) => [
        ...(r.jobs ?? []).map((j) => ({ jobId: j.job_id, executor: j.executor, sensorName: j.sensor_name, count: j.count, startedAt: at })),
        ...prev,
      ].slice(0, 20));
      setSkipped((r.skipped ?? []).map((s) => ({ assetId: s.asset_id, reason: s.reason })));
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Scan failed'),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['discovery', 'unscanned-assets'] });
      void qc.invalidateQueries({ queryKey: ['discovery', 'scan-jobs'] });
      void qc.invalidateQueries({ queryKey: ['inventory'] });
    },
  });

  const note = queryNote(q, assets.length === 0, {
    thing: 'unscanned assets',
    emptyTitle: 'Everything has been scanned',
    emptyMessage: 'Every active asset has been actively scanned at least once. New or imported assets appear here until you scan them.',
  });

  return (
    <PageWrap title="Active Scan" count={q.isLoading ? '' : assets.length}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14, flexWrap: 'wrap' }}>
        <p style={{ margin: 0, fontSize: 13, color: 'var(--app-t3)' }}>
          Assets that have never been actively scanned. Run a TLS probe to catalog and verify their cryptography — results flow back through discovery.
        </p>
        <div style={{ flex: 1 }} />
        <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 12.5, color: 'var(--app-t2)' }}>
          Run from
          <select
            aria-label="Run from"
            className="ui-select"
            value={choice}
            disabled={runFrom.loading || scan.isPending}
            onChange={(e) => setPicked(e.target.value)}
            style={{ minWidth: 200 }}
          >
            {runFrom.options.map((o) => (
              <option key={o.value} value={o.value} disabled={o.disabled} title={o.hint}>{o.label}</option>
            ))}
          </select>
        </label>
        {assets.length > 0 && (
          <PermissionGate permission={TENANT_PERMISSIONS.assets.update}>
            <button className="ui-btn sm accent" disabled={scan.isPending || runFrom.loading} onClick={() => scan.mutate(assets.map((a) => a.id))}>
              <Icon name="radar" />{scan.isPending ? 'Scanning…' : `Scan all (${assets.length})`}
            </button>
          </PermissionGate>
        )}
      </div>

      {/* Every state of the "Run from" control the spec names, said out loud. */}
      {runFrom.error && (
        <p style={{ margin: '0 0 12px', fontSize: 12, color: 'var(--warn)' }}>
          The sensor list could not be loaded, so scans run from the platform sensor. Reload to choose a tenant sensor.
        </p>
      )}
      {runFrom.noTenantSensors && (
        <p style={{ margin: '0 0 12px', fontSize: 12, color: 'var(--app-t3)' }}>
          No tenant sensors are registered, so scans run from the platform sensor — which only reaches hosts the platform can route to.
          Register one under <Link to="/discovery/sensors">Sensors &amp; Agents</Link> to scan hosts from inside your network.
        </p>
      )}

      <ActiveScanJobsPanel scans={started} skipped={skipped} />

      {note ?? (
        <DTable
          cols={COLS}
          rows={assets}
          rowKey={(a) => a.id}
          render={(a) => (
            <>
              <CellMono v={assetIdentity(a).primary} />
              {/* The PRIMARY ENDPOINT's address and port, or blank. An asset
                  with no network face has nothing to scan an address on, and
                  showing a made-up one is what the old `port` column did. */}
              <CellMono v={primaryAddressPort(a)} c="var(--app-t3)" />
              <CellTxt v={classLabel(a.class_key)} />
              <CellTxt v={a.network_segment_name || a.business_unit} />
              <CellTxt v={a.asset_status} />
              <CellTxt v={relTime(a.last_seen_at)} c="var(--app-t3)" />
              <span style={{ textAlign: 'right', display: 'inline-flex', gap: 6, justifyContent: 'flex-end' }}>
                <PermissionGate permission={TENANT_PERMISSIONS.assets.update} fallback={<span style={{ fontSize: 11, color: 'var(--app-t3)' }}>—</span>}>
                  <button className="ui-btn sm" disabled={scan.isPending || runFrom.loading} onClick={() => scan.mutate([a.id])}>
                    <Icon name="radar" />Scan
                  </button>
                </PermissionGate>
              </span>
            </>
          )}
        />
      )}
    </PageWrap>
  );
}
