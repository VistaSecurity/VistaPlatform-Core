// The Active Scan dialog: one place that starts a person's scan of
// assets — the bulk action bar on Inventory → All assets / Stale, the asset
// drawer and the full asset page all open it. It carries what Discovery →
// Active Scan used to (that page is retired):
//
// • "Run from": Auto (the observing sensor, else one on its
//     segment, else the platform) · Platform sensor · one named tenant sensor.
// • The outside-your-registered-networks question ( W5.13b): the API
//     answers 422 naming those assets BEFORE anything is stamped or
//     dispatched for them, and "Scan anyway" resends ONLY those assets with
//     the confirmation. The old page resent every asset it was asked about,
//     including ones a partial first pass had already dispatched (C.4).
//   • The selection refusals (409 count changed, 413 over the cap).
//
// The permission follows the action, not the executor: assets.update for all
// three executors; confirming an external scan additionally needs
// discovery.create, which the server enforces.
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { Link } from 'react-router';
import { clients } from '../../lib/clients';
import { Modal } from '../../components/ui';
import { useSensors } from '../discovery/queries';
import { choiceFromValue, describeScanResult, runFromOptions, type ActiveScanRequest, type ActiveScanResponse } from '../discovery/active-scan-run-from';
import { TargetVerdictError, describeExternalAsset, externalConfirmTitle, targetVerdict, type ExternalAssetTarget } from '../discovery/discover-targets';
import { assetsLabel, overCapReason, selectedCount, selectionBody, selectionRefusal, type AssetSelection } from './asset-selection';

/** What a scan request is: the selection, the executor, and the confirmation. */
export function scanBody(sel: AssetSelection, runFrom: string, confirmed: boolean): ActiveScanRequest {
  const choice = choiceFromValue(runFrom);
  return {
    ...selectionBody(sel),
    run_from: choice.run_from,
    ...(choice.sensor_id ? { sensor_id: choice.sensor_id } : {}),
    ...(confirmed ? { external_targets_confirmed: true } : {}),
  };
}

/**
 * The selection "Scan anyway" sends: only the assets the API asked about.
 * Everything else in the first request was either dispatched already or
 * reported as not scanned — sending it again would scan it twice.
 */
export function confirmSelection(targets: readonly ExternalAssetTarget[]): AssetSelection {
  const ids = new Set(targets.map((t) => t.asset_id).filter((id): id is string => !!id));
  return ids.size ? { kind: 'ids', ids } : { kind: 'none' };
}

type ScanError = Error & { partial?: ActiveScanResponse };

export function ScanDialog({ open, selection, onClose, onStarted }: {
  open: boolean;
  selection: AssetSelection;
  onClose: () => void;
  /** Every response that dispatched something — including the partial jobs
   *  of a 422, so a job that started is never silently dropped. */
  onStarted?: (r: ActiveScanResponse) => void;
}) {
  const qc = useQueryClient();
  const sensorsQ = useSensors();
  const runFrom = runFromOptions(sensorsQ.data, { loading: sensorsQ.isLoading, error: sensorsQ.isError });
  const [picked, setPicked] = useState<string | null>(null);
  // What the person picked while it is still on offer; otherwise the fleet's
  // default. Derived, so the select and the request never disagree.
  const choice = picked !== null && runFrom.options.some((o) => o.value === picked) ? picked : runFrom.defaultValue;
  const [confirm, setConfirm] = useState<ExternalAssetTarget[] | null>(null);
  const [failure, setFailure] = useState<string | null>(null);

  const n = selectedCount(selection);
  const overCap = overCapReason(selection, 'scan');

  const close = () => { setConfirm(null); setFailure(null); onClose(); };

  const scan = useMutation({
    mutationFn: async ({ sel, confirmed }: { sel: AssetSelection; confirmed: boolean }) => {
      const { data, error, response } = await clients.inventory.POST('/infrastructure-assets/scan', { body: scanBody(sel, choice, confirmed) });
      if (error || !data) {
        const verdict = targetVerdict(response.status, error);
        if (verdict.kind === 'unconfirmed') {
          const e: ScanError = new TargetVerdictError(verdict);
          // A 422 can follow jobs that DID start for other assets.
          const partial = error as Partial<ActiveScanResponse> | undefined;
          if (partial?.jobs?.length) e.partial = { message: '', job_id: partial.job_id ?? '', count: partial.count ?? 0, jobs: partial.jobs, skipped: partial.skipped ?? [] };
          throw e;
        }
        const refusal = selectionRefusal(response.status, error);
        if (refusal) throw new Error(refusal);
        const e = error as { error?: string; details?: string } | undefined;
        throw new Error(e?.details ?? e?.error ?? `Failed to scan (${response.status})`);
      }
      return data;
    },
    onSuccess: (r) => {
      const d = describeScanResult(r);
      if (d.tone === 'success') toast.success(d.text);
      else if (d.tone === 'warning') toast(d.text, { icon: '⚠️' });
      else toast.error(d.text);
      onStarted?.(r);
      close();
    },
    onError: (e: ScanError) => {
      if (e.partial) onStarted?.(e.partial);
      if (e instanceof TargetVerdictError && e.verdict.kind === 'unconfirmed') {
        setConfirm(e.verdict.targets);
        return;
      }
      setFailure(e.message);
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['inventory'] });
      void qc.invalidateQueries({ queryKey: ['asset-detail'] });
      void qc.invalidateQueries({ queryKey: ['discovery', 'scan-jobs'] });
    },
  });

  if (confirm) {
    return (
      <Modal
        open={open}
        onClose={scan.isPending ? undefined : close}
        dismissible={!scan.isPending}
        size="md"
        tone="danger"
        icon="alert-triangle"
        eyebrow="Active Scan"
        title="Scan outside your registered networks?"
        primary={
          <button className="ui-btn accent" disabled={scan.isPending} onClick={() => scan.mutate({ sel: confirmSelection(confirm), confirmed: true })}>
            {scan.isPending ? 'Scanning…' : 'Scan anyway'}
          </button>
        }
        secondary={<button className="ui-btn" disabled={scan.isPending} onClick={close}>Cancel</button>}
        footerNote={failure ? <span style={{ color: 'var(--danger-text)' }}>{failure}</span> : undefined}
      >
        <div role="alertdialog" aria-labelledby="scan-external-title">
          <div id="scan-external-title" style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--app-t1)', marginBottom: 10 }}>
            {externalConfirmTitle(confirm.length)}
          </div>
          <ul className="mono" style={{ margin: '0 0 10px', paddingLeft: 18, fontSize: 12, color: 'var(--app-t2)', maxHeight: 220, overflowY: 'auto' }}>
            {confirm.map((t) => <li key={t.asset_id ?? t.target}>{describeExternalAsset(t)}</li>)}
          </ul>
          <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>
            Only these assets are sent again. Nothing outside your registered networks is ever scanned automatically — only when you confirm it here.
            Scanning these also needs the discovery permission, and is recorded in your organization&apos;s audit log.
          </div>
        </div>
      </Modal>
    );
  }

  return (
    <Modal
      open={open}
      onClose={scan.isPending ? undefined : close}
      dismissible={!scan.isPending}
      size="md"
      icon="radar"
      eyebrow="Active Scan"
      title={`Scan ${assetsLabel(n)}`}
      description="Probe the selected assets now and catalog their cryptography. Results flow back through discovery; the jobs appear below the list and under Discovery → Discovery Jobs."
      primary={
        <button className="ui-btn accent" disabled={scan.isPending || runFrom.loading || n === 0 || overCap !== null} onClick={() => scan.mutate({ sel: selection, confirmed: false })}>
          {scan.isPending ? 'Scanning…' : `Scan ${assetsLabel(n)}`}
        </button>
      }
      secondary={<button className="ui-btn" disabled={scan.isPending} onClick={close}>Cancel</button>}
      footerNote={failure ? <span style={{ color: 'var(--danger-text)' }}>{failure}</span> : undefined}
    >
      <label style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12.5, color: 'var(--app-t2)' }}>
        Run from
        <select
          aria-label="Run from"
          className="ui-select"
          value={choice}
          disabled={runFrom.loading || scan.isPending}
          onChange={(e) => setPicked(e.target.value)}
          style={{ minWidth: 220 }}
        >
          {runFrom.options.map((o) => (
            <option key={o.value} value={o.value} disabled={o.disabled} title={o.hint}>{o.label}</option>
          ))}
        </select>
      </label>
      {runFrom.error && (
        <p style={{ margin: '10px 0 0', fontSize: 12, color: 'var(--warn)' }}>
          The sensor list could not be loaded, so the scan runs from the platform sensor. Reopen this dialog to choose a tenant sensor.
        </p>
      )}
      {runFrom.noTenantSensors && (
        <p style={{ margin: '10px 0 0', fontSize: 12, color: 'var(--app-t3)' }}>
          No tenant sensors are registered, so the scan runs from the platform sensor — which only reaches hosts the platform can route to.
          Register one under <Link to="/discovery/sensors">Sensors &amp; Agents</Link> to scan hosts from inside your network.
        </p>
      )}
      {choice === 'auto' && !runFrom.loading && !runFrom.noTenantSensors && (
        <p style={{ margin: '10px 0 0', fontSize: 12, color: 'var(--app-t3)' }}>
          Each asset is scanned from the tenant sensor that saw it, else one on its network segment, else the platform sensor.
          If the sensor that saw it is offline, another online sensor on the same segment takes it; with none, it is not scanned
          (never from the platform instead) and is listed with the reason.
        </p>
      )}
      {overCap && <p role="alert" style={{ margin: '10px 0 0', fontSize: 12, color: 'var(--danger-text)' }}>{overCap}</p>}
    </Modal>
  );
}
