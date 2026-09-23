// VISTA Operations — Settings ▸ License & Usage: the MSP usage panel
// (edition-licensing spec PR 4, spec §1 "Usage panel" / "Usage reports table" /
// "Generate report modal" / "Delivery status").
//
// Shows this month's licence usage (licensed / current / peak tenants), the
// signed monthly usage reports with their key fingerprint and delivery status,
// a Generate-report modal (a closed month, or the current month as a
// never-billed preview) and Download (the stored, signed JSON, byte for byte).
//
// MSP-only: the License & Usage page renders this panel only when the install
// runs under an MSP licence. Delivery reads "Not configured" until the
// transmitter ships — reports are stored and downloadable only.
import { useMemo, useState } from 'react';
import toast from 'react-hot-toast';
import { AlertTriangle, Download, FileSignature, Gauge, RefreshCw } from 'lucide-react';
import { Modal, ModalField, modalInputStyle } from '../../components/ui/modal';
import { StatTile, Tag, num } from '../../components/ui/primitives';
import {
  NotMSPError,
  downloadLicenseUsageReport,
  errMsg,
  selectablePeriods,
  useGenerateLicenseUsageReport,
  useLicenseUsage,
  useLicenseUsageReports,
  type LicenseUsage,
  type LicenseUsageReport,
} from './license-usage-queries';

// ── formatting ────────────────────────────────────────────────────────────────

/** " 00:15 UTC" — reporting runs on UTC, so the UI says UTC. */
export function utcStamp(iso?: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
}

/** "September 2026" for a "2026-09" period. */
export function monthLabel(period: string): string {
  const [y, m] = period.split('-').map(Number);
  if (!y || !m) return period;
  return new Date(Date.UTC(y, m - 1, 1)).toLocaleString('en-US', { month: 'long', year: 'numeric', timeZone: 'UTC' });
}

/** A readable prefix of a key fingerprint; the full value is in the title. */
export function shortFingerprint(keyID: string): string {
  return (keyID.slice(0, 16).match(/.{1,4}/g) ?? []).join(' ');
}

const mutedCell = { textAlign: 'center' as const, padding: 36, color: 'var(--op-t3)' };

// ── usage summary ─────────────────────────────────────────────────────────────

function SkeletonBlock({ h = 64 }: { h?: number }) {
  return <div data-testid="skeleton" style={{ height: h, borderRadius: 'var(--r-md, 8px)', background: 'var(--op-track)', opacity: 0.55 }} />;
}

function UsageSummary() {
  const { data, isLoading, isError, error, refetch } = useLicenseUsage();

  let body;
  if (isLoading) {
    body = (
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 12 }} aria-busy="true">
        <SkeletonBlock /><SkeletonBlock /><SkeletonBlock /><SkeletonBlock />
      </div>
    );
  } else if (isError && error instanceof NotMSPError) {
    body = <div className="t-muted" style={{ fontSize: 12.5 }}>Usage reporting applies to MSP licences only. This install is not running under one.</div>;
  } else if (isError || !data) {
    body = (
      <div role="alert" style={{ fontSize: 12.5, color: 'var(--op-t2)', display: 'flex', alignItems: 'center', gap: 10 }}>
        <AlertTriangle size={14} color="var(--danger)" />
        {errMsg(error, 'Could not load licence usage')}
        <button className="op-btn sm" onClick={() => void refetch()}><RefreshCw size={12} /> Retry</button>
      </div>
    );
  } else {
    body = <UsageTiles u={data} />;
  }

  return (
    <div className="op-panel" style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <Gauge size={16} style={{ color: 'var(--op-t3)' }} />
        <span style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>Licence usage</span>
        {data && <span className="t-muted" style={{ fontSize: 12 }}>{monthLabel(data.period.start.slice(0, 7))} (UTC)</span>}
      </div>
      {body}
    </div>
  );
}

function UsageTiles({ u }: { u: LicenseUsage }) {
  const over = u.licensed_tenants != null && u.customer_tenants > u.licensed_tenants;
  return (
    <>
      {u.signing_key_dev && (
        <div role="alert" style={{ display: 'flex', gap: 8, alignItems: 'flex-start', fontSize: 12.5, color: 'var(--op-t2)', padding: '8px 10px', borderRadius: 'var(--r-btn)', border: '1px solid var(--warn, #d97706)' }}>
          <AlertTriangle size={14} color="var(--warn, #d97706)" style={{ flex: 'none', marginTop: 2 }} />
          Reports are signed with a development key kept in the database, because no install signing key is mounted.
          That is fine for evaluation, not for production — deploy with the Helm chart, which generates and keeps one.
        </div>
      )}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 12 }}>
        <StatTile label="Licensed tenants" value={u.licensed_tenants == null ? 'No cap' : num(u.licensed_tenants)}
          sub={u.licensed_tenants == null ? 'The licence sets no tenant limit' : 'Customer tenants the licence covers'} />
        <StatTile label="Current tenants" value={num(u.current_tenants)}
          sub={u.operator_tenants > 0 ? `${num(u.customer_tenants)} customer · ${num(u.operator_tenants)} operator` : `${num(u.customer_tenants)} customer`}
          accent={over ? 'var(--danger)' : undefined} />
        <StatTile label="Peak this period" value={num(u.peak_tenants)}
          sub={u.peak_at ? `at ${utcStamp(u.peak_at)}` : 'No snapshot yet this period'} />
        <StatTile label="Daily snapshots" value={`${num(u.snapshots_taken)} / ${num(u.snapshots_expected)}`}
          sub={u.snapshots_taken < u.snapshots_expected ? 'Missing days are reported as gaps' : 'Every day so far is recorded'} />
      </div>
      {u.current_tenants === 0 && (
        <div className="t-muted" style={{ fontSize: 12 }}>
          No tenants yet. Counts start with the first tenant; the daily snapshot still runs, so the month shows as recorded rather than missing.
        </div>
      )}
      <div className="t-muted" style={{ fontSize: 11.5, lineHeight: 1.7 }}>
        Next snapshot {utcStamp(u.next_snapshot_at)} · next monthly report {utcStamp(u.next_report_at)}
        <br />
        Install id <span className="mono">{u.install_id}</span> · signing key <span className="mono" title={u.signing_key_id}>{shortFingerprint(u.signing_key_id)}</span>
      </div>
    </>
  );
}

// ── reports table ─────────────────────────────────────────────────────────────

function DeliveryCell({ r, configured }: { r: LicenseUsageReport; configured: boolean }) {
  if (!configured) return <span className="t-muted">Not configured</span>;
  switch (r.delivery_status) {
    case 'delivered':
      return <Tag color="var(--ok)">Delivered</Tag>;
    case 'failed':
      return <span title={r.last_error ?? undefined}><Tag color="var(--danger)">Failed</Tag></span>;
    default:
      return <Tag color="var(--op-t3)">Pending</Tag>;
  }
}

function ReportsTable({ onGenerate }: { onGenerate: () => void }) {
  const { data, isLoading, isError, error, refetch } = useLicenseUsageReports();
  const [busy, setBusy] = useState<string | null>(null);
  const reports = data?.reports ?? [];
  const configured = data?.delivery.configured ?? false;

  const download = async (r: LicenseUsageReport) => {
    setBusy(r.report_id);
    try {
      await downloadLicenseUsageReport(r);
    } catch (e) {
      toast.error(errMsg(e, 'Download failed'));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="op-panel" style={{ overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '13px 16px', borderBottom: '1px solid var(--op-border)' }}>
        <FileSignature size={16} style={{ color: 'var(--op-t3)' }} />
        <span style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>Usage reports</span>
        <div style={{ flex: 1 }} />
        <button className="op-btn sm primary" onClick={onGenerate}>Generate report</button>
      </div>
      <table className="op-table">
        <thead>
          <tr><th>Period</th><th>Generated</th><th>Tenants</th><th>Key fingerprint</th><th>Delivery</th><th /></tr>
        </thead>
        <tbody>
          {isLoading && [0, 1, 2].map((i) => (
            <tr key={i} data-testid="skeleton-row"><td colSpan={6}><SkeletonBlock h={14} /></td></tr>
          ))}
          {isError && !isLoading && (
            <tr><td colSpan={6} role="alert" style={mutedCell}>
              {errMsg(error, 'Could not load usage reports')}
              <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => void refetch()}>Retry</button>
            </td></tr>
          )}
          {!isLoading && !isError && reports.length === 0 && (
            <tr><td colSpan={6} style={mutedCell}>No reports yet — the first is generated on the 1st of next month.</td></tr>
          )}
          {reports.map((r) => (
            <tr key={r.report_id}>
              <td>
                {monthLabel(r.period)}
                {!r.complete && <Tag color="var(--op-t3)" style={{ marginLeft: 8 }}>Preview</Tag>}
              </td>
              <td>
                {utcStamp(r.generated_at)}
                <div className="t-muted" style={{ fontSize: 11 }}>{r.generated_by === 'scheduler' ? 'Monthly schedule' : 'On demand'}</div>
              </td>
              <td className="op-num">{num(r.tenant_count)}</td>
              <td><span className="mono" title={r.signing_key_id}>{shortFingerprint(r.signing_key_id)}</span></td>
              <td><DeliveryCell r={r} configured={configured} /></td>
              <td style={{ textAlign: 'right' }}>
                <button className="op-btn ghost sm" disabled={busy === r.report_id} onClick={() => void download(r)} aria-label={`Download the ${r.period} report`}>
                  <Download size={12} /> Download
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="t-muted" style={{ fontSize: 11.5, lineHeight: 1.6, padding: '10px 16px', borderTop: '1px solid var(--op-border)' }}>
        A report holds counts and tenant ids only — no names, users, hosts or inventory. Previews (the current month so far) are never billed.
        {!configured && ' Automatic delivery to Vista Security is not configured: reports are stored here and in the reports volume, ready to download.'}
      </div>
    </div>
  );
}

// ── generate modal ────────────────────────────────────────────────────────────

function GenerateReportModal({ open, onClose, now }: { open: boolean; onClose: () => void; now: Date }) {
  const periods = useMemo(() => selectablePeriods(now), [now]);
  const [period, setPeriod] = useState(periods[1]?.value ?? periods[0]?.value ?? '');
  const [serverError, setServerError] = useState<string | null>(null);
  const generate = useGenerateLicenseUsageReport();
  const preview = periods.find((p) => p.value === period)?.preview ?? false;

  const close = () => { setServerError(null); onClose(); };
  const submit = () => {
    setServerError(null);
    generate.mutate({ period, complete: !preview }, {
      onSuccess: (res) => {
        toast.success(res.created
          ? `Report for ${monthLabel(res.report.period)} generated`
          : `The ${monthLabel(res.report.period)} report already exists — it is unchanged`);
        close();
      },
      onError: (e) => setServerError(errMsg(e, 'Could not generate the report')),
    });
  };

  return (
    <Modal
      open={open}
      onClose={close}
      title="Generate usage report"
      description="Builds and signs the report for one UTC month. A closed month's report is made once; asking again returns it."
      primaryLabel="Generate"
      onPrimary={submit}
      primaryDisabled={!period}
      primaryLoading={generate.isPending}
      footerNote={preview ? 'A month-to-date preview is never billed.' : undefined}
    >
      <ModalField label="Period">
        <select aria-label="Report period" value={period} onChange={(e) => setPeriod(e.target.value)} style={modalInputStyle}>
          {periods.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
        </select>
      </ModalField>
      {serverError && (
        <div role="alert" style={{ fontSize: 12.5, color: 'var(--danger)' }}>{serverError}</div>
      )}
    </Modal>
  );
}

// ── panel ─────────────────────────────────────────────────────────────────────

export function LicenseUsagePanel({ now = new Date() }: { now?: Date }) {
  const [generating, setGenerating] = useState(false);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <UsageSummary />
      <ReportsTable onGenerate={() => setGenerating(true)} />
      {generating && <GenerateReportModal open onClose={() => setGenerating(false)} now={now} />}
    </div>
  );
}
