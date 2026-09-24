// Settings → License & Usage (edition-licensing spec, PR 2).
//
//   • License card — every edition. The licence this install runs under, as
//     admin-service recorded it after verifying the token (GET /admin/license;
//     the token itself never leaves the server). Core: "Vista Platform Core —
//     no licence installed", and what it takes to get Enterprise — which
//     depends on the BUILD (see CoreUpgradeNote). Expiry warnings at 30, 14
//     and 7 days.
//   • Data retention — Enterprise only. The platform-wide cap every tenant's
//     retention resolves to: unlimited (the default) or N days / years. This is
// the DATA retention cap; log retention is a separate setting.
//   • MSP usage — MSP only: licensed / current / peak tenants and the signed
//     monthly usage reports (spec PR 4). See MspUsageExtensionPoint below.
import { useState } from 'react';
import { AlertTriangle, Database, KeyRound, RefreshCw } from 'lucide-react';
import toast from 'react-hot-toast';
import { PLATFORM_PERMISSIONS, usePlatformPermissions } from '@vistasecurity/primitives/platform-auth';
import { usePlatformEdition } from '../../lib/edition';
import { LicenseUsagePanel } from './license-usage-panel';
import {
  type RetentionUnit, expiryWarning, retentionDays, retentionForm, retentionLabel,
  useLicense, useRetention, useSaveRetention,
} from './license-queries';

function fmtDate(iso?: string | null): string {
  return iso ? new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) : '—';
}

function Panel({ icon, title, subtitle, children }: { icon: React.ReactNode; title: string; subtitle?: string; children: React.ReactNode }) {
  return (
    <div className="op-panel" style={{ padding: '20px 22px', marginBottom: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, borderBottom: '1px solid var(--op-border)', paddingBottom: 14, marginBottom: 14 }}>
        <div style={{ width: 34, height: 34, borderRadius: 'var(--r-btn)', background: 'color-mix(in srgb, var(--accent) 12%, transparent)', display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 'none' }}>
          {icon}
        </div>
        <div>
          <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 15, color: 'var(--op-t1)' }}>{title}</div>
          {subtitle && <div style={{ fontSize: 12, color: 'var(--op-t3)', marginTop: 2 }}>{subtitle}</div>}
        </div>
      </div>
      {children}
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, fontSize: 12.5, padding: '5px 0' }}>
      <span style={{ color: 'var(--op-t3)' }}>{label}</span>
      <span style={{ color: 'var(--op-t1)', fontWeight: 500, textAlign: 'right', minWidth: 0, overflowWrap: 'anywhere' }}>{value}</span>
    </div>
  );
}

export function SettingsLicensePage() {
  const license = useLicense();
  const isEnterprise = license.data?.edition === 'enterprise';
  return (
    <div className="op-fade" style={{ padding: '24px', maxWidth: 780 }}>
      <LicenseCard q={license} />
      {isEnterprise && <DataRetentionSection />}
      <MspUsageExtensionPoint />
    </div>
  );
}

/**
 * EXTENSION POINT — the MSP usage panel (spec PR 4: licensed / current / peak
 * tenants, the usage-report list and delivery status). Keep it the last section
 * on the page.
 *
 * Rendered only when the licence edition is KNOWN to be MSP. That is
 * `license === 'msp'` from the edition hook, not its `isMsp`: `isMsp` fails
 * open on an unreadable read-out (so billing surfaces survive a blip), which
 * here would show an Enterprise or Core operator a panel whose every request
 * is refused. The licence card above already reports an unreadable licence.
 */
function MspUsageExtensionPoint() {
  const { license } = usePlatformEdition();
  if (license !== 'msp') return null;
  return <LicenseUsagePanel />;
}

type LicenseQuery = ReturnType<typeof useLicense>;

export function LicenseCard({ q }: { q: LicenseQuery }) {
  // The BUILD edition (GET /admin/platform/edition), not the licence: it is
  // what decides whether installing a licence can do anything at all.
  const { edition: build } = usePlatformEdition();
  const icon = <KeyRound size={16} style={{ color: 'var(--op-accent)' }} />;
  if (q.isLoading) {
    return (
      <Panel icon={icon} title="License">
        <div data-testid="license-loading" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {[0, 1, 2].map((i) => <div key={i} style={{ height: 16, width: `${70 - i * 15}%`, borderRadius: 4, background: 'var(--op-panel2)' }} />)}
        </div>
      </Panel>
    );
  }
  if (q.isError || !q.data) {
    return (
      <Panel icon={icon} title="License">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12.5, color: 'var(--danger-text, var(--danger))' }}>
          <AlertTriangle size={15} />Could not read licence status
          <button className="op-btn sm" onClick={() => void q.refetch()}><RefreshCw size={13} />Retry</button>
        </div>
      </Panel>
    );
  }
  const info = q.data;
  if (info.status === 'none') {
    return (
      <Panel icon={icon} title="Vista Platform Core — no licence installed" subtitle="Every Core capability is available; paid features need a licence.">
        {build === 'core' ? <CoreUpgradeNote /> : (
          <div style={{ fontSize: 12.5, color: 'var(--op-t2)', lineHeight: 1.6 }}>
            To install a licence, store the token Vista Security issued you in the Secret the chart mounts
            (by default <span className="mono">vistaplatform-license</span>, key <span className="mono">token</span>).
            admin-service picks it up within ten minutes, or at once after a restart; this page then shows the
            edition, licensee and expiry. An MSP licence is issued for this install's ID, shown below.
          </div>
        )}
        {info.install_id && <Row label="Install ID" value={<span className="mono">{info.install_id}</span>} />}
      </Panel>
    );
  }

  const warn = info.status === 'expired' ? 7 : expiryWarning(info.days_left);
  return (
    <Panel icon={icon} title={info.status === 'expired' ? 'Licence expired' : info.display_name}
      subtitle={info.licensee ? `Licensed to ${info.licensee}` : undefined}>
      {warn !== null && (
        <div role="alert" data-warning={warn} style={{
          display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12, padding: '9px 12px', borderRadius: 'var(--r-sm)', fontSize: 12.5,
          background: warn === 7 ? 'color-mix(in srgb, var(--danger) 12%, transparent)' : 'color-mix(in srgb, var(--warn) 12%, transparent)',
          color: 'var(--op-t1)',
        }}>
          <AlertTriangle size={14} style={{ color: warn === 7 ? 'var(--danger)' : 'var(--warn)' }} />
          {info.status === 'expired'
            ? `The licence expired on ${fmtDate(info.expires_at)}. Every tenant has dropped to Vista Platform Core until a renewed licence is installed.`
            : `The licence expires in ${info.days_left} day${info.days_left === 1 ? '' : 's'} (${fmtDate(info.expires_at)}). Every tenant drops to Vista Platform Core then — ask Vista Security for a renewal.`}
        </div>
      )}
      <Row label="Edition" value={info.status === 'expired' ? `${info.licensed_edition ?? '—'} (expired)` : info.display_name} />
      <Row label="Licensee" value={info.licensee ?? '—'} />
      <Row label="Expires" value={fmtDate(info.expires_at)} />
      {info.status === 'active' && <Row label="Days left" value={info.days_left ?? '—'} />}
      <Row label="Issued" value={fmtDate(info.issued_at)} />
      <Row label="Last verified" value={fmtDate(info.verified_at)} />
      {info.max_tenants != null && <Row label="Licensed tenants" value={info.max_tenants} />}
      {info.install_id && <Row label="Install ID" value={<span className="mono">{info.install_id}</span>} />}
    </Panel>
  );
}

/**
 * What a Core BUILD (the Core images, built without the Enterprise code) needs
 * to become Enterprise. Telling this operator to "install a licence" would be
 * wrong: the Core admin-service has no licence verifier, so a token Secret is
 * mounted and never read, and the page would go on saying Core.
 *
 * Plain text, not a link. The console has no route to the documentation — no
 * other page links to it, and the Enterprise docs are not public — so a link
 * here would be the one dead link on the console. The guide is named instead.
 */
function CoreUpgradeNote() {
  return (
    <div data-testid="core-upgrade-note" style={{ fontSize: 12.5, color: 'var(--op-t2)', lineHeight: 1.6 }}>
      This install runs the Vista Platform Core images, which do not contain the Enterprise code, so a
      licence installed here would have no effect. Moving to Enterprise takes two things: upgrading this
      release to the Enterprise chart and images, and the licence Vista Security issues you. Your
      tenants and their data stay in place. Contact Vista Security: they name the Enterprise release
      that matches this one (the two are numbered separately) and send their guide, <strong
      style={{ color: 'var(--op-t1)' }}>Upgrading from Core</strong>, including the database backup to
      take first.
    </div>
  );
}

/**
 * Save a cap and phrase the outcome: the success toast, or the inline error.
 * Split out of the component so both states are testable without a DOM.
 */
export async function submitRetention(
  save: (maxDays: number | null) => Promise<{ max_days: number | null }>,
  maxDays: number | null,
): Promise<{ ok: boolean; message: string }> {
  try {
    const saved = await save(maxDays);
    return { ok: true, message: `Saved — data retention is now ${retentionLabel(saved.max_days).toLowerCase()}. Recorded in the audit log.` };
  } catch (e) {
    return { ok: false, message: e instanceof Error ? e.message : 'Could not save the retention setting' };
  }
}

export function DataRetentionSection() {
  const q = useRetention();
  const icon = <Database size={16} style={{ color: 'var(--op-accent)' }} />;
  const title = 'Data retention';
  const subtitle = 'How long every tenant\'s inventory and history may be kept. Log retention is a separate setting.';

  if (q.isLoading) {
    return <Panel icon={icon} title={title} subtitle={subtitle}><div data-testid="retention-loading" style={{ height: 16, width: '50%', borderRadius: 4, background: 'var(--op-panel2)' }} /></Panel>;
  }
  if (q.isError || !q.data) {
    return (
      <Panel icon={icon} title={title} subtitle={subtitle}>
        <div style={{ fontSize: 12.5, color: 'var(--danger-text, var(--danger))' }}>
          Could not read the retention setting. <button className="op-btn sm" onClick={() => void q.refetch()}>Retry</button>
        </div>
      </Panel>
    );
  }
  // Keyed on the saved value, so the form re-initialises from the server's
  // answer after every save instead of syncing state in an effect.
  return (
    <Panel icon={icon} title={title} subtitle={subtitle}>
      <RetentionForm key={String(q.data.max_days)} current={q.data.max_days} />
    </Panel>
  );
}

function RetentionForm({ current }: { current: number | null }) {
  const save = useSaveRetention();
  const perms = usePlatformPermissions();
  const canEdit = perms.hasPermission(PLATFORM_PERMISSIONS.platform.settings);
  const initial = retentionForm(current);
  const [mode, setMode] = useState<'unlimited' | 'cap'>(initial.mode);
  const [amount, setAmount] = useState(initial.amount);
  const [unit, setUnit] = useState<RetentionUnit>(initial.unit);
  const [error, setError] = useState<string | null>(null);

  const days = mode === 'unlimited' ? null : retentionDays(amount, unit);
  const invalid = mode === 'cap' && days === null;
  const unchanged = mode === 'unlimited' ? current == null : days === current;

  const onSave = async () => {
    setError(null);
    const res = await submitRetention((d) => save.mutateAsync(d), mode === 'unlimited' ? null : days);
    if (res.ok) toast.success(res.message);
    else setError(res.message);
  };

  const radio = (value: 'unlimited' | 'cap', label: string) => (
    <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--op-t1)', cursor: canEdit ? 'pointer' : 'default' }}>
      <input type="radio" name="retention-mode" value={value} checked={mode === value} disabled={!canEdit || save.isPending} onChange={() => setMode(value)} />
      {label}
    </label>
  );

  return (
    <>
      <div style={{ fontSize: 12.5, color: 'var(--op-t3)', marginBottom: 12 }}>Currently: <strong style={{ color: 'var(--op-t1)' }}>{retentionLabel(current)}</strong></div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {radio('unlimited', 'Unlimited (default)')}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          {radio('cap', 'Cap at')}
          <input
            aria-label="Retention amount"
            inputMode="numeric"
            value={amount}
            disabled={!canEdit || mode !== 'cap' || save.isPending}
            onChange={(e) => setAmount(e.target.value)}
            style={{ width: 90, padding: '6px 9px', borderRadius: 'var(--r-sm)', fontSize: 12.5, border: '1px solid var(--op-border)', background: 'var(--op-panel2)', color: 'var(--op-t1)' }}
          />
          <select aria-label="Retention unit" value={unit} disabled={!canEdit || mode !== 'cap' || save.isPending} onChange={(e) => setUnit(e.target.value as RetentionUnit)} className="op-chip" style={{ height: 30 }}>
            <option value="days">days</option>
            <option value="years">years</option>
          </select>
        </div>
      </div>
      {invalid && <div style={{ fontSize: 12, color: 'var(--warn)', marginTop: 8 }}>Enter a whole number: 1 to 36500 days, or up to 100 years.</div>}
      {error && <div role="alert" style={{ fontSize: 12, color: 'var(--danger-text, var(--danger))', marginTop: 8 }}>{error}</div>}
      {canEdit ? (
        <button className="op-btn accent sm" style={{ marginTop: 14 }} disabled={invalid || unchanged || save.isPending} onClick={() => void onSave()}>
          {save.isPending ? 'Saving…' : 'Save'}
        </button>
      ) : (
        <div style={{ fontSize: 11.5, color: 'var(--op-t3)', marginTop: 12 }}>Changing retention needs the platform.settings permission.</div>
      )}
    </>
  );
}
