// The rack elevation's crypto overlay (DCIM row 2.5, ADR-0010 D10): how a
// device block is tinted by its worst OPEN finding, badged for an expiring
// certificate and marked for a weak protocol.
//
// The colour is not chosen here. A severity maps to its risk band through the
// generated ratings module (`RISK_BANDS` from @vistasecurity/primitives/ratings,
// the twin of shared/riskbands) and the band to its token through
// components/ui/risk's LEVEL_COLOR — the same pair every risk badge uses. No
// threshold is written in this file; the ladder guard would flag one.
import { RISK_BANDS, parseSeverity, severityLabel, type RiskLevel, type Severity } from '@vistasecurity/primitives/ratings';
import { LEVEL_COLOR } from '../../../components/ui/risk';

/** The posture the elevation endpoint returns with include=posture. */
export interface DevicePosture {
  assessed: boolean;
  open_findings: number;
  top_finding: { id: string; producer: string; kind: string; severity: string; score: number; summary: string } | null;
  weak_protocol: boolean;
  cert_expires_at: string | null;
}

/** Days within which a certificate expiry is badged (the server's window). */
export const CERT_EXPIRY_WINDOW_DAYS = 30;

/** The risk band a finding severity belongs to, from the generated bands. */
export function bandForSeverity(severity: string | null | undefined): RiskLevel | null {
  const s = severity ? parseSeverity(severity) : null;
  if (!s) return null;
  return RISK_BANDS.find((b) => b.severity === s)?.label ?? null;
}

export type OverlayState =
  | { kind: 'finding'; severity: Severity; band: RiskLevel; color: string; label: string }
  | { kind: 'clean'; color: string; label: string }
  | { kind: 'unassessed'; color: string; label: string }
  | { kind: 'unknown'; color: string; label: string };

/** How the overlay draws one device. "Not assessed" is never drawn as clean. */
export function overlayState(p: DevicePosture | null | undefined): OverlayState {
  if (!p) return { kind: 'unknown', color: 'var(--app-t3)', label: 'Posture not loaded' };
  const sev = p.top_finding ? parseSeverity(p.top_finding.severity) : null;
  const band = bandForSeverity(sev);
  if (sev && band) {
    const n = p.open_findings;
    return { kind: 'finding', severity: sev, band, color: LEVEL_COLOR[band], label: `${severityLabel(sev) ?? band} · ${n} open finding${n === 1 ? '' : 's'}` };
  }
  // An open finding whose severity is not one we know is still open: never
  // drawn as clean, never guessed into a band.
  if (p.top_finding || p.open_findings > 0) return { kind: 'unknown', color: 'var(--app-t3)', label: `${p.open_findings} open finding${p.open_findings === 1 ? '' : 's'}, severity not recognised` };
  if (!p.assessed) return { kind: 'unassessed', color: 'var(--app-t3)', label: 'Not assessed' };
  return { kind: 'clean', color: LEVEL_COLOR.Informational, label: 'No open findings' };
}

/** Whole days until the certificate expiry (negative once it has passed), or null. */
export function certDaysLeft(p: DevicePosture | null | undefined, now: Date = new Date()): number | null {
  if (!p?.cert_expires_at) return null;
  const t = new Date(p.cert_expires_at).getTime();
  if (Number.isNaN(t)) return null;
  return Math.floor((t - now.getTime()) / 86_400_000);
}

export function certBadgeText(days: number | null): string | null {
  if (days == null) return null;
  if (days < 0) return 'Certificate expired';
  if (days === 0) return 'Certificate expires today';
  return `Certificate expires in ${days} day${days === 1 ? '' : 's'}`;
}

/** The hover text for a block: the top finding first. */
export function overlayTooltip(name: string, p: DevicePosture | null | undefined, now: Date = new Date()): string {
  const s = overlayState(p);
  const lines = [name, s.label];
  if (p?.top_finding) lines.push(`Top finding: ${p.top_finding.summary}`);
  if (p?.weak_protocol) lines.push('Weak protocol version in use');
  const cert = certBadgeText(certDaysLeft(p, now));
  if (cert) lines.push(cert);
  return lines.join('\n');
}
