// The faceplate's crypto overlay (DCIM BUILD_PLAN row 3.4, ADR-0010 D10): how
// a port is tinted by the crypto observed behind it.
//
// The colour is not chosen here. A certified score maps to its risk band
// through the generated ratings module (`riskLevelFromScore` from
// @vistasecurity/primitives/ratings, the twin of shared/riskbands) and the band
// to its token through components/ui/risk's LEVEL_COLOR — the same pair every
// risk badge (and the rack elevation's overlay) uses. No threshold is written
// in this file.
//
// Three-valued: nothing observed is not clean (no tint, said so); observed but
// not certified is "not assessed" (grey), never Informational.
import { riskLevelFromScore, strengthLabel, type RiskLevel } from '@vistasecurity/primitives/ratings';
import { LEVEL_COLOR } from '../../../components/ui/risk';
import type { InterfacePosture } from './cabling-queries';

export type PortOverlay =
  | { kind: 'risk'; band: RiskLevel; color: string; label: string; weakProtocol: boolean }
  | { kind: 'unassessed'; color: string; label: string; weakProtocol: boolean }
  | { kind: 'none'; color: null; label: string; weakProtocol: false };

export const UNASSESSED_COLOR = 'var(--app-t3)';

export function portOverlay(p: InterfacePosture | null | undefined): PortOverlay {
  if (!p || p.configurations === 0) return { kind: 'none', color: null, label: 'Nothing cryptographic observed behind this port', weakProtocol: false };
  const n = p.configurations;
  const what = `${n} crypto configuration${n === 1 ? '' : 's'}`;
  if (p.assessed && p.worst_score != null) {
    const band = riskLevelFromScore(p.worst_score);
    return { kind: 'risk', band, color: LEVEL_COLOR[band], label: `${band} (risk ${p.worst_score}) · ${what}`, weakProtocol: p.weak_protocol };
  }
  const weakest = p.weakest_strength ? strengthLabel(p.weakest_strength) : null;
  return {
    kind: 'unassessed', color: UNASSESSED_COLOR,
    label: `Not assessed · ${what}${weakest ? ` · weakest component ${weakest}` : ''}`, weakProtocol: p.weak_protocol,
  };
}

/** The hover text: the overlay line, then the configuration behind it. */
export function overlayTooltip(name: string, p: InterfacePosture | null | undefined): string {
  const o = portOverlay(p);
  const lines = [name, o.label];
  const w = p?.worst_configuration;
  if (w) {
    const bits = [w.protocol, w.protocol_version, w.cipher_suite].filter(Boolean).join(' · ');
    lines.push(`${bits}${w.port != null ? ` on port ${w.port}` : ''}`);
  }
  if (p?.weak_protocol) lines.push('Weak protocol version in use');
  return lines.join('\n');
}
