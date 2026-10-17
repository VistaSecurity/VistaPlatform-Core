// How a wireless LAN's authentication reads (DCIM BUILD_PLAN row 4.4): the
// scheme and cipher in words, and the catalogue's verdict on the cipher as a
// risk chip. The colour comes from the algorithms catalogue row the LAN points
// at (`algorithm_risk_score`, banded by `@vistasecurity/primitives/ratings`),
// never from a list in the UI. A LAN with no catalogue row - cipher `auto`, or
// no authentication recorded - is NOT ASSESSED, drawn dashed and grey; it is
// not drawn as clean.
import { riskLevelFromScore } from '@vistasecurity/primitives/ratings';
import { RiskChip } from '../../../components/ui';
import type { WirelessLan, WirelessLink } from '../ipam/ipam-queries';

export const AUTH_TYPE_LABEL: Record<string, string> = {
  open: 'Open (no encryption)',
  wep: 'WEP',
  'wpa-personal': 'WPA Personal (shared key)',
  'wpa-enterprise': 'WPA Enterprise (802.1X)',
};
export const AUTH_CIPHER_LABEL: Record<string, string> = { auto: 'Negotiated (AES or TKIP)', tkip: 'TKIP', aes: 'AES (CCMP)' };

type Authed = Pick<WirelessLan | WirelessLink, 'auth_type' | 'auth_cipher' | 'auth_psk_present' | 'algorithm_risk_score' | 'algorithm_strength'>;

/** "WPA Personal · AES (CCMP)", or "Authentication not reported". */
export function authText(l: Pick<Authed, 'auth_type' | 'auth_cipher'>): string {
  if (!l.auth_type) return 'Authentication not reported';
  const type = AUTH_TYPE_LABEL[l.auth_type] ?? l.auth_type;
  return l.auth_cipher ? `${type} · ${AUTH_CIPHER_LABEL[l.auth_cipher] ?? l.auth_cipher}` : type;
}

/** The catalogue risk of the LAN's cipher as a chip: banded when scored,
 *  "not assessed" otherwise. */
export function AuthRisk({ lan }: { lan: Authed }) {
  const score = lan.algorithm_risk_score;
  if (typeof score !== 'number') {
    return (
      <span data-testid="auth-risk" data-assessed="false" style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11.5, color: 'var(--app-t3)' }}>
        <RiskChip level="Informational" size={18} assessed={false} title="The cipher is not in the catalogue, or is negotiated: not assessed" />Not assessed
      </span>
    );
  }
  const level = riskLevelFromScore(score);
  return (
    <span data-testid="auth-risk" data-assessed="true" data-level={level} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11.5, color: 'var(--app-t2)' }}>
      <RiskChip level={level} size={18} title={`Catalogue risk ${score} (${lan.algorithm_strength ?? 'unrated'})`} />{level}
    </span>
  );
}

/** Whether a pre-shared key exists. The key itself is never held. */
export function keyText(l: Pick<Authed, 'auth_type' | 'auth_psk_present'>): string {
  if (l.auth_type === 'open') return 'No key';
  if (l.auth_psk_present) return 'Key set';
  return '—';
}
