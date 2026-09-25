// Why a 3rd-party connection shows no certificate ( W5.13).
//
// TLS 1.3 encrypts the certificate, so a passively observed connection only
// has one if a sensor read it with its own handshake — and sensors only do
// that for a third party when the tenant turned on "Actively enrich
// third-party TLS connections". Without this hint the Connections lens shows
// a bare "—" that reads like a fault. Pure, so the decision is testable
// without rendering the page.

import type { Setting } from '../discovery/agent-config';

export const CERT_NOT_COLLECTED_HINT = 'Certificate not collected: active enrichment of third parties is off';

/** True only when the tenant's sensor fleet defaults say the opt-in is OFF.
 *  Unknown (not loaded, no permission to read them, an older platform that
 *  does not have the setting) is not "off": the hint would then be a guess. */
export function thirdPartyEnrichmentOff(settings: Setting[] | undefined): boolean {
  const s = settings?.find((x) => x.key === 'third_party_tls_enrichment');
  return s !== undefined && s.value === false;
}

/** The hint for one connection, or undefined when it does not apply: the
 *  connection has a certificate, or it was elevated (an elevated endpoint is
 *  enriched regardless of the opt-in), or the opt-in is not known to be off. */
export function certNotCollectedHint(
  conn: { cert_not_after?: string | null; elevated_asset_id?: string | null },
  enrichmentOff: boolean,
): string | undefined {
  if (!enrichmentOff || conn.cert_not_after || conn.elevated_asset_id) return undefined;
  return CERT_NOT_COLLECTED_HINT;
}
