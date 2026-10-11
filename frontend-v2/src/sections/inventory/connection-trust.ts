// 3rd Party lens · certificate trust ( slice 3).
//
// `external_connections.trust_status` is being added by the inventory service
// so the lens reads the ORGANISATION's trust decisions rather than the
// verdict of whichever probe observed the connection. It is not in the pinned
// contract yet, so it is read defensively here and the chip shows only when
// the server sent a value.
//
// The probe's own hygiene flag for an unknown CA ("Certificate signed by an
// untrusted certificate authority (not in the system trust store …)") is the
// sensor's view, and it read as a verdict. It is reworded to say whose trust
// is meant and where to change it; once the server sends `trust_status`, the
// chip carries the platform's answer and the probe's flag is dropped, because
// the two can disagree (a CA the organisation trusted is still unknown to the
// sensor's host) and the organisation's answer is the one that counts.

/** The connection's centrally evaluated trust status, when the server sent one. */
export function connectionTrustStatus(cn: unknown): string | undefined {
  const v = (cn as { trust_status?: unknown } | null | undefined)?.trust_status;
  return typeof v === 'string' && v.trim() !== '' ? v : undefined;
}

/** How the probe's unknown-CA flag begins (inventory-service external_connections_service.go). */
const PROBE_UNTRUSTED_CA = 'Certificate signed by an untrusted certificate authority';

export const UNTRUSTED_CA_FLAG_TEXT =
  'Certificate signed by a certificate authority not trusted by your organisation — trust it in Settings → Policies → Trusted CAs if it is yours';

export function isProbeUntrustedCaFlag(flag: string): boolean {
  return flag.startsWith(PROBE_UNTRUSTED_CA);
}

/**
 * The hygiene flags as the row's tooltip shows them: the unknown-CA flag
 * reworded, or dropped when the connection carries a platform trust status.
 * Every other flag passes through unchanged.
 */
export function presentHygieneFlags(flags: readonly string[] | null | undefined, trustStatus: string | undefined): string[] {
  const out: string[] = [];
  for (const f of flags ?? []) {
    if (!isProbeUntrustedCaFlag(f)) out.push(f);
    else if (!trustStatus) out.push(UNTRUSTED_CA_FLAG_TEXT);
  }
  return out;
}
