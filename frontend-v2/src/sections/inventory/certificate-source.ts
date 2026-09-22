// Where a certificate in the inventory came from.
//
// The Certificates lens lists every certificate the tenant has, and they no
// longer all arrive the same way. Three provenances now reach it:
//
//   cloud_api   a provider's API told us the certificate exists and is
//               configured on a resource. The provider issues and rotates it;
//               the tenant never holds its key, and there may be no PEM and no
//               fingerprint because the API returns metadata, not bytes.
//   discovery   bytes captured off the wire — a sensor's handshake, an active
//               probe. This is what was actually SERVED at the moment we
//               looked.
//   manual      a person uploaded it.
//
// The distinction matters for what a user does next. An expiring cloud-managed
// certificate is usually the provider's problem; an expiring observed one is
// usually theirs. Renewal advice that does not know the difference is wrong
// half the time.
//
// `unknown` and an absent value render NOTHING. "We did not record where this
// came from" is not a fourth provenance and must not be dressed up as one.

export type CertSourceBadge = {
  label: string;
  tone: string;
  detail: string;
};

export function certSourceBadge(dataSource: string | undefined | null): CertSourceBadge | null {
  switch ((dataSource ?? '').trim()) {
    case 'cloud_api':
      return {
        label: 'cloud-managed',
        tone: 'var(--accent)',
        detail: 'Reported by the cloud provider’s API. The provider issues and renews this certificate.',
      };
    case 'manual':
      return {
        label: 'uploaded',
        tone: 'var(--warn)',
        detail: 'Added by hand rather than discovered.',
      };
    case 'discovery':
      return {
        label: 'observed',
        tone: 'var(--app-t3)',
        detail: 'Captured on the wire — this is what the endpoint actually served.',
      };
    default:
      return null;
  }
}
