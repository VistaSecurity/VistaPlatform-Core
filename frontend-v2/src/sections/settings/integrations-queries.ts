// Settings · Integrations — shared edition-probe state for the Enterprise-only
// sections of the page, kept out of the components so the edition behaviour is
// unit testable (see edition-gating.test.ts).
//
// The Enterprise sections (NetBox, CMDB / ITSM sync — platform ADR-0002 M2 and
// M3) run in the Enterprise integration service, and their query factories live beside them in
// the Enterprise-only files netbox-queries.ts and cmdb-queries.ts. Each is
// FLAG-GATED first (the entitlement key is known before any request) and
// EDITION-PROBED as a backstop: an install without that service (404)
// or a stale/unentitled call (402) becomes an EditionUnavailableError, which is
// never retried and renders the upgrade card instead of a red failure.
import { isEditionUnavailable } from '@vistasecurity/primitives/features';

// siemIntegrationsQuery was removed with the H2 security fix (v1.0.0 audit):
// GET /siem/integrations now requires a PLATFORM identity, because SIEM
// integrations are platform-global config that fans every tenant's audit events
// out to every enabled receiver. No tenant surface may call it, so the query
// factory is gone rather than left to 403. admin-ui-v2 -> Security -> SIEM
// Export owns that read.

/**
 * What an edition-probed section should render.
 *
 *  - `loading`     — first fetch in flight
 *  - `unavailable` — the running build does not ship the capability ⇒ upgrade card
 *  - `error`       — a real failure ⇒ error card (retry is meaningful)
 *  - `ready`       — data is usable
 *
 * `unavailable` deliberately outranks `error`: an absent route is not a fault,
 * and showing "couldn't load" for it is exactly the broken-page UX being fixed.
 */
export type EditionSectionState = 'loading' | 'unavailable' | 'error' | 'ready';

export function editionSectionState(q: {
  isLoading: boolean;
  isError: boolean;
  error: unknown;
}): EditionSectionState {
  if (isEditionUnavailable(q.error)) return 'unavailable';
  if (q.isError) return 'error';
  if (q.isLoading) return 'loading';
  return 'ready';
}
