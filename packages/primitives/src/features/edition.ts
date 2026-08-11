// Edition awareness — the second gate, alongside the feature-flag map.
//
// Two different things can hide an Enterprise capability from a user, and they
// are NOT interchangeable:
//
//  1. ENTITLEMENT — the deployment ships the code, but this tenant's plan does
//     not include the capability. Resolved by the feature-flag map
//     (`useFeature`). This is the gate to reach for whenever the capability has
//     a registered key: it is knowable BEFORE the request, so the doomed
//     request is never fired at all.
//
//  2. EDITION — the running binary is a Core build and the route does not
//     exist. A Core service does not 403 an Enterprise route; it never mounts
//     it, so the call 404s. See docsv4/internal/operations/
//     OPEN_SOURCE_CARVE_TRACKER.md §5.5 for the seam.
//
// (1) is always preferable. (2) is the fallback for capabilities that were
// carved out of Core but have NO registered entitlement key yet — as of the
// carve that is CMDB/ITSM sync (`inventory-service/ee/cmdbsync`) and SIEM
// export (`audit-service/ee/siemexport`). With no key there is nothing to
// consult before the call, so the client learns the edition FROM the 404 and
// turns a red "couldn't load" error into an honest "not in this edition"
// notice: one request, never retried, no broken page.
//
// When those keys are registered on all three surfaces (auth-service
// `knownFeatures` + the OpenAPI `FeatureFlags` closed shape + the `FeatureName`
// union here), those surfaces should move to (1) and drop the probe.

/** HTTP status a Core build answers for a route it never mounted. */
export const EDITION_UNAVAILABLE_STATUS = 404;

/**
 * A route that EXISTS but that this tenant is not entitled to. Distinct from
 * 404 (the route is absent because this is a Core build) — same UX outcome, two
 * different causes, and both must land on the upgrade state rather than a
 * generic error.
 */
export const EDITION_UNENTITLED_STATUS = 402;

/**
 * Thrown by a query function when the backing route is absent from the running
 * build. Distinct from a transport/permission failure so the UI can render an
 * edition notice instead of an error.
 */
export class EditionUnavailableError extends Error {
  /** Duck-typed marker so detection survives module duplication in a bundle. */
  readonly editionUnavailable = true as const;
  readonly capability: string;

  constructor(capability: string) {
    super(`${capability} is not available in this edition`);
    this.name = 'EditionUnavailableError';
    this.capability = capability;
  }
}

/** True when `error` says "this build does not ship that capability". */
export function isEditionUnavailable(error: unknown): boolean {
  if (error instanceof EditionUnavailableError) return true;
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { editionUnavailable?: unknown }).editionUnavailable === true
  );
}

/**
 * Guard for a COLLECTION-level typed-client response: a 404 on a collection
 * route can only mean the route is unmounted, never "that row is gone".
 *
 * Never use this on an item route (`/things/{id}`) — there a 404 legitimately
 * means the row does not exist, and treating that as an edition signal would
 * hide a real capability.
 */
export function assertEditionPresent(capability: string, response: { status: number }): void {
  if (
    response.status === EDITION_UNAVAILABLE_STATUS ||
    response.status === EDITION_UNENTITLED_STATUS
  ) {
    throw new EditionUnavailableError(capability);
  }
}

/**
 * `retry` predicate for an edition-probed query. An absent route is a settled
 * fact — retrying it just multiplies the 404s in the console.
 */
export function editionAwareRetry(max = 1) {
  return (failureCount: number, error: unknown): boolean =>
    !isEditionUnavailable(error) && failureCount < max;
}
