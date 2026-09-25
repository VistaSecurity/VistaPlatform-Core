// Collection warnings on an interrogation job ( W0.1, finding P-17).
//
// A collector that is refused an endpoint, meets a command its target does not
// have, or stops a table at its bound still returns everything else it read —
// and until these existed the job said "completed" with no hint that half the
// device was never looked at. The job detail lists them in its processing area:
// which endpoint or command, why, and what is missing because of it.
//
// Pure view logic, kept out of the component so each state can be pinned
// without rendering the modal.
import type { deviceInterrogationComponents } from '@vistasecurity/api-contract';

export type CollectionWarning = deviceInterrogationComponents['schemas']['JobResultCollectionWarning'];
type WarningReason = CollectionWarning['reason'];
type JobResults = deviceInterrogationComponents['schemas']['JobResultsResponse'];

// Every reason the API can send. Typed as a Record over the generated union, so
// a reason added to the spec without a label here fails the typecheck.
const REASON_LABEL: Record<WarningReason, string> = {
  permission_denied: 'Permission denied',
  not_supported: 'Not supported on this device or version',
  truncated: 'Truncated',
  timeout: 'Timed out',
  unreachable: 'Unreachable',
  parse_error: 'Response could not be read',
  error: 'Error',
};

/** The human label for a warning reason. Anything unrecognised reads as "Error". */
export function warningReasonLabel(reason: string | null | undefined): string {
  // An own-property check, not a bare lookup: `REASON_LABEL['constructor']`
  // is a function, not undefined.
  if (reason && Object.prototype.hasOwnProperty.call(REASON_LABEL, reason)) {
    return REASON_LABEL[reason as WarningReason];
  }
  return REASON_LABEL.error;
}

export type CollectionWarningsView =
  // Nothing to show: no warnings were raised (or the results have not loaded,
  // in which case the modal's own loading line covers it).
  | { state: 'hidden' }
  // The warnings exist but could not be read. Never rendered as "none".
  | { state: 'error' }
  | { state: 'list'; warnings: CollectionWarning[] };

/**
 * What the Collection warnings section shows for one job's results.
 *
 * `isError` is the results query's own failure: the warnings are part of that
 * payload, so a failed load is a failed load of the warnings too — and saying
 * nothing would read as "the collector had no trouble".
 */
export function collectionWarningsView(res: JobResults | undefined, isError: boolean): CollectionWarningsView {
  if (isError) return { state: 'error' };
  if (!res) return { state: 'hidden' };
  if (res.collection_warnings_unreadable) return { state: 'error' };
  const warnings = res.collection_warnings ?? [];
  if (!Array.isArray(warnings) || warnings.length === 0) return { state: 'hidden' };
  return { state: 'list', warnings };
}
