// Discovery → Discovery Jobs → job detail: turning a cloud discovery's
// per-resource-type outcome into something a tenant can act on ( slice E).
//
// The distinction this whole file exists to preserve: **"we looked and there
// was nothing there" is not "we could not look."** Before this, both produced
// `success: true` and silence, and a revoked IAM permission looked exactly like
// an empty AWS account.
//
// Pure, out of the component, so every label and every rule is a table test —
// the same pattern scan-job-state.ts and unified-jobs.ts already use here.
import type { deviceInterrogationComponents } from '@vistasecurity/api-contract';

export type ResourceTypeOutcome = deviceInterrogationComponents['schemas']['JobResultResourceType'];
export type CollectorFailure = deviceInterrogationComponents['schemas']['JobResultCollectorFailure'];
export type RunOutcome = 'complete' | 'partial' | 'failed';

/** Display names for the resource types the Cloud modal offers. */
const TYPE_LABELS: Record<string, string> = {
  alb: 'Application load balancers',
  elb: 'Classic load balancers',
  nlb: 'Network load balancers',
  api_gateway: 'API Gateways',
  cloudfront: 'CloudFront distributions',
  kms: 'KMS keys',
  s3: 'S3 buckets',
  rds: 'RDS instances',
  key_vault: 'Key Vaults',
  storage_account: 'Storage accounts',
  app_gateway: 'Application Gateways',
  cloud_sql: 'Cloud SQL instances',
  cloud_storage: 'Cloud Storage buckets',
};

export function resourceTypeLabel(resourceType: string): string {
  return TYPE_LABELS[resourceType] ?? resourceType.replace(/_/g, ' ');
}

export type OutcomeTone = 'ok' | 'warn' | 'danger' | 'muted';

export interface OutcomeView {
  /** Short badge text. */
  label: string;
  tone: OutcomeTone;
  /** The count line — or the reason there isn't one. */
  detail: string;
  /** What the user should do, when there is something to do. */
  action?: string;
}

const REASON_ACTION: Record<string, string> = {
  access_denied:
    'The credentials for this account are not permitted to list this resource type. Grant the missing read permission and run the discovery again.',
  credentials:
    'The stored credentials were rejected. Update this cloud account’s credentials under Discovery → Cloud, then re-run.',
  throttled: 'The provider rate-limited the request. Re-running the discovery usually clears this.',
  region_unavailable: 'The account is not subscribed to this region, or the region name is not valid for this provider.',
  timeout: 'The provider did not answer in time. Re-run the discovery.',
  network: 'The platform could not reach the provider API. Check outbound network access, then re-run.',
  unknown: 'Re-run the discovery; if it persists, the provider message above is what to quote in a support request.',
};

/** What the user should do about a failure, keyed on our classification. */
export function failureAction(reason?: string): string {
  return REASON_ACTION[reason ?? 'unknown'] ?? REASON_ACTION.unknown;
}

/**
 * One resource type's row.
 *
 * `succeeded` with `found: 0` is deliberately worded as a positive statement —
 * "none in this account" — because that IS the finding. `failed` never claims
 * a count, because zero is not what was measured.
 */
export function outcomeView(o: ResourceTypeOutcome): OutcomeView {
  const failures = o.failures ?? [];
  const firstReason = failures[0]?.reason;

  switch (o.status) {
    case 'succeeded':
      return o.found > 0
        ? { label: 'Collected', tone: 'ok', detail: `${o.found} found` }
        : { label: 'Collected', tone: 'ok', detail: 'None in this account' };
    case 'partial':
      return {
        label: 'Partly collected',
        tone: 'warn',
        detail: `${o.found} found in ${o.scopes_succeeded} of ${o.scopes_attempted} regions — ${
          o.scopes_attempted - o.scopes_succeeded
        } could not be read`,
        action: failureAction(firstReason),
      };
    case 'failed':
      return {
        label: 'Could not collect',
        tone: 'danger',
        detail: 'Not measured — this is not the same as none',
        action: failureAction(firstReason),
      };
    case 'not_attempted':
    default:
      return {
        label: 'Not collected',
        tone: 'muted',
        detail: 'Requested, but this platform does not collect it for this provider yet',
      };
  }
}

/** One failure line: region, provider code, sanitized message. */
export function failureLine(f: CollectorFailure): string {
  const where = f.scope && f.scope !== 'global' ? f.scope : 'global';
  const code = f.code ? `${f.code}: ` : '';
  return `${where} — ${code}${f.message ?? 'no message'}`;
}

export interface RunBanner {
  tone: OutcomeTone;
  title: string;
  body: string;
}

/**
 * The banner at the top of the Outcome section.
 *
 * `undefined` when the run reported no verdict at all — which is NOT the same
 * as "everything succeeded", so nothing is asserted in that case.
 */
export function runBanner(outcome: string | undefined, types: ResourceTypeOutcome[]): RunBanner | undefined {
  if (!outcome) return undefined;
  const bad = types.filter((t) => t.status === 'failed' || t.status === 'partial');
  const names = bad.map((t) => resourceTypeLabel(t.resource_type).toLowerCase());
  const list = names.length ? names.join(', ') : 'some resource types';

  switch (outcome as RunOutcome) {
    case 'failed':
      return {
        tone: 'danger',
        title: 'Nothing could be collected',
        body: `Every resource type this discovery asked for failed (${list}). The inventory below is unchanged by this run — an empty result here means the account was not read, not that it is empty.`,
      };
    case 'partial':
      return {
        tone: 'warn',
        title: 'Collected in part',
        body: `Some resource types could not be read (${list}). What was collected is in Inventory; what failed is listed below with the provider's reason.`,
      };
    case 'complete':
    default:
      return {
        tone: 'ok',
        title: 'Everything requested was collected',
        body: 'Every resource type this discovery asked for was read successfully. A count of zero below means the account genuinely has none.',
      };
  }
}

/** True when the job detail has a cloud outcome worth rendering at all. */
export function hasResourceOutcomes(types: ResourceTypeOutcome[] | undefined): types is ResourceTypeOutcome[] {
  return Array.isArray(types) && types.length > 0;
}
