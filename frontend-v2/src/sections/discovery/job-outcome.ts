import type { deviceInterrogationComponents } from '@vistasecurity/api-contract';

// What a device/cloud interrogation run produced, as one line of text. Shown
// under the job's status on Discovery → Discovery Jobs. This was the Job Logs
// page's line until that page was folded into Discovery Jobs: it listed the
// same runs in a narrower form, and nothing it said may be lost in the fold.

type EnumerationCounts = deviceInterrogationComponents['schemas']['CloudEnumerationCounts'];
type CloudIdentitySummary = deviceInterrogationComponents['schemas']['CloudIdentitySummary'];
type HostInventoryCounts = deviceInterrogationComponents['schemas']['HostInventoryCounts'];

export function cloudIdentitySummary(identity: CloudIdentitySummary | undefined): string | null {
  if (!identity) return null;
  return [
    `${identity.assets_created} created, ${identity.assets_matched} matched`,
    identity.observations_retained ? `${identity.observations_retained} observations retained — awaiting identity resolution` : null,
    identity.approval_pending ? `${identity.approval_pending} awaiting approval` : null,
    identity.conflicts ? `${identity.conflicts} identity conflicts` : null,
    identity.rejected_inputs ? `${identity.rejected_inputs} rejected inputs` : null,
  ].filter(Boolean).join(' · ');
}

/**
 * The enumeration half of a cloud discovery run, as one log-line fragment.
 *
 * `undefined` means the run did not enumerate — the integration has it off, or
 * the job is not a cloud discovery — and the fragment is omitted. All-zero
 * means it ran and the account was empty, which is a different statement and
 * says so ("no compute found"). Flattening the two would make "we did not
 * look" and "there was nothing there" the same line.
 *
 * Exported for the unit test: this is the only place the two are told apart.
 */
export function enumerationSummary(e: EnumerationCounts | undefined): string | null {
  if (!e) return null;
  const count = (n: number, one: string, many: string) => (n === 1 ? `1 ${one}` : `${n} ${many}`);
  const parts = [
    e.instances ? count(e.instances, 'instance', 'instances') : null,
    e.networks ? count(e.networks, 'network', 'networks') : null,
    e.subnets ? count(e.subnets, 'subnet', 'subnets') : null,
    e.security_groups ? count(e.security_groups, 'security group', 'security groups') : null,
  ].filter(Boolean);
  return parts.length ? parts.join(', ') : 'no compute found';
}

/**
 * The host-inventory half of a run, as one log-line fragment.
 *
 * `undefined` means the job is not a host inventory (or never reached the
 * consumer) and the fragment is omitted. A run that DID reach it always says
 * something, even when every number is zero — "collected nothing" is a real
 * outcome and the line has to be able to report it, because the failure this
 * whole workstream exists to avoid is a feature that silently does nothing.
 *
 * The package count is omitted when the collector's package step FAILED, rather
 * than rendered as "0 packages": a host whose package database could not be
 * read has not been enumerated, and saying zero would make the two look alike.
 *
 * `contested` leads, because it changes what the rest of the line MEANS: the
 * numbers describe a pending asset the engine created beside a merge proposal,
 * not a settled host.
 *
 * Exported for the unit test, like enumerationSummary above it.
 */
export function hostInventorySummary(h: HostInventoryCounts | undefined): string | null {
  if (!h) return null;
  // A run the consumer reached and could NOT materialise. The counts beside it
  // are what the consumer had assembled when it failed — 91 listeners it never
  // wrote — and rendering them made a failed run read "91 listeners", a
  // success for a host that was not in the inventory. The failure is the whole
  // line; nothing after it is true of the inventory.
  if (h.failed) return `host inventory NOT materialised — ${h.failed}`;
  if (h.identity_outcome === 'unresolved') return 'evidence retained — awaiting identity resolution in Discovery → Observations';
  const count = (n: number, one: string, many: string) => (n === 1 ? `1 ${one}` : `${n} ${many}`);
  const parts = [
    h.contested ? 'identity contested — merge proposal waiting' : null,
    h.packages != null ? count(h.packages, 'package', 'packages') : null,
    h.endpoints ? count(h.endpoints, 'listener', 'listeners') : null,
    h.facts ? count(h.facts, 'fact', 'facts') : null,
    h.installs_removed ? `${h.installs_removed} removed` : null,
  ].filter(Boolean);
  return parts.length ? parts.join(', ') : 'collected nothing';
}

type InterrogationJob = deviceInterrogationComponents['schemas']['InterrogationJob'];

/**
 * The outcome line for one interrogation run, or undefined when the run
 * reports nothing beyond its asset count (which has its own column).
 */
export function interrogationOutcome(job: InterrogationJob): string | undefined {
  const line = [
    enumerationSummary(job.enumeration),
    cloudIdentitySummary(job.identity),
    hostInventorySummary(job.host_inventory),
  ].filter(Boolean).join(' · ');
  return line || undefined;
}
