import type { inventoryComponents } from '@vistasecurity/api-contract';

type Observation = inventoryComponents['schemas']['IdentityObservation'];
const time = (value?: string | null) => value ? new Date(value).toLocaleString() : 'Not recorded';
const explanations: Record<string, string> = {
  admission_or_enrichment_paused: 'Identity processing or automatic enrichment is paused.',
  authorization_changed_before_dispatch: 'The permitted scope changed before this work started.',
  authorized_probe_completed_identity_requires_corroboration: 'The permitted probe completed, but more evidence is needed to establish identity.',
  dns_did_not_provide_authorized_address: 'DNS did not return an address in a permitted network.',
  evidence_linked_existing_asset_enrichment_applies: 'This evidence is linked. Further enrichment follows the asset’s policy.',
  policy_read_failed: 'The current policy could not be loaded. This will be retried.',
  retryable_dispatch_or_result_failure: 'The attempt could not finish. It will be retried after a delay.',
  active_probes_disabled: 'Active probing is disabled in the scanning policy.',
  automatic_probes_disabled: 'Active probing is disabled in the scanning policy.',
  overlapping_network_scope_requires_source_resolution: 'Overlapping networks require a configured source to resolve the network context first.',
  platform_collector_not_authorized_for_identity_enrichment: 'A collector in the observed network is required.',
  network_scope_unresolved: 'The network for this observation is not yet established.',
  no_configured_source: 'No configured source can add evidence for this observation.',
  observing_collector_unreachable: 'The observing collector is unavailable or cannot reach the target network.',
  sensitive_device_requires_review: 'This device is excluded from automatic enrichment and needs review.',
  no_authorized_target: 'No address is eligible under the current network and exclusion policy.',
  too_many_addresses: 'DNS returned too many addresses for a bounded identity check.',
  invalid_exclusion_policy: 'Correct the network exclusions before enrichment can continue.',
  dns_collector_failed: 'DNS resolution failed on the collector. Check its connectivity and configuration.',
  probe_failed_review_collector_before_retry: 'The probe failed. Review the collector before another attempt.',
  probe_results_ingested: 'Probe results have been retained and evaluated for identity.',
  dns_context_only: 'DNS added address context. DNS alone does not establish a device identity.',
};
export function enrichmentExplanation(reason: string) {
  if (explanations[reason]) return explanations[reason];
  if (/capability|outdated|upgrade/.test(reason)) return 'This collector does not support the required identity check. Update it or use a suitable collector in the same network.';
  return reason.replace(/_/g, ' ');
}
const actions = { configured_source: 'Configured source refresh', dns: 'Scoped name resolution', probe: 'Targeted endpoint check' };
const kinds = { passive_host: 'Passive host evidence', host_inventory: 'Host inventory', peer: 'Peer evidence', cloud: 'Cloud inventory', crypto: 'Security evidence' };
const states = { pending: 'Retained — awaiting identity or approval', completed: 'Attached to an asset', superseded: 'Retained historical evidence', retrying: 'Attachment will be retried' };

export function ObservationDetails({ observation: o }: { observation: Observation }) {
  const evidence = o.retained_evidence;
  return <>
    <section aria-label="Enrichment activity" style={{ marginTop: 20 }}>
      <h4>What can happen next</h4>
      <p>Configured sources are checked before permitted, targeted network checks. A completed check may still leave the device unidentified.</p>
      <dl>
        <dt>Last attempt</dt><dd>{time(o.last_attempt_at)}</dd>
        <dt>Next eligible attempt</dt><dd>{time(o.next_attempt_at)}{o.next_attempt_at && ' · subject to current policy and collector availability'}</dd>
      </dl>
      {!o.enrichment_jobs?.length ? <p>No enrichment attempts are recorded for this observation.</p> : <ul>{o.enrichment_jobs.map((job) => <li key={job.id} style={{ marginBottom: 12 }}>
        <strong>{actions[job.action]}</strong> · {job.state}
        {job.reason && <p>{enrichmentExplanation(job.reason)}</p>}
        <dl><dt>Executor</dt><dd>{job.executor_scope}</dd><dt>Attempts</dt><dd>{job.attempts}</dd>
          <dt>Last attempt</dt><dd>{time(job.last_attempt_at)}</dd>
          {job.state !== 'completed' && <><dt>Next eligible attempt</dt><dd>{time(job.next_attempt_at)}</dd></>}
        </dl>
      </li>)}</ul>}
    </section>
    <section aria-label="Retained evidence" style={{ marginTop: 20 }}>
      <h4>Retained evidence</h4>
      <p>Evidence stays accessible while identity or monitoring approval is unresolved. Counts below describe each receipt; repeated sightings can include the same facts or certificates.</p>
      {!evidence ? <p>Detailed evidence summaries are unavailable from this server.</p> : evidence.total === 0 ? <p>No additional inventory or security details were included with these identifiers.</p> : <>
        {evidence.has_more && <p>Showing the latest {evidence.items.length} of {evidence.total} retained receipts. Older evidence is still retained.</p>}
        {evidence.items.map((item, index) => <article key={`${item.kind}:${item.source_ref}:${index}`} style={{ padding: '12px 0', borderTop: '1px solid var(--app-border)' }}>
          <h5 style={{ margin: '0 0 8px' }}>{kinds[item.kind]} · {states[item.materialization_state]}</h5>
          {item.scope === 'source_context' && <p>This is context from the same source batch. It is not all attributable to this device.</p>}
          <dl><dt>Source</dt><dd>{item.source_ref}{item.collector_version ? ` · ${item.collector_version}` : ''}</dd><dt>Observed</dt><dd>{time(item.observed_at)}</dd></dl>
          {item.reason && <p>{enrichmentExplanation(item.reason)}</p>}
          <p>{item.facts_count} facts · {item.software_count} software records · {item.endpoints_count} endpoints · {item.relationships_count} relationships</p>
          {(item.kind === 'crypto' || item.certificates_count > 0 || item.keys_count > 0 || item.crypto_configurations_count > 0) && <p>{item.certificates_count} certificates · {item.keys_count} keys · {item.crypto_configurations_count} crypto configurations</p>}
          {item.protocols.length > 0 && <p>Observed protocols: {item.protocols.join(', ')}</p>}
          {item.certificates.map((cert) => <details key={cert.sha256_fingerprint}>
            <summary>Certificate {cert.sha256_fingerprint.slice(0, 16)}…{cert.expired ? ' · expired' : ''}{cert.self_signed ? ' · self-signed' : ''}</summary>
            <dl><dt>SHA-256 fingerprint</dt><dd style={{ overflowWrap: 'anywhere' }}>{cert.sha256_fingerprint}</dd>
              <dt>Valid from</dt><dd>{time(cert.not_before)}</dd><dt>Valid until</dt><dd>{time(cert.not_after)}</dd>
            </dl>
          </details>)}
          {item.certificates_count > item.certificates.length && <p>Showing {item.certificates.length} certificate examples from this receipt.</p>}
        </article>)}
      </>}
    </section>
  </>;
}
