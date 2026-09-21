// The asset page's provisional-identity panel ( §6).
//
// A provisional item is an ordinary asset row with an extraordinary problem:
// nothing has met the device it describes. It was created because a sensor on
// one VLAN repeated an advertisement about a device on another, and the whole
// value of the row depends on the reader knowing that — otherwise it reads as
// a discovered host like any other, and the tenant either trusts a guess or
// deletes a real device.
//
// So the panel answers, in this order, the four questions a person actually
// has: what IS this, who said so, who (if anyone) can go and check, and when.
// The fourth is the one an engine-side view forgets: "no collector reaches this
// network" is not an error state to wait out — it is an instruction, and the
// panel says what to do about it.
import { Link } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { collectorReasonExplanation } from '../discovery/observation-details';

type Observation = inventoryComponents['schemas']['IdentityObservation'];

/** The one sentence that says what a provisional item IS. */
export const PROVISIONAL_LEAD = 'This item was created from an advertisement that no collector has verified directly.';

/** What a person should do when nothing can reach the device's network.
 *
 *  Read from the reason table rather than restated: the block reason
 *  `no_eligible_collector_in_target_network` and this advice are the SAME
 * sentence by design ( D8), and a second copy is how the panel and the
 *  observation card come to say slightly different things about one fact. */
export const NO_COLLECTOR_ADVICE = collectorReasonExplanation('no_eligible_collector_in_target_network');

export const APPROVAL_NOTE = 'Approving this item monitors it; its identity stays provisional until a collector on its network corroborates it or you confirm it.';

const time = (value?: string | null) => (value ? new Date(value).toLocaleString() : 'Not scheduled');

/**
 * How the evidence reached us, as a phrase that fits inside "Advertised by X
 * (…)".
 *
 * `relayed` is the admission flag a trusted intake adapter sets, not something
 * inferred from the payload — a reflected mDNS advert is hearsay by
 * construction, and that is precisely why the item is provisional. Anything
 * else a sensor produced is described as what it is rather than being upgraded
 * to a claim the evidence does not make.
 */
export function observationSourceDescription(o: Observation): string {
  const admission = (o.evidence as { admission?: { relayed?: unknown } }).admission;
  const relayed = admission?.relayed === true;
  return o.source_ref.startsWith('sensor:') && relayed ? 'reflected mDNS' : 'passive observation';
}

export function useProvisionalObservations(assetID: string) {
  return useQuery({
    queryKey: ['identity-observations', 'provisional', assetID],
    queryFn: async () => {
      const { data, response } = await clients.inventory.GET('/discovery/observations', {
        params: { query: { asset_id: assetID, state: 'unresolved', page: 1, page_size: 5 } },
      });
      if (!response.ok || !data) throw new Error('Unable to load the evidence behind this item');
      return data;
    },
  });
}

export function ProvisionalIdentityPanel({ assetID }: { assetID: string }) {
  const q = useProvisionalObservations(assetID);

  if (q.isPending) return <p role="status">Loading the evidence behind this item…</p>;
  if (q.isError) {
    return <p role="alert">
      The evidence behind this item could not be loaded.{' '}
      <button className="ui-btn sm" onClick={() => { void q.refetch(); }}>Retry</button>
    </p>;
  }

  // Newest first: the list endpoint orders `last_seen_at DESC`, so the head is
  // the most recent thing said about this device — the one whose collector
  // reachability describes the situation NOW.
  const observation = q.data.observations[0];
  if (!observation) {
    return <div style={{ fontSize: 12.5, lineHeight: 1.6, color: 'var(--app-t2)' }}>
      <p>{PROVISIONAL_LEAD}</p>
      <p>No observation is currently linked to this provisional item.</p>
    </div>;
  }

  const o = observation;
  const collector = o.collector ?? null;
  const evidenceLink = <Link to={`/discovery/observations?observation_id=${o.id}`}>Inspect discovery evidence</Link>;

  return <div style={{ fontSize: 12.5, lineHeight: 1.6, color: 'var(--app-t2)', borderLeft: '2px solid var(--warn)', paddingLeft: 10, margin: '8px 0' }}>
    <p>{PROVISIONAL_LEAD}</p>

    {collector === null ? (
      // No segment could be resolved, so there is no collector question to
      // answer. Saying "no collector reaches this network" here would name a
      // network we could not identify.
      <p>Network placement could not be resolved for this observation.</p>
    ) : (
      <>
        <p>
          Advertised by {collector.observer.name || 'an unnamed collector'}{' '}
          ({observationSourceDescription(o)}, {new Date(o.first_seen_at).toLocaleString()})
        </p>
        {!collector.observer.reachable && (
          <p>{collector.observer.name || 'The observing collector'} — {collectorReasonExplanation(collector.observer.reason)}</p>
        )}
        <p>{collector.executor
          ? `Enrichment can run through ${collector.executor.name}.`
          : NO_COLLECTOR_ADVICE}</p>
        <p>Next attempt: {time(o.next_attempt_at)}</p>
      </>
    )}

    {o.admission_reasons.includes('asset_allowance_exhausted') && (
      <p>Direct evidence was found, but this item cannot be established because the asset allowance is exhausted.</p>
    )}

    <p>{evidenceLink}</p>
    <p>{APPROVAL_NOTE}</p>
  </div>;
}
