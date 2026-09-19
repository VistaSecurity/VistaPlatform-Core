import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { assetConfidencePercent, Icon, MiniBar } from '../../components/ui';
import { DTable, CellMono, CellTxt, PageWrap, queryNote, relTime } from './kit';
import { usePendingAssets } from './queries';
import {
  MERGE_PROPOSALS_PAGE_SIZE, mergeProposalRangeLabel, useAutoAcceptedMerges,
  useMergeProposals, useResolveMergeProposal,
} from '../inventory/asset-queries';
import { assetIdentity, classLabel, primaryAddressPort } from '../inventory/asset-shape';
import { AssetMergeModal } from './asset-merge-modal';
import type { MergeProposal } from '../inventory/asset-queries';
import { MergeProposalRow } from './merge-proposal-row';
import { AutoMergedSection } from './auto-merged-section';
import { RelationshipProposalRow } from './relationship-proposal-row';
import { ClassProposalRow } from './class-proposal-row';
import { useClassProposals, useDecideClassProposal } from './class-proposal-queries';
import {
  useDecideRelationshipProposal, useRelationshipProposals,
} from '../inventory/relationship-queries';
import {
  APPROVAL_SOURCES, SOURCE_HELP, SOURCE_ICON, SOURCE_LABEL,
  countBySource, matchesSourceFilter, sourceOfAsset, sourceOfClassProposal,
  sourceOfProposal, sourceOfRelationshipProposal, type ApprovalSource,
} from './approval-sources';

// Discovery → Approvals — the single proposal queue (ADR-0006 D6).
//
// It used to be one list of discovered assets. It is now the ONE place every
// proposal lands, whatever produced it: a sensor's discovery, a spreadsheet
// import, a CMDB pull, the identification engine's belief that two records are
// one thing, a classifier's guess at a class. "No second queue anywhere" is the
// rule — a second inbox is how half the proposals in a product end up unread.

const COLS = [
  { label: 'Discovered asset', w: '1.4fr' },
  { label: 'Address', w: '1fr' },
  { label: 'Class', w: '1fr' },
  { label: 'Segment', w: '1fr' },
  { label: 'Source', w: '150px' },
  { label: 'Confidence', w: '110px' },
  { label: 'Found', w: '100px' },
  { label: '', w: '150px', align: 'right' as const },
];

function SourceChip({ source, count, active, onClick }: {
  source: ApprovalSource; count: number; active: boolean; onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      title={SOURCE_HELP[source]}
      aria-pressed={active}
      className="ui-btn sm"
      style={{
        borderColor: active ? 'var(--accent)' : 'var(--app-border2)',
        color: active ? 'var(--accent)' : 'var(--app-t2)',
        background: active ? 'color-mix(in srgb, var(--accent) 10%, transparent)' : 'var(--app-panel2)',
        // A source with nothing in it stays visible but recedes: the facet is
        // also how a user learns what this queue can contain, and hiding the
        // empty ones makes the row jump every time a proposal arrives.
        opacity: count === 0 && !active ? 0.5 : 1,
      }}
    >
      <Icon name={SOURCE_ICON[source]} size={12} />
      {SOURCE_LABEL[source]}
      <span className="mono" style={{ fontSize: 10.5, opacity: 0.8 }}>{count}</span>
    </button>
  );
}

export function ApprovalsPage() {
  const navigate = useNavigate();
  const q = usePendingAssets();
  // Merge proposals are SERVER-paged (the list is capped at 50 whether or not
  // anyone asks), so the page offset is state here and the counts come off
  // `total` rather than off the array.
  const [proposalOffset, setProposalOffset] = useState(0);
  const proposalsQ = useMergeProposals(true, proposalOffset);
  const resolve = useResolveMergeProposal();
  const [mergeReview, setMergeReview] = useState<MergeProposal>();
  // The third row kind (ADR-0006 D6). Its own read, its own error state: a
  // failed relationship read is an unknown number of proposals a person still
  // has to decide, exactly as a failed merge read is.
  const relProposalsQ = useRelationshipProposals();
  const decideRel = useDecideRelationshipProposal();
  // The fourth row kind (ADR-0006 D6, workstream 2.10b). Its own read and its
  // own error state, for the same reason the other two have theirs: a failed
  // read is an UNKNOWN number of proposals a person still has to decide, and
  // rendering it as an empty section tells them there is nothing to do.
  const classProposalsQ = useClassProposals();
  const decideClass = useDecideClassProposal();
  // What the matcher merged WITHOUT asking. Not a queue — a record, so the one
  // unattended act in this pipeline is visible to the person who enabled it.
  // Empty for every tenant on the default threshold, and the section renders
  // nothing when it is empty.
  const autoMergedQ = useAutoAcceptedMerges();
  const qc = useQueryClient();

  const allAssets = useMemo(() => q.data ?? [], [q.data]);
  const allProposals = useMemo(() => proposalsQ.data?.proposals ?? [], [proposalsQ.data]);
  const allRelProposals = useMemo(() => relProposalsQ.data?.proposals ?? [], [relProposalsQ.data]);
  const allClassProposals = useMemo(() => classProposalsQ.data?.proposals ?? [], [classProposalsQ.data]);
  // The tenant's whole proposal count, which is NOT the page length.
  const proposalTotal = proposalsQ.data?.total ?? 0;
  const relProposalTotal = relProposalsQ.data?.total ?? 0;
  const classProposalTotal = classProposalsQ.data?.total ?? 0;
  const rangeLabel = proposalsQ.data ? mergeProposalRangeLabel(proposalsQ.data) : '';
  const [selected, setSelected] = useState<ApprovalSource[]>([]);

  const counts = useMemo(
    () => countBySource(allAssets, allProposals, allRelProposals, allClassProposals),
    [allAssets, allProposals, allRelProposals, allClassProposals],
  );
  const assets = useMemo(
    () => allAssets.filter((a) => matchesSourceFilter(sourceOfAsset(a), selected)),
    [allAssets, selected],
  );
  const proposals = useMemo(
    () => allProposals.filter((p) => matchesSourceFilter(sourceOfProposal(p), selected)),
    [allProposals, selected],
  );
  const relProposals = useMemo(
    () => allRelProposals.filter((p) => matchesSourceFilter(sourceOfRelationshipProposal(p), selected)),
    [allRelProposals, selected],
  );
  const classProposals = useMemo(
    () => allClassProposals.filter((p) => matchesSourceFilter(sourceOfClassProposal(p), selected)),
    [allClassProposals, selected],
  );
  // What is on this page, and what the tenant actually has waiting. The header
  // must say the second: the merge list stops at the page size.
  const shown = assets.length + proposals.length + relProposals.length + classProposals.length;
  const queueTotal = allAssets.length + proposalTotal + relProposalTotal + classProposalTotal;
  const morePages = proposalTotal > allProposals.length;

  const toggleSource = (s: ApprovalSource) =>
    setSelected((prev) => (prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s]));

  const decide = useMutation({
    mutationFn: async ({ ids, approve }: { ids: string[]; approve: boolean }) => {
      const path = approve ? '/infrastructure-assets/approve' : '/infrastructure-assets/deny';
      const { data, error } = await clients.inventory.POST(path, { body: { asset_ids: ids } });
      if (error || !data) throw new Error(`Failed to ${approve ? 'approve' : 'deny'} asset${ids.length === 1 ? '' : 's'}`);
      return { ...data, approve };
    },
    onSuccess: (r) => toast.success(`${r.count ?? ''} asset${(r.count ?? 2) === 1 ? '' : 's'} ${r.approve ? 'approved' : 'denied'}`),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Request failed'),
    onSettled: () => {
      qc.invalidateQueries({ queryKey: ['discovery', 'pending-assets'] });
      qc.invalidateQueries({ queryKey: ['inventory'] });
    },
  });

  // The empty state depends on WHY the list is empty. A filtered no-match must
  // not read as "inbox zero" — the reviewer would walk away from work they have.
  //
  // ALL THREE reads count. "Nothing awaiting review" is a claim about the whole
  // queue, and each row kind is part of it: judging the empty state on the
  // pending-asset read alone once told a reviewer their inbox was clear while
  // the merge read was failing behind it, and adding a third kind without
  // adding it here would reintroduce exactly that.
  const filtered = selected.length > 0;
  const note = queryNote([q, proposalsQ, relProposalsQ, classProposalsQ], shown === 0 && !filtered, {
    thing: 'pending items',
    emptyTitle: 'Nothing awaiting review',
    emptyMessage: 'Newly discovered assets, imports, CMDB pulls, merge proposals, proposed relationships and proposed classes all land here for review. To skip review for trusted networks, enable "Auto-approve discoveries" on a network segment in Settings → Infrastructure.',
  });

  return (
    <PageWrap
      title="Approvals"
      // The header count is blanked while ANY read is in flight or failing: a
      // number assembled from two of three answers is a number that under-reports
      // the work waiting, and it looks authoritative either way.
      count={
        q.isLoading || proposalsQ.isLoading || proposalsQ.isError
          || relProposalsQ.isLoading || relProposalsQ.isError
          || classProposalsQ.isLoading || classProposalsQ.isError
          ? '' : queueTotal
      }
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
        <p style={{ margin: 0, fontSize: 13, color: 'var(--app-t3)' }}>
          The hinge between Discovery and Inventory, and the one queue for every proposal. Accepting an asset materializes its deferred certificates and crypto configurations into Inventory; accepting a merge makes two records one, and the surviving asset&rsquo;s History records what was merged in; accepting a relationship confirms it and starts it counting in impact analysis; accepting a class sets what the asset IS and records which rule decided it.
        </p>
        <div style={{ flex: 1 }} />
        {assets.length > 0 && (
          <PermissionGate permission={TENANT_PERMISSIONS.assets.update}>
            <button
              className="ui-btn sm"
              disabled={decide.isPending}
              title={filtered ? 'Accepts the assets matching the current source filter' : 'Accepts every pending asset'}
              onClick={() => decide.mutate({ ids: assets.map((a) => a.id), approve: true })}
            >
              <Icon name="check-check" />Accept {filtered ? `these ${assets.length}` : 'all'}
            </button>
          </PermissionGate>
        )}
      </div>

      {/* Source facet — where did this come from, which is the first thing a
          reviewer needs and the thing that decides how much scrutiny is owed. */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 14, flexWrap: 'wrap' }}>
        <span className="eyebrow-app" style={{ marginRight: 2 }}>Source</span>
        {APPROVAL_SOURCES.map((s) => (
          <SourceChip key={s} source={s} count={counts[s]} active={selected.includes(s)} onClick={() => toggleSource(s)} />
        ))}
        {filtered && (
          <button className="ui-btn sm ghost" onClick={() => setSelected([])}>
            <Icon name="x" size={12} />Clear
          </button>
        )}
      </div>

      {proposalsQ.isLoading && (
        <div style={{ fontSize: 12.5, color: 'var(--app-t3)', marginBottom: 10 }}>Loading merge proposals…</div>
      )}

      {/* The merge read failing is not "no merges". It is an unknown number of
          proposals a person still has to decide, and the reviewer has to be
          told rather than shown an empty queue. */}
      {proposalsQ.isError && (
        <div
          data-testid="merge-proposals-error"
          style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 12, padding: '9px 14px', borderRadius: 12, border: '1px solid color-mix(in srgb, var(--danger) 35%, transparent)', background: 'color-mix(in srgb, var(--danger) 8%, transparent)' }}
        >
          <Icon name="alert-triangle" size={15} style={{ color: 'var(--danger-text)', flexShrink: 0 }} />
          <span style={{ fontSize: 12.5, color: 'var(--app-t1)', flex: 1 }}>
            Couldn&rsquo;t load merge proposals — {proposalsQ.error instanceof Error ? proposalsQ.error.message : 'the request failed'}. Any merges awaiting review are not shown below.
          </span>
          <button className="ui-btn sm" onClick={() => { void proposalsQ.refetch(); }}>Retry</button>
        </div>
      )}

      {/* Same rule as the merge read: a failed relationship read is an UNKNOWN
          number of proposals a person still has to decide, and rendering it as
          an empty section would tell them there is nothing to do. */}
      {relProposalsQ.isError && (
        <div
          data-testid="relationship-proposals-error"
          style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 12, padding: '9px 14px', borderRadius: 12, border: '1px solid color-mix(in srgb, var(--danger) 35%, transparent)', background: 'color-mix(in srgb, var(--danger) 8%, transparent)' }}
        >
          <Icon name="alert-triangle" size={15} style={{ color: 'var(--danger-text)', flexShrink: 0 }} />
          <span style={{ fontSize: 12.5, color: 'var(--app-t1)', flex: 1 }}>
            Couldn&rsquo;t load relationship proposals — {relProposalsQ.error instanceof Error ? relProposalsQ.error.message : 'the request failed'}. Any relationships awaiting review are not shown below.
          </span>
          <button className="ui-btn sm" onClick={() => { void relProposalsQ.refetch(); }}>Retry</button>
        </div>
      )}

      {relProposalsQ.isLoading && (
        <div style={{ fontSize: 12.5, color: 'var(--app-t3)', marginBottom: 10 }}>Loading relationship proposals…</div>
      )}

      {/* Same rule again: a failed class read is an UNKNOWN number of proposals
          a person still has to decide, and an empty section would tell them
          there is nothing to do. */}
      {classProposalsQ.isError && (
        <div
          data-testid="class-proposals-error"
          style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 12, padding: '9px 14px', borderRadius: 12, border: '1px solid color-mix(in srgb, var(--danger) 35%, transparent)', background: 'color-mix(in srgb, var(--danger) 8%, transparent)' }}
        >
          <Icon name="alert-triangle" size={15} style={{ color: 'var(--danger-text)', flexShrink: 0 }} />
          <span style={{ fontSize: 12.5, color: 'var(--app-t1)', flex: 1 }}>
            Couldn&rsquo;t load class proposals — {classProposalsQ.error instanceof Error ? classProposalsQ.error.message : 'the request failed'}. Any classes awaiting review are not shown below.
          </span>
          <button className="ui-btn sm" onClick={() => { void classProposalsQ.refetch(); }}>Retry</button>
        </div>
      )}

      {classProposalsQ.isLoading && (
        <div style={{ fontSize: 12.5, color: 'var(--app-t3)', marginBottom: 10 }}>Loading class proposals…</div>
      )}

      {morePages && !filtered && (
        // The source chips count what is on this page. Saying so costs one line
        // and stops a reviewer reading a partial count as the whole queue.
        <div style={{ fontSize: 11.5, color: 'var(--app-t3)', margin: '-6px 0 12px' }}>
          Source counts cover the {allProposals.length} merge proposal{allProposals.length === 1 ? '' : 's'} on this page, of {proposalTotal}.
        </div>
      )}

      <AutoMergedSection
        merges={autoMergedQ.data?.merges ?? []}
        windowDays={autoMergedQ.data?.windowDays ?? 30}
      />

      {proposals.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
            <div className="eyebrow-app">
              Merge proposals ({proposalTotal})
            </div>
            {rangeLabel && (
              <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{rangeLabel}</span>
            )}
            <div style={{ flex: 1 }} />
            {(proposalOffset > 0 || morePages) && (
              <div style={{ display: 'flex', gap: 7 }}>
                <button
                  className="ui-btn sm"
                  disabled={proposalOffset === 0 || proposalsQ.isFetching}
                  onClick={() => setProposalOffset((o) => Math.max(0, o - MERGE_PROPOSALS_PAGE_SIZE))}
                  style={{ opacity: proposalOffset === 0 ? 0.5 : 1 }}
                >
                  <Icon name="chevron-left" size={13} />Prev
                </button>
                <button
                  className="ui-btn sm"
                  disabled={proposalOffset + allProposals.length >= proposalTotal || proposalsQ.isFetching}
                  onClick={() => setProposalOffset((o) => o + MERGE_PROPOSALS_PAGE_SIZE)}
                  style={{ opacity: proposalOffset + allProposals.length >= proposalTotal ? 0.5 : 1 }}
                >
                  Next<Icon name="chevron-right" size={13} />
                </button>
              </div>
            )}
          </div>
          {proposals.map((p) => (
            <MergeProposalRow
              key={p.id}
              proposal={p}
              busy={resolve.isPending}
              // Explicit source and survivor selection happens in the preview.
              onAccept={() => setMergeReview(p)}
              onKeepSeparate={() => resolve.mutate({ action: 'keep-separate', id: p.id })}
            />
          ))}
        </div>
      )}

      {mergeReview && <AssetMergeModal proposal={mergeReview} onClose={() => setMergeReview(undefined)} />}

      {relProposals.length > 0 && (
        <div data-testid="relationship-proposals-section" style={{ marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
            <div className="eyebrow-app">
              Relationship proposals ({relProposalTotal})
            </div>
            <span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>
              claims about how two approved assets are connected — nothing has confirmed these
            </span>
          </div>
          {relProposals.map((p) => (
            <RelationshipProposalRow
              key={p.id}
              proposal={p}
              busy={decideRel.isPending}
              onAccept={() => decideRel.mutate({ id: p.id, action: 'accept' })}
              onReject={() => decideRel.mutate({ id: p.id, action: 'reject' })}
            />
          ))}
          {relProposalTotal > allRelProposals.length && (
            <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>
              Showing {allRelProposals.length} of {relProposalTotal}.
            </div>
          )}
        </div>
      )}

      {classProposals.length > 0 && (
        <div data-testid="class-proposals-section" style={{ marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
            <div className="eyebrow-app">
              Class proposals ({classProposalTotal})
            </div>
            <span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>
              what the classification rules think these assets are — nothing measured it
            </span>
          </div>
          {classProposals.map((p) => (
            <ClassProposalRow
              key={p.id}
              proposal={p}
              busy={decideClass.isPending}
              // The chosen class comes from the ROW, because the row is where a
              // reviewer picks between two rules that disagreed. The server
              // requires one for that case and refuses to pick.
              onAccept={(classKey) => decideClass.mutate({ id: p.id, action: 'accept', classKey })}
              onReject={() => decideClass.mutate({ id: p.id, action: 'reject' })}
            />
          ))}
          {classProposalTotal > allClassProposals.length && (
            <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>
              Showing {allClassProposals.length} of {classProposalTotal}.
            </div>
          )}
        </div>
      )}

      {shown === 0 && filtered ? (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8, padding: '40px 20px', textAlign: 'center' }}>
          <Icon name="filter-x" size={24} style={{ color: 'var(--app-t3)' }} />
          <div style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--app-t1)' }}>Nothing from these sources</div>
          <div style={{ fontSize: 12.5, color: 'var(--app-t3)', maxWidth: 460, lineHeight: 1.6 }}>
            There is still work in the queue from other sources — clear the filter to see it.
          </div>
          <button className="ui-btn sm" onClick={() => setSelected([])} style={{ marginTop: 4 }}>Clear the filter</button>
        </div>
      ) : note ?? (
        assets.length > 0 && (
          <>
            {(proposals.length > 0 || relProposals.length > 0 || classProposals.length > 0) && <div className="eyebrow-app" style={{ marginBottom: 8 }}>Discovered assets ({assets.length})</div>}
            <DTable
              cols={COLS}
              rows={assets}
              rowKey={(a) => a.id}
              render={(a) => {
                const conf = assetConfidencePercent(a.confidence_score);
                const source = sourceOfAsset(a);
                return (
                  <>
                    <CellMono v={assetIdentity(a).primary} />
                    {/* The primary endpoint's address, or blank. A pending asset
                        with no endpoint has none to show. */}
                    <CellMono v={primaryAddressPort(a)} c="var(--app-t3)" />
                    <CellTxt v={classLabel(a.class_key)} />
                    <CellTxt v={a.network_segment_name || a.business_unit} />
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5, color: 'var(--app-t3)' }} title={SOURCE_HELP[source]}>
                      <Icon name={SOURCE_ICON[source]} size={11} />{SOURCE_LABEL[source]}
                    </span>
                    {conf != null ? (
                      <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                        <div style={{ width: 40 }}><MiniBar pct={conf} color={conf >= 70 ? 'var(--ok)' : 'var(--warn)'} /></div>
                        <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{conf}%</span>
                      </div>
                    ) : (
                      <CellTxt v="—" c="var(--app-t3)" />
                    )}
                    <CellTxt v={relTime(a.first_discovered_at || a.created_at)} c="var(--app-t3)" />
                    <span style={{ textAlign: 'right', display: 'inline-flex', gap: 6, justifyContent: 'flex-end' }}>
                      <button
                        className="ui-btn sm ghost"
                        title="Open this asset's page"
                        aria-label="Open asset page"
                        onClick={(e) => { e.stopPropagation(); void navigate(`/inventory/assets/${a.id}`); }}
                        style={{ padding: '0 6px' }}
                      >
                        <Icon name="external-link" size={12} />
                      </button>
                      <PermissionGate permission={TENANT_PERMISSIONS.assets.update} fallback={<span style={{ fontSize: 11, color: 'var(--app-t3)' }}>—</span>}>
                        <button className="ui-btn sm accent" disabled={decide.isPending} onClick={() => decide.mutate({ ids: [a.id], approve: true })}>
                          <Icon name="check" />Accept
                        </button>
                        <button className="ui-btn sm ghost" title="Reject (suppresses rediscovery)" disabled={decide.isPending} onClick={() => decide.mutate({ ids: [a.id], approve: false })}>
                          <Icon name="x" />
                        </button>
                      </PermissionGate>
                    </span>
                  </>
                );
              }}
            />
          </>
        )
      )}
    </PageWrap>
  );
}
