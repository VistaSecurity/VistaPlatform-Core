// The asset page's Relationships tab (ADR-0003, ADR-0006 D4).
//
// Three things, in the order a person needs them:
//
//   1. What is attached to this asset, grouped by direction, with the
//      provenance of each edge shown rather than implied.
//   2. What depends on this asset — the impact panel, which is the question the
//      ops buyer actually came for.
//   3. Add a relationship, with the sentence previewed before it is created.
//
// NO GRAPH IS RENDERED HERE, deliberately. The neighbourhood hook is called for
// its counts and for the "View on map" link; the graph itself is the map lens
// (workstream 2.9, `map-lens.tsx`), which is the only module that loads
// `@xyflow/react`. Drawing a second copy of it inside a tab would put a graph
// library in the bundle of every asset page.
import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS, usePermissions } from '@vistasecurity/primitives/rbac';
import type { Asset } from '@vistasecurity/api-contract';
import { Icon } from '../../components/ui';
import {
  useAssetImpact, useAssetNeighbourhood, useAssetRelationships,
  useCreateRelationship, useDecideRelationshipProposal, useDeleteRelationship,
} from './relationship-queries';
import {
  RELATIONSHIP_TYPES, SOURCE_KIND_HELP, SOURCE_KIND_LABEL, TYPE_HELP, TYPE_LABEL,
  declarationPreview, depthSummary, directionOf, edgeLabel, groupByDirection,
  impactHeadline, isDecidable, peerName, peerOf,
  type Relationship, type RelationshipType,
} from './relationships';
import { useAssetsQuery } from './asset-queries';
import { classLabel } from './asset-shape';

// ---------------------------------------------------------------- chrome --

function ProvenanceChip({ edge }: { edge: Relationship }) {
  const kind = edge.source_kind;
  // Inferred is the one that is NOT agreed fact, so it is the one that is
  // coloured. The other three are recorded observations or assertions and read
  // as ordinary metadata.
  const warn = kind === 'inferred';
  return (
    <span
      data-testid="provenance-chip"
      data-kind={kind}
      title={edge.source_ref ? `${SOURCE_KIND_HELP[kind]} (${edge.source_ref})` : SOURCE_KIND_HELP[kind]}
      style={{
        fontSize: 10.5, fontWeight: 600, padding: '1px 7px', borderRadius: 40,
        border: `1px solid ${warn ? 'color-mix(in srgb, var(--warn) 45%, transparent)' : 'var(--app-border2)'}`,
        color: warn ? 'var(--warn-text, var(--warn))' : 'var(--app-t3)',
        background: warn ? 'color-mix(in srgb, var(--warn) 9%, transparent)' : 'transparent',
        whiteSpace: 'nowrap',
      }}
    >
      {SOURCE_KIND_LABEL[kind]}
    </span>
  );
}

function StatusChip({ status }: { status: Relationship['status'] }) {
  if (status === 'active') return null;
  const help: Record<string, string> = {
    pending: 'Nobody has confirmed this yet. It is not counted in impact.',
    rejected: 'Somebody decided this was wrong.',
    stale: 'No collector has seen this recently.',
  };
  return (
    <span
      data-testid="status-chip"
      data-status={status}
      title={help[status]}
      style={{
        fontSize: 10.5, fontWeight: 600, padding: '1px 7px', borderRadius: 40,
        border: '1px solid var(--app-border2)', color: 'var(--app-t3)', whiteSpace: 'nowrap',
      }}
    >
      {status}
    </span>
  );
}

// ------------------------------------------------------------------ rows --

function EdgeRow({ edge, assetId, assetStatus, canWrite, onDelete, onDecide, busy }: {
  edge: Relationship;
  assetId: string;
  /** The status of the asset whose page this is — the end `peer` never carries.
   *  Without it a pending asset's own page offered Accept on an edge the server
   *  refuses (and used to wrongly confirm). */
  assetStatus: string | undefined;
  canWrite: boolean;
  onDelete: (id: string) => void;
  onDecide: (id: string, action: 'accept' | 'reject') => void;
  busy: boolean;
}) {
  const peer = peerOf(edge, assetId);
  const decidable = isDecidable(edge, assetStatus);
  // Only a DECLARED edge can be deleted. Showing the control on a measured one
  // would offer an action the server refuses with a 409 — and would be a lie
  // anyway, since the next collection run re-creates it.
  const deletable = edge.source_kind === 'declared';

  return (
    <div
      data-testid="relationship-row"
      data-edge-id={edge.id}
      data-status={edge.status}
      style={{
        display: 'grid', gridTemplateColumns: 'minmax(0,160px) minmax(0,1.6fr) minmax(0,1fr) auto',
        gap: 12, alignItems: 'center', padding: '9px 0', borderBottom: '1px solid var(--app-border)',
      }}
    >
      <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--app-t2)' }}>
        {edgeLabel(edge, assetId)}
      </span>

      <span style={{ minWidth: 0, display: 'flex', alignItems: 'center', gap: 7 }}>
        {peer && !peer.deleted ? (
          <Link
            to={`/inventory/assets/${peer.asset_id}`}
            style={{ fontSize: 12.5, color: 'var(--accent)', textDecoration: 'none', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
          >
            {peerName(peer)}
          </Link>
        ) : (
          // A peer that has been deleted or merged away is NAMED, not dropped:
          // an edge whose other end silently vanishes reads as a corrupt row.
          <span style={{ fontSize: 12.5, color: 'var(--app-t3)', textDecoration: 'line-through' }}>
            {peerName(peer)}
          </span>
        )}
        {peer?.class_key && (
          <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>{classLabel(peer.class_key)}</span>
        )}
      </span>

      <span style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
        <ProvenanceChip edge={edge} />
        <StatusChip status={edge.status} />
      </span>

      <span style={{ display: 'inline-flex', gap: 6, justifyContent: 'flex-end' }}>
        {decidable && canWrite && (
          <>
            <button
              className="ui-btn sm accent"
              disabled={busy}
              onClick={() => onDecide(edge.id, 'accept')}
            >
              <Icon name="check" size={12} />Accept
            </button>
            <button
              className="ui-btn sm ghost"
              title="Reject this relationship"
              aria-label="Reject relationship"
              disabled={busy}
              onClick={() => onDecide(edge.id, 'reject')}
            >
              <Icon name="x" size={12} />
            </button>
          </>
        )}
        {!decidable && deletable && canWrite && (
          <button
            className="ui-btn sm ghost"
            title="Remove this relationship"
            aria-label="Remove relationship"
            disabled={busy}
            onClick={() => onDelete(edge.id)}
            style={{ padding: '0 6px' }}
          >
            <Icon name="trash-2" size={12} />
          </button>
        )}
      </span>
    </div>
  );
}

function EdgeGroup({ title, help, edges, assetId, assetStatus, canWrite, onDelete, onDecide, busy }: {
  title: string; help: string; edges: Relationship[]; assetId: string;
  assetStatus: string | undefined; canWrite: boolean;
  onDelete: (id: string) => void; onDecide: (id: string, a: 'accept' | 'reject') => void; busy: boolean;
}) {
  if (edges.length === 0) return null;
  return (
    <div style={{ marginBottom: 22 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 9, marginBottom: 4 }}>
        <div className="eyebrow-app">{title} ({edges.length})</div>
        <span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{help}</span>
      </div>
      {edges.map((e) => (
        <EdgeRow
          key={e.id} edge={e} assetId={assetId} assetStatus={assetStatus} canWrite={canWrite}
          onDelete={onDelete} onDecide={onDecide} busy={busy}
        />
      ))}
    </div>
  );
}

// ---------------------------------------------------------- impact panel --

function ImpactPanel({ assetId }: { assetId: string }) {
  const [direction, setDirection] = useState<'downstream' | 'upstream'>('downstream');
  const q = useAssetImpact(assetId, direction);

  return (
    <div
      data-testid="impact-panel"
      style={{ padding: '13px 15px', borderRadius: 12, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)' }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 7 }}>
        <Icon name="zap" size={14} style={{ color: 'var(--accent)' }} />
        <div style={{ fontSize: 12.5, fontWeight: 700, color: 'var(--app-t1)' }}>
          {direction === 'downstream' ? 'What depends on this' : 'What this depends on'}
        </div>
        <div style={{ flex: 1 }} />
        <button
          className="ui-btn sm ghost"
          onClick={() => setDirection((d) => (d === 'downstream' ? 'upstream' : 'downstream'))}
        >
          <Icon name="arrow-left-right" size={12} />
          {direction === 'downstream' ? 'Show upstream' : 'Show downstream'}
        </button>
      </div>

      {q.isLoading && (
        <div data-testid="impact-loading" style={{ fontSize: 12, color: 'var(--app-t3)' }}>Working out the blast radius…</div>
      )}

      {/* A failed impact read must NOT render as "nothing depends on this" —
          that is a sentence somebody plans a maintenance window around. */}
      {q.isError && (
        <div data-testid="impact-error" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Icon name="alert-triangle" size={14} style={{ color: 'var(--danger-text)' }} />
          <span style={{ fontSize: 12.5, color: 'var(--app-t1)', flex: 1 }}>
            Couldn&rsquo;t work out what depends on this — {q.error instanceof Error ? q.error.message : 'the request failed'}.
            This is not an answer of &ldquo;nothing&rdquo;.
          </span>
          <button className="ui-btn sm" onClick={() => { void q.refetch(); }}>Retry</button>
        </div>
      )}

      {q.data && !q.isError && (
        <>
          <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--app-t1)' }}>
            {impactHeadline(q.data)}
          </div>
          {q.data.total > 0 && (
            <div className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 3 }}>
              {depthSummary(q.data)}
            </div>
          )}
          {q.data.truncated && (
            <div data-testid="impact-truncated" style={{ fontSize: 11.5, color: 'var(--warn-text, var(--warn))', marginTop: 5 }}>
              The closure hit the {q.data.node_cap}-asset cap, so this is a floor rather than a total.
            </div>
          )}
          <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 7, lineHeight: 1.55 }}>
            Counted over {q.data.types.length} relationship types. Observed network connections
            (<span className="mono">connects_to</span>) are deliberately not among them — a flow is not a dependency.
            Only confirmed relationships count; pending ones do not.
          </div>
          {q.data.nodes.length > 0 && (
            <div style={{ marginTop: 10, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {q.data.nodes.slice(0, 12).map((n) => (
                <Link
                  key={n.asset_id}
                  to={`/inventory/assets/${n.asset_id}`}
                  className="ui-btn sm ghost"
                  style={{ textDecoration: 'none', fontSize: 11.5 }}
                >
                  {n.display_name || `${n.asset_id.slice(0, 8)}…`}
                  <span className="mono" style={{ opacity: 0.6 }}>{n.depth}h</span>
                </Link>
              ))}
              {q.data.nodes.length > 12 && (
                <span style={{ fontSize: 11.5, color: 'var(--app-t3)', alignSelf: 'center' }}>
                  +{q.data.nodes.length - 12} more
                </span>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ------------------------------------------------------------ add modal --

function AddRelationshipModal({ asset, onClose }: { asset: Asset; onClose: () => void }) {
  const [type, setType] = useState<RelationshipType>('depends_on');
  const [direction, setDirection] = useState<'out' | 'in'>('out');
  const [search, setSearch] = useState('');
  const [picked, setPicked] = useState<{ id: string; name: string } | null>(null);
  const create = useCreateRelationship(asset.id);

  // The asset picker speaks the query language, like everything else that
  // searches inventory here — a quoted free-text term, which is what the
  // search box compiles to.
  const term = search.trim();
  const results = useAssetsQuery(term ? JSON.stringify(term) : '', 1, term.length >= 2);
  const candidates = useMemo(
    () => (results.data?.assets ?? []).filter((a) => a.id !== asset.id).slice(0, 8),
    [results.data, asset.id],
  );

  const thisName = asset.display_name || asset.hostname || `${asset.id.slice(0, 8)}…`;
  const preview = declarationPreview(type, direction, thisName, picked?.name ?? 'the other asset');

  return (
    <div
      role="dialog"
      aria-label="Add relationship"
      data-testid="add-relationship-modal"
      style={{
        position: 'fixed', inset: 0, zIndex: 60, display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: 'color-mix(in srgb, black 45%, transparent)', padding: 20,
      }}
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 'min(620px, 100%)', maxHeight: '86vh', overflow: 'auto', borderRadius: 14,
          border: '1px solid var(--app-border2)', background: 'var(--app-panel)', padding: '18px 20px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 14 }}>
          <Icon name="waypoints" size={16} style={{ color: 'var(--accent)' }} />
          <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontSize: 15.5, fontWeight: 700, color: 'var(--app-t1)' }}>
            Add a relationship
          </h2>
          <div style={{ flex: 1 }} />
          <button className="ui-btn sm ghost" aria-label="Close" onClick={onClose}><Icon name="x" size={13} /></button>
        </div>

        <label className="eyebrow-app" style={{ display: 'block', marginBottom: 5 }}>Type</label>
        <select
          aria-label="Relationship type"
          value={type}
          onChange={(e) => setType(e.target.value as RelationshipType)}
          className="ui-input"
          style={{ width: '100%', marginBottom: 4 }}
        >
          {RELATIONSHIP_TYPES.map((t) => (
            <option key={t} value={t}>{TYPE_LABEL[t]}</option>
          ))}
        </select>
        <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginBottom: 14 }}>{TYPE_HELP[type]}</div>

        <label className="eyebrow-app" style={{ display: 'block', marginBottom: 5 }}>Direction</label>
        <div style={{ display: 'flex', gap: 7, marginBottom: 14 }}>
          {(['out', 'in'] as const).map((d) => (
            <button
              key={d}
              className="ui-btn sm"
              aria-pressed={direction === d}
              onClick={() => setDirection(d)}
              style={{
                borderColor: direction === d ? 'var(--accent)' : 'var(--app-border2)',
                color: direction === d ? 'var(--accent)' : 'var(--app-t2)',
              }}
            >
              {d === 'out' ? `This ${TYPE_LABEL[type]} …` : `… ${TYPE_LABEL[type]} this`}
            </button>
          ))}
        </div>

        <label className="eyebrow-app" style={{ display: 'block', marginBottom: 5 }}>The other asset</label>
        <input
          className="ui-input"
          aria-label="Search for an asset"
          placeholder="Search by name, hostname, identifier or tag…"
          value={picked ? picked.name : search}
          onChange={(e) => { setPicked(null); setSearch(e.target.value); }}
          style={{ width: '100%' }}
        />
        {!picked && term.length >= 2 && (
          <div data-testid="asset-picker-results" style={{ marginTop: 6, border: '1px solid var(--app-border)', borderRadius: 10, overflow: 'hidden' }}>
            {results.isLoading && <div style={{ padding: '8px 11px', fontSize: 12, color: 'var(--app-t3)' }}>Searching…</div>}
            {/* A failed search is NOT "no matches" — the user would conclude
                the asset does not exist and create a duplicate. */}
            {results.isError && (
              <div data-testid="asset-picker-error" style={{ padding: '8px 11px', fontSize: 12, color: 'var(--danger-text)' }}>
                Couldn&rsquo;t search — {results.error instanceof Error ? results.error.message : 'the request failed'}. This is not a result of &ldquo;no matches&rdquo;.
              </div>
            )}
            {!results.isLoading && !results.isError && candidates.length === 0 && (
              <div style={{ padding: '8px 11px', fontSize: 12, color: 'var(--app-t3)' }}>No assets match that.</div>
            )}
            {candidates.map((a) => (
              <button
                key={a.id}
                onClick={() => setPicked({ id: a.id, name: a.display_name || a.hostname || a.id.slice(0, 8) })}
                style={{
                  display: 'block', width: '100%', textAlign: 'left', padding: '7px 11px', border: 'none',
                  borderBottom: '1px solid var(--app-border)', background: 'transparent', cursor: 'pointer',
                  fontSize: 12.5, color: 'var(--app-t1)', fontFamily: 'var(--font-body)',
                }}
              >
                {a.display_name || a.hostname || a.id.slice(0, 8)}
                <span style={{ fontSize: 11, color: 'var(--app-t3)', marginLeft: 8 }}>{classLabel(a.class_key)}</span>
              </button>
            ))}
          </div>
        )}

        {/* The sentence, before it is created. Direction is the most confusable
            part of declaring an edge — "runs on" pointing the wrong way is a
            plausible row that inverts every impact answer built on it — so the
            modal shows the whole thing with both names rather than a dropdown
            and a hope. */}
        <div
          data-testid="declaration-preview"
          style={{
            marginTop: 16, padding: '10px 13px', borderRadius: 10,
            border: '1px solid var(--app-border2)', background: 'var(--app-panel2)',
            fontSize: 13, color: 'var(--app-t1)',
          }}
        >
          {preview}
        </div>

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16 }}>
          <button className="ui-btn" onClick={onClose}>Cancel</button>
          <button
            className="ui-btn accent"
            disabled={!picked || create.isPending}
            onClick={() => {
              if (!picked) return;
              create.mutate(
                { type, peerAssetId: picked.id, direction },
                { onSuccess: onClose },
              );
            }}
          >
            <Icon name="plus" size={13} />Add relationship
          </button>
        </div>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------- tab --

export function RelationshipsTab({ asset }: { asset: Asset }) {
  const q = useAssetRelationships(asset.id);
  // Called for the counts, and left as the seam workstream 2.9's map mounts
  // onto: the same hook, the same cache key, with a renderer added.
  const nbh = useAssetNeighbourhood(asset.id, { depth: 2 });
  const del = useDeleteRelationship(asset.id);
  const decide = useDecideRelationshipProposal();
  // Not destructured: `const { hasPermission } = usePermissions()` trips
  // @typescript-eslint/unbound-method and the lint job is a warning ratchet.
  const canWrite = usePermissions().hasPermission(TENANT_PERMISSIONS.assets.update);
  const [addOpen, setAddOpen] = useState(false);

  // Memoised rather than `q.data?.relationships ?? []` inline: a fresh []
  // every render would re-run the grouping on every render.
  const edges = useMemo(() => q.data?.relationships ?? [], [q.data]);
  const grouped = useMemo(() => groupByDirection(edges, asset.id), [edges, asset.id]);
  const pendingCount = edges.filter((e) => e.status === 'pending').length;
  const busy = del.isPending || decide.isPending;

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14, marginBottom: 16 }}>
        <p style={{ margin: 0, fontSize: 12.5, color: 'var(--app-t3)', lineHeight: 1.6, flex: 1 }}>
          What this asset runs on, hosts, depends on and connects to. Relationships are collected by
          sensors, cloud APIs and device interrogation, imported from a CMDB, or declared here.
          Each one shows where it came from, because an observation and a guess are not worth the same.
        </p>
        <PermissionGate permission={TENANT_PERMISSIONS.assets.update}>
          <button className="ui-btn" onClick={() => setAddOpen(true)} style={{ height: 31, fontSize: 12.5, flexShrink: 0 }}>
            <Icon name="plus" size={13} />Add relationship
          </button>
        </PermissionGate>
      </div>

      <div style={{ marginBottom: 18 }}>
        <ImpactPanel assetId={asset.id} />
      </div>

      {q.isLoading && (
        <div data-testid="relationships-loading" style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>
          Loading relationships…
        </div>
      )}

      {/* A failed read is an UNKNOWN number of relationships, not zero. */}
      {q.isError && (
        <div
          data-testid="relationships-error"
          style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '11px 14px', borderRadius: 12, border: '1px solid var(--danger)', background: 'color-mix(in srgb, var(--danger) 7%, transparent)' }}
        >
          <Icon name="alert-triangle" size={15} style={{ color: 'var(--danger-text)', flexShrink: 0 }} />
          <span style={{ fontSize: 12.5, color: 'var(--app-t1)', flex: 1 }}>
            Couldn&rsquo;t load relationships — {q.error instanceof Error ? q.error.message : 'the request failed'}.
            This asset may still have some; they are not shown.
          </span>
          <button className="ui-btn sm" onClick={() => { void q.refetch(); }}>Retry</button>
        </div>
      )}

      {q.data && !q.isError && edges.length === 0 && (
        <div data-testid="relationships-empty" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8, padding: '38px 20px', textAlign: 'center' }}>
          <Icon name="waypoints" size={24} style={{ color: 'var(--app-t3)' }} />
          <div style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--app-t1)' }}>No relationships recorded</div>
          <div style={{ fontSize: 12.5, color: 'var(--app-t3)', maxWidth: 480, lineHeight: 1.6 }}>
            Nothing has been observed or declared about what this asset is attached to. Most of an inventory is
            a leaf, so this is a normal answer — but it means impact analysis has nothing to go on for this asset.
            Add one above if you know of it.
          </div>
        </div>
      )}

      {edges.length > 0 && (
        <>
          {pendingCount > 0 && (
            <div
              data-testid="relationships-pending-note"
              style={{ fontSize: 12, color: 'var(--app-t3)', marginBottom: 12 }}
            >
              {pendingCount} of these {pendingCount === 1 ? 'is' : 'are'} pending — proposed but not confirmed,
              and not counted in impact. They also appear in Discovery &rarr; <Link to="/discovery/approvals" style={{ color: 'var(--accent)' }}>Approvals</Link>.
            </div>
          )}
          <EdgeGroup
            title="This asset" help="edges where this asset is the subject"
            edges={grouped.outbound} assetId={asset.id} assetStatus={asset.asset_status}
            canWrite={canWrite} busy={busy}
            onDelete={(id) => del.mutate(id)}
            onDecide={(id, action) => decide.mutate({ id, action })}
          />
          <EdgeGroup
            title="Other assets" help="edges pointing at this asset"
            edges={grouped.inbound} assetId={asset.id} assetStatus={asset.asset_status}
            canWrite={canWrite} busy={busy}
            onDelete={(id) => del.mutate(id)}
            onDecide={(id, action) => decide.mutate({ id, action })}
          />
          {q.data && q.data.total > edges.length && (
            <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>
              Showing {edges.length} of {q.data.total} relationships.
            </div>
          )}
        </>
      )}

      {/* The neighbourhood's size, and the way into the map that draws it.
          Reporting the truncation here too, because a number that silently caps
          is the thing this endpoint exists to avoid. */}
      {nbh.data && nbh.data.total_nodes > 1 && (
        <div data-testid="neighbourhood-summary" style={{ marginTop: 18, display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 11.5, color: 'var(--app-t3)', lineHeight: 1.6 }}>
            Within two hops: {nbh.data.total_nodes} assets and {nbh.data.total_edges} relationships.
            {nbh.data.truncated && ' More than the map draws at once.'}
          </span>
          <Link
            to={`/inventory?lens=map&focus=${encodeURIComponent(asset.id)}`}
            className="ui-btn sm"
            style={{ textDecoration: 'none', fontSize: 12 }}
          >
            <Icon name="waypoints" size={12} />View on map
          </Link>
        </div>
      )}

      {addOpen && <AddRelationshipModal asset={asset} onClose={() => setAddOpen(false)} />}
    </div>
  );
}

export { directionOf };
