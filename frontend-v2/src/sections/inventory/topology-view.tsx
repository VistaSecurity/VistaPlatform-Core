// The Topology view (ADR-0006 D4, second half — workstream 3.8).
//
// The map's "where is everything" view, beside the neighbourhood's "what does
// this one thing touch". D4 rules out the obvious shape in the same breath as
// asking for it:
//
//	"not a force graph of thousands of nodes, which is unreadable everywhere it
//	 is tried. A hierarchical view by site → segment → class with counts,
//	 expandable to the assets in a segment, with cross-segment connection
//	 summaries drawn as aggregated edges. … The topology view needs no graph
//	 library; it is a tree with counts and can be built with the existing
//	 components."
//
// So: a tree, built from this app's own primitives, with no new dependency and
// nothing lazily loaded beyond what the map lens already loads. Every class
// node is a LINK into the asset list under the query that selects exactly the
// rows it counted (`topology-model.ts`), which is what makes the tree an index
// rather than a second copy of the inventory.
//
// The decisions live next door in `topology-model.ts` and are unit-tested; what
// is left here is markup and expansion state.
import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import { Icon } from '../../components/ui';
import { useAssetTopology } from './relationship-queries';
import { CLASS_GROUP_STYLES, classGroupOf } from './map-model';
import { classLabel } from './asset-shape';
import {
  classDrillThroughQuery, edgeSummary, segmentDrillThroughQuery, segmentKey,
  topologyAssetsHref, topologyEdgeHeadline, topologyTruncationNotice, treeAssetTotal,
  type TopologyEdge, type TopologySegment, type TopologySite,
} from './topology-model';

export function TopologyView() {
  const q = useAssetTopology();
  const t = q.data;

  // Expansion is per (site, segment) and defaults CLOSED for segments, open
  // for sites. A tenant's first look should be the shape of the estate, not
  // three hundred class rows.
  const [openSegments, setOpenSegments] = useState<Set<string>>(new Set());
  const [closedSites, setClosedSites] = useState<Set<string>>(new Set());

  const notice = useMemo(() => topologyTruncationNotice(t), [t]);
  const treeTotal = useMemo(() => treeAssetTotal(t), [t]);

  if (q.isLoading) {
    return (
      <Centered testId="topology-loading" icon="loader" title="Loading the topology…"
        message="Grouping every configuration item by site, segment and class." />
    );
  }
  if (q.isError) {
    return (
      <Centered testId="topology-error" icon="alert-triangle" tone="var(--danger-text)"
        title="Couldn't load the topology"
        message={q.error instanceof Error ? q.error.message : 'Request failed'} />
    );
  }
  if (!t || t.total_assets === 0) {
    return (
      <Centered testId="topology-empty" icon="map"
        title="Nothing to map yet"
        message="The topology groups your configuration items by site, segment and class. Run a discovery, import a spreadsheet, or add an asset by hand and the shape of the estate appears here."
        action={{ label: 'Go to Discovery', to: '/discovery' }} />
    );
  }

  const sites = t.sites ?? [];
  const edges = t.edges ?? [];
  const edgeHeadline = topologyEdgeHeadline(t);

  return (
    <div data-testid="topology-view" style={{ flex: 1, minHeight: 0, overflow: 'auto', padding: '4px 26px 30px' }}>
      {/* The headline numbers, and the honesty line under them. */}
      <div style={{ display: 'flex', alignItems: 'flex-end', gap: 26, flexWrap: 'wrap', marginBottom: 16 }}>
        <Headline n={t.total_assets} label="configuration items" />
        <Headline n={sites.length} label={sites.length === 1 ? 'site' : 'sites'} />
        <Headline
          n={t.unassigned_assets}
          label="with no site"
          // Amber when there ARE some, because that is the number that says
          // whether this diagram is the estate or a curated corner of it.
          tone={t.unassigned_assets > 0 ? 'var(--warn)' : undefined}
        />
        {/* The SERVER's count, not the drawn one. `edges` is what survived the
            cap, and reporting it as the estate's total is the headline saying
            "200 cross-segment links" about a tenant that has 900. */}
        <Headline
          n={edgeHeadline.count}
          label={edgeHeadline.label}
          suffix={edgeHeadline.partial ? ` (${edges.length.toLocaleString()} drawn)` : undefined}
          testId="topology-edge-headline"
        />
      </div>

      {/* The tree ADDS UP, or it says so. `total_assets` is counted
          independently of the grouping server-side, so a mismatch means a
          branch was lost or a cap cut one off — and a tidy picture of a subset
          is the failure this whole view exists to not commit. */}
      {treeTotal !== t.total_assets && (
        <Notice testId="topology-mismatch" tone="var(--warn)">
          The tree accounts for {treeTotal.toLocaleString()} of {t.total_assets.toLocaleString()} configuration
          items. {notice ? '' : 'Some groups are missing from this answer.'}
        </Notice>
      )}
      {notice && <Notice testId="topology-truncated" tone="var(--warn)">{notice}</Notice>}

      <div style={{ display: 'flex', gap: 22, alignItems: 'flex-start', flexWrap: 'wrap' }}>
        {/* ---- the tree ---- */}
        <div style={{ flex: '1 1 520px', minWidth: 360, display: 'flex', flexDirection: 'column', gap: 10 }}>
          {sites.map((site) => (
            <SiteBlock
              key={site.site}
              site={site}
              collapsed={closedSites.has(site.site)}
              onToggle={() => setClosedSites((s) => toggled(s, site.site))}
              openSegments={openSegments}
              onToggleSegment={(key) => setOpenSegments((s) => toggled(s, key))}
            />
          ))}
        </div>

        {/* ---- the aggregated edges ---- */}
        <div style={{ flex: '0 1 320px', minWidth: 280 }}>
          <h3 style={{ margin: '0 0 4px', fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--app-t1)' }}>
            Between segments
          </h3>
          <p style={{ margin: '0 0 11px', fontSize: 11.5, color: 'var(--app-t3)', lineHeight: 1.6 }}>
            Confirmed relationships that cross a segment boundary, aggregated. Pending ones are not drawn —
            an aggregate is the one place a single unconfirmed observation is invisible.
          </p>
          {edges.length === 0 ? (
            <div style={{ fontSize: 12, color: 'var(--app-t3)', border: '1px dashed var(--app-border2)', borderRadius: 11, padding: '16px 14px', lineHeight: 1.6 }}>
              No confirmed relationship crosses a segment boundary yet. This is not "your segments are isolated" —
              it means nothing has observed or declared a link between them.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }} data-testid="topology-edges">
              {edges.map((e, i) => <EdgeRow key={i} edge={e} />)}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function toggled(set: Set<string>, key: string): Set<string> {
  const next = new Set(set);
  if (next.has(key)) next.delete(key); else next.add(key);
  return next;
}

function Headline({ n, label, tone, suffix, testId }: {
  n: number; label: string; tone?: string; suffix?: string; testId?: string;
}) {
  return (
    <div data-testid={testId}>
      <div className="mono" style={{ fontSize: 24, fontWeight: 800, letterSpacing: '-.02em', color: tone ?? 'var(--app-t1)' }}>
        {n.toLocaleString()}
      </div>
      {/* The qualifier rides with the NUMBER, not only in the notice below: a
          reader who takes in the headline alone must still be told the picture
          is short of it. */}
      <div className="eyebrow-app" style={{ marginTop: 2 }}>{label}{suffix ?? ''}</div>
    </div>
  );
}

function Notice({ children, tone, testId }: { children: React.ReactNode; tone: string; testId: string }) {
  return (
    <div
      data-testid={testId}
      style={{
        display: 'flex', alignItems: 'flex-start', gap: 9, marginBottom: 12, padding: '10px 13px',
        borderRadius: 11, border: `1px solid ${tone}`,
        background: `color-mix(in srgb, ${tone} 8%, transparent)`,
        fontSize: 12.5, color: 'var(--app-t2)', lineHeight: 1.55,
      }}
    >
      <Icon name="alert-triangle" size={14} style={{ color: tone, flex: 'none', marginTop: 2 }} />
      <span>{children}</span>
    </div>
  );
}

function SiteBlock({ site, collapsed, onToggle, openSegments, onToggleSegment }: {
  site: TopologySite;
  collapsed: boolean;
  onToggle: () => void;
  openSegments: Set<string>;
  onToggleSegment: (key: string) => void;
}) {
  const segments = site.segments ?? [];
  return (
    <div className="panel" style={{ padding: '12px 15px' }} data-testid="topology-site">
      <button
        onClick={onToggle}
        style={{ display: 'flex', alignItems: 'center', gap: 9, width: '100%', background: 'none', border: 'none', padding: 0, cursor: 'pointer', textAlign: 'left' }}
      >
        <Icon name={collapsed ? 'chevron-right' : 'chevron-down'} size={14} style={{ color: 'var(--app-t3)' }} />
        <Icon name="building-2" size={14} style={{ color: 'var(--accent)' }} />
        <span style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--app-t1)', flex: 1 }}>{site.site}</span>
        <span className="mono" style={{ fontSize: 12, color: 'var(--app-t3)' }}>{site.asset_count.toLocaleString()}</span>
      </button>
      {!collapsed && (
        <div style={{ marginTop: 9, display: 'flex', flexDirection: 'column', gap: 5 }}>
          {segments.map((seg) => (
            <SegmentRow
              key={segmentKey(site.site, seg)}
              segment={seg}
              open={openSegments.has(segmentKey(site.site, seg))}
              onToggle={() => onToggleSegment(segmentKey(site.site, seg))}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function SegmentRow({ segment, open, onToggle }: {
  segment: TopologySegment; open: boolean; onToggle: () => void;
}) {
  const classes = segment.classes ?? [];
  // The unsegmented bucket is drawn differently on purpose: it is an ABSENCE,
  // not a segment, and giving it the same chrome as a real one would let a
  // reader take "Unsegmented" for something somebody drew.
  const isBucket = !segment.segment_id;
  return (
    <div data-testid="topology-segment" style={{ borderLeft: `2px solid ${isBucket ? 'var(--app-border2)' : 'var(--accent)'}`, paddingLeft: 11 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <button
          onClick={onToggle}
          style={{ display: 'flex', alignItems: 'center', gap: 7, flex: 1, background: 'none', border: 'none', padding: '3px 0', cursor: 'pointer', textAlign: 'left' }}
        >
          <Icon name={open ? 'chevron-down' : 'chevron-right'} size={13} style={{ color: 'var(--app-t3)' }} />
          <span style={{ fontSize: 12.5, color: isBucket ? 'var(--app-t3)' : 'var(--app-t1)', fontWeight: isBucket ? 400 : 600, fontStyle: isBucket ? 'italic' : 'normal' }}>
            {segment.segment_name}
          </span>
          <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>
            {classes.length} {classes.length === 1 ? 'class' : 'classes'}
          </span>
        </button>
        <Link
          to={topologyAssetsHref(segmentDrillThroughQuery(segment))}
          className="mono"
          style={{ fontSize: 12, color: 'var(--accent)', textDecoration: 'none' }}
          title={isBucket
            ? 'Every configuration item with no network segment recorded'
            : `Every configuration item in ${segment.segment_name}`}
        >
          {segment.asset_count.toLocaleString()}
        </Link>
      </div>
      {open && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, padding: '6px 0 8px 20px' }}>
          {classes.map((c) => {
            const style = CLASS_GROUP_STYLES[classGroupOf(c.class_key)];
            return (
              <Link
                key={c.class_key}
                data-testid="topology-class"
                to={topologyAssetsHref(classDrillThroughQuery(segment, c))}
                title={`${classLabel(c.class_key) || c.class_key} · ${c.class_path}`}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 6, padding: '3px 9px',
                  borderRadius: 40, textDecoration: 'none', fontSize: 11.5,
                  border: `1px solid color-mix(in srgb, ${style.color} 35%, transparent)`,
                  background: `color-mix(in srgb, ${style.color} 9%, transparent)`,
                  color: 'var(--app-t1)',
                }}
              >
                <Icon name={style.icon} size={11} style={{ color: style.color }} />
                {classLabel(c.class_key) || c.class_key}
                <span className="mono" style={{ color: 'var(--app-t3)' }}>{c.asset_count.toLocaleString()}</span>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}

function EdgeRow({ edge }: { edge: TopologyEdge }) {
  return (
    <div
      data-testid="topology-edge"
      style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '7px 11px', borderRadius: 10, border: '1px solid var(--app-border)', fontSize: 12 }}
    >
      <span style={{ color: 'var(--app-t1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 100 }}>
        {edge.from_segment_name}
      </span>
      <Icon name="arrow-right" size={12} style={{ color: 'var(--app-t3)', flex: 'none' }} />
      <span style={{ color: 'var(--app-t1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 100 }}>
        {edge.to_segment_name}
      </span>
      <span style={{ flex: 1 }} />
      <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)', whiteSpace: 'nowrap' }} title={edgeSummary(edge)}>
        {edge.count.toLocaleString()}
      </span>
    </div>
  );
}

function Centered({ testId, icon, tone, title, message, action }: {
  testId: string; icon: string; tone?: string; title: string; message: string;
  action?: { label: string; to: string };
}) {
  return (
    <div
      data-testid={testId}
      style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 9, padding: '54px 26px', textAlign: 'center' }}
    >
      <Icon name={icon} size={26} style={{ color: tone ?? 'var(--app-t3)' }} />
      <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--app-t1)' }}>{title}</div>
      <div style={{ fontSize: 12.5, color: 'var(--app-t3)', maxWidth: 500, lineHeight: 1.6 }}>{message}</div>
      {action && <Link to={action.to} className="ui-btn sm" style={{ marginTop: 4, textDecoration: 'none' }}>{action.label}</Link>}
    </div>
  );
}
