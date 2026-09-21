// Dashboard · ASSETS — the configuration-item view of the estate.
//
// The question this page answers is the ops one: *what do we have, how do we
// know, and what do we not know about it?* The shared Dashboard's Inventory
// Health hero answers the first two lines of that in a strip; this goes down to
// the facets themselves, because "3,412 assets" is not actionable and "1,900 of
// them have no business unit recorded" is.
//
// Every panel is a facet level over the WHOLE tenant (no query), and every
// bucket row links back into the Inventory list filtered to exactly the rows it
// counted. Nothing here is a new endpoint or a new number: it is the facet rail
// the Inventory page already draws, read as a page rather than as a filter.
import { useQuery } from '@tanstack/react-query';
import { Icon, PercentageGauge, hygienePercentageColor } from '../../components/ui';
import { clients } from '../../lib/clients';
import { useAssetFacets, type FacetLevel } from '../inventory/asset-queries';
import {
  BandHeading, BucketBars, DashboardHeader, DashboardShell, Grid, PageError, Panel, PanelLink, PanelNote, StatTile,
} from './dashboard-bits';
import {
  COMPOSITION_PANELS, LIFECYCLE_PANELS, attributeCoverage, bucketRows, drillThrough,
  facetBucketCount, inventoryQueryHref, totalAssets,
} from './assets-dashboard-metrics';
import { HERO_PENDING_HREF, HERO_PENDING_QUERY, hygieneScore, pendingCount } from './inventory-health';

/**
 * Every facet level this page reads, in ONE request fan-out.
 *
 * Typed `FacetLevel`, which is derived from the OpenAPI contract, so a level the
 * endpoint does not serve is a TypeScript error here rather than a 400 at
 * runtime and a permanently empty panel.
 *
 * `useAssetFacets` records which levels FAILED instead of returning them as
 * empty buckets, which is what lets each panel below say "couldn't load" for
 * itself while its neighbours still show real numbers.
 */
const LEVELS: readonly FacetLevel[] = [
  'class', 'environment', 'business_unit', 'ownership',
  'status', 'stale_status', 'source', 'risk',
  'site', 'owner_email', 'has_endpoints',
];

/**
 * A SECOND facet fetch, for the pending count alone.
 *
 * The facets endpoint takes one query for the whole fan-out, and this one has to
 * name `status:pending_approval` to escape the list's default `status:monitoring`
 * scope. Every other level on this page must KEEP that scope, because those are
 * the numbers the Inventory list shows. See HERO_PENDING_QUERY.
 */
const PENDING_LEVELS: readonly FacetLevel[] = ['status'];

/**
 * The Inventory Hygiene framework's materialized score — the data-quality half
 * of this page.
 *
 * Same query key as the shared Dashboard's hero and the Posture page, so all
 * three read one cached row and cannot report different scores for one tenant.
 */
function useHygiene() {
  return useQuery({
    queryKey: ['posture', 'available-frameworks'],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/frameworks/available', {});
      if (error || !data) throw new Error('Failed to load frameworks');
      return data.frameworks ?? [];
    },
    staleTime: 60_000,
  });
}

export function AssetsDashboardPage() {
  const facets = useAssetFacets('', LEVELS);
  const pendingFacets = useAssetFacets(HERO_PENDING_QUERY, PENDING_LEVELS);
  const hygieneQ = useHygiene();

  // A level is unusable if the whole fan-out errored OR this one level failed.
  // Both must be checked: `facets.isError` covers the query throwing, `failed`
  // covers one of eleven parallel requests 500ing while the rest succeeded.
  const failed = (level: string) => facets.isError || (facets.data?.failed.includes(level) ?? false);

  const total = totalAssets(facets.data?.buckets.class);
  const hygiene = hygieneQ.isError ? null : hygieneScore(hygieneQ.data);

  const pending = pendingFacets.isError ? null : pendingCount(pendingFacets.data);
  const stale = failed('stale_status') ? null : facetBucketCount(facets.data, 'stale_status', 'stale');
  const unscored = failed('risk') ? null : facetBucketCount(facets.data, 'risk', 'not_assessed');
  const noEndpoints = failed('has_endpoints') ? null : facetBucketCount(facets.data, 'has_endpoints', 'false');

  // Attribute coverage — "do we know who owns these?" — is not derivable from
  // the panel bars, which show the split among the assets that DO have a value.
  const coverage = [
    { level: 'business_unit', label: 'Business unit' },
    { level: 'owner_email', label: 'Owner' },
    { level: 'site', label: 'Site' },
    { level: 'environment', label: 'Environment' },
  ].map((c) => ({ ...c, data: failed(c.level) ? null : attributeCoverage(facets.data, c.level) }));

  if (facets.isError && hygieneQ.isError) {
    return (
      <DashboardShell testId="assets-dashboard">
        <PageError title="Couldn't load the Assets dashboard" message="Every request on this page failed. Check that inventory-service is reachable." />
      </DashboardShell>
    );
  }

  const loading = facets.isLoading;
  const emptyEstate = !loading && !facets.isError && total === 0;

  return (
    <DashboardShell testId="assets-dashboard">
      <DashboardHeader
        icon="database"
        title="Assets"
        blurb="Your configuration items — what they are, who owns them, where they run, and how complete the record is. Every bar links through to the matching list in Inventory."
      />

      {/* ---------- HERO: how many, moving which way, how good is the record ---------- */}
      <div className="fade-up panel" style={{
        position: 'relative', overflow: 'hidden', padding: '24px 30px', marginBottom: 18,
        background: 'var(--hero-bg)', border: '1px solid var(--hero-border)',
      }}>
        <div className="hero-glow" style={{ position: 'absolute', right: '-8%', top: '-70%', width: 520, height: 520, background: 'var(--accent-glow)', opacity: 0.4, pointerEvents: 'none' }} />
        <div style={{ position: 'relative', display: 'flex', gap: 34, alignItems: 'stretch', flexWrap: 'wrap' }}>
          {/* count + movement */}
          <div style={{ flex: '0 0 320px', minWidth: 280, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
            <div className="eyebrow-app" style={{ marginBottom: 9 }}>Configuration Items</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 10 }}>
              <span className="accent-text" data-testid="assets-total" style={{ fontFamily: 'var(--font-head)', fontWeight: 800, fontSize: 64, lineHeight: 0.9, letterSpacing: '-.03em' }}>
                {loading ? '…' : facets.isError ? '—' : total.toLocaleString()}
              </span>
            </div>
            <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 10 }}>
              {facets.isError ? "Couldn't load the asset facets." : 'assets under management'}
            </div>
            {/* No 30-day movement line here, deliberately.
                `/infrastructure-assets/stats` counts `COUNT(*) FROM assets
                WHERE deleted_at IS NULL` — EVERY record, including the ones
                awaiting approval and the archived ones. The headline above is
                the list's scoped population. Putting the two side by side
                produced "25 assets under management · +43 in the last 30 days",
                which is arithmetically impossible on its face and was on screen
                on 2026-09-21.

                A scoped asset-count trend would be a real addition; it needs a
                server endpoint that does not exist, so this says nothing rather
                than something wrong. */}
            <div style={{ marginTop: 14, fontSize: 11.5, color: 'var(--app-t3)', lineHeight: 1.5, maxWidth: 300 }}>
              Assets in the managed inventory. Records awaiting approval are counted
              separately, under Needs a decision.
            </div>
          </div>

          {/* things needing a decision */}
          <div style={{ flex: 1, minWidth: 340, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
            <div className="eyebrow-app" style={{ marginBottom: 11 }}>Needs a decision</div>
            <Grid min={150} gap={11}>
              <StatTile value={pending} label="Pending approval" sub="waiting on review" icon="inbox" tone="var(--warn)" href={HERO_PENDING_HREF} error={failed('status')} />
              <StatTile value={stale} label="Stale" sub="stopped being seen" icon="clock" tone="var(--warn-strong)" href={drillThrough('stale_status', 'stale')} error={failed('stale_status')} />
              <StatTile value={unscored} label="Unscored" sub="no risk signal yet" icon="search" tone="var(--app-t3)" href={drillThrough('risk', 'not_assessed')} error={failed('risk')} />
              {/* has_endpoints has no query field, so this tile is deliberately
                  not a link — see drillThrough. A tile that opens the whole
                  inventory under a number that counted a subset is worse than a
                  tile you cannot click. */}
              <StatTile value={noEndpoints} label="No endpoints" sub="nothing to probe yet" icon="unplug" tone="var(--app-t3)" error={failed('has_endpoints')} />
            </Grid>
          </div>

          {/* data quality */}
          <div style={{ flex: '0 0 250px', minWidth: 220, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
            <div className="eyebrow-app" style={{ marginBottom: 11 }}>Record Quality</div>
            {hygieneQ.isError || !hygiene ? (
              <PanelNote>Couldn't load the hygiene score.</PanelNote>
            ) : !hygiene.present ? (
              <PanelNote>The Inventory Hygiene framework is not in the catalogue.</PanelNote>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                {/* null → "Not assessed", never 0 and never 100. Null happens
                    both before the engine has produced a rollup and after it has
                    when NO control could be assessed (#1369); rendering either
                    as a number is a claim we have not earned. */}
                <PercentageGauge value={hygieneQ.isLoading ? null : hygiene.score} size={92} label="" stroke={8} />
                <div style={{ fontSize: 11.5, color: 'var(--app-t3)', lineHeight: 1.5 }}>
                  {hygiene.score === null ? (
                    <span>Not assessed yet.</span>
                  ) : (
                    <>
                      <div style={{ color: hygienePercentageColor(hygiene.score), fontWeight: 700, fontSize: 12.5 }}>Inventory Hygiene</div>
                      <div>{hygiene.passing ?? 0} passing · {hygiene.failing ?? 0} failing</div>
                      {(hygiene.notAssessed ?? 0) > 0 && <div>{hygiene.notAssessed} not assessed</div>}
                    </>
                  )}
                  <div style={{ marginTop: 7 }}>
                    <PanelLink to="/risk-compliance/posture?tab=frameworks">Open the frameworks</PanelLink>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {emptyEstate ? (
        <div className="panel fade-up" style={{ padding: '44px 24px', textAlign: 'center' }}>
          <Icon name="radar" size={26} style={{ color: 'var(--accent)' }} />
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--app-t1)', marginTop: 12 }}>No assets yet</div>
          <div style={{ fontSize: 12.5, color: 'var(--app-t3)', marginTop: 4, marginBottom: 14 }}>
            Nothing has been discovered or imported into this tenant. Start a discovery to populate the inventory.
          </div>
          <PanelLink to="/discovery">Go to Discovery</PanelLink>
        </div>
      ) : (
        <>
          {/* ---------- COMPOSITION ---------- */}
          <div className="fade-up" style={{ marginBottom: 18, animationDelay: '.05s' }}>
            <BandHeading title="Composition" note="what the estate is made of" />
            <Grid min={330}>
              {COMPOSITION_PANELS.map((p) => {
                const { rows, total: sum } = bucketRows(p.level, facets.data?.buckets[p.level], p.limit);
                return (
                  <Panel
                    key={p.level}
                    icon={p.icon}
                    title={p.title}
                    caption={p.caption}
                    loading={facets.isLoading}
                    error={failed(p.level)}
                    empty={rows.length === 0}
                    emptyText="No values recorded for this attribute."
                    testId={`assets-panel-${p.level}`}
                    footer={<PanelLink to={inventoryQueryHref('')}>Open in Inventory</PanelLink>}
                  >
                    <BucketBars rows={rows} total={sum} />
                  </Panel>
                );
              })}
            </Grid>
          </div>

          {/* ---------- LIFECYCLE & PROVENANCE ---------- */}
          <div className="fade-up" style={{ marginBottom: 18, animationDelay: '.1s' }}>
            <BandHeading title="Lifecycle and provenance" note="where each record is in its life, and where it came from" />
            <Grid min={330}>
              {LIFECYCLE_PANELS.map((p) => {
                const { rows, total: sum } = bucketRows(p.level, facets.data?.buckets[p.level], p.limit);
                return (
                  <Panel
                    key={p.level}
                    icon={p.icon}
                    title={p.title}
                    caption={p.caption}
                    loading={facets.isLoading}
                    error={failed(p.level)}
                    empty={rows.length === 0}
                    emptyText="No values recorded for this attribute."
                    testId={`assets-panel-${p.level}`}
                  >
                    <BucketBars rows={rows} total={sum} />
                  </Panel>
                );
              })}
            </Grid>
          </div>

          {/* ---------- ATTRIBUTE COVERAGE ---------- */}
          <div className="fade-up" style={{ animationDelay: '.15s' }}>
            <BandHeading title="Attribute coverage" note="how much of the estate carries each attribute at all" />
            <div className="panel" style={{ padding: 20 }}>
              <p style={{ margin: '0 0 16px', fontSize: 11.5, color: 'var(--app-t3)' }}>
                The share of assets with a value recorded. A low number here is a data-quality gap, not a risk —
                but it is what makes the panels above less useful than they look.
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {coverage.map((c) => (
                  <div key={c.level} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <span style={{ fontSize: 12, color: 'var(--app-t2)', width: 116, flex: 'none' }}>{c.label}</span>
                    {c.data === null ? (
                      <span style={{ fontSize: 11.5, color: failed(c.level) ? 'var(--danger-text)' : 'var(--app-t3)' }}>
                        {failed(c.level) ? "Couldn't load" : facets.isLoading ? 'Loading…' : 'Nothing recorded'}
                      </span>
                    ) : (
                      <>
                        <div style={{ flex: 1, height: 15, borderRadius: 5, background: 'var(--app-track)', overflow: 'hidden' }}>
                          <div style={{
                            width: c.data.percent + '%', height: '100%', borderRadius: 5,
                            background: hygienePercentageColor(c.data.percent), minWidth: c.data.known ? 3 : 0,
                          }} />
                        </div>
                        <span className="mono" style={{ fontSize: 12, color: 'var(--app-t2)', width: 46, textAlign: 'right' }}>{c.data.percent}%</span>
                        <span style={{ fontSize: 10.5, color: 'var(--app-t3)', width: 130, textAlign: 'right' }}>
                          {c.data.known.toLocaleString()} of {c.data.total.toLocaleString()} recorded
                        </span>
                      </>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </>
      )}
    </DashboardShell>
  );
}
