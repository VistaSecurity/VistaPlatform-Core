// The Inventory health hero (ADR-0006 D5, workstream 3.8).
//
// D5: "The hero becomes Inventory health (assets by class with pending and
// stale counts, data-quality score from the ADR-0005 health checks) BESIDE the
// existing Cryptographic posture index. … The ops persona reads the left half,
// the compliance persona the right, and both see the same page. No new
// dashboard."
//
// So this is a second hero panel on the SAME page, laid out to that split: the
// class breakdown and the two lifecycle counts on the left, the data-quality
// score on the right. It is deliberately not a new route and not a tab.
//
// Every number here is three-valued, and the arithmetic that makes that true
// lives in `inventory-health.ts` — see there for why summing the class facet's
// buckets would count most of the estate three times, and why a hygiene score
// of null must never render as 100.
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router';
import { Icon, PercentageGauge, hygienePercentageColor } from '../../components/ui';
import { clients } from '../../lib/clients';
import { useAssetFacets, type FacetLevel } from '../inventory/asset-queries';
import { CLASS_GROUP_STYLES, classGroupOf } from '../inventory/map-model';
import {
  HERO_PENDING_HREF, HERO_STALE_QUERY, bucketCount, classSlices, hygieneScore,
  inventoryQueryHref, totalFromClasses, type ClassSlice, type HygieneScore,
} from './inventory-health';

/**
 * The three facet levels the hero reads, over the WHOLE tenant (no query).
 *
 * Typed as `FacetLevel`, which is derived from the OpenAPI contract, so a level
 * the endpoint does not serve is a TypeScript error here rather than a 400 at
 * runtime and a permanently empty tile.
 */
const HERO_LEVELS: readonly FacetLevel[] = ['class', 'status', 'stale_status'];

/**
 * The Inventory Hygiene score, from the same `/frameworks/available` rollup the
 * Posture page reads.
 *
 * One call, one cache key shared with Posture — the hero and the framework's
 * own page read the same row, so they cannot report different scores for the
 * same tenant.
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

export function InventoryHealthHero() {
  const facets = useAssetFacets('', HERO_LEVELS);
  const hygieneQ = useHygiene();

  const classes = classSlices(facets.data?.buckets.class);
  const total = totalFromClasses(facets.data?.buckets.class);
  const classFailed = facets.isError || (facets.data?.failed.includes('class') ?? false);
  const pending = facets.isError ? null : bucketCount(facets.data, 'status', 'pending_approval');
  const stale = facets.isError ? null : bucketCount(facets.data, 'stale_status', 'stale');
  const hygiene = hygieneQ.isError ? null : hygieneScore(hygieneQ.data);

  const max = Math.max(...classes.map((c) => c.count), 1);

  return (
    <div
      className="fade-up panel"
      data-testid="inventory-health-hero"
      style={{
        position: 'relative', overflow: 'hidden', padding: '22px 30px', margin: '0 0 18px',
        background: 'var(--hero-bg)', border: '1px solid var(--hero-border)',
      }}
    >
      <div
        className="hero-glow"
        style={{ position: 'absolute', right: '-8%', top: '-70%', width: 520, height: 520, background: 'var(--accent-glow)', opacity: 0.4, pointerEvents: 'none' }}
      />
      <div style={{ position: 'relative', display: 'flex', gap: 34, alignItems: 'stretch', flexWrap: 'wrap' }}>
        {/* ---- the ops half: what is out there, and what needs a decision ---- */}
        <div style={{ flex: '0 0 320px', minWidth: 280, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          <div className="eyebrow-app" style={{ marginBottom: 9 }}>Inventory Health</div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 9 }}>
            <Link
              to={inventoryQueryHref('')}
              className="accent-text"
              data-testid="hero-total"
              style={{ fontFamily: 'var(--font-head)', fontWeight: 800, fontSize: 56, lineHeight: 0.9, letterSpacing: '-.03em', textDecoration: 'none' }}
            >
              {facets.isLoading ? '…' : classFailed ? '—' : total.toLocaleString()}
            </Link>
            <span style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>configuration items</span>
          </div>
          <p style={{ margin: '14px 0 0', fontSize: 13, lineHeight: 1.55, color: 'var(--app-t2)', maxWidth: 300 }}>
            {classFailed
              ? "Couldn't load the inventory breakdown."
              : 'Everything the platform tracks, whatever it is made of — not only the things that speak TLS.'}
          </p>

          <div style={{ display: 'flex', gap: 22, marginTop: 20 }}>
            <HeroCount
              testId="hero-count-pending"
              label="Pending approval"
              value={pending}
              // Approvals is ONE queue (ADR-0006 D1/D6). This links at the
              // queue itself rather than at a filtered asset list, because a
              // second place to approve things is the second inbox the ADR
              // rules out.
              to={HERO_PENDING_HREF}
              tone="var(--warn)"
              hint="Discovered assets waiting for someone to accept or deny them."
            />
            <HeroCount
              testId="hero-count-stale"
              label="Stale"
              value={stale}
              to={inventoryQueryHref(HERO_STALE_QUERY)}
              tone="var(--app-t3)"
              hint="Not seen recently. Still in the inventory, and still counted."
            />
          </div>
        </div>

        {/* ---- assets by class ---- */}
        <div style={{ flex: 1, minWidth: 320, display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
            <h3 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14.5, color: 'var(--app-t1)' }}>
              By class
            </h3>
            <Link to="/inventory?lens=map&view=topology" style={{ fontSize: 10.5, color: 'var(--accent)', textDecoration: 'none' }}>
              Topology <Icon name="arrow-up-right" size={11} />
            </Link>
          </div>
          {classFailed ? (
            <div style={{ flex: 1, minHeight: 120, borderRadius: 12, border: '1px dashed var(--app-border2)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, color: 'var(--app-t3)' }}>
              Couldn't load the class breakdown.
            </div>
          ) : facets.isLoading ? (
            <div style={{ flex: 1, minHeight: 120, borderRadius: 12, border: '1px dashed var(--app-border2)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, color: 'var(--app-t3)' }}>
              Loading…
            </div>
          ) : classes.length === 0 ? (
            <div style={{ flex: 1, minHeight: 120, display: 'flex', flexDirection: 'column', alignItems: 'flex-start', justifyContent: 'center', gap: 7 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--app-t1)' }}>Nothing in the inventory yet</div>
              <div style={{ fontSize: 12, color: 'var(--app-t3)', maxWidth: 380, lineHeight: 1.6 }}>
                Run a discovery, import a spreadsheet, or add an asset by hand — the class breakdown fills in as things arrive.
              </div>
              <Link to="/discovery" className="ui-btn sm" style={{ marginTop: 4, textDecoration: 'none' }}>Go to Discovery</Link>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }} data-testid="hero-class-breakdown">
              {classes.map((c) => <ClassRow key={c.path || 'other'} slice={c} max={max} />)}
            </div>
          )}
        </div>

        {/* ---- the compliance half: is the data any good? ---- */}
        <div style={{ flex: '0 0 250px', minWidth: 220, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          <div className="eyebrow-app" style={{ marginBottom: 9 }}>Data Quality</div>
          <HygieneBlock hygiene={hygiene} loading={hygieneQ.isLoading} />
        </div>
      </div>
    </div>
  );
}

/**
 * One lifecycle count.
 *
 * `null` is the third state and renders as an em dash with "Couldn't load"
 * beside it — never as 0. A reassuring zero is exactly what a person takes at
 * face value, and "nothing is waiting for you" is the most reassuring thing
 * this tile can say.
 */
function HeroCount({ label, value, to, tone, hint, testId }: {
  label: string; value: number | null; to: string; tone: string; hint: string; testId: string;
}) {
  const failed = value === null;
  return (
    <Link to={to} title={failed ? "Couldn't load this count." : hint} style={{ textDecoration: 'none' }}>
      <div className="mono" data-testid={testId} style={{ fontSize: 19, fontWeight: 700, color: failed ? 'var(--danger-text)' : tone, letterSpacing: '-.01em' }}>
        {failed ? '—' : value.toLocaleString()}
      </div>
      <div className="eyebrow-app" style={{ marginTop: 3 }}>{failed ? "Couldn't load" : label}</div>
    </Link>
  );
}

/** One class bar, clickable through to the list it counted. */
function ClassRow({ slice, max }: { slice: ClassSlice; max: number }) {
  const style = CLASS_GROUP_STYLES[classGroupOf(slice.path)];
  const pct = (slice.count / max) * 100;
  const row = (
    <>
      <span style={{ width: 20, flex: 'none', display: 'flex', alignItems: 'center', color: style.color }}>
        <Icon name={style.icon} size={13} />
      </span>
      <span style={{ fontSize: 12, color: 'var(--app-t2)', width: 106, flex: 'none', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {slice.label}
      </span>
      <span style={{ flex: 1, height: 13, borderRadius: 5, background: 'var(--app-track)', overflow: 'hidden' }}>
        <span style={{ display: 'block', width: pct + '%', height: '100%', background: style.color, borderRadius: 5, minWidth: slice.count ? 3 : 0 }} />
      </span>
      <span className="mono" style={{ fontSize: 12, color: 'var(--app-t2)', width: 44, textAlign: 'right' }}>
        {slice.count.toLocaleString()}
      </span>
    </>
  );
  // "Other" is a ROLL-UP, not a class, so there is no query that selects it and
  // it is not a link. Making it one would send a reader to a list that is not
  // the rows the number came from.
  if (slice.other) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 9 }} title="Every remaining class, together.">{row}</div>
    );
  }
  return (
    <Link
      to={inventoryQueryHref(`class:${slice.path}`)}
      style={{ display: 'flex', alignItems: 'center', gap: 9, textDecoration: 'none' }}
      title={`${slice.label} — and everything beneath it in the taxonomy`}
    >
      {row}
    </Link>
  );
}

/**
 * The data-quality block.
 *
 * Three states, and the middle one is the one that matters. `Not assessed` is
 * shown whenever the Inventory Hygiene framework has produced no score — before
 * the first evaluation, and after one in which no control could be assessed
 *. Neither is 100%, and a hero that rounded "we have not looked" up to
 * a clean bill of health would be the exact dishonesty the platform's score-0
 * convention exists to prevent.
 */
function HygieneBlock({ hygiene, loading }: { hygiene: HygieneScore | null; loading: boolean }) {
  if (loading) {
    return <div style={{ fontSize: 12, color: 'var(--app-t3)' }}>Loading…</div>;
  }
  if (!hygiene) {
    return (
      <div data-testid="hygiene-error" style={{ fontSize: 12.5, color: 'var(--danger-text)' }}>
        Couldn't load the data-quality score.
      </div>
    );
  }
  if (!hygiene.present) {
    return (
      <div data-testid="hygiene-absent" style={{ fontSize: 12.5, color: 'var(--app-t3)', lineHeight: 1.6 }}>
        The Inventory Hygiene framework is not in this catalogue.
      </div>
    );
  }
  if (hygiene.score === null) {
    return (
      <div data-testid="hygiene-not-assessed">
        <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 22, color: 'var(--app-t2)' }}>
          Not assessed
        </div>
        <p style={{ margin: '10px 0 0', fontSize: 12.5, color: 'var(--app-t3)', lineHeight: 1.6 }}>
          {hygiene.activated
            ? 'Inventory Hygiene is active but has produced no score yet. It reconciles when assets change.'
            : 'Activate the free Inventory Hygiene framework to get a data-quality score.'}
        </p>
        <Link to="/risk-compliance/posture" className="ui-btn sm" style={{ marginTop: 10, textDecoration: 'none' }}>
          {hygiene.activated ? 'Open Posture' : 'Activate it'}
        </Link>
      </div>
    );
  }
  return (
    <div data-testid="hygiene-score" style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
      <PercentageGauge value={hygiene.score} color={hygienePercentageColor(hygiene.score)} size={86} label="" stroke={7} />
      <div style={{ display: 'flex', flexDirection: 'column', gap: 7, fontSize: 11 }}>
        <Stat n={hygiene.passing} label="checks passing" color="var(--ok)" />
        <Stat n={hygiene.failing} label="failing" color="var(--warn-strong)" />
        {/* The honest third bucket, shown even at zero: a coverage line that
            silently omits it reads as "everything was checked". */}
        <Stat n={hygiene.notAssessed} label="not assessed" color="var(--app-t3)" />
      </div>
    </div>
  );
}

function Stat({ n, label, color }: { n: number | null; label: string; color: string }) {
  return (
    <span style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
      <span style={{ width: 7, height: 7, borderRadius: 50, background: color, flex: 'none' }} />
      <span className="mono" style={{ fontSize: 13, fontWeight: 700, color }}>{n ?? '—'}</span>
      <span style={{ color: 'var(--app-t3)' }}>{label}</span>
    </span>
  );
}
