// Dashboard · COMPLIANCE — where the tenant stands against the frameworks it
// has taken on, and what it would take to close the gap.
//
// This page OVERLAPS Risk & Compliance → Posture → Overview, knowingly: the
// owner chose a full compliance dashboard over a gap-scoped one on,
// with the overlap named. What keeps the overlap safe is that every number here
// comes from the same hook, with the same react-query key, as the Posture page
// — `useFrameworkContext`, the `['posture','available-frameworks']` rollup,
// `usePostureByControl`. One fetch, one cached answer, two renderings. The
// failure this guards against is specific and has happened: the Dashboard read
// "0 critical findings" while the Findings page listed four, because the two
// surfaces asked different questions of different tables and nobody could see
// the disagreement.
//
// Posture stays the place you go to WORK a framework — the control grid, the
// per-control re-evaluation, the algorithm reference. This is the place you go
// to see where you stand.
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router';
import { Icon, LevelDot, PercentageGauge, frameworkPercentageColor } from '../../components/ui';
import { clients } from '../../lib/clients';
import { PostureTrendChart } from '../../components/posture-trend-chart';
import { sevLevel } from '../findings/model';
import { useFrameworkContext, usePostureByControl, usePostureTrend } from '../findings/queries';
import { fetchDashboardTicketStats } from './dashboard-queries';
import {
  BandHeading, DashboardHeader, DashboardShell, Grid, PageError, Panel, PanelLink, PanelNote, StatTile,
} from './dashboard-bits';
import {
  COMPLIANCE_FINDINGS_ROUTE, COMPLIANCE_FRAMEWORKS_ROUTE, COMPLIANCE_POSTURE_ROUTE, COMPLIANCE_REMEDIATION_ROUTE,
  WORKFLOW_SCOPE_NOTE, activationCoverage, frameworkCards, openFindingsTotal, remediationRollup,
  severityRows, sortFrameworkCards, targetNoun, ticketCategories, workflowStages,
} from './compliance-dashboard-metrics';

/**
 * Every published framework with its materialized score.
 *
 * SAME key as the Posture page's framework browser and the shared Dashboard's
 * hygiene tile. Sharing the key is the whole mitigation for this page's overlap
 * with Posture: three surfaces, one fetch, one answer.
 */
function useAvailableFrameworks() {
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

/** Tenant-wide finding counts, every producer. */
function useFindingStats() {
  return useQuery({
    queryKey: ['dashboard', 'findings-statistics'],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/findings/statistics', {});
      if (error || !data) throw new Error('Failed to load finding statistics');
      return data;
    },
    staleTime: 60_000,
  });
}

function useTickets() {
  return useQuery({ queryKey: ['dashboard', 'ticket-stats'], queryFn: fetchDashboardTicketStats, staleTime: 60_000 });
}

/** A framework score ring. `null` draws no arc and reads "—". */
function ScoreRing({ score, size = 54, stroke = 5 }: { score: number | null; size?: number; stroke?: number }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const unscored = score === null;
  const col = unscored ? 'var(--app-t3)' : frameworkPercentageColor(score);
  return (
    <div
      style={{ position: 'relative', width: size, height: size, flex: 'none' }}
      title={unscored ? 'No control could be assessed yet, so there is no score to show.' : undefined}
    >
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--app-track)" strokeWidth={stroke} />
        {!unscored && (
          <circle
            cx={size / 2} cy={size / 2} r={r} fill="none" stroke={col} strokeWidth={stroke} strokeLinecap="round"
            strokeDasharray={c} strokeDashoffset={c * (1 - score / 100)} style={{ transition: 'stroke-dashoffset .8s ease' }}
          />
        )}
      </svg>
      <span className="mono" style={{
        position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontSize: size * 0.27, fontWeight: 700, color: col,
      }}>{unscored ? '—' : score}</span>
    </div>
  );
}

export function ComplianceDashboardPage() {
  const frameworksQ = useAvailableFrameworks();
  const ctxQ = useFrameworkContext();
  const statsQ = useFindingStats();
  const exposuresQ = usePostureByControl(6);
  const trendQ = usePostureTrend(30);
  const ticketsQ = useTickets();

  const cards = sortFrameworkCards(frameworkCards(frameworksQ.data));
  const coverage = activationCoverage(cards);

  // The overall score comes from the SERVER (`status.overall_score`), not from
  // averaging the cards. Averaging would be a second opinion about a number the
  // engine already computes with severity weighting — and a mean of per-framework
  // percentages is not the severity-weighted score, it just looks like one.
  const overall = ctxQ.data?.status?.overall_score;
  const overallScore = typeof overall === 'number' ? Math.round(overall) : null;

  const severities = severityRows(statsQ.data?.all_producer_severity_counts);
  const stages = workflowStages(statsQ.data);
  // The sum of the rungs, not `active_findings` — see openFindingsTotal. The
  // two differ by every non-compliance producer, and the tile links at a page
  // that shows the wider set.
  const activeFindings = statsQ.isError ? null : openFindingsTotal(statsQ.data?.all_producer_severity_counts);
  const exposures = exposuresQ.data ?? [];
  const tickets = remediationRollup(ticketsQ.isError ? null : ticketsQ.data);
  const categories = ticketCategories(ticketsQ.isError ? null : ticketsQ.data);

  if (frameworksQ.isError && ctxQ.isError && statsQ.isError) {
    return (
      <DashboardShell testId="compliance-dashboard">
        <PageError title="Couldn't load the Compliance dashboard" message="Every request on this page failed. Check that compliance-engine is reachable." />
      </DashboardShell>
    );
  }

  const noFrameworks = !frameworksQ.isLoading && !frameworksQ.isError && cards.length === 0;

  return (
    <DashboardShell testId="compliance-dashboard">
      <DashboardHeader
        icon="shield-check"
        title="Compliance"
        blurb="Where you stand against each framework, what is failing, and how the remediation is moving. To work a framework control by control, open Risk & Compliance → Posture."
      />

      {/* ---------- HERO: overall standing + trend ---------- */}
      <div className="fade-up panel" style={{
        position: 'relative', overflow: 'hidden', padding: '24px 30px', marginBottom: 18,
        background: 'var(--hero-bg)', border: '1px solid var(--hero-border)',
      }}>
        <div className="hero-glow" style={{ position: 'absolute', left: '-16%', top: '-80%', width: 600, height: 600, background: 'var(--accent-glow)', opacity: 0.6, pointerEvents: 'none' }} />
        <div style={{ position: 'relative', display: 'flex', gap: 34, alignItems: 'stretch', flexWrap: 'wrap' }}>
          <div style={{ flex: '0 0 320px', minWidth: 280, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
            <div className="eyebrow-app" style={{ marginBottom: 9 }}>Overall Compliance</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 18 }}>
              {/* null → "—". The server returns null when NO framework in the
                  set was scored; a 0 there would read as total failure and a
                  100 as a clean bill, and we have earned neither. */}
              <PercentageGauge value={ctxQ.isLoading || ctxQ.isError ? null : overallScore} size={104} label="" stroke={9} />
              <div style={{ fontSize: 12, color: 'var(--app-t2)', lineHeight: 1.6 }}>
                {ctxQ.isError ? (
                  <span style={{ color: 'var(--app-t3)' }}>Couldn't load the overall score.</span>
                ) : overallScore === null && !ctxQ.isLoading ? (
                  <span style={{ color: 'var(--app-t3)' }}>Nothing has been assessed yet.</span>
                ) : (
                  <>
                    <div>severity-weighted, across</div>
                    <div>
                      <strong className="mono" style={{ color: 'var(--app-t1)', fontSize: 15 }}>{coverage.activated}</strong>
                      {' '}activated {coverage.activated === 1 ? 'framework' : 'frameworks'}
                    </div>
                    <div style={{ color: 'var(--app-t3)', fontSize: 11 }}>of {coverage.available} in the catalogue</div>
                  </>
                )}
                <div style={{ marginTop: 8 }}>
                  <PanelLink to={COMPLIANCE_FRAMEWORKS_ROUTE}>Manage frameworks</PanelLink>
                </div>
              </div>
            </div>
          </div>

          <div style={{ flex: 1, minWidth: 360, display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
              <h3 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14.5, color: 'var(--app-t1)' }}>Posture trend · 30 days</h3>
              <span style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>risk index · lower is better</span>
            </div>
            {trendQ.isError ? (
              <TrendBox>Couldn't load the posture trend.</TrendBox>
            ) : trendQ.isLoading ? (
              <TrendBox>Loading…</TrendBox>
            ) : (
              <div style={{ flex: 1, display: 'flex', alignItems: 'center' }}>
                <PostureTrendChart points={trendQ.data ?? []} height={150} />
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ---------- OPEN FINDINGS by severity ---------- */}
      <div className="fade-up" style={{ marginBottom: 18, animationDelay: '.05s' }}>
        <BandHeading title="Open findings" note="every producer — compliance, end-of-life, vulnerability, configuration and crypto" />
        <Grid min={150} gap={11}>
          <StatTile
            value={activeFindings} label="Open" sub="across every producer" icon="circle-alert"
            tone="var(--accent)" href={COMPLIANCE_FINDINGS_ROUTE} error={statsQ.isError}
          />
          {severities.map((s) => (
            <StatTile
              key={s.key} value={s.count} label={s.label} sub={`${s.label.toLowerCase()} severity`}
              icon="shield-alert" tone={s.tone} href={s.href} error={statsQ.isError}
            />
          ))}
        </Grid>
      </div>

      {/* ---------- FRAMEWORK SCORECARDS ---------- */}
      <div className="fade-up" style={{ marginBottom: 18, animationDelay: '.1s' }}>
        <BandHeading title="Frameworks" note="activated first, then worst score" />
        {frameworksQ.isError ? (
          <div className="panel" style={{ padding: 20 }}><PanelNote tone="var(--danger-text)">Couldn't load the framework catalogue.</PanelNote></div>
        ) : frameworksQ.isLoading ? (
          <div className="panel" style={{ padding: 20 }}><PanelNote>Loading…</PanelNote></div>
        ) : noFrameworks ? (
          <div className="panel" style={{ padding: '38px 24px', textAlign: 'center' }}>
            <Icon name="shield-check" size={24} style={{ color: 'var(--accent)' }} />
            <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--app-t1)', marginTop: 11 }}>No frameworks in the catalogue</div>
            <div style={{ fontSize: 12.5, color: 'var(--app-t3)', marginTop: 4, marginBottom: 13 }}>
              Nothing has been published for this tenant to activate yet.
            </div>
            <PanelLink to={COMPLIANCE_FRAMEWORKS_ROUTE}>Open Frameworks</PanelLink>
          </div>
        ) : (
          <Grid min={280} gap={13}>
            {cards.map((c) => (
              <Link
                key={c.code}
                to={COMPLIANCE_FRAMEWORKS_ROUTE}
                className="panel"
                style={{ padding: '16px 17px', display: 'flex', gap: 14, alignItems: 'center', textDecoration: 'none' }}
              >
                <ScoreRing score={c.score} />
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                    <span style={{
                      fontSize: 13, fontWeight: 700, color: 'var(--app-t1)', fontFamily: 'var(--font-head)',
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    }} title={c.name}>{c.name}</span>
                    {/* "Preview" is not a badge for decoration: an unactivated
                        framework's score is what the tenant WOULD score, not an
                        obligation they hold, and the two must not look alike. */}
                    {!c.activated && (
                      <span style={{
                        fontSize: 9, fontWeight: 700, letterSpacing: '.08em', textTransform: 'uppercase',
                        color: 'var(--app-t3)', border: '1px solid var(--app-border2)', borderRadius: 4, padding: '1px 5px', flex: 'none',
                      }}>Preview</span>
                    )}
                  </div>
                  {/* The coverage line is the honesty of the score beside it:
                      92% over 3 of 40 assessed controls is not a 92% framework. */}
                  <div style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 4 }}>
                    {c.total === 0 ? 'No controls defined' : `${c.assessed} of ${c.total} controls assessed`}
                  </div>
                  <div style={{ display: 'flex', gap: 11, marginTop: 6, fontSize: 10.5, color: 'var(--app-t3)' }}>
                    <span style={{ color: 'var(--ok)' }}>{c.passing} passing</span>
                    <span style={{ color: c.failing ? 'var(--danger-text)' : 'var(--app-t3)' }}>{c.failing} failing</span>
                    {c.notAssessed > 0 && <span>{c.notAssessed} not assessed</span>}
                  </div>
                </div>
              </Link>
            ))}
          </Grid>
        )}
      </div>

      {/* ---------- SUPPORTING ROW ---------- */}
      <div className="fade-up" style={{ animationDelay: '.15s' }}>
        <Grid min={340} gap={16}>
          {/* top exposures */}
          <Panel
            icon="octagon-alert"
            title="Top exposures"
            caption="Active findings grouped by the control that failed, worst first"
            loading={exposuresQ.isLoading}
            error={exposuresQ.isError}
            empty={exposures.length === 0}
            emptyText="No control has an open finding against it."
            testId="compliance-exposures"
            footer={<PanelLink to={COMPLIANCE_POSTURE_ROUTE}>Open Posture</PanelLink>}
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: 11 }}>
              {exposures.map((g) => (
                <Link
                  key={g.control_id}
                  to={COMPLIANCE_FINDINGS_ROUTE}
                  style={{ display: 'flex', alignItems: 'center', gap: 11, textDecoration: 'none' }}
                >
                  {/* The canonical ladder, not a local one: `sevLevel` parses
                      the registry spelling (including `med`) and `LevelDot`
                      draws it in the one colour the rest of the product uses
                      for that rung. */}
                  <LevelDot level={sevLevel(g.worst_severity)} size={7} />
                  <span style={{ flex: 1, minWidth: 0 }}>
                    <span style={{
                      display: 'block', fontSize: 12, color: 'var(--app-t1)', fontWeight: 600,
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    }} title={g.control_name}>{g.control_name}</span>
                    {/* target_kind, not "assets": the endpoint says what
                        affected_assets counts, and calling 12 certificates
                        "12 assets" costs the reader a wasted click. */}
                    <span style={{ display: 'block', fontSize: 10.5, color: 'var(--app-t3)' }}>
                      {g.framework_name} · {g.affected_assets.toLocaleString()} {targetNoun(g.target_kind, g.affected_assets)}
                    </span>
                  </span>
                  <span className="mono" style={{ fontSize: 13, fontWeight: 700, color: 'var(--app-t1)', flex: 'none' }}>{g.finding_count.toLocaleString()}</span>
                </Link>
              ))}
            </div>
          </Panel>

          {/* workflow state */}
          <Panel
            icon="list-checks"
            title="Finding workflow"
            caption={`What has been done with the findings we raised. ${WORKFLOW_SCOPE_NOTE}`}
            loading={statsQ.isLoading}
            error={statsQ.isError}
            testId="compliance-workflow"
            footer={<PanelLink to={COMPLIANCE_FINDINGS_ROUTE}>Open Findings</PanelLink>}
          >
            {/* Rows, not a stacked bar. These states do not partition the
                population — a resurfaced finding is also counted in its current
                state — and a stacked bar would assert a partition that is not
                there. */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 11 }}>
              {stages.map((s) => (
                <div key={s.key} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{ width: 8, height: 8, borderRadius: 50, background: s.tone, flex: 'none' }} />
                  <span style={{ fontSize: 12, color: 'var(--app-t1)', fontWeight: 600, width: 86, flex: 'none' }}>{s.label}</span>
                  <span className="mono" style={{ fontSize: 15, fontWeight: 700, color: s.tone, width: 54 }}>{s.count.toLocaleString()}</span>
                  <span style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>{s.hint}</span>
                </div>
              ))}
            </div>
          </Panel>

          {/* remediation standing */}
          <Panel
            icon="wrench"
            title="Remediation"
            caption="Tickets raised to close the gap, and whether they are on time"
            loading={ticketsQ.isLoading}
            error={ticketsQ.isError}
            empty={tickets.total === 0}
            emptyText="No remediation tickets have been raised yet."
            testId="compliance-remediation"
            footer={<PanelLink to={COMPLIANCE_REMEDIATION_ROUTE}>Open the queue</PanelLink>}
          >
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 20, marginBottom: 15 }}>
              <div>
                <div className="mono" style={{ fontSize: 26, fontWeight: 800, color: 'var(--app-t1)' }}>{tickets.total?.toLocaleString() ?? '—'}</div>
                <div className="eyebrow-app" style={{ marginTop: 3 }}>Tickets</div>
              </div>
              <div>
                <div className="mono" style={{ fontSize: 26, fontWeight: 800, color: tickets.overdue ? 'var(--danger)' : 'var(--app-t1)' }}>{tickets.overdue?.toLocaleString() ?? '—'}</div>
                <div className="eyebrow-app" style={{ marginTop: 3 }}>Overdue</div>
              </div>
              <div>
                <div className="mono" style={{ fontSize: 26, fontWeight: 800, color: 'var(--ok)' }}>
                  {tickets.onTrackPercent === null ? '—' : `${tickets.onTrackPercent}%`}
                </div>
                <div className="eyebrow-app" style={{ marginTop: 3 }}>On track</div>
              </div>
            </div>
            {categories.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
                {categories.slice(0, 5).map((c) => (
                  <div key={c.label} style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 11.5 }}>
                    <span style={{ color: 'var(--app-t2)', flex: 1, textTransform: 'capitalize' }}>{c.label}</span>
                    <span className="mono" style={{ color: 'var(--app-t1)', fontWeight: 600 }}>{c.count.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </Grid>
      </div>
    </DashboardShell>
  );
}

function TrendBox({ children }: { children: React.ReactNode }) {
  return (
    <div style={{
      flex: 1, minHeight: 150, borderRadius: 12, border: '1px dashed var(--app-border2)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, color: 'var(--app-t3)',
    }}>{children}</div>
  );
}
