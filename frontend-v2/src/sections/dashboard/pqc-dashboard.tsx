// Dashboard · PQC — post-quantum readiness and the migration worklist.
//
// This is the one of the three focused dashboards that fills a real hole. PQC
// data has existed since the PQC Readiness feature, but that feature
// deliberately collapsed its scope to "no new page, no new endpoint" and shipped
// as a compliance framework — so the only PQC surfaces in the product are two
// tiles on the shared Dashboard and a framework score on Posture.
//
// `/pqc/progress` has been returning a per-family breakdown with the
// catalogue's own `migrate_to` recommendation on every request since then, and
// nothing has ever rendered it. That worklist is the substance of this page; the
// rest is the four-way partition the shared Dashboard shows two of.
//
// The framework is untouched and remains the source of the PQC *score* that
// compliance reads. This page answers the different question: what, specifically,
// do we have to replace, and with what.
import { useQuery } from '@tanstack/react-query';
import { Icon, PercentageGauge } from '../../components/ui';
import { clients } from '../../lib/clients';
import {
  BandHeading, DashboardHeader, DashboardShell, Grid, PageError, Panel, PanelLink, PanelNote, StatTile,
} from './dashboard-bits';
import {
  NIST_DEPRECATED_YEAR, NIST_DISALLOWED_YEAR, PQC_ALGORITHMS_ROUTE, PQC_CONFIGURATIONS_ROUTE,
  PQC_FRAMEWORK_CODE, PQC_FRAMEWORK_ROUTE, PQC_KEYS_ROUTE,
  migrationWorklist, nistTimeline, pqcCategories, pqcHeadline, safeFamilies,
} from './pqc-dashboard-metrics';
import { hygieneScore } from './inventory-health';

function usePqcProgress() {
  return useQuery({
    queryKey: ['dashboard', 'pqc-progress'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/pqc/progress', {});
      if (error || !data) throw new Error('Failed to load PQC progress');
      return data.progress;
    },
    staleTime: 60_000,
  });
}

/**
 * The PQC Readiness framework's materialized score.
 *
 * Same `['posture','available-frameworks']` key the Posture page, the shared
 * Dashboard's hygiene tile and the Compliance dashboard all use — one fetch,
 * one cached answer. `hygieneScore` is the generic "pull one framework's rollup
 * out of the list" reader despite its name; it is reused rather than copied so
 * the null-handling (: null means BOTH "not scored yet" and "nothing could
 * be assessed", and is never 0 or 100) has exactly one implementation.
 */
function usePqcFramework() {
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

export function PqcDashboardPage() {
  const pqcQ = usePqcProgress();
  const fwQ = usePqcFramework();

  const head = pqcHeadline(pqcQ.isError ? null : pqcQ.data);
  const categories = pqcCategories(pqcQ.isError ? null : pqcQ.data);
  const worklist = migrationWorklist(pqcQ.isError ? null : pqcQ.data);
  const safe = safeFamilies(pqcQ.isError ? null : pqcQ.data);
  const milestones = nistTimeline(new Date());

  // `hygieneScore` finds a row by framework code; PQC Readiness is a Core
  // seeded framework, so this is present for every tenant.
  const fw = fwQ.isError ? null : hygieneScore(fwQ.data, PQC_FRAMEWORK_CODE);

  if (pqcQ.isError && fwQ.isError) {
    return (
      <DashboardShell testId="pqc-dashboard">
        <PageError title="Couldn't load the PQC dashboard" message="Every request on this page failed. Check that inventory-service is reachable." />
      </DashboardShell>
    );
  }

  const showEmpty = !pqcQ.isLoading && !pqcQ.isError && head.empty;

  return (
    <DashboardShell testId="pqc-dashboard">
      <DashboardHeader
        icon="key-round"
        title="Post-Quantum Readiness"
        blurb="How much of your cryptography survives a cryptographically relevant quantum computer, what has to be replaced, and what to replace it with. Classification follows NIST IR 8547."
      />

      {/* ---------- HERO ---------- */}
      <div className="fade-up panel" style={{
        position: 'relative', overflow: 'hidden', padding: '24px 30px', marginBottom: 18,
        background: 'var(--hero-bg)', border: '1px solid var(--hero-border)',
      }}>
        <div className="hero-glow" style={{ position: 'absolute', left: '-16%', top: '-80%', width: 620, height: 620, background: 'var(--accent-glow)', opacity: 0.6, pointerEvents: 'none' }} />
        <div style={{ position: 'relative', display: 'flex', gap: 34, alignItems: 'stretch', flexWrap: 'wrap' }}>
          <div style={{ flex: '0 0 330px', minWidth: 290, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
            <div className="eyebrow-app" style={{ marginBottom: 9 }}>Quantum Readiness</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 18 }}>
              {/* A tenant with NO crypto configurations gets null, not 0%.
                  Zero percent reads as "everything you have is broken"; the
                  truth is that nothing has been found to assess. */}
              <PercentageGauge value={pqcQ.isLoading || pqcQ.isError ? null : head.readinessPercent} size={112} label="" stroke={9} />
              <div style={{ fontSize: 12, color: 'var(--app-t2)', lineHeight: 1.6 }}>
                {pqcQ.isError ? (
                  <span style={{ color: 'var(--app-t3)' }}>Couldn't load PQC progress.</span>
                ) : head.empty && !pqcQ.isLoading ? (
                  <span style={{ color: 'var(--app-t3)' }}>No crypto configurations discovered yet.</span>
                ) : (
                  <>
                    <div>
                      <strong className="mono" style={{ color: 'var(--app-t1)', fontSize: 16 }}>{head.safe.toLocaleString()}</strong>
                      {' '}of{' '}
                      <strong className="mono" style={{ color: 'var(--app-t1)', fontSize: 16 }}>{head.total.toLocaleString()}</strong>
                    </div>
                    <div>configurations need no migration</div>
                    <div style={{ color: 'var(--app-t3)', fontSize: 11, marginTop: 4 }}>
                      post-quantum or symmetric-only
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* the four-way partition */}
          <div style={{ flex: 1, minWidth: 380, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
            <div className="eyebrow-app" style={{ marginBottom: 11 }}>
              Every configuration, classified exactly once
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {categories.map((c) => (
                <div key={c.key} style={{ display: 'flex', alignItems: 'center', gap: 11 }}>
                  <Icon name={c.icon} size={15} style={{ color: c.tone, flex: 'none' }} />
                  <span className="mono" style={{ fontSize: 19, fontWeight: 700, color: c.tone, width: 62, flex: 'none' }}>
                    {pqcQ.isError ? '—' : c.count.toLocaleString()}
                  </span>
                  <span style={{ minWidth: 0 }}>
                    <span style={{ display: 'block', fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>{c.label}</span>
                    <span style={{ display: 'block', fontSize: 10.5, color: 'var(--app-t3)' }}>{c.hint}</span>
                  </span>
                </div>
              ))}
            </div>
            <div style={{ marginTop: 13, fontSize: 10.5, color: 'var(--app-t3)' }}>
              These four sum to {head.total.toLocaleString()} — the family worklist below does not, because a
              configuration is counted under every algorithm family it uses.
            </div>
          </div>
        </div>
      </div>

      {showEmpty ? (
        <div className="panel fade-up" style={{ padding: '44px 24px', textAlign: 'center' }}>
          <Icon name="key-round" size={26} style={{ color: 'var(--accent)' }} />
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--app-t1)', marginTop: 12 }}>No cryptography discovered yet</div>
          <div style={{ fontSize: 12.5, color: 'var(--app-t3)', marginTop: 4, marginBottom: 14 }}>
            Readiness is measured over discovered crypto configurations. Run a discovery to populate them.
          </div>
          <PanelLink to="/discovery">Go to Discovery</PanelLink>
        </div>
      ) : (
        <>
          {/* ---------- HEADLINE TILES ---------- */}
          <div className="fade-up" style={{ marginBottom: 18, animationDelay: '.05s' }}>
            <Grid min={160} gap={11}>
              <StatTile
                value={head.needsMigration} label="Needs migration" sub="classical asymmetric in use"
                icon="shield-alert" tone="var(--warn-strong)" href={PQC_CONFIGURATIONS_ROUTE} error={pqcQ.isError}
              />
              <StatTile
                value={worklist.length} label="Families to replace" sub="distinct algorithm families"
                icon="shapes" tone="var(--danger-soft)" error={pqcQ.isError}
              />
              <StatTile
                value={head.unclassified} label="Not yet assessed" sub="no algorithm data resolved"
                icon="circle-help" tone="var(--app-t3)" href={PQC_CONFIGURATIONS_ROUTE} error={pqcQ.isError}
              />
              <StatTile
                value={fw && fw.present ? fw.score : null} label="PQC Readiness score" sub={fw?.activated ? 'framework activated' : 'preview — not activated'}
                icon="shield-check" tone="var(--accent)" href={PQC_FRAMEWORK_ROUTE} error={fwQ.isError}
              />
            </Grid>
          </div>

          {/* ---------- MIGRATION WORKLIST ---------- */}
          <div className="fade-up" style={{ marginBottom: 18, animationDelay: '.1s' }}>
            <BandHeading title="Migration worklist" note="algorithm families that a quantum computer breaks, biggest first" />
            <Grid min={400} gap={16}>
              <Panel
                icon="list-checks"
                title="Replace these"
                caption="Each row is an algorithm family in use, with the catalogue's recommended post-quantum replacement. A configuration appears under every family it uses, so these counts do not sum to the configuration total."
                loading={pqcQ.isLoading}
                error={pqcQ.isError}
                empty={worklist.length === 0}
                emptyText="Nothing in your inventory uses a quantum-vulnerable algorithm family."
                testId="pqc-worklist"
                footer={<PanelLink to={PQC_ALGORITHMS_ROUTE}>Algorithm reference</PanelLink>}
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {worklist.map((r) => (
                    <div key={r.family} style={{ display: 'flex', alignItems: 'center', gap: 11 }}>
                      <span className="mono" style={{ fontSize: 15, fontWeight: 700, color: 'var(--warn-strong)', width: 52, flex: 'none' }}>
                        {r.count.toLocaleString()}
                      </span>
                      <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)', width: 110, flex: 'none', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={r.family}>
                        {r.family}
                      </span>
                      <Icon name="arrow-right" size={13} style={{ color: 'var(--app-t3)', flex: 'none' }} />
                      {/* No invented recommendation. The catalogue either has a
                          migrate_to for this family or it does not, and guessing
                          one here would be this page asserting cryptographic
                          advice the algorithms table never made. */}
                      {r.migrateTo ? (
                        <span className="mono" style={{ fontSize: 12, fontWeight: 600, color: 'var(--ok)' }}>{r.migrateTo}</span>
                      ) : (
                        <span style={{ fontSize: 11.5, color: 'var(--app-t3)', fontStyle: 'italic' }}>no recommendation in the catalogue</span>
                      )}
                    </div>
                  ))}
                </div>
              </Panel>

              <Panel
                icon="shield-check"
                title="Already quantum-safe"
                /* NOT "needs no action". SHA-1 appears in this list, correctly on
                   this page's terms — what breaks SHA-1 is classical collision
                   resistance, not Shor or Grover — and a panel that told a reader
                   SHA-1 needed no action would be false in every sense except the
                   narrow one meant. Quantum readiness is one axis; say which. */
                caption="Not quantum-migration targets: post-quantum algorithms, and symmetric ones whose key sizes hold up. This says nothing about an algorithm's classical strength — a weak hash is still weak. Risk & Compliance answers that."
                loading={pqcQ.isLoading}
                error={pqcQ.isError}
                empty={safe.length === 0}
                emptyText="No quantum-safe algorithm family is in use yet."
                testId="pqc-safe-families"
                footer={<PanelLink to={PQC_KEYS_ROUTE}>Key inventory</PanelLink>}
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {safe.map((r) => (
                    <div key={r.family} style={{ display: 'flex', alignItems: 'center', gap: 11 }}>
                      <span className="mono" style={{ fontSize: 15, fontWeight: 700, color: 'var(--ok)', width: 52, flex: 'none' }}>
                        {r.count.toLocaleString()}
                      </span>
                      <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }} title={r.family}>{r.family}</span>
                    </div>
                  ))}
                </div>
              </Panel>
            </Grid>
          </div>

          {/* ---------- THE DEADLINE ---------- */}
          <div className="fade-up" style={{ animationDelay: '.15s' }}>
            <BandHeading title="The NIST timeline" note="IR 8547 — the dates the classification above is measured against" />
            <div className="panel" style={{ padding: 22 }}>
              <div style={{ display: 'flex', gap: 26, flexWrap: 'wrap', alignItems: 'stretch' }}>
                {milestones.map((m) => (
                  <div key={m.year} style={{ flex: '1 1 220px', minWidth: 210 }}>
                    <div style={{ display: 'flex', alignItems: 'baseline', gap: 9 }}>
                      <span className="mono" style={{
                        fontSize: 30, fontWeight: 800, letterSpacing: '-.02em',
                        color: m.passed ? 'var(--danger)' : 'var(--app-t1)',
                      }}>{m.year}</span>
                      <span style={{
                        fontSize: 10, fontWeight: 700, letterSpacing: '.08em', textTransform: 'uppercase',
                        color: m.passed ? 'var(--danger)' : 'var(--warn-strong)',
                      }}>{m.label}</span>
                    </div>
                    {/* "passed" rather than a negative countdown: in 2031 a
                        naive subtraction renders "-1 years away", which is not
                        a sentence. */}
                    <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 3 }}>
                      {m.passed
                        ? 'this date has passed'
                        : m.yearsAway <= 0
                          ? 'this year'
                          : `${m.yearsAway} ${m.yearsAway === 1 ? 'year' : 'years'} away`}
                    </div>
                    <p style={{ margin: '9px 0 0', fontSize: 12, color: 'var(--app-t2)', lineHeight: 1.5 }}>{m.detail}</p>
                  </div>
                ))}
                <div style={{ flex: '1 1 260px', minWidth: 240, borderLeft: '1px solid var(--app-border2)', paddingLeft: 24 }}>
                  <div className="eyebrow-app" style={{ marginBottom: 8 }}>What this means for you</div>
                  {pqcQ.isError ? (
                    <PanelNote tone="var(--danger-text)">Couldn't load the configuration counts.</PanelNote>
                  ) : (
                    <p style={{ margin: 0, fontSize: 12.5, color: 'var(--app-t2)', lineHeight: 1.6 }}>
                      <strong className="mono" style={{ color: 'var(--warn-strong)', fontSize: 15 }}>{head.needsMigration.toLocaleString()}</strong>
                      {' '}of your {head.total.toLocaleString()} crypto {head.total === 1 ? 'configuration' : 'configurations'} use an
                      algorithm that is deprecated after {NIST_DEPRECATED_YEAR} and disallowed after {NIST_DISALLOWED_YEAR}.
                      {head.unclassified > 0 && (
                        <>
                          {' '}A further <strong className="mono" style={{ color: 'var(--app-t1)' }}>{head.unclassified.toLocaleString()}</strong> could not be
                          classified at all — those are unknowns, not safe.
                        </>
                      )}
                    </p>
                  )}
                  <div style={{ marginTop: 12 }}>
                    <PanelLink to={PQC_CONFIGURATIONS_ROUTE}>See the configurations</PanelLink>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </DashboardShell>
  );
}
