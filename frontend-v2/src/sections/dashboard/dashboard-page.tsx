import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router';
import { clients } from '../../lib/clients';
import { Icon, LevelBar, LevelDot, MiniBar, RiskGauge, levelFromScore, riskColor } from '../../components/ui';
import { PostureTrendChart } from '../../components/posture-trend-chart';
import { getDashboardPqcMetric } from './dashboard-metrics';

// Dashboard — the command center, ported to the mock's four layers (Dashboard.jsx):
// cinematic hero, "needs attention" triage strip, lifecycle pipeline, supporting
// row. Every number is a live rollup. The posture TREND chart is fed by
// inventory /risk/posture/trend (ADR-0007); a brand-new tenant with no history
// yet sees a flat seeded baseline at its current posture, not a blank chart.

const BLUE = 'var(--info)', GREEN = 'var(--ok)', RED = 'var(--danger)', ORANGE = 'var(--warn-strong)';

function useRollups() {
  const risk = useQuery({
    queryKey: ['dashboard', 'risk-summary'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/risk/summary', {});
      if (error || !data) throw new Error('Failed to load risk summary');
      return data.risk_summary;
    },
  });
  const sensors = useQuery({
    queryKey: ['dashboard', 'sensors'],
    queryFn: async () => {
      const { data } = await clients.sensors.GET('/sensors', {});
      return data?.sensors ?? [];
    },
  });
  const pqc = useQuery({
    queryKey: ['dashboard', 'pqc-summary'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/pqc/summary', {});
      if (error || !data) throw new Error('Failed to load PQC summary');
      return data;
    },
  });
  const expiring = useQuery({
    queryKey: ['dashboard', 'expiring-certs'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/certificates/expiring', { params: { query: { days: 365 } } });
      if (error || !data) throw new Error('Failed to load expiring certificates');
      return data.certificates ?? [];
    },
  });
  const tickets = useQuery({
    queryKey: ['dashboard', 'ticket-stats'],
    queryFn: async () => {
      const { data } = await clients.compliance.GET('/tickets/stats', {});
      return data?.stats;
    },
  });
  // 30-day posture trend (ADR-0007). New tenants get a flat seeded baseline at
  // their current posture rather than a blank chart.
  const trend = useQuery({
    queryKey: ['dashboard', 'posture-trend'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/risk/posture/trend', { params: { query: { days: 30 } } });
      if (error || !data) throw new Error('Failed to load posture trend');
      return data.trend ?? [];
    },
  });
  // Observed 3rd-party (external) connections — the /inventory?lens=connections rollup.
  const connections = useQuery({
    queryKey: ['dashboard', 'external-connections-summary'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/external-connections/summary', {});
      if (error || !data) throw new Error('Failed to load external connections summary');
      return data;
    },
  });
  return { risk, sensors, pqc, expiring, tickets, trend, connections };
}

export function DashboardPage() {
  const nav = useNavigate();
  const { risk, sensors, pqc, expiring, tickets, trend, connections } = useRollups();
  const s = risk.data;
  const total = s?.total_assets ?? 0;
  const high = s?.high_risk ?? 0;
  const crit = s?.critical_findings ?? 0;
  const crypto = s?.total_crypto ?? 0;
  const unknown = s?.unknown_risk ?? 0;
  const pctHigh = total ? Math.round((high / total) * 100) : 0;
  const lvl = levelFromScore(pctHigh);
  // The dashboard's PQC number is ALWAYS config adoption (% of crypto configs on PQC
  // algorithms, /pqc/summary) so the % and the config counts beside it are one metric.
  // It must never swap to the PQC Readiness framework's severity-weighted score — that
  // lives on the Risk & Compliance posture surfaces and answers a different question;
  // the old activation-dependent fallback made this stat jump 7.6→45 on a settings click.
  const pqcMetric = getDashboardPqcMetric(pqc.data);
  const pqcPct = pqcMetric.adoptionPercent;
  const pqcReady = pqcMetric.pqcReady;
  const pqcTotal = pqcMetric.total;

  const sensorList = sensors.data ?? [];
  const sensorsOnline = sensorList.filter((x) => (x.status || '').toLowerCase() === 'active').length;

  const certs = expiring.data ?? [];
  const expSoon = certs.filter((c) => typeof c.days_until_expiry === 'number' && c.days_until_expiry >= 0 && c.days_until_expiry <= 30).length;
  const buckets = [
    { label: 'Expired', n: certs.filter((c) => (c.days_until_expiry ?? 1) < 0).length, color: RED },
    { label: '≤ 7d', n: certs.filter((c) => { const d = c.days_until_expiry; return typeof d === 'number' && d >= 0 && d <= 7; }).length, color: RED },
    { label: '8–30d', n: certs.filter((c) => { const d = c.days_until_expiry; return typeof d === 'number' && d > 7 && d <= 30; }).length, color: ORANGE },
    { label: '31–90d', n: certs.filter((c) => { const d = c.days_until_expiry; return typeof d === 'number' && d > 30 && d <= 90; }).length, color: 'accent' },
    { label: '> 90d', n: certs.filter((c) => { const d = c.days_until_expiry; return typeof d === 'number' && d > 90; }).length, color: 'accent' },
  ];
  const expMax = Math.max(...buckets.map((b) => b.n), 1);

  const cx = connections.data;
  const extTotal = cx?.total ?? 0;
  const extHosts = cx?.source_hosts ?? 0;
  const extStats: [string, number][] = [
    ['Weak crypto', cx?.weak_crypto ?? 0],
    ['Legacy TLS', cx?.legacy_tls ?? 0],
    ['Expired certs', cx?.expired_certs ?? 0],
    ['PQC-resistant', cx?.pqc_resistant ?? 0],
  ];

  const tk = tickets.data;
  const tkTotal = tk?.total ?? 0;
  const tkOverdue = tk?.overdue ?? 0;
  const onTrackPct = tkTotal ? Math.round(((tkTotal - tkOverdue) / tkTotal) * 100) : null;

  if (risk.isError) {
    return <Center icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load dashboard" message={risk.error instanceof Error ? risk.error.message : 'Request failed'} />;
  }

  const attention = [
    { id: 'crit', count: crit, label: 'Critical findings', sub: 'across all assets', icon: 'circle-alert', tone: RED, route: '/risk-compliance/findings' },
    { id: 'high', count: high, label: 'High-risk assets', sub: 'risk score ≥ 60', icon: 'server', tone: 'var(--danger-soft)', route: '/inventory?lens=infrastructure' },
    { id: 'exp', count: expSoon, label: 'Certs expiring', sub: 'within 30 days', icon: 'file-badge', tone: ORANGE, route: '/inventory?lens=certificate' },
    { id: 'unk', count: unknown, label: 'Unscored assets', sub: 'no risk signal yet', icon: 'search', tone: 'var(--warn)', route: '/inventory?lens=infrastructure' },
    { id: 'pqc', count: pqcMetric.configsOnClassicalCrypto, label: 'Not PQC-ready', sub: 'configs on classical crypto', icon: 'key-round', tone: BLUE, route: '/inventory?lens=configuration' },
    { id: 'tick', count: tkOverdue, label: 'Overdue tickets', sub: 'past SLA', icon: 'wrench', tone: ORANGE, route: '/remediation/plans' },
  ];

  return (
    <div style={{ padding: '20px 26px 44px', height: '100%', overflow: 'auto' }}>
      {/* ---------- HERO — cinematic accent posture ---------- */}
      <div className="fade-up panel" style={{
        position: 'relative', overflow: 'hidden', padding: '26px 30px',
        background: 'var(--hero-bg)', border: '1px solid var(--hero-border)',
      }}>
        <div className="hero-glow" style={{ position: 'absolute', left: '-18%', top: '-80%', width: 640, height: 640, background: 'var(--accent-glow)', opacity: 0.7, pointerEvents: 'none' }} />
        <div className="hero-glow" style={{ position: 'absolute', right: '-5%', top: '-60%', width: 560, height: 560, background: 'var(--accent-glow)', opacity: 0.5, pointerEvents: 'none' }} />

        <div style={{ position: 'relative', display: 'flex', gap: 34, alignItems: 'stretch', flexWrap: 'wrap' }}>
          {/* score block */}
          <div style={{ flex: '0 0 340px', minWidth: 300, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
            <div className="eyebrow-app" style={{ marginBottom: 9 }}>Cryptographic Posture</div>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 16 }}>
              <div style={{ position: 'relative', flex: 'none', width: 92, height: 92, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <div className="hero-glow" style={{ position: 'absolute', inset: '-30%', background: 'var(--accent-glow)', opacity: 0.8 }} />
                <div style={{ position: 'relative', width: 84, height: 84, borderRadius: 22, background: 'var(--accent-gradient)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 6px 14px rgba(0,0,0,.5)' }}>
                  <Icon name="shield" size={42} style={{ color: 'var(--accent-fg)' }} />
                </div>
              </div>
              <div>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
                  <span className="accent-text" style={{ fontFamily: 'var(--font-head)', fontWeight: 800, fontSize: 76, lineHeight: 0.9, letterSpacing: '-.03em' }}>{risk.isLoading ? '…' : pctHigh}</span>
                  <span className="mono" style={{ fontSize: 14, color: 'var(--app-t3)' }}>/100</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginTop: 10 }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5, fontWeight: 700, color: riskColor(lvl), background: `color-mix(in srgb, ${riskColor(lvl)} 11%, transparent)`, borderRadius: 40, padding: '3px 10px' }}>
                    <LevelDot level={lvl} size={7} />{lvl} risk
                  </span>
                </div>
                <div style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 4 }}>risk index · % of assets at high risk</div>
              </div>
            </div>
            <p style={{ margin: '20px 0 0', fontSize: 14.5, lineHeight: 1.5, color: 'var(--app-t2)', maxWidth: 330 }}>
              <strong style={{ color: 'var(--app-t1)', fontWeight: 600 }}>{crit.toLocaleString()} critical</strong> findings open across{' '}
              <strong style={{ color: 'var(--app-t1)', fontWeight: 600 }}>{total.toLocaleString()}</strong> monitored assets.
            </p>
            <div style={{ display: 'flex', gap: 22, marginTop: 20 }}>
              {([['Assets', total.toLocaleString()], ['Configs', crypto.toLocaleString()], ['Critical', crit.toLocaleString()], ['PQC configs', pqcPct + '%']] as const).map(([k, v]) => (
                <div key={k}>
                  <div className="mono" style={{ fontSize: 19, fontWeight: 700, color: 'var(--app-t1)', letterSpacing: '-.01em' }}>{risk.isLoading ? '…' : v}</div>
                  <div className="eyebrow-app" style={{ marginTop: 3 }}>{k}</div>
                </div>
              ))}
            </div>
          </div>

          {/* posture trend — risk-index time-series (ADR-0007) */}
          <div style={{ flex: 1, minWidth: 360, display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
              <h3 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14.5, color: 'var(--app-t1)' }}>Posture trend · 30 days</h3>
              <span style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>risk index · lower is better</span>
            </div>
            {trend.isError ? (
              <div style={{ flex: 1, minHeight: 150, borderRadius: 12, border: '1px dashed var(--app-border2)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, color: 'var(--app-t3)' }}>
                Couldn't load the posture trend.
              </div>
            ) : trend.isLoading ? (
              <div style={{ flex: 1, minHeight: 150, borderRadius: 12, border: '1px dashed var(--app-border2)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, color: 'var(--app-t3)' }}>
                Loading…
              </div>
            ) : (
              <div style={{ flex: 1, display: 'flex', alignItems: 'center' }}>
                <PostureTrendChart points={trend.data ?? []} height={150} />
              </div>
            )}
          </div>

          {/* third-party connections — external exposure, styled to mirror the posture block (lens=connections) */}
          <div onClick={() => nav('/inventory?lens=connections')} style={{ flex: '0 0 300px', minWidth: 240, display: 'flex', flexDirection: 'column', justifyContent: 'center', cursor: 'pointer' }}>
            <div className="eyebrow-app" style={{ marginBottom: 9 }}>External Exposure</div>
            {connections.isError ? (
              <p style={{ margin: 0, fontSize: 12.5, color: 'var(--app-t3)' }}>Couldn't load external connections.</p>
            ) : (
              <>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
                  <span className="accent-text" style={{ fontFamily: 'var(--font-head)', fontWeight: 800, fontSize: 52, lineHeight: 0.9, letterSpacing: '-.03em' }}>{connections.isLoading ? '…' : extTotal.toLocaleString()}</span>
                </div>
                <p style={{ margin: '14px 0 0', fontSize: 14.5, lineHeight: 1.5, color: 'var(--app-t2)', maxWidth: 300 }}>
                  observed 3rd-party connections from{' '}
                  <strong style={{ color: 'var(--app-t1)', fontWeight: 600 }}>{extHosts.toLocaleString()}</strong> internal {extHosts === 1 ? 'host' : 'hosts'}.
                </p>
                <div style={{ display: 'flex', gap: 22, marginTop: 20, flexWrap: 'wrap' }}>
                  {extStats.map(([k, v]) => (
                    <div key={k}>
                      <div className="mono" style={{ fontSize: 19, fontWeight: 700, color: 'var(--app-t1)', letterSpacing: '-.01em' }}>{connections.isLoading ? '…' : v.toLocaleString()}</div>
                      <div className="eyebrow-app" style={{ marginTop: 3 }}>{k}</div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {/* ---------- NEEDS ATTENTION strip ---------- */}
      <div className="fade-up" style={{ marginBottom: 18, animationDelay: '.05s' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 11 }}>
          <Icon name="activity" size={15} style={{ color: 'var(--accent)' }} />
          <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14.5, color: 'var(--app-t1)' }}>Needs attention now</h2>
          <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>— prioritized across every section</span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 11 }}>
          {attention.map((a) => (
            <button key={a.id} onClick={() => nav(a.route)} className="panel" style={{ padding: '14px 15px', textAlign: 'left', cursor: 'pointer', position: 'relative', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
              <span style={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: 3, background: a.tone }} />
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Icon name={a.icon} size={16} style={{ color: a.tone }} />
                <Icon name="arrow-up-right" size={13} style={{ color: 'var(--app-t3)' }} />
              </div>
              <div className="mono" style={{ fontSize: 27, fontWeight: 800, color: 'var(--app-t1)', margin: '10px 0 3px', letterSpacing: '-.02em' }}>{a.count.toLocaleString()}</div>
              <div style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--app-t1)', lineHeight: 1.25 }}>{a.label}</div>
              <div style={{ fontSize: 10.5, color: 'var(--app-t3)', marginTop: 1 }}>{a.sub}</div>
            </button>
          ))}
        </div>
      </div>

      {/* ---------- LIFECYCLE PIPELINE ---------- */}
      <div className="fade-up" style={{ marginBottom: 18, animationDelay: '.1s' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 11 }}>
          <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14.5, color: 'var(--app-t1)' }}>The lifecycle, end to end</h2>
          <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>— discovery flows through to remediation</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'stretch', flexWrap: 'wrap', gap: '0 0' }}>
          <Stage icon="radar" accent={BLUE} title="Discovery" hero={String(sensorsOnline)} heroUnit={`/ ${sensorList.length} sensors`} caption="sensors online" onClick={() => nav('/discovery')}
            viz={
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, width: '100%' }}>
                <div style={{ display: 'flex', gap: 5 }}>
                  {sensorList.slice(0, 10).map((x, i) => {
                    const on = (x.status || '').toLowerCase() === 'active';
                    return <span key={i} style={{ width: 9, height: 9, borderRadius: 50, background: on ? GREEN : RED, boxShadow: on ? 'none' : `0 0 6px ${RED}` }} />;
                  })}
                </div>
                <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>{sensorsOnline}/{sensorList.length} active</span>
              </div>
            }
            stats={[['Sensors', String(sensorList.length), null]]} />
          <Connector />
          <Stage icon="database" accent={GREEN} title="Inventory" hero={crypto.toLocaleString()} heroUnit={`· ${total.toLocaleString()} assets`} caption="crypto configurations" onClick={() => nav('/inventory')}
            viz={
              <div style={{ width: '100%' }}>
                <LevelBar counts={{ High: high, Medium: s?.medium_risk ?? 0, Low: s?.low_risk ?? 0, Informational: unknown }} h={9} />
                <div style={{ display: 'flex', gap: 12, marginTop: 8 }}>
                  {([['High', high], ['Medium', s?.medium_risk ?? 0], ['Informational', unknown]] as const).map(([l, n]) => (
                    <span key={l} style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 10.5, color: 'var(--app-t3)' }}><LevelDot level={l} size={6} />{n}</span>
                  ))}
                </div>
              </div>
            }
            stats={[['Assets', total.toLocaleString(), null], ['Unscored', String(unknown), null]]} />
          <Connector />
          <Stage icon="shield-check" accent="var(--accent)" title="Risk & Compliance" hero={crit.toLocaleString()} heroColor="var(--danger-soft)" caption="critical findings" onClick={() => nav('/risk-compliance/findings')}
            viz={
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%', fontSize: 11, color: 'var(--app-t3)' }}>
                <LevelDot level="High" size={7} />{high} high-risk assets in scope
              </div>
            }
            stats={[['High-risk', String(high), null], ['PQC configs', pqcPct + '%', null]]} />
          <Connector />
          <Stage icon="wrench" accent={ORANGE} title="Remediation" hero={String(tkOverdue)} heroColor={tkOverdue ? RED : undefined} caption="overdue · past SLA" onClick={() => nav('/remediation/plans')}
            viz={
              onTrackPct == null ? (
                <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>No open tickets yet.</span>
              ) : (
                <div style={{ width: '100%' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10.5, color: 'var(--app-t3)', marginBottom: 5 }}>
                    <span>On track</span><span className="mono" style={{ color: GREEN, fontWeight: 700 }}>{onTrackPct}%</span>
                  </div>
                  <MiniBar pct={onTrackPct} color={GREEN} h={7} />
                </div>
              )
            }
            stats={[['Open tickets', String(tkTotal), null]]} />
        </div>
      </div>

      {/* ---------- SUPPORTING ROW ---------- */}
      <div className="fade-up" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16, alignItems: 'start', animationDelay: '.15s' }}>
        {/* cert expiry outlook */}
        <div className="panel" style={{ padding: 20 }}>
          <h3 style={{ margin: '0 0 3px', fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14.5, color: 'var(--app-t1)' }}>Certificate expiry outlook</h3>
          <p style={{ margin: '0 0 16px', fontSize: 11.5, color: 'var(--app-t3)' }}>Upcoming certificate expirations (next 365 days{certs.length >= 100 ? ', first 100' : ''})</p>
          {expiring.isLoading ? (
            <div style={{ fontSize: 12, color: 'var(--app-t3)' }}>Loading…</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {buckets.map((b) => (
                <div key={b.label} style={{ display: 'flex', alignItems: 'center', gap: 11 }}>
                  <span style={{ fontSize: 11.5, color: 'var(--app-t2)', width: 64, flex: 'none' }}>{b.label}</span>
                  <div style={{ flex: 1, height: 16, borderRadius: 5, background: 'var(--app-track)', overflow: 'hidden' }}>
                    <div style={{ width: (b.n / expMax) * 100 + '%', height: '100%', background: b.color === 'accent' ? 'var(--accent-gradient)' : b.color, borderRadius: 5, minWidth: b.n ? 3 : 0 }} />
                  </div>
                  <span className="mono" style={{ fontSize: 12, color: 'var(--app-t2)', width: 26, textAlign: 'right' }}>{b.n}</span>
                </div>
              ))}
            </div>
          )}
        </div>
        {/* quantum readiness */}
        <div className="panel" style={{ padding: 20 }}>
          <h3 style={{ margin: '0 0 3px', fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14.5, color: 'var(--app-t1)' }}>Quantum readiness</h3>
          <p style={{ margin: '0 0 18px', fontSize: 11.5, color: 'var(--app-t3)' }}>Post-quantum migration progress</p>
          <div style={{ display: 'flex', alignItems: 'center', gap: 18 }}>
            <RiskGauge score={pqcPct} level={pqcPct >= 50 ? 'Low' : 'Critical'} size={104} label="" stroke={8} />
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 11 }}>
              {([[pqcReady, 'quantum-ready configs', GREEN], [pqcTotal - pqcReady, 'awaiting migration', 'var(--app-t2)']] as const).map(([v, k, c], i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
                  <span style={{ width: 8, height: 8, borderRadius: 50, background: c, flex: 'none' }} />
                  <span className="mono" style={{ fontSize: 16, fontWeight: 700, color: c }}>{v.toLocaleString()}</span>
                  <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>{k}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Stage({ icon, accent, title, hero, heroUnit, heroColor, caption, viz, stats, onClick }: {
  icon: string; accent: string; title: string; hero: string; heroUnit?: string; heroColor?: string; caption: string;
  viz: React.ReactNode; stats: [string, string, string | null][]; onClick: () => void;
}) {
  return (
    <button onClick={onClick} className="panel" style={{ flex: '1 1 0', minWidth: 210, padding: '17px 18px 16px', textAlign: 'left', cursor: 'pointer', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 15 }}>
        <span style={{ width: 28, height: 28, borderRadius: 8, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: `color-mix(in srgb, ${accent} 12%, transparent)`, color: accent }}><Icon name={icon} size={15} /></span>
        <span style={{ fontSize: 13, fontWeight: 700, fontFamily: 'var(--font-head)', color: 'var(--app-t1)', flex: 1 }}>{title}</span>
        <Icon name="arrow-up-right" size={14} style={{ color: 'var(--app-t3)' }} />
      </div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 7 }}>
        <span className="mono" style={{ fontSize: 34, fontWeight: 800, color: heroColor || 'var(--app-t1)', letterSpacing: '-.02em', lineHeight: 0.95 }}>{hero}</span>
        {heroUnit && <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{heroUnit}</span>}
      </div>
      <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 3 }}>{caption}</div>
      <div style={{ margin: '15px 0 14px', minHeight: 30, display: 'flex', alignItems: 'center' }}>{viz}</div>
      <div style={{ display: 'flex', gap: 18, marginTop: 'auto' }}>
        {stats.map(([k, v, c], i) => (
          <div key={i}>
            <div className="mono" style={{ fontSize: 14, fontWeight: 700, color: c || 'var(--app-t1)' }}>{v}</div>
            <div style={{ fontSize: 10.5, color: 'var(--app-t3)', marginTop: 2 }}>{k}</div>
          </div>
        ))}
      </div>
    </button>
  );
}

function Connector() {
  return (
    <div style={{ flex: 'none', width: 26, display: 'flex', alignItems: 'center', justifyContent: 'center', alignSelf: 'center' }}>
      <Icon name="chevron-right" size={18} style={{ color: 'var(--app-border2)' }} />
    </div>
  );
}

function Center({ icon, tone, title, message }: { icon: string; tone: string; title: string; message: string }) {
  return (
    <div style={{ padding: '64px 24px', textAlign: 'center', color: 'var(--app-t3)' }}>
      <Icon name={icon} size={26} style={{ color: tone }} />
      <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--app-t1)', marginTop: 12 }}>{title}</div>
      <div style={{ fontSize: 12.5, marginTop: 4 }}>{message}</div>
    </div>
  );
}
