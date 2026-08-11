// About — version / build surface. Shows this console's build plus the platform
// version aggregate from monitoring-service GET /version (per-service breakdown
// + the four-state release-skew badge). Reachable from the profile menu.
import { useQuery } from '@tanstack/react-query';
import { clients } from '../lib/clients';
import { Icon } from '../components/ui';

const STATUS_META: Record<string, { color: string; bg: string; icon: string; label: string; note: string }> = {
  aligned: { color: 'var(--ok)', bg: 'color-mix(in srgb, var(--ok) 13%, transparent)', icon: 'check-check', label: 'All services aligned', note: 'Every reachable service reports the same version.' },
  skew: { color: 'var(--danger)', bg: 'color-mix(in srgb, var(--danger) 13%, transparent)', icon: 'alert-triangle', label: 'Version skew detected', note: 'Two or more services report different versions.' },
  degraded: { color: 'var(--warn)', bg: 'color-mix(in srgb, var(--warn) 14%, transparent)', icon: 'shield-alert', label: 'Degraded', note: 'Reporting services agree, but a peer is unreachable.' },
  unknown: { color: 'var(--app-t3)', bg: 'var(--app-panel2)', icon: 'circle-alert', label: 'Version unknown', note: 'No real version reported (normal in local dev).' },
};

const CONSOLE_BUILD = import.meta.env.PROD ? 'production' : 'development';

export function AboutPage() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['about', 'version'],
    queryFn: async () => {
      const { data, error } = await clients.monitoring.GET('/version', {});
      if (error || !data) throw new Error('Failed to load version information');
      return data;
    },
    staleTime: 60_000,
  });

  const meta = data ? (STATUS_META[data.status] ?? STATUS_META.unknown) : null;
  const services = data?.services ?? [];

  return (
    <div style={{ padding: '24px 26px 40px', height: '100%', overflowY: 'auto' }}>
      <div style={{ maxWidth: 760, margin: '0 auto' }}>
        {/* brand / console build */}
        <div className="panel" style={{ padding: 24, borderRadius: 16, display: 'flex', alignItems: 'center', gap: 18, marginBottom: 16 }}>
          <div style={{ width: 54, height: 54, borderRadius: 14, flex: 'none', background: 'var(--accent-gradient)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 8px 22px color-mix(in srgb, var(--accent) 28%, transparent)' }}>
            <Icon name="shield" size={28} style={{ color: 'var(--accent-fg)' }} />
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="wordmark accent-text" style={{ fontSize: 22, fontWeight: 900, letterSpacing: '.16em' }}>VISTA</div>
            <div style={{ fontSize: 12.5, color: 'var(--app-t3)', marginTop: 3 }}>
              Console · {CONSOLE_BUILD} build
            </div>
          </div>
          {data?.self?.app_version && (
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: 10, color: 'var(--app-t3)', textTransform: 'uppercase', letterSpacing: '.08em' }}>Platform</div>
              <div className="mono" style={{ fontSize: 18, fontWeight: 700, color: 'var(--app-t1)' }}>{data.self.app_version}</div>
            </div>
          )}
        </div>

        {isError ? (
          <div className="panel" style={{ padding: '40px 24px', borderRadius: 14, textAlign: 'center', color: 'var(--app-t3)' }}>
            <Icon name="alert-triangle" size={24} style={{ color: 'var(--danger-text)' }} />
            <div style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--app-t1)', marginTop: 10 }}>Couldn't load version information</div>
            <div style={{ fontSize: 12.5, marginTop: 4 }}>The platform version service didn't respond.</div>
          </div>
        ) : isLoading || !data || !meta ? (
          <div className="panel" style={{ padding: '40px 24px', borderRadius: 14, textAlign: 'center', color: 'var(--app-t3)' }}>
            <Icon name="loader" size={20} style={{ animation: 'spin 1.1s linear infinite' }} />
            <div style={{ fontSize: 12.5, marginTop: 10 }}>Loading platform version…</div>
            <style>{'@keyframes spin { to { transform: rotate(360deg); } }'}</style>
          </div>
        ) : (
          <>
            {/* skew badge */}
            <div className="panel" style={{ padding: 18, borderRadius: 14, marginBottom: 16, display: 'flex', alignItems: 'center', gap: 14 }}>
              <span style={{ width: 42, height: 42, borderRadius: 11, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: meta.bg, color: meta.color }}>
                <Icon name={meta.icon} size={20} />
              </span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 14, fontWeight: 700, color: meta.color }}>{meta.label}</div>
                <div style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 2 }}>{meta.note}</div>
              </div>
              <div className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)', textAlign: 'right' }}>
                {data.summary.reachable}/{data.summary.total} reachable<br />{data.summary.reporting} reporting
              </div>
            </div>

            {/* skew fields, when present */}
            {data.status === 'skew' && (data.skew?.length ?? 0) > 0 && (
              <div className="panel" style={{ padding: 16, borderRadius: 14, marginBottom: 16 }}>
                <div className="eyebrow-app" style={{ color: 'var(--danger)', marginBottom: 8 }}>Mismatched fields</div>
                {data.skew!.map((s) => (
                  <div key={s.field} style={{ display: 'flex', gap: 12, padding: '5px 0', fontSize: 12 }}>
                    <span style={{ width: 90, flex: 'none', color: 'var(--app-t3)' }}>{s.field}</span>
                    <span className="mono" style={{ color: 'var(--app-t1)' }}>{s.values.join('  ·  ')}</span>
                  </div>
                ))}
              </div>
            )}

            {/* per-service breakdown */}
            <div className="panel" style={{ borderRadius: 14, overflow: 'hidden' }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1.6fr) 120px 100px 110px', gap: 12, padding: '0 16px', height: 36, alignItems: 'center', borderBottom: '1px solid var(--app-border2)' }}>
                {['Service', 'Version', 'Chart', 'Status'].map((h) => <span key={h} className="eyebrow-app">{h}</span>)}
              </div>
              {services.length === 0 ? (
                <div style={{ padding: '24px 16px', fontSize: 12.5, color: 'var(--app-t3)', textAlign: 'center' }}>No peer services reported (single-service or local dev).</div>
              ) : (
                services.map((s, i) => {
                  const healthy = s.status === 'healthy';
                  return (
                    <div key={s.service} style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1.6fr) 120px 100px 110px', gap: 12, padding: '0 16px', minHeight: 42, alignItems: 'center', borderTop: i ? '1px solid var(--app-border)' : 'none' }}>
                      <span style={{ fontSize: 12.5, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{s.service}</span>
                      <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t2)' }}>{s.tag || s.app_version || '—'}</span>
                      <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{s.chart || '—'}</span>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11.5, color: healthy ? 'var(--ok)' : 'var(--danger-text)' }}>
                        <span style={{ width: 6, height: 6, borderRadius: 50, background: healthy ? 'var(--ok)' : 'var(--danger-text)' }} />
                        {healthy ? 'healthy' : 'unreachable'}
                      </span>
                    </div>
                  );
                })
              )}
            </div>

            <p style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 14, lineHeight: 1.55 }}>
              Version skew means services are running mismatched releases — usually a partial or interrupted upgrade. Aligned is the healthy state.
            </p>
          </>
        )}
      </div>
    </div>
  );
}
