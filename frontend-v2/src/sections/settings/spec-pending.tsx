// Fallback panels for settings/profile pages: the mock's "Spec'd — design
// pending" card for pages awaiting build-out, and the RBAC access notice shown
// when the signed-in user lacks a page's required permission.
import { Icon } from '../../components/ui';
import { SPage } from './kit';
import type { SettingsNavItem } from './nav';

export function SpecPendingPage({ meta, eyebrow }: { meta: SettingsNavItem & { section?: string }; eyebrow?: string }) {
  return (
    <SPage eyebrow={eyebrow ?? meta.section ?? 'Settings'} title={meta.label || 'Settings'} job={meta.job}>
      <div className="panel" style={{ padding: '30px 26px', display: 'flex', alignItems: 'center', gap: 18 }}>
        <span style={{ width: 46, height: 46, borderRadius: 12, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', color: 'var(--accent)' }}>
          <Icon name="drafting-compass" size={22} />
        </span>
        <div>
          <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--app-t1)' }}>Spec'd — build pending</div>
          <div style={{ fontSize: 12.5, color: 'var(--app-t3)', marginTop: 3, lineHeight: 1.55, maxWidth: 520 }}>
            This page's intent is locked in the redesign spec. It's being wired to live data next.
          </div>
        </div>
      </div>
    </SPage>
  );
}

export function AccessNotice({ meta, eyebrow }: { meta: SettingsNavItem & { section?: string }; eyebrow?: string }) {
  return (
    <SPage eyebrow={eyebrow ?? meta.section ?? 'Settings'} title={meta.label || 'Settings'} job={meta.job}>
      <div className="panel" style={{ padding: '30px 26px', display: 'flex', alignItems: 'center', gap: 18 }}>
        <span style={{ width: 46, height: 46, borderRadius: 12, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', color: 'var(--app-t3)' }}>
          <Icon name="lock" size={20} />
        </span>
        <div>
          <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--app-t1)' }}>You don't have access to this page</div>
          <div style={{ fontSize: 12.5, color: 'var(--app-t3)', marginTop: 3, lineHeight: 1.55, maxWidth: 520 }}>
            Viewing this page requires the <span className="mono">{meta.permission}</span> permission. Ask an organization admin if you need it.
          </div>
        </div>
      </div>
    </SPage>
  );
}
