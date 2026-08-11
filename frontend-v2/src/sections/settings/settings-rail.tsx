// The Settings / My Profile sidebar layer — ported from the mock Shell.jsx's
// settings layer ("Back to Console" + grouped settings nav, or the profile nav
// with an identity card). Rendered by the app shell in place of the primary
// rail whenever the route is under /settings or /profile.
import { Link, useLocation } from 'react-router';
import { useAuth } from '@vistasecurity/primitives/auth';
import { useFeatures } from '@vistasecurity/primitives/features';
import { Icon } from '../../components/ui';
import { SAvatar } from './kit';
import { visibleProfileNav, visibleSettingsNav, type SettingsNavItem } from './nav';

function NavItem({ to, item, active }: { to: string; item: SettingsNavItem; active: boolean }) {
  const danger = item.danger;
  return (
    <Link
      to={to}
      className="nav-sub"
      title={item.job}
      style={{
        display: 'flex', alignItems: 'center', gap: 9, width: '100%',
        padding: '7px 10px 7px 14px', borderRadius: 8, textDecoration: 'none',
        background: active ? 'var(--rail-active)' : 'transparent',
        color: active ? 'var(--rail-accent)' : danger ? 'var(--danger-text)' : 'var(--rail-t2)',
        fontFamily: 'var(--font-body)', fontSize: 12.5, fontWeight: active ? 600 : 500,
      }}
    >
      <Icon name={item.icon} size={14} style={{ flex: 'none', opacity: active ? 1 : 0.8 }} />
      <span>{item.label}</span>
    </Link>
  );
}

export function SettingsRail() {
  const { pathname } = useLocation();
  const inProfile = pathname.startsWith('/profile');
  const page = pathname.split('/')[2] || '';
  const { user } = useAuth();
  // Edition/entitlement gating for the rail. `useFeatures` defaults every flag
  // to false while loading, so Enterprise-only entries appear on resolve rather
  // than flashing and disappearing.
  const { features } = useFeatures();
  const sections = visibleSettingsNav(features);
  const profileItems = visibleProfileNav();

  return (
    <aside
      style={{
        width: 234, flex: 'none', background: 'var(--app-rail)',
        borderRight: '1px solid var(--app-rail-border)', display: 'flex', flexDirection: 'column', height: '100%',
      }}
    >
      <Link
        to="/dashboard"
        className="nav-item"
        style={{ display: 'flex', alignItems: 'center', gap: 9, margin: '12px 12px 2px', padding: '8px 12px', borderRadius: 9, textDecoration: 'none', color: 'var(--rail-t2)', fontFamily: 'var(--font-body)', fontSize: 12.5, fontWeight: 600 }}
      >
        <Icon name="arrow-left" size={15} /><span>Back to Console</span>
      </Link>

      <div style={{ padding: '2px 20px 12px', display: 'flex', alignItems: 'center', gap: 9 }}>
        <Icon name={inProfile ? 'user-round' : 'settings'} size={18} style={{ color: 'var(--accent)' }} />
        <span style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 16.5, color: 'var(--rail-t1)', letterSpacing: '-.01em', whiteSpace: 'nowrap' }}>
          {inProfile ? 'My Profile' : 'Settings'}
        </span>
      </div>

      {inProfile && user && (
        <div style={{ margin: '0 12px 10px', padding: '11px 12px', borderRadius: 12, background: 'var(--rail-active)', display: 'flex', alignItems: 'center', gap: 10 }}>
          <SAvatar name={`${user.first_name} ${user.last_name}`} size={34} />
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 12.5, fontWeight: 700, color: 'var(--rail-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {user.first_name} {user.last_name}
            </div>
            <div className="mono" style={{ fontSize: 10, color: 'var(--rail-t2)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{user.email}</div>
          </div>
        </div>
      )}

      <nav style={{ padding: '4px 12px 10px', display: 'flex', flexDirection: 'column', gap: 2, overflowY: 'auto', flex: 1 }}>
        {inProfile
          ? profileItems.map((it) => (
              <NavItem key={it.key} to={`/profile/${it.key}`} item={it} active={page === it.key} />
            ))
          : sections.map((sec, si) => (
              <div key={sec.section} style={{ marginTop: si ? 12 : 0 }}>
                <div style={{ padding: '0 10px 5px 14px', fontSize: 9.5, fontWeight: 700, letterSpacing: '.1em', textTransform: 'uppercase', color: 'var(--rail-t3)' }}>
                  {sec.section}
                </div>
                {sec.items.map((it) => (
                  <NavItem key={it.key} to={`/settings/${it.key}`} item={it} active={page === it.key} />
                ))}
              </div>
            ))}
      </nav>
    </aside>
  );
}
