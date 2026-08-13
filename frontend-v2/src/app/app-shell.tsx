// Vista Console app shell — the sidebar rail (5-section IA) + topbar, wrapping
// the routed section content via <Outlet/>. Faithful in structure to the mock's
// Shell.jsx; styling uses the ported design tokens. The topbar bell is live
// (notification-bell.tsx); the command palette owns global search.
import { useState, useEffect, useCallback } from 'react';
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router';
import {
  LayoutDashboard, Radar, Database, ShieldCheck, Wrench,
  Shield, Settings, Search, Bell, type LucideIcon,
} from 'lucide-react';
import { useAuth } from '@vistasecurity/primitives/auth';
import { usePermissions } from '@vistasecurity/primitives/rbac';
import { useOnboardingStatus } from '../sections/onboarding/queries';
import { ONBOARDING_PERMISSIONS } from '../sections/onboarding/step-meta';
import { OnboardingNudge } from '../sections/onboarding/onboarding-nudge';
import { ErrorBoundary } from './error-boundary';
import { NotificationBell } from './notification-bell';
import { CommandPalette } from './command-palette';
import { SECTIONS, type NavSection } from './nav';
import { Icon as LensIcon } from '../components/ui';
import { usePlatformBranding, BrandLogo } from './platform-branding';
import { INVENTORY_LENSES, DEFAULT_LENS, type InventoryLens } from '../sections/inventory/lenses';
import { SettingsRail } from '../sections/settings/settings-rail';
import { FINDINGS_LENSES, DEFAULT_FINDINGS_LENS, SCOPE_LABEL } from '../sections/findings/lenses';
import { POSTURE_TABS, DEFAULT_POSTURE_TAB } from '../sections/posture/tabs';

const ICONS: Record<string, LucideIcon> = {
  LayoutDashboard, Radar, Database, ShieldCheck, Wrench, Shield, Settings, Search, Bell,
};

function Icon({ name, size = 17 }: { name: string; size?: number }) {
  const L = ICONS[name];
  return L ? <L size={size} /> : null;
}

function LensGroupLabel({ children, indent = 39 }: { children: React.ReactNode; indent?: number }) {
  return <div style={{ padding: `7px 10px 3px ${indent}px`, fontSize: 9.5, fontWeight: 700, letterSpacing: '.1em', textTransform: 'uppercase', color: 'var(--rail-t3)' }}>{children}</div>;
}

// A contextual sub-link shown nested *under* an active sub-nav item — the
// Findings lenses and the Posture views both hang off the item you clicked,
// indented one level deeper (52px vs the 41px of the items themselves) so the
// nesting reads correctly.
function ContextSubLink({ to, icon, label, active }: { to: string; icon: string; label: string; active: boolean }) {
  return (
    <Link to={to} className="nav-sub"
      style={{ display: 'flex', alignItems: 'center', gap: 9, width: '100%', padding: '6px 10px 6px 52px', borderRadius: 8, textDecoration: 'none', background: active ? 'var(--rail-active)' : 'transparent', color: active ? 'var(--rail-accent)' : 'var(--rail-t2)', fontFamily: 'var(--font-body)', fontSize: 12.5, fontWeight: active ? 600 : 500 }}>
      <LensIcon name={icon} size={14} /><span>{label}</span>
    </Link>
  );
}

function LensLink({ lens, active }: { lens: InventoryLens; active: boolean }) {
  return (
    <Link
      to={`/inventory?lens=${lens.key}`}
      className="nav-sub"
      title={lens.live ? '' : 'Built next'}
      style={{
        display: 'flex', alignItems: 'center', gap: 9, width: '100%',
        padding: '6px 10px 6px 39px', borderRadius: 8, textDecoration: 'none',
        background: active ? 'var(--rail-active)' : 'transparent',
        color: active ? 'var(--rail-accent)' : 'var(--rail-t2)',
        fontFamily: 'var(--font-body)', fontSize: 12.5, fontWeight: active ? 600 : 500,
        opacity: lens.live ? 1 : 0.55,
      }}
    >
      <LensIcon name={lens.icon} size={14} /><span>{lens.label}</span>
    </Link>
  );
}

function isSectionActive(section: NavSection, pathname: string): boolean {
  if (pathname === section.path) return true;
  const base = '/' + pathname.split('/')[1];
  return base === '/' + section.path.split('/')[1];
}

function Sidebar() {
  const { pathname, search } = useLocation();
  const { name, logoUrl } = usePlatformBranding();
  const currentLens = new URLSearchParams(search).get('lens') || DEFAULT_LENS;
  // Settings / My Profile replace the primary rail with their own nav layer
  // (mock Shell.jsx's settings layer).
  if (pathname.startsWith('/settings') || pathname.startsWith('/profile')) return <SettingsRail />;
  return (
    <aside
      style={{
        width: 234, flex: 'none', background: 'var(--app-rail)',
        borderRight: '1px solid var(--app-rail-border)', display: 'flex', flexDirection: 'column', height: '100%',
      }}
    >
      <div style={{ padding: '20px 18px 16px', display: 'flex', alignItems: 'center', gap: 11, borderBottom: '1px solid var(--app-rail-border)' }}>
        <BrandLogo
          url={logoUrl} size={30} radius={8} alt={name}
          fallback={
            <div style={{ width: 30, height: 30, borderRadius: 8, background: 'var(--accent-gradient)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Icon name="Shield" size={17} />
            </div>
          }
        />
        <div style={{ lineHeight: 1 }}>
          <div className="wordmark accent-text" style={{ fontSize: 17 }}>{name}</div>
          <div style={{ fontSize: 9.5, color: 'var(--rail-t2)', letterSpacing: '.12em', marginTop: 3, textTransform: 'uppercase' }}>Console</div>
        </div>
      </div>

      <nav style={{ padding: '14px 12px 8px', display: 'flex', flexDirection: 'column', gap: 3, overflowY: 'auto', flex: 1 }}>
        {SECTIONS.map((s) => {
          const active = isSectionActive(s, pathname);
          return (
            <div key={s.id}>
              <NavLink
                to={s.path}
                className={'nav-item' + (active ? ' active' : '')}
                style={{
                  position: 'relative', display: 'flex', alignItems: 'center', gap: 11, width: '100%',
                  padding: '9px 14px 9px 18px', border: 'none', borderRadius: 9, textDecoration: 'none',
                  background: active ? 'var(--rail-active)' : 'transparent',
                  color: active ? 'var(--rail-accent)' : 'var(--rail-t2)',
                  fontFamily: 'var(--font-body)', fontSize: 13.5, fontWeight: active ? 600 : 500,
                }}
              >
                <Icon name={s.icon} size={17} />
                <span>{s.label}</span>
              </NavLink>

              {active && s.groups && (
                <div className="fade-up" style={{ margin: '3px 0 7px', display: 'flex', flexDirection: 'column', gap: 1 }}>
                  {s.groups.map((g, gi) => (
                    <div key={gi}>
                      {g.label && (
                        <div style={{ padding: '7px 10px 3px 41px', fontSize: 9.5, fontWeight: 700, letterSpacing: '.1em', textTransform: 'uppercase', color: 'var(--rail-t3)' }}>
                          {g.label}
                        </div>
                      )}
                      {g.items.map((it) => {
                        // Contextual sub-links hang *under the active item itself*
                        // (not after the whole group), so e.g. the Findings lenses
                        // nest under Findings — not below CBOM.
                        const onFindings = it.path === '/risk-compliance/findings' && pathname === '/risk-compliance/findings';
                        const onPosture = it.path === '/risk-compliance/posture' && pathname === '/risk-compliance/posture';
                        const curLens = new URLSearchParams(search).get('lens') || DEFAULT_FINDINGS_LENS;
                        const curTab = new URLSearchParams(search).get('tab') || DEFAULT_POSTURE_TAB;
                        return (
                          <div key={it.path}>
                            <NavLink
                              to={it.path}
                              end
                              className="nav-sub"
                              style={({ isActive }) => ({
                                display: 'flex', alignItems: 'center', gap: 9, width: '100%',
                                padding: '6px 10px 6px 41px', borderRadius: 8, textDecoration: 'none',
                                background: isActive ? 'var(--rail-subactive)' : 'transparent',
                                color: isActive ? 'var(--rail-t1)' : 'var(--rail-t2)',
                                fontFamily: 'var(--font-body)', fontSize: 12.5, fontWeight: isActive ? 600 : 500,
                              })}
                            >
                              {it.label}
                            </NavLink>

                            {onFindings && (
                              <div className="fade-up" style={{ margin: '2px 0 5px', display: 'flex', flexDirection: 'column', gap: 1 }}>
                                {/* L-5: lenses are grouped and labeled by which finding
                                    universe they read (crypto-risk stream vs. persisted
                                    compliance findings) — switching groups changes what
                                    "Open" is counting, and that needs to be visible right
                                    where the user makes the switch. */}
                                {(['compliance', 'crypto'] as const).map((scope) => (
                                  <div key={scope}>
                                    <LensGroupLabel indent={54}>{SCOPE_LABEL[scope]}</LensGroupLabel>
                                    {FINDINGS_LENSES.filter((l) => l.scope === scope).map((l) => (
                                      <ContextSubLink key={l.key} to={`/risk-compliance/findings?lens=${l.key}`} icon={l.icon} label={l.label} active={curLens === l.key} />
                                    ))}
                                  </div>
                                ))}
                              </div>
                            )}

                            {onPosture && (
                              <div className="fade-up" style={{ margin: '2px 0 5px', display: 'flex', flexDirection: 'column', gap: 1 }}>
                                <LensGroupLabel indent={54}>Views</LensGroupLabel>
                                {POSTURE_TABS.map((t) => (
                                  <ContextSubLink key={t.key} to={`/risk-compliance/posture?tab=${t.key}`} icon={t.icon} label={t.label} active={curTab === t.key} />
                                ))}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  ))}
                </div>
              )}

              {active && s.id === 'inventory' && (
                <div className="fade-up" style={{ margin: '3px 0 7px', display: 'flex', flexDirection: 'column', gap: 1 }}>
                  <LensGroupLabel>Lenses</LensGroupLabel>
                  {INVENTORY_LENSES.filter((l) => l.primary).map((l) => (
                    <LensLink key={l.key} lens={l} active={pathname === '/inventory' && currentLens === l.key} />
                  ))}
                  <LensGroupLabel>By Protocol</LensGroupLabel>
                  {INVENTORY_LENSES.filter((l) => !l.primary).map((l) => (
                    <LensLink key={l.key} lens={l} active={pathname === '/inventory' && currentLens === l.key} />
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </nav>

      <Link
        to="/settings"
        className="nav-item"
        style={{ display: 'flex', alignItems: 'center', gap: 11, margin: '0 12px 4px', padding: '8px 14px 8px 18px', borderRadius: 9, background: 'transparent', color: 'var(--rail-t2)', fontSize: 13, fontWeight: 500, textDecoration: 'none' }}
      >
        <Icon name="Settings" size={16} />
        <span>Settings</span>
      </Link>

      <ProfileChip />
    </aside>
  );
}

type Theme = 'dark' | 'light';

function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(() => {
    const stored = localStorage.getItem('vista-theme') as Theme | null;
    return stored ?? 'dark';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('vista-theme', theme);
  }, [theme]);

  const toggle = useCallback(() => setTheme(t => t === 'dark' ? 'light' : 'dark'), []);
  return [theme, toggle];
}

// Bottom-of-rail account chip → popover with My Profile / Org Settings / Sign out.
// Mirrors the mock's ProfileMenu (Shell.jsx + settings/profile.jsx); only items
// with real destinations are shown — no dead controls.
function ProfileChip() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [theme, toggleTheme] = useTheme();

  // "Getting Started" is shown only while the onboarding banner is live (required
  // && !completed && !dismissed) and only to users who can act on at least one
  // step (read-only viewers aren't nagged).
  const { hasAnyPermission } = usePermissions();
  const { data: onboarding } = useOnboardingStatus();
  const showGettingStarted = !!onboarding?.show_banner && hasAnyPermission(ONBOARDING_PERMISSIONS);

  const first = user?.first_name ?? '';
  const last = user?.last_name ?? '';
  const name = `${first} ${last}`.trim() || user?.email || 'Account';
  const initials = ((first[0] ?? '') + (last[0] ?? '')).toUpperCase() || (user?.email?.[0] ?? '?').toUpperCase();
  const role = user?.role ?? '';

  const signOut = async () => {
    setOpen(false);
    await logout(); // clears session → RequireAuth redirects to /login
    navigate('/login', { replace: true });
  };

  const MenuItem = ({ icon, label, onClick, danger }: { icon: string; label: string; onClick: () => void; danger?: boolean }) => (
    <button onClick={onClick} className="nav-sub" style={{ display: 'flex', alignItems: 'center', gap: 11, width: '100%', padding: '9px 12px', border: 'none', background: 'transparent', cursor: 'pointer', borderRadius: 8, color: danger ? 'var(--rail-danger)' : 'var(--rail-t1)', fontSize: 13, textAlign: 'left', fontFamily: 'var(--font-body)' }}>
      <LensIcon name={icon} size={15} style={{ color: danger ? 'var(--rail-danger)' : 'var(--rail-t3)', flex: 'none' }} /><span>{label}</span>
    </button>
  );

  return (
    <div style={{ position: 'relative', margin: '0 12px 12px' }}>
      <button
        onClick={() => setOpen((v) => !v)}
        className="nav-item"
        style={{ display: 'flex', alignItems: 'center', gap: 11, width: '100%', padding: '8px 12px', borderRadius: 11, border: '1px solid var(--app-rail-border)', background: open ? 'var(--rail-hover)' : 'transparent', cursor: 'pointer', textAlign: 'left' }}
      >
        <span style={{ width: 30, height: 30, borderRadius: 9, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--accent-gradient)', color: 'var(--accent-fg)', fontWeight: 800, fontSize: 12 }}>{initials}</span>
        <span style={{ minWidth: 0, flex: 1, lineHeight: 1.25 }}>
          <span style={{ display: 'block', fontSize: 12.5, fontWeight: 600, color: 'var(--rail-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{name}</span>
          {role && <span style={{ display: 'block', fontSize: 10.5, color: 'var(--rail-t3)', textTransform: 'capitalize' }}>{role.replace(/_/g, ' ')}</span>}
        </span>
        <LensIcon name="chevron-up" size={15} style={{ color: 'var(--rail-t3)', flex: 'none', transform: open ? 'none' : 'rotate(180deg)', transition: 'transform .15s ease' }} />
      </button>

      {open && (
        <>
          <div onClick={() => setOpen(false)} style={{ position: 'fixed', inset: 0, zIndex: 79 }} />
          <div style={{ position: 'absolute', left: 0, right: 0, bottom: 'calc(100% + 6px)', zIndex: 80, background: 'var(--app-panel)', border: '1px solid var(--app-border2)', borderRadius: 14, boxShadow: 'var(--app-shadow)', padding: 7, animation: 'popIn .15s ease both' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '9px 10px 11px', borderBottom: '1px solid var(--app-border)', marginBottom: 5 }}>
              <span style={{ width: 34, height: 34, borderRadius: 10, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--accent-gradient)', color: 'var(--accent-fg)', fontWeight: 800, fontSize: 13 }}>{initials}</span>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--app-t1)' }}>{name}</div>
                <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{user?.email}</div>
              </div>
            </div>
            {showGettingStarted && (
              <MenuItem icon="list-checks" label="Getting Started" onClick={() => { setOpen(false); navigate('/getting-started'); }} />
            )}
            <MenuItem icon="user" label="My Profile" onClick={() => { setOpen(false); navigate('/profile'); }} />
            <MenuItem icon="building-2" label="Organization Settings" onClick={() => { setOpen(false); navigate('/settings'); }} />
            <MenuItem icon="info" label="About" onClick={() => { setOpen(false); navigate('/about'); }} />
            <MenuItem icon={theme === 'dark' ? 'sun' : 'moon'} label={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'} onClick={toggleTheme} />
            <div style={{ height: 1, background: 'var(--app-border)', margin: '5px 6px' }} />
            <MenuItem icon="log-out" label="Sign out" onClick={signOut} danger />
          </div>
        </>
      )}
    </div>
  );
}

function Topbar({ onOpenSearch }: { onOpenSearch: () => void }) {
  return (
    <header style={{ height: 62, flex: 'none', borderBottom: '1px solid var(--app-border)', background: 'var(--app-bg)', display: 'flex', alignItems: 'center', gap: 16, padding: '0 22px' }}>
      <div style={{ flex: 1 }} />
      <button className="ui-btn ghost" title="Search (⌘K)" onClick={onOpenSearch}><Icon name="Search" size={15} />Search…</button>
      <NotificationBell />
    </header>
  );
}

export function AppShell() {
  const { pathname } = useLocation();
  const [searchOpen, setSearchOpen] = useState(false);
  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      {/* Fires the once-per-session onboarding login nudge (renders nothing). */}
      <OnboardingNudge />
      {/* Global ⌘K search — mounted once; owns its own ⌘K listener. */}
      <CommandPalette open={searchOpen} onOpenChange={setSearchOpen} />
      <Sidebar />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        <Topbar onOpenSearch={() => setSearchOpen(true)} />
        <main style={{ flex: 1, minHeight: 0, overflow: 'auto' }}>
          {/* Section-level boundary: a crash in one routed section renders a
              compact fallback inside the shell instead of taking down the
              whole app. Keyed by pathname so navigating away clears a crashed
              section. The top-level boundary in main.tsx is the backstop. */}
          <ErrorBoundary key={pathname} section>
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}
