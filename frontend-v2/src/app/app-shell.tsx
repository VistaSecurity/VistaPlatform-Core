// Vista Console app shell — the sidebar rail (5-section IA) + topbar, wrapping
// the routed section content via <Outlet/>. Faithful in structure to the mock's
// Shell.jsx; styling uses the ported design tokens. The topbar bell is live
// (notification-bell.tsx); the command palette owns global search.
import { useState, useEffect, useCallback, useRef } from 'react';
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
import { SECTIONS, type NavSection, type NavSubItem } from './nav';
import { Icon as LensIcon } from '../components/ui';
import { usePlatformBranding, BrandLogo } from './platform-branding';
import { INVENTORY_LENSES, DEFAULT_LENS } from '../sections/inventory/lenses';
import { SettingsDrawer, type RailLayer } from '../sections/settings/settings-drawer';
import { FINDINGS_LENSES, DEFAULT_FINDINGS_LENS, SCOPE_LABEL, SCOPE_ORDER } from '../sections/findings/lenses';
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

/**
 * One Inventory sub-nav item, driven by the nav registry (ADR-0006 D1).
 *
 * The registry is the single source for what Inventory contains; the ICON comes
 * from the lens catalogue, because a lens already declares one and a second copy
 * in the nav registry is a second thing to keep in step. An item with no lens
 * (the Pending cross-link) borrows the section it points at.
 */
function InventoryNavLink({ item, active }: { item: NavSubItem; active: boolean }) {
  const lens = item.lens ? INVENTORY_LENSES.find((l) => l.key === item.lens) : undefined;
  const icon = lens?.icon ?? 'inbox';
  const pending = !!item.crossLink;
  return (
    <Link
      to={item.path}
      className="nav-sub"
      title={lens?.placeholder ? `Arrives in ${lens.placeholder.phase}` : pending ? 'Review in Discovery → Approvals' : ''}
      style={{
        display: 'flex', alignItems: 'center', gap: 9, width: '100%',
        padding: '6px 10px 6px 39px', borderRadius: 8, textDecoration: 'none',
        background: active ? 'var(--rail-active)' : 'transparent',
        color: active ? 'var(--rail-accent)' : 'var(--rail-t2)',
        fontFamily: 'var(--font-body)', fontSize: 12.5, fontWeight: active ? 600 : 500,
        opacity: lens && !lens.live ? 0.55 : 1,
      }}
    >
      <LensIcon name={icon} size={14} /><span style={{ flex: 1 }}>{item.label}</span>
      {pending && <LensIcon name="arrow-up-right" size={12} />}
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
  const navigate = useNavigate();
  const { name, logoUrl } = usePlatformBranding();
  const currentLens = new URLSearchParams(search).get('lens') || DEFAULT_LENS;

  // --- Settings / My Profile drawer ---------------------------------------
  // Two things can open the layer. The ROUTE opens it when you arrive with a
  // deep link or a bookmark to /settings/members; the Settings toggle and the
  // profile menu open it WITHOUT navigating, so asking for the nav does not
  // also drop you on a page you did not pick. A hand-opened layer therefore
  // takes precedence over the route's — that is what lets you switch from the
  // settings nav to the profile nav while a settings page is still on screen.
  const routeLayer: RailLayer | null =
    pathname.startsWith('/settings') ? 'settings' : pathname.startsWith('/profile') ? 'profile' : null;
  // A hand-opened layer remembers WHERE it was opened, which is what lets it
  // expire on its own: it stays open while you are inside settings/profile, and
  // stops applying the moment you land on a different console page — so a
  // Command-K jump or "About" can never leave the settings nav stranded over a
  // console page. Derived rather than synced in an effect, because an effect
  // would cascade an extra render and be one more thing free to disagree with
  // the route.
  const [manual, setManual] = useState<{ layer: RailLayer; at: string } | null>(null);
  const manualLayer = manual && (routeLayer !== null || manual.at === pathname) ? manual.layer : null;
  const openLayer = manualLayer ?? routeLayer;
  // Where closing returns you. Captured when the layer is opened by hand; a
  // deep link has no console page behind it, hence the fallback.
  const returnTo = useRef<string | null>(null);

  // The drawer slides out over 220ms, so it is still on screen after the layer
  // closes. If its contents fell back to a default then, you would watch the
  // profile nav turn into the settings nav on the way down. This remembers the
  // last layer that was actually up, so the thing being dismissed stays on
  // screen until it is gone. Written from the handlers rather than an effect —
  // an effect here would cascade a render, and a ref cannot be read back during
  // one. Seeded from the route so a layer arrived at by deep link is remembered
  // too: the chip is the only in-app way into /profile, so without the seed a
  // bookmarked profile page would slide out as the settings nav.
  const [shownLayer, setShownLayer] = useState<RailLayer>(routeLayer ?? 'settings');

  const openRailLayer = useCallback((layer: RailLayer) => {
    if (!routeLayer) returnTo.current = pathname + search;
    setManual({ layer, at: pathname });
    setShownLayer(layer);
    // Switching layers while a page of the OTHER layer is routed would leave
    // the nav and the content disagreeing — land on the new layer instead.
    if (routeLayer && routeLayer !== layer) void navigate(layer === 'profile' ? '/profile' : '/settings');
  }, [routeLayer, pathname, search, navigate]);

  const closeRailLayer = useCallback(() => {
    // Freeze what is on screen for the slide-out before the layer goes away.
    if (openLayer) setShownLayer(openLayer);
    setManual(null);
    // Only navigate when a settings/profile PAGE is actually on screen. Opening
    // the drawer for a look and closing it again is a no-op, not a redirect.
    if (routeLayer) void navigate(returnTo.current ?? '/dashboard');
  }, [openLayer, routeLayer, navigate]);

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

      {/* The console nav and the drawer share this region: the drawer is
          absolutely positioned within it, so it covers exactly the nav list —
          not the brand block above, not the Settings toggle and profile chip
          below, which stay reachable while the layer is open. */}
      <div style={{ position: 'relative', flex: 1, minHeight: 0, display: 'flex' }}>
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

              {/* Inventory's groups are rendered by their own block below: its
                  items differ by `?lens=`, which a pathname-matching NavLink
                  cannot tell apart — every one of them would light up at once. */}
              {active && s.groups && s.id !== 'inventory' && (
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
                                {SCOPE_ORDER.map((scope) => (
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

              {active && s.id === 'inventory' && s.groups && (
                <div className="fade-up" style={{ margin: '3px 0 7px', display: 'flex', flexDirection: 'column', gap: 1 }}>
                  {s.groups.map((g, gi) => (
                    <div key={g.label ?? gi}>
                      {g.label && <LensGroupLabel>{g.label}</LensGroupLabel>}
                      {g.items.map((item) => (
                        <InventoryNavLink
                          key={item.path}
                          item={item}
                          // An asset PAGE (`/inventory/assets/:id`) keeps "All
                          // assets" lit: the page is where a row from that list
                          // leads, and dropping the highlight there would make
                          // the rail say you had left the inventory.
                          active={
                            item.lens
                              ? (pathname === '/inventory' && currentLens === item.lens)
                                || (pathname.startsWith('/inventory/assets/') && item.lens === 'assets')
                              : false
                          }
                        />
                      ))}
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </nav>
        <SettingsDrawer
          layer={openLayer ?? shownLayer}
          open={!!openLayer}
          page={routeLayer ? pathname.split('/')[2] || '' : ''}
          onClose={closeRailLayer}
        />
      </div>

      <button
        type="button"
        onClick={() => (openLayer === 'settings' ? closeRailLayer() : openRailLayer('settings'))}
        className={'nav-item' + (openLayer === 'settings' ? ' active' : '')}
        aria-expanded={openLayer === 'settings'}
        style={{
          display: 'flex', alignItems: 'center', gap: 11, margin: '0 12px 4px',
          padding: '8px 14px 8px 18px', border: 'none', borderRadius: 9, cursor: 'pointer', textAlign: 'left',
          background: openLayer === 'settings' ? 'var(--rail-active)' : 'transparent',
          color: openLayer === 'settings' ? 'var(--rail-accent)' : 'var(--rail-t2)',
          fontFamily: 'var(--font-body)', fontSize: 13, fontWeight: openLayer === 'settings' ? 600 : 500,
        }}
      >
        <Icon name="Settings" size={16} />
        <span style={{ flex: 1 }}>Settings</span>
        <LensIcon name="chevron-up" size={14} style={{ color: 'var(--rail-t3)', flex: 'none', transform: openLayer === 'settings' ? 'rotate(180deg)' : 'none', transition: 'transform .2s ease' }} />
      </button>

      <ProfileChip
        onOpenLayer={openRailLayer}
        profileLayerOpen={openLayer === 'profile'}
        onCloseLayer={closeRailLayer}
      />
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
function ProfileChip({ onOpenLayer, profileLayerOpen, onCloseLayer }: {
  onOpenLayer: (layer: RailLayer) => void;
  /** True while the PROFILE layer is up — the chip then acts as that layer's
   *  close control (see the click handler). Not set for the settings layer:
   *  Settings has its own toggle, and the chip stays a menu there. */
  profileLayerOpen: boolean;
  onCloseLayer: () => void;
}) {
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
    void navigate('/login', { replace: true });
  };

  const MenuItem = ({ icon, label, onClick, danger }: { icon: string; label: string; onClick: () => void; danger?: boolean }) => (
    <button onClick={onClick} className="nav-sub" style={{ display: 'flex', alignItems: 'center', gap: 11, width: '100%', padding: '9px 12px', border: 'none', background: 'transparent', cursor: 'pointer', borderRadius: 8, color: danger ? 'var(--rail-danger)' : 'var(--rail-t1)', fontSize: 13, textAlign: 'left', fontFamily: 'var(--font-body)' }}>
      <LensIcon name={icon} size={15} style={{ color: danger ? 'var(--rail-danger)' : 'var(--rail-t3)', flex: 'none' }} /><span>{label}</span>
    </button>
  );

  return (
    <div style={{ position: 'relative', margin: '0 12px 12px' }}>
      <button
        // The chip owns the profile layer the way the Settings button owns its
        // own: whatever opened the layer, the persistent control at the bottom
        // of the rail is what shuts it. Without this the profile drawer had no
        // toggle at all — its trigger lives in a popover that closes on use, so
        // the only way out was the drawer's own chevron, and the layer behaved
        // differently from the one directly above it.
        onClick={() => { if (profileLayerOpen) { onCloseLayer(); return; } setOpen((v) => !v); }}
        className="nav-item"
        aria-expanded={profileLayerOpen || open}
        title={profileLayerOpen ? 'Close My Profile' : undefined}
        style={{
          display: 'flex', alignItems: 'center', gap: 11, width: '100%', padding: '8px 12px',
          borderRadius: 11, cursor: 'pointer', textAlign: 'left',
          border: '1px solid ' + (profileLayerOpen ? 'var(--rail-accent)' : 'var(--app-rail-border)'),
          background: profileLayerOpen ? 'var(--rail-active)' : open ? 'var(--rail-hover)' : 'transparent',
        }}
      >
        <span style={{ width: 30, height: 30, borderRadius: 9, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--accent-gradient)', color: 'var(--accent-fg)', fontWeight: 800, fontSize: 12 }}>{initials}</span>
        <span style={{ minWidth: 0, flex: 1, lineHeight: 1.25 }}>
          <span style={{ display: 'block', fontSize: 12.5, fontWeight: 600, color: profileLayerOpen ? 'var(--rail-accent)' : 'var(--rail-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{name}</span>
          {role && <span style={{ display: 'block', fontSize: 10.5, color: 'var(--rail-t3)', textTransform: 'capitalize' }}>{role.replace(/_/g, ' ')}</span>}
        </span>
        <LensIcon name="chevron-up" size={15} style={{ color: profileLayerOpen ? 'var(--rail-accent)' : 'var(--rail-t3)', flex: 'none', transform: open && !profileLayerOpen ? 'none' : 'rotate(180deg)', transition: 'transform .15s ease' }} />
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
              <MenuItem icon="list-checks" label="Getting Started" onClick={() => { setOpen(false); void navigate('/getting-started'); }} />
            )}
            {/* These open the rail drawer rather than navigating — same layer
                and same semantics as the Settings toggle just below the chip. */}
            <MenuItem icon="user" label="My Profile" onClick={() => { setOpen(false); onOpenLayer('profile'); }} />
            <MenuItem icon="building-2" label="Organization Settings" onClick={() => { setOpen(false); onOpenLayer('settings'); }} />
            <MenuItem icon="info" label="About" onClick={() => { setOpen(false); void navigate('/about'); }} />
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
