// VISTA Operations app shell — sidebar (lockup + grouped nav + user footer) +
// topbar, wrapping routed section content via <Outlet/>. Ported from the design
// kit's ops-shell.jsx (Sidebar + Topbar) against the operator theme tokens.
//
// Operator-only signatures from the design that are DATA-dependent — the tenant
// switcher, scope bar, break-glass impersonation banner, the live platform
// status mini-card, command palette, and per-route primary actions — are wired
// with the data layer during the Tenants/Overview slices. They're intentionally
// omitted here so the foundation shell shows no fake data.
import { useEffect, useState } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router';
import {
  Shield, Gauge, Building2, Radar, Workflow, Wallet, Activity, ToggleRight,
  Library, UsersRound, ScrollText, ChevronsUpDown, Search, Bell, LogOut, Settings2, ShieldAlert, FileCheck2, Layers, Megaphone, LifeBuoy, type LucideIcon,
} from 'lucide-react';
import { usePlatformAuth, usePlatformPermissions } from '@vistasecurity/primitives/platform-auth';
import { SECTIONS, resolveActive, visibleSections } from './nav';
import { editionLabel, usePlatformEdition } from '../lib/edition';
import { usePlatformBranding, BrandLogo } from './platform-branding';
import { CommandPalette } from './command-palette';
import { TenantSwitcher, ScopeBar } from './tenant-switcher';
import { NotificationBell } from './notification-bell';

const ICONS: Record<string, LucideIcon> = {
  Gauge, Building2, Radar, Workflow, Wallet, Activity, ToggleRight, Library, UsersRound, ScrollText, Bell, Settings2, ShieldAlert, FileCheck2, Layers, Megaphone, LifeBuoy,
};

function NavIcon({ name, size = 16.5 }: { name: string; size?: number }) {
  const L = ICONS[name];
  return L ? <L size={size} /> : null;
}

function initialsOf(first?: string, last?: string, email?: string): string {
  const a = first?.[0] ?? '';
  const b = last?.[0] ?? '';
  const fromName = (a + b).trim();
  if (fromName) return fromName.toUpperCase();
  return (email?.[0] ?? '?').toUpperCase();
}

export function AppShell() {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const { user, logout } = usePlatformAuth();
  const { hasPermission } = usePlatformPermissions();
  const { name, logoUrl } = usePlatformBranding();
  const { capabilities, edition } = usePlatformEdition();
  const [paletteOpen, setPaletteOpen] = useState(false);

  // Global ⌘K / Ctrl+K opens the command palette.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPaletteOpen((o) => !o); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const active = resolveActive(pathname);
  const activeId = active.sectionId;
  const activeChildId = active.child?.id;
  const activeGrandchildId = active.grandchild?.id;

  // Group the flat nav for rendering: ungrouped block, then Platform, then
  // Governance. Each group is filtered by BOTH gates (nav.ts `visibleSections`):
  // permission, so a least-privilege role never sees a section it lacks, and
  // edition, so a Core build never offers MSP/Enterprise sections whose backend
  // it does not mount. The route guards (RequirePlatformPermission /
  // RequirePlatformEdition) back both up against deep links.
  const visible = visibleSections(hasPermission, capabilities);
  const groups: { label: string | null; items: typeof SECTIONS }[] = [
    { label: null, items: visible.filter((s) => s.group === null) },
    { label: 'Platform', items: visible.filter((s) => s.group === 'Platform') },
    { label: 'Governance', items: visible.filter((s) => s.group === 'Governance') },
  ];

  return (
    <div style={{ display: 'flex', height: '100vh', background: 'var(--op-bg)' }}>
      {/* ---- sidebar ---- */}
      <aside style={{ width: 232, flex: 'none', background: 'var(--op-rail)', borderRight: '1px solid var(--op-rail-border)', display: 'flex', flexDirection: 'column', height: '100%' }}>
        {/* lockup — VISTA · OPERATIONS / INTERNAL (distinct from the customer Console) */}
        <NavLink to="/overview" title="Mission Control" style={{ padding: '18px 16px 15px', display: 'flex', alignItems: 'center', gap: 11, borderBottom: '1px solid var(--op-rail-border)', textDecoration: 'none' }}>
          <BrandLogo
            url={logoUrl} size={30} radius="var(--r-sm)" shadow="0 0 14px color-mix(in srgb, var(--accent) 40%, transparent)" alt={name}
            fallback={
              <div style={{ width: 30, height: 30, borderRadius: 'var(--r-sm)', background: 'var(--accent-gradient)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 14px color-mix(in srgb, var(--accent) 40%, transparent)', flex: 'none' }}>
                <Shield size={16} style={{ color: '#0A0A0A' }} />
              </div>
            }
          />
          <div style={{ lineHeight: 1, textAlign: 'left', flex: 1, minWidth: 0 }}>
            <div className="wordmark accent-text" style={{ fontSize: 16 }}>{name}</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
              <span style={{ fontSize: 9, color: 'var(--rail-t2)', letterSpacing: '.18em', textTransform: 'uppercase', fontWeight: 600 }}>Operations</span>
              <span style={{ fontSize: 7.5, fontWeight: 700, letterSpacing: '.1em', color: 'var(--warn-light)', background: 'color-mix(in srgb, var(--accent) 16%, transparent)', border: '1px solid color-mix(in srgb, var(--accent) 30%, transparent)', borderRadius: 4, padding: '1px 4px', textTransform: 'uppercase' }}>Internal</span>
              {/* Edition badge — the one always-visible place an operator can see
                  which build they are running. It is what makes hiding the
                  MSP/Enterprise sections honest rather than merely quiet. */}
              {editionLabel(edition) && (
                <span title={`admin-service is running the ${editionLabel(edition)} edition`} style={{ fontSize: 7.5, fontWeight: 700, letterSpacing: '.1em', color: 'var(--rail-t2)', background: 'rgba(255,255,255,.06)', border: '1px solid rgba(255,255,255,.14)', borderRadius: 4, padding: '1px 4px', textTransform: 'uppercase' }}>{editionLabel(edition)}</span>
              )}
            </div>
          </div>
        </NavLink>

        {/* grouped nav */}
        <nav style={{ padding: '12px 12px 8px', display: 'flex', flexDirection: 'column', gap: 2, overflowY: 'auto', flex: 1 }}>
          {groups.map((g, gi) => (
            <div key={gi} style={{ marginTop: g.label ? 14 : 0 }}>
              {g.label && (
                <div style={{ padding: '4px 10px 6px 14px', fontSize: 9.5, fontWeight: 700, letterSpacing: '.13em', textTransform: 'uppercase', color: 'var(--rail-t3)' }}>{g.label}</div>
              )}
              {g.items.map((it) => {
                const isActive = activeId === it.id;
                return (
                  <div key={it.id}>
                    <NavLink
                      to={`/${it.id}`}
                      className="nav-item"
                      style={{
                        position: 'relative', display: 'flex', alignItems: 'center', gap: 11, width: '100%',
                        padding: '8px 14px 8px 18px', borderRadius: 'var(--r-btn)', textDecoration: 'none',
                        background: isActive ? 'var(--op-accent-soft)' : 'transparent',
                        color: isActive ? 'var(--op-accent-text)' : 'var(--rail-t2)',
                        fontFamily: 'var(--font-body)', fontSize: 13, fontWeight: isActive ? 600 : 500, letterSpacing: '-.01em',
                      }}
                    >
                      {isActive && <span style={{ position: 'absolute', left: 0, top: '50%', transform: 'translateY(-50%)', width: 3, height: 17, borderRadius: 4, background: 'var(--op-accent)' }} />}
                      <NavIcon name={it.icon} />
                      <span>{it.label}</span>
                    </NavLink>
                    {/* left-rail sub-nav: indented children of the active section */}
                    {isActive && it.children?.length ? (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 1, margin: '2px 0 4px' }}>
                        {it.children.map((c) => {
                          const childActive = activeChildId === c.id;
                          return (
                            <div key={c.id}>
                              <NavLink
                              to={`/${it.id}/${c.id}`}
                              className="nav-item"
                              style={{
                                position: 'relative', display: 'flex', alignItems: 'center', width: '100%',
                                padding: '6px 14px 6px 41px', borderRadius: 'var(--r-btn)', textDecoration: 'none',
                                background: childActive ? 'var(--op-accent-soft)' : 'transparent',
                                color: childActive ? 'var(--op-accent-text)' : 'var(--rail-t3)',
                                fontFamily: 'var(--font-body)', fontSize: 12.5, fontWeight: childActive ? 600 : 500, letterSpacing: '-.01em',
                              }}
                            >
                              {childActive && <span style={{ position: 'absolute', left: 22, top: '50%', transform: 'translateY(-50%)', width: 5, height: 5, borderRadius: 5, background: 'var(--op-accent)' }} />}
                              <span>{c.label}</span>
                            </NavLink>
                            {/* grandchildren: indented one level deeper under this child */}
                            {c.children?.length ? (
                              <div style={{ display: 'flex', flexDirection: 'column', gap: 1, margin: '1px 0 2px' }}>
                                {c.children.map((gc) => {
                                  const gcActive = activeChildId === c.id && activeGrandchildId === gc.id;
                                  return (
                                    <NavLink
                                      key={gc.id}
                                      to={`/${it.id}/${c.id}/${gc.id}`}
                                      className="nav-item"
                                      style={{
                                        position: 'relative', display: 'flex', alignItems: 'center', width: '100%',
                                        padding: '5px 14px 5px 56px', borderRadius: 'var(--r-btn)', textDecoration: 'none',
                                        background: gcActive ? 'var(--op-accent-soft)' : 'transparent',
                                        color: gcActive ? 'var(--op-accent-text)' : 'var(--rail-t3)',
                                        fontFamily: 'var(--font-body)', fontSize: 12, fontWeight: gcActive ? 600 : 500, letterSpacing: '-.01em',
                                      }}
                                    >
                                      {gcActive && <span style={{ position: 'absolute', left: 38, top: '50%', transform: 'translateY(-50%)', width: 4, height: 4, borderRadius: 4, background: 'var(--op-accent)' }} />}
                                      <span>{gc.label}</span>
                                    </NavLink>
                                  );
                                })}
                              </div>
                            ) : null}
                            </div>
                          );
                        })}
                      </div>
                    ) : null}
                  </div>
                );
              })}
            </div>
          ))}
        </nav>

        {/* user footer */}
        <button
          onClick={() => navigate('/staff')}
          className="row-hover"
          style={{ padding: '11px 16px', borderTop: '1px solid var(--op-rail-border)', display: 'flex', alignItems: 'center', gap: 10, width: '100%', background: 'transparent', border: 'none', borderTopWidth: 1, borderTopStyle: 'solid', cursor: 'pointer', textAlign: 'left' }}
        >
          <span style={{ width: 30, height: 30, borderRadius: 50, background: 'var(--op-avatar)', border: '1px solid rgba(255,255,255,.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11.5, fontWeight: 700, color: 'var(--accent-light)', flex: 'none', fontFamily: 'var(--font-head)' }}>
            {initialsOf(user?.first_name, user?.last_name, user?.email)}
          </span>
          <div style={{ lineHeight: 1.3, flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 12.5, color: 'var(--rail-t1)', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {user ? `${user.first_name} ${user.last_name}`.trim() || user.email : '—'}
            </div>
            <div style={{ fontSize: 10.5, color: 'var(--rail-t2)' }}>{user?.role ?? 'Platform user'}</div>
          </div>
          <ChevronsUpDown size={14} style={{ color: 'var(--rail-t2)' }} />
        </button>
      </aside>

      {/* ---- content column ---- */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        <header style={{ height: 60, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 22px', borderBottom: '1px solid var(--op-border)', background: 'var(--op-bg2)' }}>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 17, color: 'var(--op-t1)', lineHeight: 1.15 }}>{active.title}</div>
            {active.subtitle && <div style={{ fontSize: 11.5, color: 'var(--op-t3)' }}>{active.subtitle}</div>}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <TenantSwitcher />
            {/* search (⌘K) — opens the command palette */}
            <button className="op-chip" onClick={() => setPaletteOpen(true)} style={{ minWidth: 150, cursor: 'pointer', color: 'var(--op-t3)' }} title="Command palette">
              <Search size={14} />
              <span style={{ flex: 1, textAlign: 'left' }}>Search…</span>
              <kbd style={{ fontSize: 10, fontFamily: 'var(--font-body)', color: 'var(--op-t3)', border: '1px solid var(--op-border2)', borderRadius: 4, padding: '0 5px' }}>⌘K</kbd>
            </button>
            <NotificationBell />
            <button className="op-btn ghost sm" onClick={() => { logout(); navigate('/login', { replace: true }); }} title="Sign out">
              <LogOut size={14} /> Sign out
            </button>
          </div>
        </header>

        <ScopeBar />

        <main style={{ flex: 1, overflowY: 'auto' }}>
          <Outlet />
        </main>
      </div>

      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </div>
  );
}
