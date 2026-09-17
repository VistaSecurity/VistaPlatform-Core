// The Settings / My Profile sidebar layer, rendered as a DRAWER that slides up
// over the primary rail's nav list rather than replacing the whole rail.
//
// Why a drawer and not a swap: the swap took the profile chip and the rail's
// identity off screen with it, so the one control that tells you who you are
// vanished exactly when you went to manage who you are. The drawer covers only
// the nav list — the brand block above it and the Settings toggle + profile
// chip below it stay put — so the rail never loses its anchors and the Settings
// button can toggle the layer closed again from the same place you opened it.
//
// Open/closed is owned by the app shell (it has to coordinate with the route);
// this component is presentational and controlled.
import { useEffect, useRef } from 'react';
import { Link } from 'react-router';
import { useAuth } from '@vistasecurity/primitives/auth';
import { useFeatures } from '@vistasecurity/primitives/features';
import { Icon } from '../../components/ui';
import { SAvatar } from './kit';
import { visibleProfileNav, visibleSettingsNav, type SettingsNavItem } from './nav';

export type RailLayer = 'settings' | 'profile';

function NavItem({ to, item, active, onNavigate }: { to: string; item: SettingsNavItem; active: boolean; onNavigate?: () => void }) {
  const danger = item.danger;
  return (
    <Link
      to={to}
      className="nav-sub"
      title={item.job}
      onClick={onNavigate}
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

export function SettingsDrawer({
  layer, open, page, onClose,
}: {
  /** Which nav this drawer is showing. Driven by state, NOT by the pathname —
   *  the drawer can be open before you have navigated anywhere. */
  layer: RailLayer;
  open: boolean;
  /** The settings/profile page key currently routed to, for the active mark.
   *  Empty while the drawer is open but no page has been picked yet. */
  page: string;
  onClose: () => void;
}) {
  const { user } = useAuth();
  // Edition/entitlement gating for the nav. `useFeatures` defaults every flag
  // to false while loading, so Enterprise-only entries appear on resolve rather
  // than flashing and disappearing.
  const { features } = useFeatures();
  const sections = visibleSettingsNav(features);
  const profileItems = visibleProfileNav();
  const inProfile = layer === 'profile';
  const scroller = useRef<HTMLElement>(null);

  // Escape closes, matching every other overlay in the console.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  // A reopen starts at the top rather than wherever the last visit was scrolled
  // to — the list is ~27 items over 10 sections, so a stale offset reads as the
  // wrong nav.
  useEffect(() => { if (open && scroller.current) scroller.current.scrollTop = 0; }, [open, layer]);

  return (
    <div
      className={'rail-drawer' + (open ? ' open' : '')}
      aria-hidden={!open}
      aria-label={inProfile ? 'My Profile navigation' : 'Settings navigation'}
    >
      <div style={{ padding: '14px 12px 10px 20px', display: 'flex', alignItems: 'center', gap: 9, flex: 'none' }}>
        <Icon name={inProfile ? 'user-round' : 'settings'} size={18} style={{ color: 'var(--accent)', flex: 'none' }} />
        <span style={{ flex: 1, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 16.5, color: 'var(--rail-t1)', letterSpacing: '-.01em', whiteSpace: 'nowrap' }}>
          {inProfile ? 'My Profile' : 'Settings'}
        </span>
        <button
          type="button"
          onClick={onClose}
          className="nav-sub"
          title="Close (Esc)"
          aria-label="Close"
          style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: 26, height: 26, flex: 'none', border: 'none', background: 'transparent', borderRadius: 8, cursor: 'pointer', color: 'var(--rail-t3)' }}
        >
          <Icon name="chevron-down" size={16} />
        </button>
      </div>

      {inProfile && user && (
        <div style={{ margin: '0 12px 10px', padding: '11px 12px', borderRadius: 12, background: 'var(--rail-active)', display: 'flex', alignItems: 'center', gap: 10, flex: 'none' }}>
          <SAvatar name={`${user.first_name} ${user.last_name}`} size={34} />
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 12.5, fontWeight: 700, color: 'var(--rail-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {user.first_name} {user.last_name}
            </div>
            <div className="mono" style={{ fontSize: 10, color: 'var(--rail-t2)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{user.email}</div>
          </div>
        </div>
      )}

      <nav ref={scroller} style={{ padding: '0 12px 12px', display: 'flex', flexDirection: 'column', gap: 2, overflowY: 'auto', flex: 1, minHeight: 0 }}>
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
    </div>
  );
}
