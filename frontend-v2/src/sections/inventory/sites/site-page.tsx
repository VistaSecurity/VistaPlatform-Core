// The site page (DCIM row 2.1) — `/inventory/sites/:id`. Overview of one site:
// where it is (address, time zone, coordinates), what it holds (assets,
// locations, racks, prefixes, VLANs), its locations, its
// findings by environment, and its change log and journal. Reached from the
// Sites lens, an asset's header ("Site › Location") and the Infrastructure
// sites management page.
import { useState, type ReactNode } from 'react';
import { Link, useParams } from 'react-router';
import { Icon, MetaRow, SectionLabel } from '../../../components/ui';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { ObjectChanges } from '../dcim/object-changes';
import { ObjectContacts } from '../dcim/object-contacts';
import { ObjectImages } from '../dcim/object-images';
import { ObjectJournal } from '../dcim/object-journal';
import { PanelEmpty, PanelError, PanelLoading } from '../dcim/substrate-states';
import { assetsLensHref } from '../builtin-views';
import { useRacks } from '../racks/racks-queries';
import { SITE_STATUSES, flattenNodes, useLocations, useSite, useSiteEnvironments, type Site } from './sites-queries';

function Count({ label, value, to, note }: { label: string; value: number; to?: string; note?: string }) {
  const body = (
    <>
      <div className="mono" style={{ fontSize: 20, fontWeight: 700, color: 'var(--app-t1)' }}>{value}</div>
      <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{label}</div>
      {note && <div style={{ fontSize: 10.5, color: 'var(--app-t3)', marginTop: 2 }}>{note}</div>}
    </>
  );
  const style = { flex: '1 1 120px', border: '1px solid var(--app-border)', borderRadius: 10, padding: '10px 12px', background: 'var(--app-panel)', textDecoration: 'none' } as const;
  return to ? <Link to={to} data-testid={`site-count-${label.toLowerCase()}`} style={style}>{body}</Link> : <div data-testid={`site-count-${label.toLowerCase()}`} style={style}>{body}</div>;
}

function Card({ children }: { children: ReactNode }) {
  return <div style={{ border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-panel)', padding: 16 }}>{children}</div>;
}

const statusLabel = (s: Site['operational_status']) => SITE_STATUSES.find((x) => x.value === s)?.label ?? s;

export function SitePage() {
  const { id } = useParams();
  const q = useSite(id);
  const locations = useLocations(id, !!id);
  const envs = useSiteEnvironments(id);
  const [tab, setTab] = useState<'changes' | 'journal'>('changes');

  const back = (
    <Link to="/inventory?lens=sites" style={{ display: 'inline-flex', alignItems: 'center', gap: 3, fontSize: 12.5, color: 'var(--app-t3)', textDecoration: 'none' }}>
      <Icon name="chevron-left" size={13} />Sites
    </Link>
  );
  if (q.isLoading) return <div style={{ padding: '22px 26px' }}>{back}<div style={{ marginTop: 14 }}><PanelLoading label="Loading site…" /></div></div>;
  if (q.isError || !q.data) {
    const notFound = q.error instanceof Error && q.error.message === 'not-found';
    return (
      <div style={{ padding: '22px 26px' }}>
        {back}
        <div style={{ marginTop: 14 }}>
          {notFound
            ? <PanelEmpty icon="search-x" title="Site not found" message="This site no longer exists. It may have been deleted, and its assets moved to another site." />
            : <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />}
        </div>
      </div>
    );
  }
  const site = q.data;
  const counts = site.counts ?? { assets: site.asset_count, locations: 0, racks: 0, prefixes: 0, vlans: 0 };
  const coords = site.latitude != null && site.longitude != null ? `${site.latitude}, ${site.longitude}` : '';
  const locRows = flattenNodes(locations.data ?? []);

  return (
    <div data-testid="site-page" style={{ padding: '14px 26px 40px', display: 'flex', flexDirection: 'column', gap: 16, overflowY: 'auto', height: '100%' }}>
      {back}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
          <Icon name="building-2" size={14} style={{ color: 'var(--app-t3)' }} />
          <span className="eyebrow-app">Site{site.region_name ? ` · ${site.region_name}` : ''}{site.group_name ? ` · ${site.group_name}` : ''}</span>
          {site.operational_status !== 'active' && (
            <span style={{ fontSize: 10.5, fontWeight: 700, color: 'var(--app-t3)', border: '1px solid var(--app-border2)', borderRadius: 40, padding: '1px 8px' }}>{statusLabel(site.operational_status)}</span>
          )}
        </div>
        <h1 style={{ margin: '3px 0 2px', fontFamily: 'var(--font-head)', fontSize: 19, fontWeight: 700, color: 'var(--app-t1)' }}>{site.name}</h1>
        {site.description && <div style={{ fontSize: 12.5, color: 'var(--app-t2)' }}>{site.description}</div>}
      </div>

      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <Count label="Assets" value={counts.assets} to={assetsLensHref(`site.id = "${site.id}"`)} />
        <Count label="Locations" value={counts.locations} />
        <Count label="Racks" value={counts.racks} to={`/inventory?lens=racks&site=${site.id}`} />
        <Count label="Prefixes" value={counts.prefixes} />
        <Count label="VLANs" value={counts.vlans} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 14, alignItems: 'start' }}>
        <Card>
          <SectionLabel icon="map-pin">Where</SectionLabel>
          <MetaRow k="Physical address" v={site.physical_address} />
          <MetaRow k="Shipping address" v={site.shipping_address} />
          <MetaRow k="Time zone" v={site.time_zone} />
          <MetaRow k="Coordinates" v={coords} />
          <MetaRow k="Facility" v={site.facility} />
          <MetaRow k="Business unit" v={site.business_unit_name} />
          <MetaRow k="ASNs" v={site.asns.length ? site.asns.join(', ') : ''} />
          <PermissionGate permission={TENANT_PERMISSIONS.dcim.read}>
            <SectionLabel icon="users">Contacts</SectionLabel>
            <div data-testid="site-contacts"><ObjectContacts kind="site" id={site.id} /></div>
            <SectionLabel icon="image-plus">Images</SectionLabel>
            <div data-testid="site-images"><ObjectImages kind="site" id={site.id} /></div>
          </PermissionGate>
        </Card>

        <Card>
          <SectionLabel icon="layers">Locations</SectionLabel>
          {locations.isLoading ? <PanelLoading label="Loading locations…" />
            : locations.isError ? <PanelError message="Couldn't load the site's locations." onRetry={() => { void locations.refetch(); }} />
              : locRows.length === 0 ? <div style={{ fontSize: 12, color: 'var(--app-t3)' }}>No locations inside this site yet. Add halls, cages or rows from Infrastructure → Sites &amp; locations.</div>
                : locRows.map(({ node, depth }) => (
                  <div key={node.id} data-testid="site-location" style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12.5, padding: '4px 0', paddingLeft: depth * 16 }}>
                    <Icon name="map-pin" size={12} style={{ color: 'var(--app-t3)' }} />{node.name}
                    <span className="mono" style={{ marginLeft: 'auto', fontSize: 11.5, color: 'var(--app-t3)' }}>{node.asset_count}</span>
                  </div>
                ))}
        </Card>

        <SiteRacksCard siteId={site.id} />

        <Card>
          <SectionLabel icon="shield-alert">Findings by environment</SectionLabel>
          {envs.isLoading ? <PanelLoading label="Loading…" />
            : envs.isError ? <PanelError message="Couldn't load the site's summary." onRetry={() => { void envs.refetch(); }} />
              : (envs.data ?? []).length === 0
                ? <div style={{ fontSize: 12, color: 'var(--app-t3)' }}>No assets in this site have been summarised yet. The summary refreshes on a schedule.</div>
                : (envs.data ?? []).map((e) => (
                  <MetaRow key={e.environment} k={e.environment}
                    v={`${e.asset_count} assets · ${e.critical_findings} critical · ${e.high_findings} high · ${e.expired_certs} expired certificates`} />
                ))}
        </Card>
      </div>

      <Card>
        <div role="tablist" style={{ display: 'flex', gap: 4, borderBottom: '1px solid var(--app-border)' }}>
          {(['changes', 'journal'] as const).map((t) => (
            <button key={t} type="button" role="tab" aria-selected={tab === t} className="ui-btn ghost sm"
              style={{ borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent', borderRadius: 0 }} onClick={() => setTab(t)}>
              {t === 'changes' ? 'Changes' : 'Journal'}
            </button>
          ))}
        </div>
        <div style={{ marginTop: 8 }}>
          {tab === 'changes' ? <ObjectChanges kind="site" id={site.id} /> : <ObjectJournal kind="site" id={site.id} />}
        </div>
      </Card>
    </div>
  );
}

/** The site's racks (DCIM row 2.5): each opens its rack page; the header
 *  opens the Racks lens filtered to this site. */
function SiteRacksCard({ siteId }: { siteId: string }) {
  const racks = useRacks({ siteId });
  const rows = racks.data ?? [];
  return (
    <Card>
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <SectionLabel icon="server">Racks</SectionLabel>
        <Link to={`/inventory?lens=racks&site=${siteId}`} data-testid="site-racks-lens" style={{ marginLeft: 'auto', fontSize: 12, marginTop: 14 }}>Open in Racks</Link>
      </div>
      {racks.isLoading ? <PanelLoading label="Loading racks…" />
        : racks.isError ? <PanelError message="Couldn't load the site's racks." onRetry={() => { void racks.refetch(); }} />
          : rows.length === 0 ? <div data-testid="site-racks-empty" style={{ fontSize: 12, color: 'var(--app-t3)' }}>No racks in this site yet. Add them from Infrastructure → Racks.</div>
            : rows.map((r) => (
              <Link key={r.id} to={`/inventory/racks/${r.id}`} data-testid="site-rack" style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12.5, padding: '5px 0', textDecoration: 'none', color: 'var(--app-t1)', borderBottom: '1px solid var(--app-border)' }}>
                <Icon name="server" size={12} style={{ color: 'var(--app-t3)' }} />
                <span style={{ fontWeight: 600 }}>{r.name}</span>
                {r.location && <span style={{ color: 'var(--app-t3)' }}>· {r.location.name}</span>}
                <span className="mono" style={{ marginLeft: 'auto', fontSize: 11.5, color: 'var(--app-t3)' }}>
                  {r.utilization ? `${r.utilization.utilization}%` : '—'} · {r.device_count ?? 0} dev
                </span>
              </Link>
            ))}
    </Card>
  );
}
