// The asset form's Site and Location selects (DCIM row 2.1). The location
// list is the chosen site's locations only — an asset's location must be in its
// site, and the API refuses one that is not — and choosing another site clears
// the location.
import { ModalField, ModalSelect } from '../../../components/ui';
import { flattenNodes, useLocations, useSites } from './sites-queries';

export interface Placement { siteId: string; locationId: string }

/** The asset-write fields for a placement. An edit that clears the site sends
 *  the clear spelling ("" clears the location with it); a create omits it. */
export function placementFields(p: Placement, clear: boolean): { site_id?: string; location_id?: string } {
  if (p.siteId) return { site_id: p.siteId, location_id: p.locationId || (clear ? '' : undefined) };
  return clear ? { site_id: '' } : {};
}

export function SiteLocationSelect({ value, onChange }: { value: Placement; onChange: (p: Placement) => void }) {
  const sites = useSites();
  const locations = useLocations(value.siteId || undefined, !!value.siteId);
  const rows = flattenNodes(locations.data ?? []);
  return (
    <>
      <ModalField label="Site">
        <ModalSelect aria-label="Site" value={value.siteId} disabled={sites.isLoading}
          onChange={(e) => onChange({ siteId: e.target.value, locationId: '' })}>
          <option value="">{sites.isLoading ? 'Loading…' : sites.isError ? 'Could not load sites' : 'None'}</option>
          {(sites.data ?? []).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
        </ModalSelect>
      </ModalField>
      <ModalField label="Location" hint={value.siteId ? 'Inside the site.' : 'Choose a site first.'}>
        <ModalSelect aria-label="Location" value={value.locationId} disabled={!value.siteId || locations.isLoading}
          onChange={(e) => onChange({ ...value, locationId: e.target.value })}>
          <option value="">{value.siteId && locations.isLoading ? 'Loading…' : 'None'}</option>
          {rows.map(({ node, depth }) => <option key={node.id} value={node.id}>{`${'  '.repeat(depth)}${node.name}`}</option>)}
        </ModalSelect>
      </ModalField>
    </>
  );
}
