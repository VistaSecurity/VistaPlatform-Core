// Regions, site groups, sites and locations (DCIM row 2.1): the list queries
// and the pure helpers around them. Settings → Sites, the Sites lens, the site
// page and the asset form's selects all read through here.
import { useQuery } from '@tanstack/react-query';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { clients } from '../../../lib/clients';

export type Region = inventoryComponents['schemas']['Region'];
export type SiteGroup = inventoryComponents['schemas']['SiteGroup'];
export type Site = inventoryComponents['schemas']['Site'];
export type Location = inventoryComponents['schemas']['Location'];
export type SiteStatus = Site['operational_status'];

export const SITES_KEY = ['dcim', 'sites'] as const;
export const REGIONS_KEY = ['dcim', 'regions'] as const;
export const SITE_GROUPS_KEY = ['dcim', 'site-groups'] as const;
export const LOCATIONS_KEY = ['dcim', 'locations'] as const;

/** Every query key this module owns, for invalidation after a write. */
export const ALL_SITE_KEYS = [SITES_KEY, REGIONS_KEY, SITE_GROUPS_KEY, LOCATIONS_KEY] as const;

export const SITE_STATUSES: { value: SiteStatus; label: string }[] = [
  { value: 'planned', label: 'Planned' }, { value: 'staged', label: 'Staged' }, { value: 'active', label: 'Active' },
  { value: 'decommissioning', label: 'Decommissioning' }, { value: 'retired', label: 'Retired' },
];

export function useRegions(enabled = true) {
  return useQuery({
    queryKey: REGIONS_KEY,
    enabled,
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/dcim/regions', {});
      if (error || !data) throw new Error('Failed to load regions');
      return data.regions ?? [];
    },
  });
}

export function useSiteGroups(enabled = true) {
  return useQuery({
    queryKey: SITE_GROUPS_KEY,
    enabled,
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/dcim/site-groups', {});
      if (error || !data) throw new Error('Failed to load site groups');
      return data.site_groups ?? [];
    },
  });
}

export function useSites(enabled = true) {
  return useQuery({
    queryKey: SITES_KEY,
    enabled,
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/dcim/sites', {});
      if (error || !data) throw new Error('Failed to load sites');
      return data.sites ?? [];
    },
  });
}

/** One site with its counts (the site page). */
export function useSite(id: string | undefined) {
  return useQuery({
    queryKey: [...SITES_KEY, id],
    enabled: !!id,
    queryFn: async () => {
      const { data, error, response } = await clients.inventory.GET('/dcim/sites/{id}', { params: { path: { id: id! } } });
      if (response.status === 404) throw new Error('not-found');
      if (error || !data) throw new Error('Failed to load the site');
      return data;
    },
  });
}

/** Locations, all of the tenant's or one site's (`siteId`). */
export function useLocations(siteId?: string, enabled = true) {
  return useQuery({
    queryKey: [...LOCATIONS_KEY, siteId ?? 'all'],
    enabled,
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/dcim/locations', { params: { query: siteId ? { site_id: siteId } : {} } });
      if (error || !data) throw new Error('Failed to load locations');
      return data.locations ?? [];
    },
  });
}

/** The site's findings by environment (the operational per-site summary). */
export function useSiteEnvironments(id: string | undefined) {
  return useQuery({
    queryKey: ['operational', 'sites', id, 'environments'],
    enabled: !!id,
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/operational/sites/{id}/environments', { params: { path: { id: id! } } });
      if (error || !data) throw new Error('Failed to load the site summary');
      return data.environments ?? [];
    },
  });
}

interface TreeNode { id: string; name: string; parent_id: string | null }

/**
 * Parents before children, siblings by name, with each row's depth. A node
 * whose parent is missing (or part of a cycle) is shown at the top level
 * rather than dropped: a hidden row is one nobody can fix.
 */
export function flattenNodes<T extends TreeNode>(nodes: readonly T[]): { node: T; depth: number }[] {
  const ids = new Set(nodes.map((n) => n.id));
  const kids = new Map<string | null, T[]>();
  for (const n of nodes) {
    const key = n.parent_id && ids.has(n.parent_id) ? n.parent_id : null;
    kids.set(key, [...(kids.get(key) ?? []), n]);
  }
  for (const list of kids.values()) list.sort((a, b) => a.name.localeCompare(b.name));
  const out: { node: T; depth: number }[] = [];
  const seen = new Set<string>();
  const walk = (parent: string | null, depth: number) => {
    for (const n of kids.get(parent) ?? []) {
      if (seen.has(n.id)) continue;
      seen.add(n.id);
      out.push({ node: n, depth });
      walk(n.id, depth + 1);
    }
  };
  walk(null, 0);
  for (const n of nodes) if (!seen.has(n.id)) out.push({ node: n, depth: 0 });
  return out;
}

/** Ids of a node and everything beneath it (it cannot be re-parented into these). */
export function subtreeIds<T extends TreeNode>(nodes: readonly T[], id: string): Set<string> {
  const out = new Set<string>([id]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const n of nodes) {
      if (n.parent_id && out.has(n.parent_id) && !out.has(n.id)) { out.add(n.id); grew = true; }
    }
  }
  return out;
}

/** One row of the Settings → Sites tree. */
export type SiteTreeRow =
  | { kind: 'region'; id: string; depth: number; region: Region }
  | { kind: 'site_group'; id: string; depth: number; group: SiteGroup }
  | { kind: 'site'; id: string; depth: number; site: Site }
  | { kind: 'location'; id: string; depth: number; location: Location };

/**
 * The Settings → Sites tree: Region › Site group › Site › Location. Each
 * region lists its child regions, then its sites grouped by site group, and
 * each site its location tree. Sites in no region come last under "No region";
 * NetBox lets a site sit in a region, a group, both or neither, and every case
 * has a row.
 */
export function buildSiteTree(regions: readonly Region[], groups: readonly SiteGroup[], sites: readonly Site[], locations: readonly Location[]): SiteTreeRow[] {
  const out: SiteTreeRow[] = [];
  const groupName = new Map(groups.map((g) => [g.id, g]));
  const regionIds = new Set(regions.map((r) => r.id));
  const sitesIn = (regionId: string | null) => sites
    .filter((s) => (regionId ? s.region_id === regionId : !s.region_id || !regionIds.has(s.region_id)))
    .sort((a, b) => a.name.localeCompare(b.name));
  const pushSites = (list: Site[], depth: number) => {
    // Grouped sites under their group (one header per group), then the rest.
    const byGroup = new Map<string, Site[]>();
    const loose: Site[] = [];
    for (const s of list) {
      if (s.group_id && groupName.has(s.group_id)) byGroup.set(s.group_id, [...(byGroup.get(s.group_id) ?? []), s]);
      else loose.push(s);
    }
    const ordered = [...byGroup.keys()].sort((a, b) => groupName.get(a)!.name.localeCompare(groupName.get(b)!.name));
    for (const gid of ordered) {
      out.push({ kind: 'site_group', id: `${gid}@${depth}:${list[0]?.region_id ?? 'none'}`, depth, group: groupName.get(gid)! });
      for (const s of byGroup.get(gid)!) pushSite(s, depth + 1);
    }
    for (const s of loose) pushSite(s, depth);
  };
  const pushSite = (s: Site, depth: number) => {
    out.push({ kind: 'site', id: s.id, depth, site: s });
    for (const { node, depth: d } of flattenNodes(locations.filter((l) => l.site_id === s.id))) {
      out.push({ kind: 'location', id: node.id, depth: depth + 1 + d, location: node });
    }
  };
  for (const { node, depth } of flattenNodes(regions)) {
    out.push({ kind: 'region', id: node.id, depth, region: node });
    pushSites(sitesIn(node.id), depth + 1);
  }
  pushSites(sitesIn(null), 0);
  return out;
}
