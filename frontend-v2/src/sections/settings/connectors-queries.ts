// Settings · Integrations — the connector catalogue and the NetBox connector.
//
// The catalogue is Core and registry-driven: `GET /connectors` answers from
// standards/connectors.yaml, so what this page offers and what the platform can
// actually do are the same list by construction. The list beside the page is
// what this replaces — the CMDB platform names used to live in a
// `PLATFORM_LABEL` object in a modal file, and nothing could see it drift.
//
// The NetBox queries are Enterprise-gated and edition-probed for the same two
// reasons the CMDB ones are (see integrations-queries.ts): the `connector_netbox`
// flag is the primary gate, and the response probe is the backstop for a Core
// build. A Core build answers 402 from a stub at the same path rather than 404 —
// see services/inventory-service/internal/handlers/connector_edition.go — and
// `assertEditionPresent` treats both as "not in this edition".
import { assertEditionPresent, editionAwareRetry } from '@vistasecurity/primitives/features';
import { clients } from '../../lib/clients';
import type { inventoryComponents } from '@vistasecurity/api-contract';

export type ConnectorEntry = inventoryComponents['schemas']['ConnectorCatalogueEntry'];
export type ConnectorGroup = inventoryComponents['schemas']['ConnectorCatalogueGroup'];
export type NetBoxConnection = inventoryComponents['schemas']['NetBoxConnection'];
export type ConnectorRun = inventoryComponents['schemas']['ConnectorRun'];
export type NetBoxDriftReport = inventoryComponents['schemas']['NetBoxDriftReport'];

export const CONNECTOR_CATALOGUE_KEY = ['settings', 'connector-catalogue'] as const;
export const NETBOX_CONNECTIONS_KEY = ['settings', 'netbox-connections'] as const;

/**
 * The connector catalogue, grouped by kind. Core — every edition serves it, so
 * it is NOT edition-probed.
 */
export function connectorCatalogueQuery() {
  return {
    queryKey: CONNECTOR_CATALOGUE_KEY,
    // The registry changes on deploy, not on the hour. Re-fetching it on every
    // mount of the Integrations page buys nothing.
    staleTime: 5 * 60 * 1000,
    queryFn: async (): Promise<ConnectorGroup[]> => {
      const { data, response } = await clients.inventory.GET('/connectors', {});
      if (!response.ok || !data) throw new Error('Failed to load the connector catalogue');
      return data.groups ?? [];
    },
  };
}

/** Configured NetBox connections. Enterprise-only; 402 on Core. */
export function netboxConnectionsQuery(enabled = true) {
  return {
    queryKey: NETBOX_CONNECTIONS_KEY,
    enabled,
    retry: editionAwareRetry(),
    queryFn: async (): Promise<NetBoxConnection[]> => {
      const { data, response } = await clients.inventory.GET('/connectors/netbox/connections', {});
      assertEditionPresent('The NetBox connector', response);
      if (!response.ok || !data) throw new Error('Failed to load NetBox connections');
      return data.connections ?? [];
    },
  };
}

/** Run history for one connection. */
export function netboxRunsQuery(connectionId: string) {
  return {
    queryKey: ['settings', 'netbox-runs', connectionId] as const,
    retry: editionAwareRetry(),
    queryFn: async (): Promise<ConnectorRun[]> => {
      const { data, response } = await clients.inventory.GET('/connectors/netbox/connections/{id}/runs', {
        params: { path: { id: connectionId } },
      });
      assertEditionPresent('The NetBox connector', response);
      if (!response.ok || !data) throw new Error('Failed to load the run history');
      return data.runs ?? [];
    },
  };
}

/**
 * Drift between NetBox and the inventory.
 *
 * Not cached: it reads a fresh NetBox snapshot server-side, and the question it
 * answers ("do these two agree RIGHT NOW") is worthless from a stale copy.
 */
export function netboxDriftQuery(connectionId: string) {
  return {
    queryKey: ['settings', 'netbox-drift', connectionId] as const,
    retry: editionAwareRetry(),
    staleTime: 0,
    gcTime: 0,
    queryFn: async (): Promise<NetBoxDriftReport> => {
      const { data, response } = await clients.inventory.GET('/connectors/netbox/connections/{id}/drift', {
        params: { path: { id: connectionId } },
      });
      assertEditionPresent('The NetBox connector', response);
      if (!response.ok || !data) throw new Error('Could not compare NetBox with the inventory');
      return data;
    },
  };
}

// ---------------------------------------------------------------------------
// Pure presentation rules
// ---------------------------------------------------------------------------
//
// These are here rather than inline in the component so the "what may a tenant
// click" rules are unit-testable without a DOM — connectors-catalogue.test.ts
// drives them in both polarities.

/**
 * What the catalogue card should do about a connector.
 *
 *  - `add`      — addable now, and this page has a flow for it.
 *  - `elsewhere`— addable, but it is configured on another page. Say where;
 *                 do NOT render a button that does nothing.
 *  - `upgrade`  — your plan or edition does not include it.
 *  - `soon`     — nobody can use it yet. NOT an upgrade prompt: offering to
 *                 sell something that does not exist is the worse mistake.
 */
export type ConnectorAction = 'add' | 'elsewhere' | 'upgrade' | 'soon';

/**
 * Where a connector that this page cannot add is configured instead.
 *
 * Deliberately sparse: a connector with no entry here simply shows no hint.
 * Inventing a location would send people somewhere that does not exist, which
 * is worse than saying nothing.
 */
export const CONFIGURED_ELSEWHERE: Record<string, string> = {
  slack: 'Add it as a notification channel above.',
  pagerduty: 'Add it as a notification channel above.',
  datadog: 'Configured in the audit pipeline (SIEM forwarders above).',
  splunk: 'Configured in the audit pipeline (SIEM forwarders above).',
  aws: 'Connected under Discovery → Cloud.',
  azure: 'Connected under Discovery → Cloud.',
  gcp: 'Connected under Discovery → Cloud.',
  custom: 'Use "Add connection" at the top of this page.',
};

/** Connector keys this page can add directly. */
export const ADDABLE_HERE = new Set(['netbox', 'servicenow', 'device42', 'solarwinds', 'oomnitza']);

export function connectorAction(entry: ConnectorEntry): ConnectorAction {
  if (entry.addable) return ADDABLE_HERE.has(entry.key) ? 'add' : 'elsewhere';
  // `unavailable_reason` is the server's answer and is authoritative; the
  // status fallback covers an older server that does not send it.
  if (entry.unavailable_reason === 'upgrade') return 'upgrade';
  if (entry.unavailable_reason === 'unavailable') return 'soon';
  return entry.status === 'live' ? 'upgrade' : 'soon';
}

/**
 * Whether a catalogue card is SELECTABLE — i.e. whether clicking it does
 * anything at all.
 *
 * A `registered` connector is one the database would accept and no code
 * implements. It must be shown (a tenant asking "can you read my Vault?"
 * deserves an answer) and must not be selectable, because selecting it would
 * configure something that never runs.
 */
export function isSelectable(entry: ConnectorEntry): boolean {
  return connectorAction(entry) === 'add';
}

/** The short line under a catalogue card. */
export function connectorCaption(entry: ConnectorEntry): string {
  switch (connectorAction(entry)) {
    case 'add':
      return entry.direction === 'pull' ? 'Pulls into your inventory' :
        entry.direction === 'push' ? 'Sends data out' : 'Two-way sync';
    case 'elsewhere':
      return CONFIGURED_ELSEWHERE[entry.key] ?? '';
    case 'upgrade':
      return `Included in ${entry.edition === 'msp' ? 'MSP' : 'Enterprise'}`;
    case 'soon':
      return 'Not yet available';
  }
}

// ---------------------------------------------------------------------------
// Device-role mapping
// ---------------------------------------------------------------------------
//
// A NetBox device role is the customer's own vocabulary, so the shipped table
// cannot know that a site calls its firewalls "edge-guard". The connection
// carries per-connection overrides for exactly that, and the run summary's
// `unmapped_roles` count is the thing that sends a tenant here — a count with
// no remedy on the page is a dead end.

/** One row of the role-mapping editor. Order is preserved so editing is stable. */
export interface RoleMappingRow {
  role: string;
  classKey: string;
}

/**
 * The stored `role_class_overrides` record as editable rows.
 *
 * Sorted by role so the list does not reshuffle between renders — a JS object's
 * key order is insertion order, and a round trip through the API does not
 * promise to preserve it.
 */
export function roleMappingRows(overrides?: Record<string, string> | null): RoleMappingRow[] {
  return Object.entries(overrides ?? {})
    .map(([role, classKey]) => ({ role, classKey }))
    .sort((a, b) => a.role.localeCompare(b.role));
}

/**
 * Rows back to the record the API takes.
 *
 * A row with either half blank is DROPPED rather than sent: a half-filled row
 * is someone mid-edit, and the server refuses a mapping naming no class (400),
 * which would turn an unfinished row into a failed save of everything else on
 * the form. The server still normalises the key — this does not try to
 * reimplement normalizeRole, because two implementations of one rule is how
 * they come to disagree.
 */
export function roleMappingRecord(rows: RoleMappingRow[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const r of rows) {
    const role = r.role.trim();
    const classKey = r.classKey.trim();
    if (role === '' || classKey === '') continue;
    out[role] = classKey;
  }
  return out;
}

/** Tone for a run's status chip. */
export function runTone(status: string): 'ok' | 'warn' | 'danger' | 'muted' {
  switch (status) {
    case 'success':
      return 'ok';
    case 'partial':
      return 'warn';
    case 'failed':
      return 'danger';
    default:
      return 'muted';
  }
}

/**
 * A one-line summary of what a run did, in the order a person reads it.
 *
 * Every number is shown, zeros included. "0 devices" is an answer, and a
 * summary that hid it would make a run that imported nothing look the same as
 * one that was never asked to.
 */
export function runSummaryLine(run: ConnectorRun): string {
  const s = run.summary;
  const parts = [
    `${s.devices} device${s.devices === 1 ? '' : 's'}`,
    `${s.assets_created} created`,
    `${s.assets_matched} matched`,
    `${s.segments_created} new segment${s.segments_created === 1 ? '' : 's'}`,
  ];
  if (s.assets_proposed > 0) parts.push(`${s.assets_proposed} needing review`);
  if (s.assets_skipped > 0) parts.push(`${s.assets_skipped} skipped`);
  if (s.unmapped_roles > 0) parts.push(`${s.unmapped_roles} unmapped role${s.unmapped_roles === 1 ? '' : 's'}`);
  if (s.errors > 0) parts.push(`${s.errors} error${s.errors === 1 ? '' : 's'}`);
  return parts.join(' · ');
}
