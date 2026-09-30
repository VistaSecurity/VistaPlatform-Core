// Settings · Integrations — the connector catalogue.
//
// The catalogue is Core and registry-driven: `GET /connectors` answers from
// standards/connectors.yaml, so what this page offers and what the platform can
// actually do are the same list by construction. The list beside the page is
// what this replaces — the CMDB platform names used to live in a
// `PLATFORM_LABEL` object in a modal file, and nothing could see it drift.
//
// The NetBox connector's own queries live in netbox-queries.ts: the connector
// runs in an Enterprise-only service (platform ADR-0002 M2), and
// that file ships only where the service does.
import { clients } from '../../lib/clients';
import type { inventoryComponents } from '@vistasecurity/api-contract';

export type ConnectorEntry = inventoryComponents['schemas']['ConnectorCatalogueEntry'];
export type ConnectorGroup = inventoryComponents['schemas']['ConnectorCatalogueGroup'];

export const CONNECTOR_CATALOGUE_KEY = ['settings', 'connector-catalogue'] as const;

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
 *  - `operator` — it works, but only the platform operator configures it (SIEM
 *                 export forwards the whole deployment's audit stream). No
 *                 button, whatever the tenant's plan: there is nothing for a
 *                 tenant to click.
 *  - `upgrade`  — your plan or edition does not include it.
 *  - `soon`     — nobody can use it yet (registered or planned). NOT an
 *                 upgrade prompt: offering to sell something that does not
 *                 exist is the worse mistake.
 */
export type ConnectorAction = 'add' | 'elsewhere' | 'operator' | 'upgrade' | 'soon';

/**
 * Where a connector that this page cannot add is configured instead.
 *
 * Deliberately sparse: a connector with no entry here simply shows no hint.
 * Inventing a location would send people somewhere that does not exist, which
 * is worse than saying nothing. Every key here must be live and configured by
 * the tenant — a registered connector is configured nowhere, and an
 * operator-configured one is not this tenant's to locate.
 */
export const CONFIGURED_ELSEWHERE: Record<string, string> = {
  email: 'Add it with “Add connection” at the top of this page.',
  slack: 'Add it with “Add connection” at the top of this page.',
  pagerduty: 'Add it with “Add connection” at the top of this page.',
  webhook: 'Add it with “Add connection” at the top of this page.',
  in_app: 'Created for every tenant; delivers to the notification bell.',
  aws: 'Connected under Discovery → Cloud.',
  azure: 'Connected under Discovery → Cloud.',
  gcp: 'Connected under Discovery → Cloud.',
  sbom_upload: 'Upload a document under Discovery → Sources → SBOM Upload.',
};

/** Connector keys this page can add directly. */
export const ADDABLE_HERE = new Set(['netbox', 'servicenow', 'device42', 'solarwinds', 'oomnitza']);

export function connectorAction(entry: ConnectorEntry): ConnectorAction {
  // Status first, and not overridable: nothing that is not live is ever
  // addable, offered as an upgrade, or dressed as configured elsewhere — the
  // server's flags are believed only for a connector that works.
  if (entry.status !== 'live') return 'soon';
  // Live, but the platform operator configures it. Checked before `addable`
  // so a server that got this wrong still cannot make a button appear.
  if (entry.configured_by === 'platform_operator') return 'operator';
  if (entry.addable) return ADDABLE_HERE.has(entry.key) ? 'add' : 'elsewhere';
  // `unavailable_reason` is the server's answer and is authoritative; the
  // fallback covers an older server that does not send it.
  if (entry.unavailable_reason === 'operator') return 'operator';
  return 'upgrade';
}

/**
 * The badge on a catalogue card, or null.
 *
 * `Soon` is for a connector that is registered or planned and for nothing
 * else. The edition badge (Enterprise / MSP) is shown for any LIVE connector
 * the registry says is not Core, entitled or not, so the card says what the
 * capability is rather than only what this tenant happens to hold.
 */
export function connectorBadge(entry: ConnectorEntry): { label: string; tone: 'edition' | 'soon' } | null {
  if (entry.status !== 'live') return { label: 'Soon', tone: 'soon' };
  if (entry.edition === 'enterprise') return { label: 'Enterprise', tone: 'edition' };
  if (entry.edition === 'msp') return { label: 'MSP', tone: 'edition' };
  return null;
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
    case 'operator':
      return 'Configured by your platform operator';
    case 'upgrade':
      return `Included in ${entry.edition === 'msp' ? 'MSP' : 'Enterprise'}`;
    case 'soon':
      return 'Not yet available';
  }
}
