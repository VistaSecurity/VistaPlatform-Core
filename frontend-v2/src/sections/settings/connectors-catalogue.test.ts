// Settings · Integrations — the connector catalogue.
//
// Two things are pinned here:
//
//  1. PARITY. The TypeScript connector registry (generated into
//     @vistasecurity/primitives/connectors) must agree with
//     standards/connectors.yaml, key for key and status for status. `make
//     audit` asserts the same thing from the generator's side; this asserts it
//     from the side that actually renders, because a UI reading a stale mirror
//     is how a connector comes to be offered that the platform cannot run.
//
//  2. SELECTABILITY. A `registered` connector — one the database accepts and
//     nothing implements — must be shown and must not be selectable. Both
//     polarities, because a rule that could only ever say "no" would pass the
//     negative half of this file while breaking the product.
//
// Reading the YAML rather than importing it is deliberate, and copies
// feature-registration.test.ts: there is no build step that would bring a YAML
// document into TypeScript, and a cheap regex over a flat list beats a
// dependency — provided the anchors are asserted non-empty, which they are.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { CONNECTORS, connectorsByKind, getConnector, isAddable, populatedKinds, unavailableReason } from '@vistasecurity/primitives/connectors';
import {
  ADDABLE_HERE,
  CONFIGURED_ELSEWHERE,
  connectorAction,
  connectorBadge,
  connectorCaption,
  isSelectable,
  type ConnectorEntry,
} from './connectors-queries';

const repoRoot = fileURLToPath(new URL('../../../../', import.meta.url));

/**
 * `key:` / `status:` / `configured_by:` from standards/connectors.yaml, in file
 * order. `configured_by` defaults to `tenant`, as the generator does.
 */
function registryFromYaml(): Array<{ key: string; status: string; configuredBy: string }> {
  const src = readFileSync(repoRoot + 'standards/connectors.yaml', 'utf8');
  const body = src.slice(src.indexOf('\nconnectors:'));
  expect(body.length, 'could not find the `connectors:` list in standards/connectors.yaml').toBeGreaterThan(100);
  const out: Array<{ key: string; status: string; configuredBy: string }> = [];
  let current: { key: string; status: string; configuredBy: string } | null = null;
  for (const line of body.split('\n')) {
    const key = /^\s*-\s+key:\s*([a-z0-9_]+)\s*$/.exec(line);
    if (key) {
      current = { key: key[1], status: '', configuredBy: 'tenant' };
      out.push(current);
      continue;
    }
    if (!current) continue;
    const status = /^\s*status:\s*([a-z]+)\s*$/.exec(line);
    if (status) current.status = status[1];
    const by = /^\s*configured_by:\s*([a-z_]+)\s*$/.exec(line);
    if (by) current.configuredBy = by[1];
  }
  return out;
}

/** A catalogue entry as the API would send it, for the pure-rule tests. */
function entry(over: Partial<ConnectorEntry> = {}): ConnectorEntry {
  return {
    key: 'netbox',
    label: 'NetBox',
    kind: 'network_source_of_truth',
    direction: 'pull',
    status: 'live',
    description: 'Pulls sites, prefixes, VLANs, device types and devices.',
    edition: 'enterprise',
    entitled: true,
    configured_by: 'tenant',
    addable: true,
    ...over,
  };
}

describe('connector registry parity', () => {
  const yaml = registryFromYaml();

  it('reads a non-empty registry from both sides (the anchors still match)', () => {
    expect(yaml.length).toBeGreaterThan(10);
    expect(CONNECTORS.length).toBeGreaterThan(10);
  });

  it('has exactly the same keys, in the same order', () => {
    expect(CONNECTORS.map((c) => c.key)).toEqual(yaml.map((c) => c.key));
  });

  it('agrees about every connector status', () => {
    const generated = Object.fromEntries(CONNECTORS.map((c) => [c.key, c.status]));
    const declared = Object.fromEntries(yaml.map((c) => [c.key, c.status]));
    expect(generated).toEqual(declared);
  });

  it('agrees about who configures every connector', () => {
    const generated = Object.fromEntries(CONNECTORS.map((c) => [c.key, c.configuredBy]));
    const declared = Object.fromEntries(yaml.map((c) => [c.key, c.configuredBy]));
    expect(generated).toEqual(declared);
    // SIEM export is the one platform-global, operator-configured family.
    const operator = CONNECTORS.filter((c) => c.configuredBy === 'platform_operator').map((c) => c.key).sort();
    expect(operator).toEqual(['datadog', 'elastic', 'generic_webhook', 'splunk']);
    for (const key of operator) {
      const c = getConnector(key)!;
      expect(c.kind).toBe('siem');
      expect(c.feature).toBe('siem_export');
    }
  });

  it('carries the `registered` status for the keys nothing implements', () => {
    for (const key of ['hashicorp_vault', 'github', 'gitlab', 'bitbucket', 'custom']) {
      const c = getConnector(key);
      expect(c, `${key} is missing from the registry`).toBeTruthy();
      expect(c!.status, `${key} must be registered, not live — nothing collects it`).toBe('registered');
    }
  });

  it('ships netbox as a live, pull-only network source of truth', () => {
    const nb = getConnector('netbox');
    expect(nb).toBeTruthy();
    expect(nb!.status).toBe('live');
    expect(nb!.kind).toBe('network_source_of_truth');
    // v1 writes NOTHING back to NetBox. Changing this to `both` must come with
    // an actual writer.
    expect(nb!.direction).toBe('pull');
    expect(nb!.feature).toBe('connector_netbox');
  });

  it('groups every connector under a populated kind', () => {
    const grouped = populatedKinds().flatMap((k) => connectorsByKind(k));
    expect(grouped.length).toBe(CONNECTORS.length);
  });
});

describe('registry-driven addability', () => {
  it('needs BOTH live status and the entitlement', () => {
    const nb = getConnector('netbox')!;
    expect(isAddable(nb, { connector_netbox: true })).toBe(true);
    expect(isAddable(nb, { connector_netbox: false })).toBe(false);
    expect(isAddable(nb, {})).toBe(false);
  });

  it('never makes a registered connector addable, however entitled the tenant is', () => {
    const gh = getConnector('github')!;
    expect(isAddable(gh, {})).toBe(false);
    // Entitle everything: status alone must still hold it back.
    expect(isAddable(gh, { everything: true })).toBe(false);
    expect(unavailableReason(gh, { everything: true })).toBe('unavailable');
  });

  it('distinguishes "you have not bought it" from "it does not exist yet"', () => {
    expect(unavailableReason(getConnector('netbox')!, {})).toBe('upgrade');
    expect(unavailableReason(getConnector('jira')!, {})).toBe('unavailable');
    expect(unavailableReason(getConnector('aws')!, {})).toBeNull();
  });
});

describe('catalogue card rules', () => {
  it('offers Add only for connectors this page can actually add', () => {
    expect(connectorAction(entry({ key: 'netbox' }))).toBe('add');
    expect(connectorAction(entry({ key: 'servicenow', kind: 'cmdb' }))).toBe('add');
    // Addable, but configured on another page. A button here would do nothing.
    expect(connectorAction(entry({ key: 'slack', kind: 'notification', edition: 'core' }))).toBe('elsewhere');
    expect(connectorAction(entry({ key: 'aws', kind: 'cloud', edition: 'core' }))).toBe('elsewhere');
  });

  it('is not selectable unless this page can add it', () => {
    expect(isSelectable(entry({ key: 'netbox' }))).toBe(true);
    expect(isSelectable(entry({ key: 'slack', kind: 'notification' }))).toBe(false);
  });

  it('renders a REGISTERED connector as not-yet-available and not selectable', () => {
    const gh = entry({
      key: 'github', label: 'GitHub', kind: 'sbom_source', status: 'registered',
      edition: 'core', entitled: true, addable: false, unavailable_reason: 'unavailable',
    });
    expect(connectorAction(gh)).toBe('soon');
    expect(isSelectable(gh)).toBe(false);
    expect(connectorCaption(gh)).toBe('Not yet available');
  });

  it('renders an unentitled Enterprise connector as an upgrade, not as "coming soon"', () => {
    const nb = entry({ entitled: false, addable: false, unavailable_reason: 'upgrade' });
    expect(connectorAction(nb)).toBe('upgrade');
    expect(isSelectable(nb)).toBe(false);
    expect(connectorCaption(nb)).toBe('Included in Enterprise');
  });

  // Both polarities on the same connector, which is the pair that matters: a
  // rule that always says "no" passes half of this file.
  it('flips with the entitlement and nothing else', () => {
    const entitled = entry({ entitled: true, addable: true });
    const not = entry({ entitled: false, addable: false, unavailable_reason: 'upgrade' });
    expect(isSelectable(entitled)).toBe(true);
    expect(isSelectable(not)).toBe(false);
  });

  it('falls back to status when an older server sends no reason', () => {
    expect(connectorAction(entry({ addable: false, unavailable_reason: undefined }))).toBe('upgrade');
    expect(connectorAction(entry({ status: 'planned', addable: false, unavailable_reason: undefined }))).toBe('soon');
  });

  it('every key it claims to add directly is a real, live registry key', () => {
    expect(ADDABLE_HERE.size).toBeGreaterThan(0);
    for (const key of ADDABLE_HERE) {
      const c = getConnector(key);
      expect(c, `${key} is not in the connector registry`).toBeTruthy();
      expect(c!.status, `${key} is offered as addable but is not live`).toBe('live');
    }
  });

  it('every "configured elsewhere" hint names a live, tenant-configured registry key', () => {
    expect(Object.keys(CONFIGURED_ELSEWHERE).length).toBeGreaterThan(0);
    for (const key of Object.keys(CONFIGURED_ELSEWHERE)) {
      const c = getConnector(key);
      expect(c, `${key} has a location hint but is not in the registry`).toBeTruthy();
      // A hint on a registered connector points at a place that cannot
      // configure it (the old `custom` hint sent people to the channel modal);
      // a hint on an operator-configured one points a tenant at a page they
      // cannot use.
      expect(c!.status, `${key} has a location hint but is not live`).toBe('live');
      expect(c!.configuredBy, `${key} has a location hint but a tenant cannot configure it`).toBe('tenant');
    }
  });

  // SIEM export: platform-global, so the operator configures it. A tenant sees
  // the card and never a button, entitled or not — both polarities.
  it('renders an operator-configured connector without a button, entitled or not', () => {
    const entitled = entry({
      key: 'splunk', label: 'Splunk', kind: 'siem', direction: 'push', edition: 'enterprise',
      entitled: true, configured_by: 'platform_operator', addable: false, unavailable_reason: 'operator',
    });
    const not = entry({ ...entitled, entitled: false });
    for (const e of [entitled, not]) {
      expect(connectorAction(e)).toBe('operator');
      expect(isSelectable(e)).toBe(false);
      expect(connectorCaption(e)).toBe('Configured by your platform operator');
      expect(connectorBadge(e)).toEqual({ label: 'Enterprise', tone: 'edition' });
    }
  });

  it('never lets a server flag make an operator-configured or unbuilt connector selectable', () => {
    // A server that wrongly says addable must not make a button appear.
    const wrongOperator = entry({ key: 'splunk', kind: 'siem', configured_by: 'platform_operator', addable: true });
    expect(connectorAction(wrongOperator)).toBe('operator');
    expect(isSelectable(wrongOperator)).toBe(false);
    const wrongRegistered = entry({ key: 'custom', kind: 'generic', status: 'registered', addable: true });
    expect(connectorAction(wrongRegistered)).toBe('soon');
    expect(isSelectable(wrongRegistered)).toBe(false);
  });

  // `custom` used to sit under CMDB / ITSM with a hint sending people to "Add
  // connection", which opens the notification-channel modal. Nothing reads a
  // custom row, so it is a registered, inert card.
  it('renders `custom` as an inert, not-yet-available card that points nowhere', () => {
    const custom = getConnector('custom')!;
    expect(custom.status).toBe('registered');
    expect(custom.kind).toBe('generic');
    expect(ADDABLE_HERE.has('custom')).toBe(false);
    expect('custom' in CONFIGURED_ELSEWHERE).toBe(false);
    const e = entry({
      key: 'custom', label: custom.label, kind: 'generic', direction: 'both', status: 'registered',
      edition: 'core', addable: false, unavailable_reason: 'unavailable',
    });
    expect(connectorAction(e)).toBe('soon');
    expect(isSelectable(e)).toBe(false);
    expect(connectorCaption(e)).toBe('Not yet available');
  });

  it('shows the Soon badge for registered and planned connectors and for nothing else', () => {
    expect(connectorBadge(entry({ status: 'registered', edition: 'core' }))).toEqual({ label: 'Soon', tone: 'soon' });
    expect(connectorBadge(entry({ status: 'planned', edition: 'enterprise' }))).toEqual({ label: 'Soon', tone: 'soon' });
    // Live Core: no badge. Live Enterprise: the edition badge, entitled or not.
    expect(connectorBadge(entry({ key: 'slack', kind: 'notification', edition: 'core' }))).toBeNull();
    expect(connectorBadge(entry({ entitled: true }))).toEqual({ label: 'Enterprise', tone: 'edition' });
    expect(connectorBadge(entry({ entitled: false, addable: false, unavailable_reason: 'upgrade' })))
      .toEqual({ label: 'Enterprise', tone: 'edition' });
    expect(connectorBadge(entry({ edition: 'msp' }))).toEqual({ label: 'MSP', tone: 'edition' });
  });

  it('gives every live tenant-configured non-page connector a location hint', () => {
    // Otherwise its card would show an empty caption. Cloud, notification
    // channels, in-app and the SBOM upload are all configured elsewhere.
    for (const c of CONNECTORS) {
      if (c.status !== 'live' || c.configuredBy !== 'tenant' || ADDABLE_HERE.has(c.key)) continue;
      expect(CONFIGURED_ELSEWHERE[c.key], `${c.key} is live but has no location hint`).toBeTruthy();
    }
  });
});
