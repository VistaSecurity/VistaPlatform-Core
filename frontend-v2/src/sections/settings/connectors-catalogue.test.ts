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
  connectorCaption,
  isSelectable,
  roleMappingRecord,
  roleMappingRows,
  runSummaryLine,
  runTone,
  type ConnectorEntry,
  type ConnectorRun,
} from './connectors-queries';

const repoRoot = fileURLToPath(new URL('../../../../', import.meta.url));

/** `key:` / `status:` pairs from standards/connectors.yaml, in file order. */
function registryFromYaml(): Array<{ key: string; status: string }> {
  const src = readFileSync(repoRoot + 'standards/connectors.yaml', 'utf8');
  const body = src.slice(src.indexOf('\nconnectors:'));
  expect(body.length, 'could not find the `connectors:` list in standards/connectors.yaml').toBeGreaterThan(100);
  const out: Array<{ key: string; status: string }> = [];
  let current: string | null = null;
  for (const line of body.split('\n')) {
    const key = /^\s*-\s+key:\s*([a-z0-9_]+)\s*$/.exec(line);
    if (key) {
      current = key[1];
      continue;
    }
    const status = /^\s*status:\s*([a-z]+)\s*$/.exec(line);
    if (status && current) {
      out.push({ key: current, status: status[1] });
      current = null;
    }
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

  it('carries the `registered` status for the four keys nothing implements', () => {
    for (const key of ['hashicorp_vault', 'github', 'gitlab', 'bitbucket']) {
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

  it('every "configured elsewhere" hint names a real registry key', () => {
    for (const key of Object.keys(CONFIGURED_ELSEWHERE)) {
      expect(getConnector(key), `${key} has a location hint but is not in the registry`).toBeTruthy();
    }
  });
});

describe('run summaries', () => {
  const run = (over: Partial<ConnectorRun['summary']> = {}): ConnectorRun => ({
    id: 'r1',
    connection_id: 'c1',
    status: 'success',
    trigger_type: 'manual',
    errors: [],
    summary: {
      sites: 0, prefixes: 0, vlans: 0, device_types: 0, devices: 0,
      segments_created: 0, segments_matched: 0, assets_created: 0, assets_matched: 0,
      assets_proposed: 0, assets_skipped: 0, unmapped_roles: 0, vlans_without_prefix: 0, errors: 0,
      ...over,
    },
  });

  // "0 devices" is an answer. A summary that hid it would make a run that
  // imported nothing look the same as one that was never asked to.
  it('reports zeros rather than hiding them', () => {
    expect(runSummaryLine(run())).toContain('0 devices');
    expect(runSummaryLine(run())).toContain('0 created');
  });

  it('mentions review, skips and unmapped roles only when there are any', () => {
    expect(runSummaryLine(run())).not.toContain('needing review');
    expect(runSummaryLine(run({ assets_proposed: 2 }))).toContain('2 needing review');
    expect(runSummaryLine(run({ assets_skipped: 1 }))).toContain('1 skipped');
    expect(runSummaryLine(run({ unmapped_roles: 1 }))).toContain('1 unmapped role');
    expect(runSummaryLine(run({ unmapped_roles: 3 }))).toContain('3 unmapped roles');
  });

  it('pluralises the device count', () => {
    expect(runSummaryLine(run({ devices: 1 }))).toContain('1 device ');
    expect(runSummaryLine(run({ devices: 2 }))).toContain('2 devices');
  });

  it('tones a run by its outcome', () => {
    expect(runTone('success')).toBe('ok');
    expect(runTone('partial')).toBe('warn');
    expect(runTone('failed')).toBe('danger');
    expect(runTone('in_progress')).toBe('muted');
    expect(runTone('')).toBe('muted');
  });
});

// The device-role mapping editor's conversion, both directions.
//
// The run summary reports how many roles it could not map, and this editor is
// where a tenant answers that. The rules worth pinning are the ones a UI gets
// wrong quietly: a stable order, and a half-filled row that is dropped rather
// than sent — the server refuses a mapping naming no class, so sending one
// would turn a row somebody was still typing into a failed save of everything
// else on the form.
describe('the device-role mapping editor', () => {
  it('is empty for a connection with no overrides', () => {
    expect(roleMappingRows(undefined)).toEqual([]);
    expect(roleMappingRows(null)).toEqual([]);
    expect(roleMappingRows({})).toEqual([]);
  });

  it('orders rows by role, so the list does not reshuffle between renders', () => {
    expect(roleMappingRows({ zebra: 'switch', alpha: 'firewall' })).toEqual([
      { role: 'alpha', classKey: 'firewall' },
      { role: 'zebra', classKey: 'switch' },
    ]);
  });

  it('round-trips a mapping', () => {
    const stored = { 'edge-guard': 'firewall', 'top-of-rack': 'switch' };
    expect(roleMappingRecord(roleMappingRows(stored))).toEqual(stored);
  });

  it('drops a half-filled row rather than sending it', () => {
    expect(roleMappingRecord([
      { role: 'edge-guard', classKey: 'firewall' },
      { role: '', classKey: 'switch' },
      { role: 'spare', classKey: '' },
    ])).toEqual({ 'edge-guard': 'firewall' });
  });

  it('trims — a trailing space is not part of a role name', () => {
    expect(roleMappingRecord([{ role: '  edge-guard ', classKey: ' firewall ' }]))
      .toEqual({ 'edge-guard': 'firewall' });
  });
});
