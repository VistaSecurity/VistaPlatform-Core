import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import {
  CABLE_COMPATIBLE_TERMINATIONS,
  CABLE_LENGTH_UNITS,
  CABLE_LENGTH_UNIT_LABELS,
  CABLE_STATUS_LABELS,
  CABLE_STATUSES,
  CONSOLE_PORT_TYPE_LABELS,
  INTERFACE_DUPLEX_LABELS,
  INTERFACE_MODE_LABELS,
  POE_MODE_LABELS,
  POE_TYPE_LABELS,
  PORT_TYPE_LABELS,
  POWER_OUTLET_TYPE_LABELS,
  POWER_PORT_TYPE_LABELS,
  CABLE_TYPE_GROUP,
  CABLE_TYPE_LABELS,
  CABLE_TYPES,
  cableCompatible,
  CONSOLE_PORT_TYPES,
  INTERFACE_DUPLEXES,
  INTERFACE_MODES,
  INTERFACE_TYPE_GROUP,
  INTERFACE_TYPE_LABELS,
  INTERFACE_TYPE_SPEED_KBPS,
  INTERFACE_TYPES,
  OBJECT_KINDS,
  POE_MODES,
  POE_TYPES,
  PORT_TYPES,
  POWER_OUTLET_TYPES,
  POWER_PORT_TYPES,
  WIRELESS_CHANNELS,
} from './index';

// Read the YAML (the source of truth), not the Go file, so this fails if either
// generated mirror drifts from the registry.
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../../..');
const load = (f: string) => parse(fs.readFileSync(path.join(root, 'standards', f), 'utf8'));
// The private working tree keeps the public attribution file under public/.
// The public-tree export installs that file at the repository root.
const noticePath = fs.existsSync(path.join(root, 'public', 'NOTICE'))
  ? path.join(root, 'public', 'NOTICE')
  : path.join(root, 'NOTICE');
type E = { key: string; label: string; group?: string; speed_kbps?: number; frequency_mhz?: number; width_mhz?: number };
const ifc = load('interface-types.yaml') as Record<string, unknown> & { interface_types: Record<string, E[]> };
const cab = load('cable-types.yaml') as {
  cable_types: E[]; length_units: E[]; cable_status: E[]; compatible_terminations: Record<string, string[]>;
};
const keys = (es: E[]) => es.map((e) => e.key);
const keyShape = /^[A-Za-z0-9][A-Za-z0-9.]*(-[A-Za-z0-9.]+)*$/;

describe('DCIM type registries', () => {
  const flat = Object.values(ifc.interface_types).flat();
  const cases: [string, readonly string[], string[]][] = [
    ['interface types', INTERFACE_TYPES, keys(flat)],
    ['console port types', CONSOLE_PORT_TYPES, keys(ifc.console_port_types as E[])],
    ['port types', PORT_TYPES, keys(ifc.port_types as E[])],
    ['power port types', POWER_PORT_TYPES, keys(ifc.power_port_types as E[])],
    ['power outlet types', POWER_OUTLET_TYPES, keys(ifc.power_outlet_types as E[])],
    ['duplex', INTERFACE_DUPLEXES, keys(ifc.duplex as E[])],
    ['interface modes', INTERFACE_MODES, keys(ifc.interface_modes as E[])],
    ['poe modes', POE_MODES, keys(ifc.poe_modes as E[])],
    ['poe types', POE_TYPES, keys(ifc.poe_types as E[])],
    ['cable types', CABLE_TYPES, keys(cab.cable_types)],
    ['length units', CABLE_LENGTH_UNITS, keys(cab.length_units)],
    ['cable status', CABLE_STATUSES, keys(cab.cable_status)],
    ['wireless channels', WIRELESS_CHANNELS.map((c) => c.key), keys(ifc.wireless_channels as E[])],
  ];

  it.each(cases)('%s equal the YAML in order, unique and well-formed', (_n, got, want) => {
    expect([...got]).toEqual(want);
    expect(new Set(got).size).toBe(got.length);
    for (const k of got) expect(k).toMatch(keyShape);
  });

  it('carries labels, groups and speeds from the YAML', () => {
    for (const [g, es] of Object.entries(ifc.interface_types)) {
      for (const e of es) {
        const k = e.key as (typeof INTERFACE_TYPES)[number];
        expect(INTERFACE_TYPE_LABELS[k]).toBe(e.label);
        expect(INTERFACE_TYPE_GROUP[k]).toBe(g);
        expect(INTERFACE_TYPE_SPEED_KBPS[k]).toBe(e.speed_kbps);
      }
    }
    for (const e of cab.cable_types) {
      const k = e.key as (typeof CABLE_TYPES)[number];
      expect(CABLE_TYPE_LABELS[k]).toBe(e.label);
      expect(CABLE_TYPE_GROUP[k]).toBe(e.group);
    }
    const ch = Object.fromEntries(WIRELESS_CHANNELS.map((c) => [c.key, c]));
    for (const e of ifc.wireless_channels as E[]) {
      expect(ch[e.key]).toMatchObject({ label: e.label, frequencyMHz: e.frequency_mhz, widthMHz: e.width_mhz });
    }
  });

  it('matches the Go constants', () => {
    const go = fs.readFileSync(path.join(root, 'shared', 'dcim', 'types_gen.go'), 'utf8');
    const goKeys = (type: string) =>
      [...go.matchAll(new RegExp(`^\\t${type}\\w+\\s+${type} = "([^"]+)"`, 'gm'))].map((m) => m[1]);
    expect(goKeys('InterfaceType')).toEqual([...INTERFACE_TYPES]);
    expect(goKeys('PortType')).toEqual([...PORT_TYPES]);
    expect(goKeys('ConsolePortType')).toEqual([...CONSOLE_PORT_TYPES]);
    expect(goKeys('CableType')).toEqual([...CABLE_TYPES]);
  });

  it('has the compatibility matrix, symmetric, over real object kinds', () => {
    expect(CABLE_COMPATIBLE_TERMINATIONS).toEqual(
      Object.fromEntries(
        Object.entries(cab.compatible_terminations)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([a, l]) => [a, [...l].sort()]),
      ),
    );
    for (const [a, list] of Object.entries(CABLE_COMPATIBLE_TERMINATIONS)) {
      expect(OBJECT_KINDS).toContain(a);
      for (const b of list) expect(cableCompatible(b, a)).toBe(true);
    }
    expect(cableCompatible('power_outlet', 'power_port')).toBe(true);
    expect(cableCompatible('power_port', 'power_port')).toBe(false);
    expect(OBJECT_KINDS).not.toContain('power_feed');
    expect(cableCompatible('interface', 'interface')).toBe(true);
    expect(cableCompatible('asset', 'interface')).toBe(false);
  });

  it('has a public/NOTICE line crediting NetBox for the choice lists', () => {
    const notice = fs.readFileSync(noticePath, 'utf8');
    const para = notice.split(/\n\s*\n/).find((p) => p.includes('standards/interface-types.yaml'));
    expect(para).toBeDefined();
    expect(para).toContain('NetBox');
    expect(para).toContain('Apache License 2.0');
  });

  it('has a public/NOTICE line crediting the device-type library at the vendored commit (row 2.2)', () => {
    const notice = fs.readFileSync(noticePath, 'utf8');
    const para = notice.split(/\n\s*\n|\n- /).find((p) => p.includes('devicetype-library'));
    expect(para).toBeDefined();
    expect(para).toContain('CC0-1.0');
    const source = fs.readFileSync(path.join(root, 'standards', 'devicetype-library', 'SOURCE.yaml'), 'utf8');
    const commit = /^commit: ([0-9a-f]{40})$/m.exec(source)?.[1];
    expect(commit).toBeDefined();
    expect(para).toContain(commit as string);
  });

  it('is exactly NetBox v4.3.5: every NetBox key present, no key NetBox lacks, same labels', () => {
    const snap = JSON.parse(
      fs.readFileSync(path.join(root, 'standards', 'netbox-choices.v4.3.5.json'), 'utf8'),
    ) as {
      netbox_version: string;
      choices: Record<string, { name: string | null; choices: [string, string][] }[]>;
      compatible_termination_types: Record<string, string[]>;
    };
    expect(snap.netbox_version).toBe('4.3.5');
    const nb = (c: string) =>
      Object.fromEntries(snap.choices[c].flatMap((g) => g.choices));
    const ours: [string, Record<string, string>][] = [
      ['InterfaceType', INTERFACE_TYPE_LABELS],
      ['ConsolePortType', CONSOLE_PORT_TYPE_LABELS],
      ['PortType', PORT_TYPE_LABELS],
      ['PowerPortType', POWER_PORT_TYPE_LABELS],
      ['PowerOutletType', POWER_OUTLET_TYPE_LABELS],
      ['InterfaceDuplex', INTERFACE_DUPLEX_LABELS],
      ['InterfaceMode', INTERFACE_MODE_LABELS],
      ['InterfacePoEMode', POE_MODE_LABELS],
      ['InterfacePoEType', POE_TYPE_LABELS],
      ['CableType', CABLE_TYPE_LABELS],
      ['CableLengthUnit', CABLE_LENGTH_UNIT_LABELS],
      ['LinkStatus', CABLE_STATUS_LABELS],
      ['WirelessChannel', Object.fromEntries(WIRELESS_CHANNELS.map((c) => [c.key, c.label]))],
    ];
    for (const [cls, mine] of ours) {
      expect(mine, cls).toEqual(nb(cls));
    }
    const squash = (k: string) => k.replace(/_/g, '');
    const mine = Object.fromEntries(
      Object.entries(CABLE_COMPATIBLE_TERMINATIONS).map(([a, l]) => [squash(a), l.map(squash).sort()]),
    );
    // NetBox kinds deferred until power ships (ADR-0010 D9) are not in our registry.
    const deferred = new Set(['powerfeed']);
    const theirs = Object.fromEntries(
      Object.entries(snap.compatible_termination_types)
        .filter(([a]) => !deferred.has(a))
        .map(([a, l]) => [a, l.filter((k) => !deferred.has(k)).sort()]),
    );
    expect(mine).toEqual(theirs);
  });
});
