#!/usr/bin/env node
// Generates the DCIM type registries from standards/interface-types.yaml and
// standards/cable-types.yaml (asset-inventory ADR-0010; DCIM BUILD_PLAN row 0.4).
//
// Outputs:
//   shared/dcim/types_gen.go                          (whole file)
//   packages/primitives/src/dcim/types.gen.ts         (whole file)
//   api/openapi/inventory-service.openapi.yaml        (1 generated region: InterfaceType,
//                                                      CableType, PortType, ConsolePortType)
//
// Nothing is emitted into SQL: DATA_MODEL keeps these columns CHECK-free text,
// validated in Go and TypeScript. The parity tests pin the two mirrors to the YAML.
//
// Run via `make generate`; `make audit` runs `--check` and fails on drift.
// `--root <dir>` points the generator at another tree (the tests use it).
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';
import { loadVocabulary, pascal } from './generate-vocabulary.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Kebab-case with the dots NetBox keys carry ("ieee802.11ac", "2.5gbase-t"). NetBox's
// keys are case-sensitive and a few outlet keys are upper-case ("CS6360C").
export const TYPE_KEY = /^[A-Za-z0-9][A-Za-z0-9.]*(-[A-Za-z0-9.]+)*$/;
export const CABLE_GROUPS = ['copper', 'fibre', 'power', 'other'];

export const INTERFACE_GROUP_LABELS = {
  virtual: 'Virtual',
  ethernet_fixed: 'Ethernet (fixed)', ethernet_modular: 'Ethernet (modular)',
  ethernet_backplane: 'Ethernet (backplane)', wireless: 'Wireless', cellular: 'Cellular',
  sonet: 'SONET', fibre_channel: 'Fibre Channel', infiniband: 'InfiniBand', serial: 'Serial', atm: 'ATM',
  coaxial: 'Coaxial', pon: 'PON', stacking: 'Stacking', other: 'Other',
};

// Simple key/label registries: [yaml file, yaml path, Go prefix, TS const, TS type].
const SIMPLE = [
  ['interface', 'console_port_types', 'ConsolePortType', 'CONSOLE_PORT_TYPE', 'ConsolePortType'],
  ['interface', 'port_types', 'PortType', 'PORT_TYPE', 'PortType'],
  ['interface', 'power_port_types', 'PowerPortType', 'POWER_PORT_TYPE', 'PowerPortType'],
  ['interface', 'power_outlet_types', 'PowerOutletType', 'POWER_OUTLET_TYPE', 'PowerOutletType'],
  ['interface', 'duplex', 'InterfaceDuplex', 'INTERFACE_DUPLEX', 'InterfaceDuplex'],
  ['interface', 'interface_modes', 'InterfaceMode', 'INTERFACE_MODE', 'InterfaceMode'],
  ['interface', 'poe_modes', 'PoEMode', 'POE_MODE', 'PoEMode'],
  ['interface', 'poe_types', 'PoEType', 'POE_TYPE', 'PoEType'],
  ['cable', 'length_units', 'CableLengthUnit', 'CABLE_LENGTH_UNIT', 'CableLengthUnit'],
  ['cable', 'cable_status', 'CableStatus', 'CABLE_STATUS', 'CableStatus'],
];

export function keyPascal(key) {
  return key.split(/[-._]/).filter(Boolean).map((p) => p.charAt(0).toUpperCase() + p.slice(1)).join('');
}

function readYaml(root, name) {
  return yaml.parse(fs.readFileSync(path.join(root, 'standards', name), 'utf8')) || {};
}

function checkList(what, list, errors, extra) {
  if (!Array.isArray(list) || list.length === 0) { errors.push(`${what}: must be a non-empty list`); return []; }
  const seen = new Set();
  const names = new Set();
  for (const e of list) {
    if (!TYPE_KEY.test(e?.key ?? '')) { errors.push(`${what}: bad key ${JSON.stringify(e?.key)} (lower-kebab)`); continue; }
    if (seen.has(e.key)) errors.push(`${what}: duplicate key ${e.key}`);
    seen.add(e.key);
    const n = keyPascal(e.key);
    if (names.has(n)) errors.push(`${what}: keys collide on the Go name ${n} (${e.key})`);
    names.add(n);
    if (typeof e.label !== 'string' || !e.label.trim()) errors.push(`${what}: ${e.key} has no label`);
    if (extra) extra(e);
  }
  return list;
}

export function loadTypes(root) {
  const errors = [];
  const itypes = readYaml(root, 'interface-types.yaml');
  const ctypes = readYaml(root, 'cable-types.yaml');

  // Interface types, flattened in registry order, remembering their group.
  const groups = itypes.interface_types || {};
  const interfaceTypes = [];
  const seen = new Set();
  for (const [g, list] of Object.entries(groups)) {
    if (!INTERFACE_GROUP_LABELS[g]) errors.push(`interface_types: unknown group "${g}" (add its label to the generator)`);
    checkList(`interface_types.${g}`, list, errors, (e) => {
      if (e.speed_kbps !== undefined && !(Number.isInteger(e.speed_kbps) && e.speed_kbps > 0)) {
        errors.push(`interface_types.${g}.${e.key}: speed_kbps must be a positive integer`);
      }
      if (seen.has(e.key)) errors.push(`interface type ${e.key} appears in two groups`);
      seen.add(e.key);
      interfaceTypes.push({ key: e.key, label: e.label, group: g, speed: e.speed_kbps });
    });
  }
  if (interfaceTypes.length === 0) errors.push('interface_types: empty');
  const names = new Map();
  for (const t of interfaceTypes) {
    const n = keyPascal(t.key);
    if (names.has(n)) errors.push(`interface_types: ${t.key} and ${names.get(n)} collide on the Go name ${n}`);
    names.set(n, t.key);
  }

  const simple = SIMPLE.map(([file, name, goPrefix, tsConst, tsType]) => {
    const src = file === 'interface' ? itypes : ctypes;
    const list = checkList(name, src[name], errors).map((e) => ({ key: e.key, label: e.label }));
    return { name, goPrefix, tsConst, tsType, list };
  });

  const cableTypes = checkList('cable_types', ctypes.cable_types, errors, (e) => {
    if (!CABLE_GROUPS.includes(e.group)) errors.push(`cable_types.${e.key}: group "${e.group}" must be one of ${CABLE_GROUPS.join(', ')}`);
  }).map((e) => ({ key: e.key, label: e.label, group: e.group }));

  const channels = checkList('wireless_channels', itypes.wireless_channels, errors, (e) => {
    for (const f of ['frequency_mhz', 'width_mhz']) {
      if (!(Number.isInteger(e[f]) && e[f] > 0)) errors.push(`wireless_channels.${e.key}: ${f} must be a positive integer`);
    }
  }).map((e) => ({ key: e.key, label: e.label, frequency: e.frequency_mhz, width: e.width_mhz }));

  // Termination compatibility: kinds must be real ObjectKinds and the matrix symmetric.
  const vocab = loadVocabulary(root);
  if (vocab.errors.length) errors.push(`vocabulary.yaml invalid: ${vocab.errors.join('; ')}`);
  const kindKeys = new Set(vocab.kinds.map((k) => k.key));
  const matrix = ctypes.compatible_terminations || {};
  const kindsInMatrix = Object.keys(matrix);
  if (kindsInMatrix.length === 0) errors.push('compatible_terminations: empty');
  for (const [a, list] of Object.entries(matrix)) {
    if (!kindKeys.has(a)) errors.push(`compatible_terminations: "${a}" is not an ObjectKind`);
    if (!Array.isArray(list) || list.length === 0) { errors.push(`compatible_terminations.${a}: must be a non-empty list`); continue; }
    if (new Set(list).size !== list.length) errors.push(`compatible_terminations.${a}: duplicate entries`);
    for (const b of list) {
      if (!kindKeys.has(b)) errors.push(`compatible_terminations.${a}: "${b}" is not an ObjectKind`);
      else if (!(matrix[b] || []).includes(a)) errors.push(`compatible_terminations: ${a} lists ${b} but ${b} does not list ${a} (the matrix must be symmetric)`);
    }
  }
  // Sorted so the generated output does not depend on the YAML's line order.
  const compat = kindsInMatrix.sort().map((a) => [a, [...(matrix[a] || [])].sort()]);

  return { errors, interfaceTypes, simple, cableTypes, channels, compat };
}

const HEADER = 'Code generated by scripts/generate-dcim-types.mjs from standards/interface-types.yaml and standards/cable-types.yaml. DO NOT EDIT — edit the YAML and run `make generate`.';
const q = (s) => JSON.stringify(s);

function goEnum(goType, prefix, items, doc) {
  const names = items.map((i) => `${prefix}${keyPascal(i.key)}`);
  const w = Math.max(...names.map((n) => n.length));
  const consts = items.map((i, n) => `\t${names[n].padEnd(w)} ${goType} = ${q(i.key)}`).join('\n');
  const list = names.map((n) => `\t${n},`).join('\n');
  const lw = Math.max(...names.map((n) => n.length)) + 1;
  const labels = items.map((i, n) => `\t${`${names[n]}:`.padEnd(lw)} ${q(i.label)},`).join('\n');
  const lower = goType.charAt(0).toLowerCase() + goType.slice(1);
  const plural = /(x|s)$/.test(goType) ? `${goType}es` : `${goType}s`;
  return `// ${goType} is ${doc}
type ${goType} string

const (
${consts}
)

var ${lower}Values = []${goType}{
${list}
}

var ${lower}Labels = map[${goType}]string{
${labels}
}

// All${plural} lists every ${goType} in registry order.
func All${plural}() []${goType} {
	return append([]${goType}(nil), ${lower}Values...)
}

// ${goType}Label is the UI label ("" for an unknown value).
func ${goType}Label(t ${goType}) string { return ${lower}Labels[t] }

// Parse${goType} returns the value for a registry key.
func Parse${goType}(s string) (${goType}, bool) {
	t := ${goType}(s)
	_, ok := ${lower}Labels[t]
	return t, ok
}
`;
}

function emitGo(d) {
  const parts = [`// ${HEADER}\n\npackage dcim\n`];
  parts.push(goEnum('InterfaceType', 'InterfaceType', d.interfaceTypes, 'the type of an interface (NetBox InterfaceTypeChoices).'));
  // group + speed lookups
  const gw = Math.max(...d.interfaceTypes.map((t) => `InterfaceType${keyPascal(t.key)}`.length)) + 1;
  const sw = Math.max(...d.interfaceTypes.filter((t) => t.speed).map((t) => `InterfaceType${keyPascal(t.key)}`.length)) + 1;
  parts.push(`var interfaceTypeGroups = map[InterfaceType]string{
${d.interfaceTypes.map((t) => `\t${`InterfaceType${keyPascal(t.key)}:`.padEnd(gw)} ${q(t.group)},`).join('\n')}
}

var interfaceTypeSpeedsKbps = map[InterfaceType]int64{
${d.interfaceTypes.filter((t) => t.speed).map((t) => `\t${`InterfaceType${keyPascal(t.key)}:`.padEnd(sw)} ${t.speed},`).join('\n')}
}

// InterfaceTypeGroup is the registry group of a type ("ethernet_modular", "virtual", ...), or "" if unknown.
func InterfaceTypeGroup(t InterfaceType) string { return interfaceTypeGroups[t] }

// InterfaceTypeSpeedKbps is the nominal line rate the type names, in kbit/s; false when it names none.
func InterfaceTypeSpeedKbps(t InterfaceType) (int64, bool) {
	s, ok := interfaceTypeSpeedsKbps[t]
	return s, ok
}
`);
  const docs = {
    ConsolePortType: 'the connector of a console port or console server port (NetBox ConsolePortTypeChoices).',
    PortType: 'the connector of a front or rear port (NetBox PortTypeChoices).',
    PowerPortType: 'the plug of a power port (NetBox PowerPortTypeChoices).',
    PowerOutletType: 'the receptacle of a power outlet (NetBox PowerOutletTypeChoices).',
    InterfaceDuplex: 'the duplex setting of an interface.',
    InterfaceMode: 'the 802.1Q mode of an interface.',
    PoEMode: 'the power-over-Ethernet role of an interface.',
    PoEType: 'the power-over-Ethernet standard of an interface.',
    CableLengthUnit: 'the unit of a cable length.',
    CableStatus: 'the status of a cable.',
  };
  for (const s of d.simple) parts.push(goEnum(s.goPrefix, s.goPrefix, s.list, docs[s.goPrefix]));
  parts.push(goEnum('CableType', 'CableType', d.cableTypes, 'the medium of a cable (NetBox CableTypeChoices).'));
  const cw = Math.max(...d.cableTypes.map((t) => `CableType${keyPascal(t.key)}`.length)) + 1;
  parts.push(`var cableTypeGroups = map[CableType]string{
${d.cableTypes.map((t) => `\t${`CableType${keyPascal(t.key)}:`.padEnd(cw)} ${q(t.group)},`).join('\n')}
}

// CableTypeGroup is "copper", "fibre", "power", "coaxial" or "other" ("" if unknown).
func CableTypeGroup(t CableType) string { return cableTypeGroups[t] }
`);
  parts.push(`// WirelessChannel is one entry of the wireless channel registry.
type WirelessChannel struct {
	Key          string
	Label        string
	FrequencyMHz int
	WidthMHz     int
}

var wirelessChannels = []WirelessChannel{
${d.channels.map((c) => `\t{Key: ${q(c.key)}, Label: ${q(c.label)}, FrequencyMHz: ${c.frequency}, WidthMHz: ${c.width}},`).join('\n')}
}

// AllWirelessChannels lists every wireless channel in registry order.
func AllWirelessChannels() []WirelessChannel {
	return append([]WirelessChannel(nil), wirelessChannels...)
}

// ParseWirelessChannel returns the channel for a registry key.
func ParseWirelessChannel(key string) (WirelessChannel, bool) {
	for _, c := range wirelessChannels {
		if c.Key == key {
			return c, true
		}
	}
	return WirelessChannel{}, false
}
`);
  const kw = Math.max(...d.compat.map(([a]) => `ObjectKind${pascal(a)}`.length)) + 1;
  parts.push(`// compatibleTerminations is the termination compatibility matrix (NetBox
// COMPATIBLE_TERMINATION_TYPES), written out in both directions.
var compatibleTerminations = map[ObjectKind][]ObjectKind{
${d.compat.map(([a, list]) => `\t${`ObjectKind${pascal(a)}:`.padEnd(kw)} {${list.map((b) => `ObjectKind${pascal(b)}`).join(', ')}},`).join('\n')}
}

// CableCompatible reports whether a cable may join a termination of kind a to one of kind b.
func CableCompatible(a, b ObjectKind) bool {
	for _, k := range compatibleTerminations[a] {
		if k == b {
			return true
		}
	}
	return false
}

// CableCompatibleKinds lists the termination kinds a may be cabled to, sorted by key.
func CableCompatibleKinds(a ObjectKind) []ObjectKind {
	return append([]ObjectKind(nil), compatibleTerminations[a]...)
}
`);
  return parts.join('\n');
}

function tsEnum(constName, typeName, items, labelsName) {
  return `export const ${constName}${/(X|S)$/.test(constName) ? "ES" : "S"} = [
${items.map((i) => `  ${q(i.key)},`).join('\n')}
] as const;

export type ${typeName} = (typeof ${constName}${/(X|S)$/.test(constName) ? "ES" : "S"})[number];

export const ${labelsName}: Record<${typeName}, string> = {
${items.map((i) => `  ${q(i.key)}: ${q(i.label)},`).join('\n')}
};
`;
}

function emitTS(d) {
  const parts = [`// ${HEADER}\n`];
  parts.push(tsEnum('INTERFACE_TYPE', 'InterfaceType', d.interfaceTypes, 'INTERFACE_TYPE_LABELS'));
  const groupKeys = [...new Set(d.interfaceTypes.map((t) => t.group))];
  parts.push(`export const INTERFACE_TYPE_GROUPS = [
${groupKeys.map((g) => `  ${q(g)},`).join('\n')}
] as const;

export type InterfaceTypeGroup = (typeof INTERFACE_TYPE_GROUPS)[number];

export const INTERFACE_TYPE_GROUP_LABELS: Record<InterfaceTypeGroup, string> = {
${groupKeys.map((g) => `  ${q(g)}: ${q(INTERFACE_GROUP_LABELS[g])},`).join('\n')}
};

export const INTERFACE_TYPE_GROUP: Record<InterfaceType, InterfaceTypeGroup> = {
${d.interfaceTypes.map((t) => `  ${q(t.key)}: ${q(t.group)},`).join('\n')}
};

/** Nominal line rate in kbit/s, for the types that name one. */
export const INTERFACE_TYPE_SPEED_KBPS: Partial<Record<InterfaceType, number>> = {
${d.interfaceTypes.filter((t) => t.speed).map((t) => `  ${q(t.key)}: ${t.speed},`).join('\n')}
};
`);
  for (const s of d.simple) parts.push(tsEnum(s.tsConst, s.tsType, s.list, `${s.tsConst}_LABELS`));
  parts.push(tsEnum('CABLE_TYPE', 'CableType', d.cableTypes, 'CABLE_TYPE_LABELS'));
  parts.push(`export type CableTypeGroup = ${CABLE_GROUPS.map(q).join(' | ')};

export const CABLE_TYPE_GROUP: Record<CableType, CableTypeGroup> = {
${d.cableTypes.map((t) => `  ${q(t.key)}: ${q(t.group)},`).join('\n')}
};
`);
  parts.push(`export interface WirelessChannel {
  key: string;
  label: string;
  frequencyMHz: number;
  widthMHz: number;
}

export const WIRELESS_CHANNELS: readonly WirelessChannel[] = [
${d.channels.map((c) => `  { key: ${q(c.key)}, label: ${q(c.label)}, frequencyMHz: ${c.frequency}, widthMHz: ${c.width} },`).join('\n')}
];
`);
  parts.push(`/** Termination kinds (ObjectKind keys) a cable end of the given kind may be cabled to. */
export const CABLE_COMPATIBLE_TERMINATIONS: Readonly<Record<string, readonly string[]>> = {
${d.compat.map(([a, list]) => `  ${a}: [${list.map(q).join(', ')}],`).join('\n')}
};

export function cableCompatible(a: string, b: string): boolean {
  return (CABLE_COMPATIBLE_TERMINATIONS[a] ?? []).includes(b);
}
`);
  return parts.join('\n');
}

function emitSpecRegion(d) {
  const en = (name, desc, items) => `    ${name}:
      type: string
      description: '${desc}'
      enum:
${items.map((i) => `      - ${i.key}`).join('\n')}`;
  const simple = (n) => d.simple.find((s) => s.name === n).list;
  return [
    en('InterfaceType', 'Interface type (standards/interface-types.yaml; NetBox InterfaceTypeChoices).', d.interfaceTypes),
    en('ConsolePortType', 'Console or console server port connector (standards/interface-types.yaml).', simple('console_port_types')),
    en('PortType', 'Front or rear port connector (standards/interface-types.yaml).', simple('port_types')),
    en('CableType', 'Cable medium (standards/cable-types.yaml; NetBox CableTypeChoices).', d.cableTypes),
  ].join('\n');
}

function spliceRegion(src, begin, end, body, what) {
  const bi = src.indexOf(begin);
  const ei = src.indexOf(end);
  if (bi === -1 || ei === -1 || ei < bi) {
    throw new Error(`region markers for "${what}" not found (or out of order) — expected:\n  ${begin}\n  ${end}`);
  }
  return `${src.slice(0, bi + begin.length)}\n${body}\n${src.slice(ei)}`;
}

export function buildOutputs(root) {
  const d = loadTypes(root);
  if (d.errors.length) throw new Error(`type registries invalid:\n  ${d.errors.join('\n  ')}`);
  const specPath = path.join(root, 'api', 'openapi', 'inventory-service.openapi.yaml');
  const spec = spliceRegion(
    fs.readFileSync(specPath, 'utf8'),
    '    # BEGIN GENERATED: dcim types — from standards/interface-types.yaml and standards/cable-types.yaml (make generate)',
    '    # END GENERATED: dcim types',
    emitSpecRegion(d), 'dcim types',
  );
  return [
    [path.join(root, 'shared', 'dcim', 'types_gen.go'), emitGo(d)],
    [path.join(root, 'packages', 'primitives', 'src', 'dcim', 'types.gen.ts'), emitTS(d)],
    [specPath, spec],
  ];
}

function main() {
  const argv = process.argv.slice(2);
  const checkOnly = argv.includes('--check');
  const ri = argv.indexOf('--root');
  const root = ri >= 0 ? path.resolve(argv[ri + 1]) : path.resolve(__dirname, '..');
  let outputs;
  try {
    outputs = buildOutputs(root);
  } catch (e) {
    console.error(`dcim-types: ${e.message}`);
    process.exit(1);
  }
  if (checkOnly) {
    const stale = outputs
      .filter(([p, c]) => (fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '') !== c)
      .map(([p]) => path.relative(root, p));
    if (stale.length) {
      console.error(`dcim-types: out of date — run \`make generate\`:\n  ${stale.join('\n  ')}`);
      process.exit(1);
    }
    console.log(`dcim-types check OK (${outputs.length} artefacts)`);
    return;
  }
  for (const [p, c] of outputs) {
    fs.ensureDirSync(path.dirname(p));
    fs.writeFileSync(p, c);
    console.log(`Generated: ${path.relative(root, p)}`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
