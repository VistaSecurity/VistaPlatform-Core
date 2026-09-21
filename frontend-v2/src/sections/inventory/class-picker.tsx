// The class picker and the class-driven attribute form (ADR-0006 D8).
//
// "The asset form and the import wizard's column mapper are driven by the
// class's attribute registry, so adding a class adds its fields to both without
// page edits."
//
// That is the whole design: nothing below enumerates a class or an attribute.
// The class list is `ASSET_CLASS_KEYS`, the fields are `ATTRIBUTE_SCHEMAS`, and
// both are generated from `standards/asset-classes.yaml`. The form the user
// sees for a server and the form they see for an S3 bucket differ because the
// YAML says they differ, not because two branches were written.
import {
  ASSET_CLASSES, ATTRIBUTE_SCHEMAS, CLASS_TREE,
  type AssetAttributeProperty, type AssetClassKey, type AssetClassNode,
} from '@vistasecurity/primitives/assets';
import { COLLECTOR_MINTED_KINDS, USER_ENTERABLE_IDENTIFIER_KINDS } from '@vistasecurity/primitives/query';
import { Icon, ModalField, ModalInput, ModalSelect } from '../../components/ui';

/** Flattens the tree into `[{ key, depth }]` for an indented `<select>`. A
 *  native select is the right control here: the picker is one field of a form,
 *  not the facet rail, and 50 options with indentation is a list a user can
 *  scan and type-ahead through. */
export function flattenClassTree(nodes: readonly AssetClassNode[] = CLASS_TREE, depth = 0): { key: AssetClassKey; depth: number }[] {
  const out: { key: AssetClassKey; depth: number }[] = [];
  for (const n of nodes) {
    out.push({ key: n.key, depth });
    out.push(...flattenClassTree(n.children, depth + 1));
  }
  return out;
}

/** Class keys under the `service` branch. A service identifies by
 *  (tenant, class, name) and has no address or serial to be known by
 *  (ADR-0002 D3), which is why `display_name` is REQUIRED there and cosmetic
 *  everywhere else. Derived from the class path, so a subclass added to the
 *  branch later inherits the rule instead of needing this list edited. */
export function isServiceBranch(classKey: string | null | undefined): boolean {
  const cls = ASSET_CLASSES[(classKey ?? '') as AssetClassKey];
  if (!cls) return false;
  return cls.path === 'service' || cls.path.startsWith('service.');
}

export function ClassPicker({ value, onChange, disabled }: {
  value: string;
  onChange: (key: string) => void;
  disabled?: boolean;
}) {
  const options = flattenClassTree();
  const cls = ASSET_CLASSES[value as AssetClassKey];
  return (
    <ModalField
      label="Class"
      hint={cls ? cls.description : 'The class decides which fields this asset has, so pick it first.'}
    >
      <ModalSelect value={value} onChange={(e) => onChange(e.target.value)} disabled={disabled} aria-label="Class">
        <option value="">Select a class…</option>
        {options.map(({ key, depth }) => (
          <option key={key} value={key}>
            {'  '.repeat(depth)}{depth > 0 ? '└ ' : ''}{ASSET_CLASSES[key].label}
          </option>
        ))}
      </ModalSelect>
    </ModalField>
  );
}

/** One attribute input, shaped by its declared type. An `enum` becomes a select,
 *  a boolean a checkbox, an integer a numeric input, everything else text. */
function AttributeInput({ name, prop, value, onChange }: {
  name: string;
  prop: AssetAttributeProperty;
  value: string;
  onChange: (v: string) => void;
}) {
  if (prop.enum && prop.enum.length > 0) {
    return (
      <ModalSelect value={value} onChange={(e) => onChange(e.target.value)} aria-label={name}>
        <option value="">—</option>
        {prop.enum.map((v) => <option key={v} value={v}>{v}</option>)}
      </ModalSelect>
    );
  }
  if (prop.type === 'boolean') {
    return (
      <ModalSelect value={value} onChange={(e) => onChange(e.target.value)} aria-label={name}>
        <option value="">—</option>
        <option value="true">Yes</option>
        <option value="false">No</option>
      </ModalSelect>
    );
  }
  if (prop.type === 'integer' || prop.type === 'number') {
    return <ModalInput value={value} onChange={(e) => onChange(e.target.value)} inputMode="numeric" aria-label={name} />;
  }
  if (prop.type === 'array') {
    return <ModalInput value={value} onChange={(e) => onChange(e.target.value)} placeholder="comma-separated" aria-label={name} />;
  }
  return <ModalInput value={value} onChange={(e) => onChange(e.target.value)} aria-label={name} />;
}

/** The attribute fields a class declares, rendered two-up. */
export function ClassAttributeFields({ classKey, values, onChange }: {
  classKey: string;
  values: Record<string, string>;
  onChange: (name: string, v: string) => void;
}) {
  const schema = ATTRIBUTE_SCHEMAS[classKey as AssetClassKey];
  const names = Object.keys(schema?.properties ?? {});
  if (names.length === 0) {
    return (
      <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginBottom: 14 }}>
        {classKey
          ? `${ASSET_CLASSES[classKey as AssetClassKey]?.label ?? classKey} declares no class-specific attributes.`
          : 'Pick a class to see its fields.'}
      </div>
    );
  }
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 14px' }}>
      {names.map((name) => (
        <ModalField key={name} label={humaniseAttribute(name)} hint={schema.properties[name].description}>
          <AttributeInput
            name={name}
            prop={schema.properties[name]}
            value={values[name] ?? ''}
            onChange={(v) => onChange(name, v)}
          />
        </ModalField>
      ))}
    </div>
  );
}

/** `operating_system` → `Operating system`, `os_version` → `OS version`. */
export function humaniseAttribute(name: string): string {
  const words = name.split('_');
  const head = words[0] === 'os' || words[0] === 'cpu' || words[0] === 'ip'
    ? words[0].toUpperCase()
    : words[0].charAt(0).toUpperCase() + words[0].slice(1);
  const rest = words.slice(1).map((w) => (w === 'id' ? 'ID' : w === 'mb' ? 'MB' : w));
  return [head, ...rest].join(' ');
}

/**
 * Coerces the form's string values into the typed `attributes` object the API
 * validates against the class schema.
 *
 * An empty string is OMITTED rather than sent as `""`. The two are different
 * facts — "the operator left it blank" versus "the operator set it to empty" —
 * and the second is never what anyone meant. A number that does not parse is
 * also omitted rather than sent as NaN, which JSON would render as `null` and
 * the schema would reject with a message about a type nobody typed.
 */
export function buildAttributes(classKey: string, values: Record<string, string>): Record<string, unknown> {
  const schema = ATTRIBUTE_SCHEMAS[classKey as AssetClassKey];
  const out: Record<string, unknown> = {};
  if (!schema) return out;
  for (const [name, prop] of Object.entries(schema.properties)) {
    const raw = (values[name] ?? '').trim();
    if (raw === '') continue;
    if (prop.type === 'integer' || prop.type === 'number') {
      const n = Number(raw);
      if (!Number.isFinite(n)) continue;
      out[name] = prop.type === 'integer' ? Math.trunc(n) : n;
      continue;
    }
    if (prop.type === 'boolean') {
      if (raw !== 'true' && raw !== 'false') continue;
      out[name] = raw === 'true';
      continue;
    }
    if (prop.type === 'array') {
      const parts = raw.split(',').map((s) => s.trim()).filter(Boolean);
      if (parts.length === 0) continue;
      out[name] = parts;
      continue;
    }
    out[name] = raw;
  }
  return out;
}

/** Turns an asset's stored `attributes` back into the form's string values. */
export function attributesToValues(attributes: unknown): Record<string, string> {
  if (!attributes || typeof attributes !== 'object' || Array.isArray(attributes)) return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(attributes as Record<string, unknown>)) {
    if (v === null || v === undefined) continue;
    out[k] = Array.isArray(v) ? v.map(String).join(', ') : String(v);
  }
  return out;
}

// ------------------------------------------------------- identifier editor --

export interface IdentifierDraft {
  kind: string;
  value: string;
  /** Where it came from. Absent = a row the person is adding now (declared). */
  sourceKind?: string;
  /** The scope the server gave it, carried back verbatim on save. */
  scope?: string;
}

/**
 * May a person retire this identifier?
 *
 * Only what a person declared. A collector-minted kind is issued by us to a
 * running agent or is the provider's own name for a resource; anything measured,
 * imported or inferred is a fact about the world. The server enforces exactly
 * this (`asset_update_identity.go`) and reports what it KEPT — so a form that
 * offered a remove button here would produce a click that looks like a deletion,
 * reads as saved, and changes nothing.
 */
export function isEditableIdentifier(row: IdentifierDraft): boolean {
  if (COLLECTOR_MINTED_KINDS.includes(row.kind)) return false;
  return (row.sourceKind ?? 'declared') === 'declared';
}

/** Why a row is read-only, in words a person can act on. */
export function identifierLockReason(row: IdentifierDraft): string {
  if (COLLECTOR_MINTED_KINDS.includes(row.kind)) {
    return 'Issued by a collector, not by a person — an edit form does not retire it.';
  }
  const src = row.sourceKind ?? 'declared';
  return `Observed by ${src} collection. Only identifiers a person declared can be edited here.`;
}

/**
 * The kinds this form offers — the registry's kinds minus the collector-minted
 * ones, DERIVED in `@vistasecurity/primitives/query`.
 *
 * It used to be a hand-written list under the name `WRITABLE_IDENTIFIER_KINDS`,
 * which is ALSO the name of a primitives export meaning something else
 * entirely: every spelling the QUERY language accepts, aliases included. Two
 * constants, one name, opposite jobs — `mac` belongs in one and must never
 * reach the other. The lists happened to agree the day it was written; nothing
 * made them keep agreeing, and the next kind added to the registry would have
 * been missing here with no test to say so.
 *
 * Deriving it also puts the options in the registry's order, which is the
 * engine's precedence order — strongest identifier first.
 */
export const FORM_IDENTIFIER_KINDS: readonly string[] = USER_ENTERABLE_IDENTIFIER_KINDS;

export const IDENTIFIER_KIND_LABEL: Record<string, string> = {
  agent_id: 'Agent ID',
  sensor_id: 'Sensor ID',
  cloud_resource_id: 'Cloud resource ID',
  fqdn: 'FQDN',
  hostname: 'Hostname',
  ip_address: 'IP address',
  mac_address: 'MAC address',
  serial_number: 'Serial number',
  ssh_host_key_fingerprint: 'SSH host key fingerprint',
  cmdb_sys_id: 'CMDB sys_id',
  name: 'Name',
};

export function IdentifierEditor({ rows, onChange }: {
  rows: IdentifierDraft[];
  onChange: (rows: IdentifierDraft[]) => void;
}) {
  return (
    <div style={{ marginBottom: 15 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
        <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>Identifiers</div>
        <button className="ui-btn sm" onClick={() => onChange([...rows, { kind: 'hostname', value: '' }])}>
          <Icon name="plus" size={12} />Add identifier
        </button>
      </div>
      <div style={{ fontSize: 11, color: 'var(--app-t3)', marginBottom: 7, lineHeight: 1.5 }}>
        How this thing is known. A serial you type in is as much identity as one a scanner read — what differs is the source, which the platform records. Identifiers are what let two sightings of one machine become one asset instead of two.
      </div>
      {rows.length === 0 && <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>No identifiers yet.</div>}
      {rows.map((row, idx) => {
        // A row the server owns is SHOWN and locked, not hidden. Hiding it made
        // the asset look like it had fewer ways of being known than it has, and
        // an agent id the form never mentioned still decides every future match.
        const editable = isEditableIdentifier(row);
        if (!editable) {
          return (
            <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }} title={identifierLockReason(row)}>
              <span style={{ flex: '0 0 190px', fontSize: 12, color: 'var(--app-t2)', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                <Icon name="lock" size={11} style={{ color: 'var(--app-t3)', flex: 'none' }} />
                {IDENTIFIER_KIND_LABEL[row.kind] ?? row.kind}
              </span>
              <span className="mono" style={{ flex: 1, minWidth: 0, fontSize: 12, color: 'var(--app-t2)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {row.value}
              </span>
              <span style={{ flex: 'none', fontSize: 10.5, color: 'var(--app-t3)', padding: '0 7px' }}>
                {row.sourceKind ?? 'measured'}
              </span>
            </div>
          );
        }
        return (
          <div key={idx} style={{ display: 'flex', gap: 8, marginBottom: 6 }}>
            <ModalSelect
              aria-label={`Identifier ${idx + 1} kind`}
              value={row.kind}
              style={{ flex: '0 0 190px' }}
              onChange={(e) => { const n = [...rows]; n[idx] = { ...n[idx], kind: e.target.value }; onChange(n); }}
            >
              {FORM_IDENTIFIER_KINDS.map((k) => <option key={k} value={k}>{IDENTIFIER_KIND_LABEL[k]}</option>)}
            </ModalSelect>
            <ModalInput
              aria-label={`Identifier ${idx + 1} value`}
              value={row.value}
              placeholder={placeholderFor(row.kind)}
              style={{ flex: 1 }}
              onChange={(e) => { const n = [...rows]; n[idx] = { ...n[idx], value: e.target.value }; onChange(n); }}
            />
            <button
              className="ui-btn sm ghost"
              style={{ color: 'var(--danger-text)', flex: 'none' }}
              title="Remove identifier"
              aria-label={`Remove identifier ${idx + 1}`}
              onClick={() => onChange(rows.filter((_, i) => i !== idx))}
            >
              <Icon name="x" size={13} />
            </button>
          </div>
        );
      })}
      {rows.some((r) => !isEditableIdentifier(r)) && (
        <div style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 5, lineHeight: 1.5 }}>
          The locked rows were recorded by a collector rather than typed by a person. They are kept whatever this form sends — the platform will not let an edit screen delete a fact about the world.
        </div>
      )}
    </div>
  );
}

function placeholderFor(kind: string): string {
  switch (kind) {
    case 'fqdn': return 'web-prod-01.example.com';
    case 'hostname': return 'web-prod-01';
    case 'ip_address': return '10.0.0.1';
    case 'mac_address': return 'aa:bb:cc:dd:ee:ff';
    case 'serial_number': return 'J7K2QX1';
    case 'ssh_host_key_fingerprint': return 'SHA256:…';
    case 'cmdb_sys_id': return 'a1b2c3d4e5f6…';
    case 'name': return 'Payroll';
    default: return '';
  }
}
