// The production catalogue over the generated registries.
//
// The point of these is the seam, not the vocabulary: a query that resolves
// against the static test catalogue must resolve the same way here, because the
// only thing that differs is where the class keys and fact keys come from.
// Everything else is `fields.ts` and `base-catalog.ts`, which the conformance
// suite already holds to Go's behaviour.

import { describe, expect, it } from 'vitest';

import { ASSET_CLASSES, ASSET_CLASS_KEYS } from '../assets';
import { FACT_KEY_DEFS, FACT_KEY_ORDER } from '../facts';
import { check } from './index';
import { CVSS_LADDER, newRegistryCatalog } from './registry-catalog';
import { LADDER, newTestCatalog } from './test-catalog';
import { defaultOptions, withLadder } from './validate';

const registry = newRegistryCatalog();
const opts = withLadder(defaultOptions(), CVSS_LADDER);

function codes(src: string, target = 'asset'): string[] {
  const out = check(src, target, registry, opts);
  return out.ok ? [] : out.errors.map((e) => e.code);
}

describe('it is the same language, over a generated vocabulary', () => {
  const shared = [
    'environment:production and class:server',
    'risk >= high and not exists(owner_email)',
    'last_seen < now-30d and status:monitoring',
    'endpoint:(port:443 and protocol:tls)',
    'depends_on(3):(display_name:"Payroll")',
    'id.serial_number:* and not id.cloud_resource_id:*',
    'tag.env:prod and not environment:production',
    'risk_score:[40 to 69]',
    'hostname ~ "^web[0-9]{2}$"',
    'any_rel:(id.any:"aa:bb:cc:00:11:22")',
  ];

  it('accepts every query the static catalogue accepts, where the vocabulary is shared', () => {
    const test = newTestCatalog();
    for (const q of shared) {
      const a = check(q, 'asset', test, withLadder(defaultOptions(), LADDER));
      const b = check(q, 'asset', registry, opts);
      expect(a.ok, `static: ${q}`).toBe(true);
      expect(b.ok, `registry: ${q}`).toBe(true);
      if (a.ok && b.ok) expect(b.value.canonical).toBe(a.value.canonical);
    }
  });

  it('still enforces §6 — it is not a catalogue that accepts everything', () => {
    expect(codes('hostnaem:web-1')).toEqual(['unknown_field']);
    expect(codes('risk >= 70')).toEqual(['type_mismatch']);
    expect(codes('environment < production')).toEqual(['operator_not_allowed']);
    expect(codes('depends_on(7):(class:server)')).toEqual(['depth_exceeded']);
  });
});

describe('classes come from the generated taxonomy', () => {
  it('resolves every platform class key, by key and by path', () => {
    for (const key of ASSET_CLASS_KEYS) {
      expect(registry.classExists(key), key).not.toBeNull();
      expect(registry.classExists(ASSET_CLASSES[key].path), key).not.toBeNull();
    }
    expect(registry.classKeys().length).toBe(ASSET_CLASS_KEYS.length);
  });

  it('rejects a class the taxonomy does not have, and names the closest', () => {
    const out = check('class:serverr', 'asset', registry, opts);
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.errors[0].code).toBe('unknown_value');
    // Unlike the static catalogue, this one publishes its class keys, so the
    // "did you mean" is available.
    expect(out.errors[0].suggestion).toBe('did you mean "server"?');
  });

  it('accepts tenant leaf subclasses when the app supplies them', () => {
    // Tenant subclasses are runtime data, not generated (ADR-0002 D2). A
    // subclass is matched by its parent's subtree term either way (§5.3); what
    // supplying it changes is whether the exact key resolves.
    expect(codes('class:acme_edge_router')).toEqual(['unknown_value']);
    const withTenant = newRegistryCatalog({
      tenantClasses: [{ key: 'acme_edge_router', path: 'hardware.network_device.acme_edge_router' }],
    });
    expect(check('class:acme_edge_router', 'asset', withTenant, opts).ok).toBe(true);
  });
});

describe('facts come from the generated registry', () => {
  it('resolves every registered key', () => {
    for (const key of FACT_KEY_ORDER) {
      expect(codes(`exists(fact.${key})`), key).toEqual([]);
    }
  });

  it('maps the declared value type onto the operators §4.4 allows', () => {
    // `integer` is a number, so it orders; `string` is a keyword, so it does
    // not; `date` is a timestamp, so `now-30d` type-checks.
    expect(codes('fact.net.uptime_seconds >= 86400')).toEqual([]);
    expect(codes('fact.os.name:linux')).toEqual([]);
    expect(codes('fact.os.name < linux')).toEqual(['operator_not_allowed']);
    expect(codes('fact.eol.os.date > now+90d')).toEqual([]);
    expect(codes('fact.eol.os.date > soon')).toEqual(['type_mismatch']);
    expect(codes('fact.mgmt.plaintext:true')).toEqual([]);
    expect(codes('fact.mgmt.plaintext:yes')).toEqual(['type_mismatch']);
  });

  it('makes an array or object key presence-only', () => {
    // §4.4 gives a json field no operator row at all. The accessor for a jsonb
    // value yields its raw TEXT, so keyword[] would generate `unnest(text)` and
    // `array_length(text)` — errors from Postgres, not answers. `exists(…)` is
    // the only honest question about one, and it still works.
    expect(FACT_KEY_DEFS['net.interfaces'].type).toBe('array');
    expect(codes('exists(fact.net.interfaces)')).toEqual([]);
    expect(codes('fact.net.interfaces:eth0')).toEqual(['operator_not_allowed']);
    expect(codes('fact.net.interfaces in (eth0, eth1)')).toEqual(['operator_not_allowed']);
    // A real text[] COLUMN is a different thing and keeps array-contains.
    expect(codes('risk_assessed_by:crypto')).toEqual([]);
  });

  it('enforces a fact key enum where the registry declares one', () => {
    expect(codes('fact.cloud.provider:aws')).toEqual([]);
    expect(codes('fact.cloud.provider:digitalocean')).toEqual(['unknown_value']);
  });

  it('rejects an unregistered key rather than accepting anything dotted', () => {
    expect(codes('fact.not.registered:1')).toEqual(['unknown_field']);
  });
});

describe('the attr namespace, from the generated class schemas', () => {
  // This used to be "the attribute gap, asserted rather than papered over":
  // nothing generated the per-class attribute schemas for TypeScript, so the
  // catalogue shipped with an EMPTY attr vocabulary and every `attr.<name>`
  // reported unknown_field. Closed in workstream 0.8e — the schemas are
  // generated into `@vistasecurity/primitives/assets` and folded here by the
  // same rule Go's `buildAttributeFields` applies.

  it('resolves an attribute the registry declares', () => {
    expect(codes('attr.provider:aws')).toEqual([]);
    expect(codes('attr.cpu_count >= 8')).toEqual([]);
    expect(codes('attr.model:Cat*')).toEqual([]);
  });

  it('enforces the enum the YAML declares', () => {
    expect(codes('attr.provider:digitalocean')).toEqual(['unknown_value']);
  });

  it('still rejects an attribute nothing declares', () => {
    // The alternative — accepting any `attr.<key>` as a keyword — would take a
    // typo, give it a type nobody declared, and send it to the server as if it
    // had been checked: a guess wearing the clothes of an answer, which is the
    // shape §5.2 exists to prevent.
    expect(codes('attr.managed:true')).toEqual(['unknown_field']);
    expect(codes('attr.not_an_attribute:1')).toEqual(['unknown_field']);
  });

  it('applies the registry type mapping, not a default', () => {
    // os_version is a string in the YAML — "22.04.3 LTS" — so it is a keyword,
    // and `< 3` is not a question that can be asked of it. The static §4.3
    // catalogue used to type it NUMBER, which made that predicate legal in the
    // spec fixtures and refused in the product; both sides now say keyword.
    expect(codes('attr.os_version < 3')).toEqual(['operator_not_allowed']);
    expect(codes('attr.os_version:"22.04"')).toEqual([]);
    // array → json: `exists` and nothing else, because the accessor yields raw
    // text and `unnest(text)` is an error from Postgres, not an answer.
    expect(codes('exists(attr.industrial_protocols)')).toEqual([]);
    expect(codes('attr.industrial_protocols:modbus')).toEqual(['operator_not_allowed']);
  });

  it('is flat and global — one name, not one per class (§4.2)', () => {
    // `attr.model` is declared by `hardware` and inherited by everything under
    // it; the query is a predicate over `assets`, whose jsonb holds whichever
    // class's keys the row carries, so the field resolves with no class term.
    expect(codes('attr.model:"MX204"')).toEqual([]);
    expect(codes('class:network_device and attr.model:"MX204"')).toEqual([]);
  });

  it('drops the description where two classes describe one attribute differently', () => {
    // `cpu_count` is "Logical CPU count." on `computer` and "Allocated virtual
    // CPUs." on `virtual` — two unrelated branches, one jsonb key. Showing one
    // class's wording as if it were the field's is a small lie in a tooltip;
    // showing none is not. Go's buildAttributeFields does the same.
    const attr = (name: string) => registry.fields('asset').find((f) => f.name === name);
    expect(attr('attr.cpu_count')?.type).toBe('number');
    expect(attr('attr.cpu_count')?.description).toBeUndefined();
    // One declarer, so the description survives — along with the enum.
    expect(attr('attr.provider')?.description).toBe('Cloud provider.');
    expect(attr('attr.provider')?.enum).toEqual(['aws', 'azure', 'gcp', 'oci', 'other']);
  });

  it('takes an explicit override on top of the generated vocabulary', () => {
    const withAttrs = newRegistryCatalog({
      attributeKeys: { experimental_key: { type: 'number' } },
    });
    expect(check('attr.experimental_key >= 8', 'asset', withAttrs, opts).ok).toBe(true);
    // …without dropping what the registry declares.
    expect(check('attr.provider:aws', 'asset', withAttrs, opts).ok).toBe(true);
    // …and only for the catalogue that asked for it.
    expect(codes('attr.experimental_key >= 8')).toEqual(['unknown_field']);
  });
});

describe('the band ladder', () => {
  it('is the CVSS ×10 ladder the server uses (§5.5)', () => {
    // One ladder, or badges band High at >= 60 while facets use >= 70 — the
    // drift the single-ladder rule exists to make impossible.
    expect(CVSS_LADDER.bands()).toEqual([
      { label: 'Critical', min: 90 },
      { label: 'High', min: 70 },
      { label: 'Medium', min: 40 },
      { label: 'Low', min: 1 },
      { label: 'Informational', min: 0 },
    ]);
    expect(CVSS_LADDER.bands()).toEqual(LADDER.bands());
  });
});
