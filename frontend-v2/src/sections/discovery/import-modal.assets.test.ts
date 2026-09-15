// The import wizard's asset mapping (ADR-0006 D8, workstream 1.10).
//
// Two things changed and both are pinned here. The class list is now the
// GENERATED registry — the one it replaced carried nine values that were never
// class keys, so every row using one was rejected by the server with a message
// about a class this very wizard had offered. And identifier columns
// (serial/MAC/FQDN/hostname/IP) now become IDENTIFIERS rather than plain fields,
// which is what lets a spreadsheet be re-imported without duplicating machines
// the platform already knows about.
import { describe, expect, it } from 'vitest';
import { ASSET_CLASSES, ASSET_CLASS_KEYS } from '@vistasecurity/primitives/assets';
import { ASSET_FIELDS, IDENTIFIER_COLUMNS, autoGuess, buildAsset } from './import-modal';

const classField = ASSET_FIELDS.find((f) => f.key === 'class_key')!;

describe('the class column', () => {
  it('offers exactly the generated class keys — no more, no fewer', () => {
    // The nine invalid values this replaced were `vm`, `database`, `other` and
    // six more that were never class keys at all.
    expect(classField.enumOptions).toEqual([...ASSET_CLASS_KEYS]);
  });

  it('offers only values the registry knows', () => {
    for (const v of classField.enumOptions ?? []) {
      expect(ASSET_CLASS_KEYS).toContain(v as (typeof ASSET_CLASS_KEYS)[number]);
    }
  });

  it('labels each option with the class’s human name, not its key', () => {
    // The stored value is `network_device`; the word a user recognises is
    // "Network device". Showing the key would make the picker unreadable.
    for (const key of ASSET_CLASS_KEYS) {
      expect(classField.enumLabels?.[key]).toBe(ASSET_CLASSES[key].label);
    }
  });

  it('is required — an asset has exactly one class', () => {
    expect(classField.required).toBe(true);
  });

  it('still auto-maps a spreadsheet’s "Asset Type" column, which is what people call it', () => {
    const mapping = autoGuess(ASSET_FIELDS, ['Asset Type', 'Hostname', 'IP Address']);
    expect(mapping.class_key).toBe('Asset Type');
  });
});

describe('identifier columns', () => {
  it('maps the five identifying columns to identifier kinds', () => {
    expect(IDENTIFIER_COLUMNS.map((c) => c.kind)).toEqual([
      'fqdn', 'hostname', 'ip_address', 'mac_address', 'serial_number',
    ]);
  });

  it('claims a "Host Name" column for the hostname identifier, not for the display name', () => {
    // Auto-mapping takes fields in order and a column can only be claimed once.
    // With `display_name` listed first, its `name` guess matched "Host Name" by
    // substring and left the hostname identifier unmapped — so every row failed
    // the identity floor with no identifier at all.
    const mapping = autoGuess(ASSET_FIELDS, ['Host Name']);
    expect(mapping.hostname).toBe('Host Name');
    expect(mapping.display_name).toBe('');
  });

  it('auto-guesses each of them from plausible spreadsheet headers', () => {
    const mapping = autoGuess(ASSET_FIELDS, ['FQDN', 'Host Name', 'IP Address', 'MAC Address', 'Serial Number']);
    expect(mapping.fqdn).toBe('FQDN');
    expect(mapping.hostname).toBe('Host Name');
    expect(mapping.ip_address).toBe('IP Address');
    expect(mapping.mac_address).toBe('MAC Address');
    expect(mapping.serial_number).toBe('Serial Number');
  });

  it('recognises a "Service Tag" column as a serial, which is what Dell calls it', () => {
    expect(autoGuess(ASSET_FIELDS, ['Service Tag']).serial_number).toBe('Service Tag');
  });
});

describe('buildAsset', () => {
  const mapping = {
    class_key: 'Type', hostname: 'Host', ip_address: 'IP', serial_number: 'Serial',
    mac_address: '', fqdn: '', display_name: '', environment: 'Env',
    operating_system: 'OS', support_group: 'Team', business_unit: '', owner_email: '', description: '',
  };

  it('turns identifier columns into IDENTIFIERS, in registry order', () => {
    const { input, error } = buildAsset(
      { Type: 'server', Host: 'web-01', IP: '10.0.0.1', Serial: 'J7K2QX1', Env: 'production', OS: 'Ubuntu', Team: 'SRE' },
      mapping, {},
    );
    expect(error).toBeNull();
    expect(input.class_key).toBe('server');
    expect(input.identifiers).toEqual([
      { kind: 'hostname', value: 'web-01' },
      { kind: 'ip_address', value: '10.0.0.1' },
      { kind: 'serial_number', value: 'J7K2QX1' },
    ]);
  });

  it('puts the OS in ATTRIBUTES for a class that declares one', () => {
    const { input } = buildAsset({ Type: 'server', Host: 'web-01', OS: 'Ubuntu' }, mapping, {});
    expect(input.attributes).toEqual({ operating_system: 'Ubuntu' });
  });

  it('DROPS the OS for a class that has no such attribute', () => {
    // A switch has no `operating_system` slot; `additionalProperties: false`
    // means sending one would be rejected by the schema. Dropping it is better
    // than failing the row over a column the wizard itself offered.
    const { input, error } = buildAsset({ Type: 'switch', Host: 'sw-01', OS: 'NX-OS' }, mapping, {});
    expect(error).toBeNull();
    expect(input.attributes).toBeUndefined();
  });

  it('carries the support group through', () => {
    const { input } = buildAsset({ Type: 'server', Host: 'web-01', Team: 'Platform SRE' }, mapping, {});
    expect(input.support_group).toBe('Platform SRE');
  });

  it('rejects a row with no class', () => {
    expect(buildAsset({ Host: 'web-01' }, mapping, {}).error).toMatch(/class is required/i);
  });

  it('rejects a class the registry does not know, and names it', () => {
    // The failure the old list produced on every row. It now fails in the
    // BROWSER, at preview time, with the offending value quoted — rather than
    // as a server rejection after the upload.
    const { error } = buildAsset({ Type: 'vm', Host: 'web-01' }, mapping, {});
    expect(error).toMatch(/not a known class/i);
    expect(error).toContain('vm');
  });

  it('rejects a row with a class but NO identifier', () => {
    expect(buildAsset({ Type: 'server' }, mapping, {}).error).toMatch(/identifier/i);
  });

  it('requires a NAME for a service instead of an identifier', () => {
    const svcMapping = { ...mapping, display_name: 'Name' };
    expect(buildAsset({ Type: 'business_service' }, svcMapping, {}).error).toMatch(/name/i);
    const ok = buildAsset({ Type: 'business_service', Name: 'Payroll' }, svcMapping, {});
    expect(ok.error).toBeNull();
    expect(ok.input.display_name).toBe('Payroll');
  });

  it('falls back to the column default when a row leaves the class blank', () => {
    // The wizard's enum default is how a spreadsheet with no type column at all
    // still imports: the user picks one class for the whole file.
    const { input, error } = buildAsset({ Host: 'web-01' }, mapping, { class_key: 'workstation' });
    expect(error).toBeNull();
    expect(input.class_key).toBe('workstation');
  });

  it('omits the identifiers array entirely when there are none, rather than sending []', () => {
    const { input } = buildAsset({ Type: 'business_service' }, { ...mapping, display_name: 'Name' }, {});
    expect(input.identifiers).toBeUndefined();
  });
});

describe('identifier columns are guessed on whole words, never substrings (gate1 C1)', () => {
  // Substring matching read `ip` out of the middle of ordinary English words, so
  // a CMDB export with a "Description" column silently mapped it onto the
  // ip_address IDENTIFIER. That is not a mis-filed value: an identifier is what
  // the engine matches on, so a free-text column became identity.
  it('does not read an IP identifier out of "Description"', () => {
    expect(autoGuess(ASSET_FIELDS, ['Description']).ip_address).toBe('');
  });

  it('does not read an IP identifier out of "Equipment"', () => {
    expect(autoGuess(ASSET_FIELDS, ['Equipment']).ip_address).toBe('');
  });

  it('gives "Email Address" to the owner email, not to the IP identifier', () => {
    const mapping = autoGuess(ASSET_FIELDS, ['Email Address']);
    expect(mapping.ip_address).toBe('');
    expect(mapping.owner_email).toBe('Email Address');
  });

  it('still takes a bare "Address" column as the IP identifier', () => {
    // The whole header IS an address word — the one case where `address` alone
    // means the machine's address rather than a person's.
    expect(autoGuess(ASSET_FIELDS, ['Address']).ip_address).toBe('Address');
  });

  it('still recognises the IP column by its own word', () => {
    for (const header of ['IP', 'IP Address', 'Management IP', 'ip_addr', 'IPv4']) {
      expect(autoGuess(ASSET_FIELDS, [header]).ip_address).toBe(header);
    }
  });

  it('does not read a hostname identifier out of "Hosting Provider"', () => {
    expect(autoGuess(ASSET_FIELDS, ['Hosting Provider']).hostname).toBe('');
  });

  it('leaves an unrecognised column unmapped rather than guessing', () => {
    const mapping = autoGuess(ASSET_FIELDS, ['Equipment']);
    expect(Object.values(mapping).filter((c) => c === 'Equipment')).toEqual([]);
  });

  it('marks every identifier column as an identifier field, and nothing else (both polarities)', () => {
    const identifierKeys = [...IDENTIFIER_COLUMNS.map((c) => c.key)].sort();
    const flagged = ASSET_FIELDS.filter((f) => f.identifier).map((f) => f.key).sort();
    expect(flagged).toEqual(identifierKeys);
    // …and the flag is what selects word matching, so an unflagged identifier
    // column would silently fall back to substring guessing.
    for (const f of ASSET_FIELDS) {
      expect(f.identifier === true).toBe(identifierKeys.includes(f.key));
    }
  });
});
