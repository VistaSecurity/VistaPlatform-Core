// Settings → Policies → Identification rules.
//
// The page explains how the platform decides that two sightings are one thing,
// so every claim on it is a claim about the identification engine. Two of them
// were wrong at once and neither could fail loudly: the page showed a single
// global ladder while the engine walks a PER-CLASS order, and it had the scoped
// flag backwards on two kinds. A user reading it would have concluded that a
// printer is identified by an agent id it cannot have, and that an FQDN only
// resolves inside a segment — which the engine actively refuses.
//
// So the order is read from the registry rather than restated, and what remains
// hand-written (the per-kind notes) is pinned against the registry here.
import { describe, expect, it } from 'vitest';
import { ASSET_CLASSES, ATTRIBUTE_SCHEMAS, type AssetClassKey } from '@vistasecurity/primitives/assets';
import { IDENTIFIER_KIND_NOTES, kindsInUse, ownAttributes, precedenceForClass } from './pages-classes';

describe('precedenceForClass', () => {
  it('is the REGISTRY’s order for the class, not a copy of one', () => {
    for (const key of Object.keys(ASSET_CLASSES) as AssetClassKey[]) {
      expect(precedenceForClass(key)).toEqual([...ASSET_CLASSES[key].identifierPrecedence]);
    }
  });

  it('differs between classes — which is the whole reason it is not one list', () => {
    // A computer can run an agent; bare hardware cannot. A page showing one
    // ladder has to be wrong about one of them.
    expect(precedenceForClass('computer')[0]).toBe('agent_id');
    expect(precedenceForClass('hardware')[0]).toBe('serial_number');
    expect(precedenceForClass('hardware')).not.toContain('agent_id');
  });

  it('identifies a declared service by its name', () => {
    // ADR-0002 D3 erratum: a service has no address or serial to be known by.
    expect(precedenceForClass('service')).toContain('name');
  });

  it('returns an empty list for a class this build has never heard of', () => {
    expect(precedenceForClass('tenant_custom_thing')).toEqual([]);
  });

  it('hands back a copy, so a caller cannot reorder the registry in place', () => {
    const order = precedenceForClass('server');
    order.reverse();
    expect(precedenceForClass('server')).toEqual([...ASSET_CLASSES.server.identifierPrecedence]);
  });
});

describe('IDENTIFIER_KIND_NOTES', () => {
  it('explains every kind any class actually uses', () => {
    // The drift guard: a kind added to the YAML and used by a class would
    // otherwise render as a bare snake_case key with no explanation, on the one
    // page whose job is explaining.
    const missing = kindsInUse().filter((k) => !IDENTIFIER_KIND_NOTES[k]);
    expect(missing).toEqual([]);
  });

  it('describes no kind the registry has never heard of', () => {
    const used = new Set(kindsInUse());
    const stale = Object.keys(IDENTIFIER_KIND_NOTES).filter((k) => !used.has(k));
    expect(stale).toEqual([]);
  });

  it('marks scoped EXACTLY the four kinds a scope means something for', () => {
    // Mirrors `Kind.AcceptsScope` in shared/identity: the segment for hostname
    // and ip_address, the class key for name, the sync profile for cmdb_sys_id.
    // The engine REJECTS a scope on any of the other six, because a scope
    // nobody asked for splits the uniqueness key and quietly makes one
    // identifier into two assets.
    const scoped = Object.entries(IDENTIFIER_KIND_NOTES)
      .filter(([, n]) => n.scoped)
      .map(([k]) => k)
      .sort();
    expect(scoped).toEqual(['cmdb_sys_id', 'hostname', 'ip_address', 'name']);
  });

  it('gives every kind a label and a reason, not a bare key', () => {
    for (const [kind, note] of Object.entries(IDENTIFIER_KIND_NOTES)) {
      expect(note.label, kind).toBeTruthy();
      expect(note.label, kind).not.toBe(kind);
      expect(note.why.length, kind).toBeGreaterThan(30);
    }
  });
});

describe('ownAttributes', () => {
  it('is what the class ADDS, not what it inherits', () => {
    // The generated schema is the EFFECTIVE one, so the difference against the
    // parent is the only thing that says what this class contributes.
    expect(ownAttributes('computer')).toContain('operating_system');
    expect(ownAttributes('server')).not.toContain('operating_system');
  });

  it('is the WHOLE effective schema for a top-level class, which inherits nothing', () => {
    expect(ASSET_CLASSES.hardware.parent).toBeNull();
    expect(ownAttributes('hardware')).toEqual(Object.keys(ATTRIBUTE_SCHEMAS.hardware.properties));
  });

  it('never names an attribute the class does not have at all', () => {
    for (const key of Object.keys(ASSET_CLASSES) as AssetClassKey[]) {
      const effective = new Set(Object.keys(ATTRIBUTE_SCHEMAS[key]?.properties ?? {}));
      for (const a of ownAttributes(key)) expect(effective.has(a), `${key}.${a}`).toBe(true);
    }
  });
});
