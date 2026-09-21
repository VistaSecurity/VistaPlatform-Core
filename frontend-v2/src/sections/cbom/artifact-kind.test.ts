// The artifact-kind surface: what the list badges, what the Generate dialog
// offers, and which downloads a kind can actually produce.
//
// The download question is the one worth a test. The server refuses `ocsf` for
// anything but an inventory artifact and `spdx`/`pdf` for anything but a CBOM,
// so a menu that offered them regardless would hand the user a button that 400s
// — and the fastest way to teach someone a feature is broken is to let them
// click something that never works.
import { describe, it, expect } from 'vitest';
import { ARTIFACT_KINDS, downloadFormatsFor, kindMeta } from './kit';

describe('ARTIFACT_KINDS', () => {
  it('offers every kind the server accepts, crypto first', () => {
    // Not "at least four": the Generate dialog IS the only way a tenant reaches
    // three of these, so a kind missing here is a feature with no front door.
    expect(ARTIFACT_KINDS.map((k) => k.key)).toEqual(['cbom', 'sbom', 'hbom', 'inventory']);
  });

  it('gives every kind a one-line explanation', () => {
    // The blurb is the control's whole reason for being a card rather than a
    // dropdown: "HBOM" tells a user nothing, and someone who picks the wrong
    // kind finds out when an auditor opens the file.
    for (const k of ARTIFACT_KINDS) {
      expect(k.blurb.length, `${k.key} has no blurb`).toBeGreaterThan(20);
      expect(k.label, `${k.key} has no label`).toBeTruthy();
      expect(k.icon, `${k.key} has no icon`).toBeTruthy();
    }
  });
});

describe('kindMeta', () => {
  it('treats an absent kind as cbom', () => {
    // Rows written before the artifact_kind column existed read back as 'cbom'
    // through the repository's COALESCE. An undefined one from an older cached
    // response is the same artifact and must render the same.
    expect(kindMeta(undefined).key).toBe('cbom');
    expect(kindMeta(null).key).toBe('cbom');
    expect(kindMeta('').key).toBe('cbom');
  });

  it('renders an unknown kind as itself rather than mislabelling it', () => {
    // A server newer than this bundle can return a kind the UI has never heard
    // of. Falling back to `cbom` would put a CBOM badge on an artifact that is
    // not one — mislabelled evidence, which is worse than an unstyled row.
    const m = kindMeta('quantum-bom');
    expect(m.key).toBe('quantum-bom');
    expect(m.label).toBe('QUANTUM-BOM');
  });
});

describe('downloadFormatsFor', () => {
  it('offers CycloneDX for every kind — it is the canonical form of all four', () => {
    for (const k of [...ARTIFACT_KINDS.map((x) => x.key), undefined, null]) {
      const formats = downloadFormatsFor(k).map((f) => f.format);
      expect(formats, `kind ${k} lost CycloneDX`).toContain('cyclonedx');
    }
  });

  it('offers OCSF only for an inventory artifact', () => {
    // Both polarities. Without the positive half this would pass on a build
    // that never offered OCSF at all.
    expect(downloadFormatsFor('inventory').map((f) => f.format)).toContain('ocsf');
    for (const k of ['cbom', 'sbom', 'hbom', undefined, null]) {
      expect(downloadFormatsFor(k).map((f) => f.format), `kind ${k} offered OCSF`).not.toContain('ocsf');
    }
  });

  it('explains what each format is for', () => {
    // The menu item's second line is what stops someone downloading NDJSON
    // expecting a document, or CycloneDX expecting SIEM events.
    for (const f of downloadFormatsFor('inventory')) {
      expect(f.label, 'format has no label').toBeTruthy();
      expect(f.hint.length, `${f.format} has no hint`).toBeGreaterThan(20);
    }
  });

  it('names the format in every label, short name and hint, for every kind', () => {
    // The compact list button shows `short` and its tooltip shows `hint`. A
    // hint that described the bytes without naming the format ("the canonical
    // bytes") is how three of the four kinds came to look like they had no
    // CycloneDX export at all — only the inventory row's menu spelled it out.
    const nameOf: Record<string, string> = { cyclonedx: 'CycloneDX', ocsf: 'OCSF' };
    for (const k of [...ARTIFACT_KINDS.map((x) => x.key), undefined, null]) {
      for (const f of downloadFormatsFor(k)) {
        const name = nameOf[f.format];
        expect(name, `no display name for format ${f.format}`).toBeTruthy();
        expect(f.short, `kind ${k}: ${f.format} short name`).toBe(name);
        expect(f.label, `kind ${k}: ${f.format} label`).toContain(name);
        expect(f.hint, `kind ${k}: ${f.format} hint does not name the format`).toContain(name);
      }
    }
  });
});
