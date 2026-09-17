// Reachability for automatic active scanning (FEATURE_IMPLEMENTATION_FRAMEWORK).
//
// "A feature is done only when it is reachable by a user and gated correctly,
// and no layer ships without its consumer." Everything here compiles perfectly
// with the wiring deleted:
//
//   - the page exists but `sensor-config` stays `built: false`, so the rail
//     hides it and a deep link renders the "Spec'd — design pending"
//     placeholder over a live endpoint and a running worker;
//   - the nav entry flips to built but the router never dispatches the key, so
//     the entry leads to the same placeholder;
//   - the page renders the controls but never the activity section, which is
//     the ONLY place in the product where scans the platform ran unasked are
//     visible — discovery jobs have no listing page of their own.
//
// The unit tests next door cover what the form COMPUTES; this covers whether
// anything reaches it.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { SETTINGS_NAV, visibleSettingsNav, settingsPageMeta } from './nav';
import { defaultFeatures } from '@vistasecurity/primitives/features';

const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');
const settingsPage = read('./settings-page.tsx');
const autoScanPage = read('./pages-auto-scan.tsx');

describe('Active Scanning is reachable', () => {
  const item = SETTINGS_NAV
    .flatMap((s) => s.items.map((i) => ({ ...i, section: s.section })))
    .find((i) => i.key === 'sensor-config');

  it('has a nav entry under Infrastructure, marked built', () => {
    // The negative polarity of the same fact: left `built: false`, the entry
    // renders the "arrives in a later release" placeholder over a live endpoint
    // AND a worker that is already scanning the tenant's network.
    expect(item).toBeDefined();
    expect(item?.section).toBe('Infrastructure');
    expect(item?.built).toBe(true);
  });

  it('is named for what it does, not for a piece of hardware', () => {
    // It was spec'd as "Sensor Configuration". It is not about sensors: it
    // decides whether the PLATFORM probes the tenant's own network unasked, and
    // nobody looking for that clicks a page named after a sensor.
    expect(item?.label).toBe('Active Scanning');
    expect(item?.label).not.toMatch(/sensor/i);
  });

  it('the job line says the page DECIDES something', () => {
    expect(item?.job).toMatch(/decide|whether/i);
    expect(item?.job).toMatch(/scan/i);
  });

  it('is gated on settings.read, not left ungated', () => {
    expect(item?.permission).toBe('settings.read');
  });

  it('is NOT edition-gated — automatic scanning is Core', () => {
    // A `feature` here would hide the page on a Core install, where the worker
    // still runs. The tenant would be scanned by a capability they cannot see.
    expect(item?.feature).toBeUndefined();
    const visible = visibleSettingsNav(defaultFeatures)
      .flatMap((s) => s.items)
      .find((i) => i.key === 'sensor-config');
    expect(visible, 'the entry disappears with every feature flag off').toBeDefined();
  });

  it('the settings router dispatches the key to the page', () => {
    expect(settingsPage).toContain("import { AutoScanPage }");
    expect(settingsPage).toMatch(/case 'sensor-config':\s*return <AutoScanPage/);
  });

  it('settingsPageMeta resolves the key, so the page gets its title and job line', () => {
    expect(settingsPageMeta('sensor-config').label).toBe('Active Scanning');
  });
});

describe('the page reaches the endpoints and reports what the platform did', () => {
  it('reads the policy through the generated client', () => {
    expect(autoScanPage).toMatch(/clients\.inventory\.GET\('\/discovery\/auto-scan'/);
  });

  it('writes it back through the generated client', () => {
    // Without a PUT the page is a viewer for a policy nobody can change, and
    // the endpoint has no caller.
    expect(autoScanPage).toMatch(/clients\.inventory\.PUT\('\/discovery\/auto-scan'/);
  });

  it('gates the write on settings.update', () => {
    expect(autoScanPage).toMatch(/PermissionGate[\s\S]{0,120}TENANT_PERMISSIONS\.settings\.update/);
  });

  it('RENDERS the activity section', () => {
    // The wiring line. Delete `<ScanActivitySection …/>` and everything still
    // compiles, every unit test stays green, and the only place a tenant can
    // see that the platform has been scanning their network disappears.
    expect(autoScanPage).toMatch(/<ScanActivitySection\s+summary=/);
  });

  it('RENDERS the not-scanned panel, and it reads the summary field the server fills', () => {
    // The panel for the tenant the sweep refuses in full: a Tailscale or
    // ZeroTier estate is entirely carrier-grade NAT, and without this they
    // read "Automatic scanning: on" over a sweep that never scans a host.
    // Delete `<NotScannedSection …/>` and everything compiles, the unit tests
    // for the panel's logic stay green, and the panel is gone.
    expect(autoScanPage).toMatch(/<NotScannedSection\s+summary=/);
    expect(autoScanPage).toMatch(/describeNotScanned\(summary\.not_scanned\)/);
  });

  it('the not-scanned rows offer the register-the-segment action as a LINK to the segments page', () => {
    // A call to action that names a page and does not link to it is a
    // scavenger hunt. The href comes from the logic module so the test next
    // door pins which reasons get it.
    expect(autoScanPage).toMatch(/<Link to=\{row\.registerSegmentsHref\}/);
    expect(autoScanPage).toMatch(/Register the segment to include these hosts/);
  });

  it('distinguishes "every eligible host was scanned" from "no pass has run yet"', () => {
    expect(autoScanPage).toMatch(/Every eligible host was scanned/);
    expect(autoScanPage).toMatch(/No pass has run yet/);
  });

  it('labels the runs as automatic', () => {
    // These rows sit next to nothing else, so the row itself has to say who
    // started the scan.
    expect(autoScanPage).toMatch(/<STag>Automatic<\/STag>/);
  });

  it('says what happens when nothing has run yet', () => {
    // "No automatic scans yet" and a blank table are the same pixels and
    // different facts.
    expect(autoScanPage).toMatch(/No automatic scans yet/);
  });

  it('states the scope rule on the page, not only in the docs', () => {
    // A tenant admin deciding whether to leave this on needs to know what it
    // will never touch, at the moment they decide.
    expect(autoScanPage).toMatch(/public addresses and third-party systems are never probed/i);
  });

  it('says where the scan runs FROM, beside the switch', () => {
    // The limit a tenant would otherwise discover by finding a host that is in
    // the inventory, in scope, and never scanned: automatic scans go out from
    // the in-cluster platform sensor, so they reach only what the platform can
    // route to. Tenant-sensor dispatch does not exist.
    expect(autoScanPage).toMatch(/platform sensor inside the cluster/i);
    expect(autoScanPage).toMatch(/only reach hosts the\s*\n?\s*platform itself can route to/i);
  });
});
