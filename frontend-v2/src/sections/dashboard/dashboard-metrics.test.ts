import { describe, expect, it } from 'vitest';
import { check, defaultOptions, newRegistryCatalog, CVSS_LADDER, withLadder } from '@vistasecurity/primitives/query';
import {
  DASHBOARD_CRITICAL_FINDINGS_ROUTE, DASHBOARD_HIGH_RISK_ASSETS_ROUTE, DASHBOARD_HIGH_RISK_QUERY,
  DASHBOARD_UNSCORED_ASSETS_ROUTE, DASHBOARD_UNSCORED_QUERY,
  getDashboardPqcMetric, getDiscoveryFleetMetric, isAgentRow,
} from './dashboard-metrics';
import { readFileSync } from 'node:fs';
import { FINDINGS_SUBJECT_LENS, isFindingsLens } from '../findings/lenses';
import { parseSeverityFilter, segOwnsSeverityAxis, SEVERITY_FILTER_VALUES } from '../findings/model';
import { queryToFacets } from '../inventory/facet-query';
import { INVENTORY_LENSES } from '../inventory/lenses';

describe('dashboard findings links', () => {
  // This pin was `?lens=framework` while the tile counted only the compliance
  // producer. The COUNT was widened (it reads
  // /findings/statistics.all_producer_severity_counts now, so an end-of-life
  // Critical is a critical finding on the Dashboard as well as on the Findings
  // page), so the link had to widen with it — a tile that counts every producer
  // and lands on a page grouped by framework CONTROL sends the user somewhere
  // its number cannot be found.
  it('deep-links the critical count to the lens that shows every producer', () => {
    expect(DASHBOARD_CRITICAL_FINDINGS_ROUTE).toBe('/risk-compliance/findings?lens=producer&severity=critical');
  });

  // The severity axis. The tile counts ONE RUNG of the ladder, and the page it
  // opens lists every severity — so without this parameter, clicking
  // "40 critical findings" landed on a list of several hundred rows with
  // nothing saying which forty were meant. That is the same failure the
  // High-risk assets tile was fixed for below ("a tile that counts a subset
  // must link to that subset"); it survived here only because the findings page
  // had no severity parameter to carry.
  //
  // Asserted on the PARSED parameter rather than the string, and against the
  // page's own vocabulary rather than the literal 'critical', so a rename of the
  // rung fails here instead of silently producing a filter that matches nothing.
  it('carries the severity rung the tile counts, in a spelling the page accepts', () => {
    const severity = new URLSearchParams(DASHBOARD_CRITICAL_FINDINGS_ROUTE.split('?')[1]).get('severity');
    expect(severity).toBe('critical');
    expect(parseSeverityFilter(severity)).toBe('critical');
    // Both polarities: parseSeverityFilter returns null for anything it does not
    // recognize, so an assertion that only checked "not null" would pass on a
    // route carrying a rung the page then ignores.
    expect(parseSeverityFilter('crit')).toBeNull();
    expect(SEVERITY_FILTER_VALUES).toContain('critical');
  });

  // The other half of the same contract, and the half a route-only assertion
  // cannot see: the page has to READ the parameter and send it to the SERVER.
  //
  // Server-side is load-bearing, not a style preference. useFindingsList stops
  // at FINDINGS_PAGE_CAP pages, so a severity narrowing applied to the returned
  // array would under-report any tenant whose Criticals sit past the cap — the
  // tile would say 40 and the page would show twelve, which is the divergence
  // this whole pairing exists to prevent, arriving from the opposite direction.
  it('is read by the findings page and applied by the server', () => {
    const page = readFileSync(new URL('../findings/findings-page.tsx', import.meta.url), 'utf8');
    // read from the URL, through the validator
    expect(page).toMatch(/parseSeverityFilter\(params\.get\('severity'\)\)/);
    // handed to the list query rather than used to filter its result
    expect(page).toMatch(/useFindingsList\([^)]*severityF/);
    // and visible + clearable, because a filter arriving from a link is one the
    // reader never chose
    expect(page).toContain('findings-severity-filter');
    // The button must be WIRED, not merely present. `/clearSeverity/` matched
    // the function's own declaration, so unhooking it from the banner left this
    // green — the inert-check failure this repository keeps re-finding, caught
    // by mutation-testing this very assertion.
    expect(page).toMatch(/onClick=\{clearSeverity\}/);
    // and it must actually drop the parameter rather than set it to something
    expect(page).toMatch(/clearSeverity = \(\) => setParams\(\(prm\) => \{\s*prm\.delete\('severity'\);/);

    const queries = readFileSync(new URL('../findings/queries.ts', import.meta.url), 'utf8');
    // sent as a query PARAMETER on the request, not applied to `all`
    expect(queries).toMatch(/severity: sev/);
  });

  // `?severity=` and the page's own "Critical + High" chip are the SAME axis
  // under two controls, so they must not intersect: arriving from this tile and
  // then clicking a chip labelled "Critical + High" would otherwise show
  // Criticals only — a control that reads as applied and is not, which is the
  // failure the subject and severity banners both exist to prevent.
  it('resolves its severity filter against the page own severity chip', () => {
    // The RULE, exercised for real rather than read off the source: only the
    // severity chip owns this axis, and both polarities are asserted because a
    // predicate that returns true for everything would drop the URL filter on
    // every chip click, and one that returns false for everything is the
    // intersecting behaviour this prevents.
    expect(segOwnsSeverityAxis('crit')).toBe(true);
    expect(segOwnsSeverityAxis('open')).toBe(false);
    expect(segOwnsSeverityAxis('mine')).toBe(false);
    expect(segOwnsSeverityAxis('unassigned')).toBe(false);

    // The WIRING, which a unit test of the rule cannot see. Anchored at `if (`
    // on purpose: an un-anchored match still succeeded with the call disabled
    // behind `if (false && …)`, which is how this assertion first shipped inert.
    const page = readFileSync(new URL('../findings/findings-page.tsx', import.meta.url), 'utf8');
    expect(page).toMatch(/if \(segOwnsSeverityAxis\(k\) && severityF\) clearSeverity\(\);/);
    // Every seg chip goes through selectSeg, so the rule cannot be bypassed by
    // one of the two chip rows still calling setSeg directly.
    expect(page).not.toMatch(/onClick=\{\(\) => setSeg\(/);
    expect(page).toMatch(/onClick=\{\(\) => selectSeg\(k\)\}/);
  });

  it('names the every-producer lens structurally, not by a string that happens to match', () => {
    const lens = new URLSearchParams(DASHBOARD_CRITICAL_FINDINGS_ROUTE.split('?')[1]).get('lens');
    // The registry's own name for "the findings-scoped lens that shows every
    // producer's rows without a framework in the way".
    expect(lens).toBe(FINDINGS_SUBJECT_LENS);
    expect(isFindingsLens(lens!)).toBe(true);
    // Both polarities. `framework` and `control` are findings-scoped too, so
    // isFindingsLens alone accepts the lens this tile used to point at — the
    // assertion that catches a revert has to name them.
    expect(lens).not.toBe('framework');
    expect(lens).not.toBe('control');
  });
});

describe('dashboard risk tiles link to what they counted (gate1 C7)', () => {
  // Both tiles used to link at `/inventory?lens=infrastructure` — a retired lens
  // key that redirects to the UNFILTERED list. "High-risk assets: 12" landed the
  // user on every asset in the tenant with nothing saying which twelve.
  const CATALOG = newRegistryCatalog();
  const OPTIONS = withLadder(defaultOptions(), CVSS_LADDER);

  it('carries a query, not just a lens', () => {
    expect(DASHBOARD_HIGH_RISK_ASSETS_ROUTE).toContain('query=');
    expect(DASHBOARD_UNSCORED_ASSETS_ROUTE).toContain('query=');
  });

  it('names a lens that still exists', () => {
    for (const route of [DASHBOARD_HIGH_RISK_ASSETS_ROUTE, DASHBOARD_UNSCORED_ASSETS_ROUTE]) {
      const lens = new URLSearchParams(route.split('?')[1]).get('lens');
      expect(INVENTORY_LENSES.some((l) => l.key === lens), `no such lens: ${lens}`).toBe(true);
    }
  });

  it('filters to the assets the tile counted', () => {
    // `high_risk` is the ≥ High band, which includes Critical.
    expect(queryToFacets(DASHBOARD_HIGH_RISK_QUERY).facets.risk).toEqual(['critical', 'high']);
    // "Unscored" is the ABSENCE of a score, which the language spells
    // `not_assessed` — never "low".
    expect(queryToFacets(DASHBOARD_UNSCORED_QUERY).facets.risk).toEqual(['not_assessed']);
  });

  it('writes a query the server would accept', () => {
    for (const q of [DASHBOARD_HIGH_RISK_QUERY, DASHBOARD_UNSCORED_QUERY]) {
      const res = check(q, 'asset', CATALOG, OPTIONS);
      expect(res.ok, `invalid query: ${q} — ${res.ok ? '' : res.errors.map((e) => e.message).join('; ')}`).toBe(true);
    }
  });

  it('URL-encodes the query so the parentheses survive the address bar', () => {
    const parsed = new URLSearchParams(DASHBOARD_HIGH_RISK_ASSETS_ROUTE.split('?')[1]);
    expect(parsed.get('query')).toBe(DASHBOARD_HIGH_RISK_QUERY);
  });
});

describe('dashboard PQC metric', () => {
  it('uses inventory PQC adoption rather than a framework-style score, and keeps needsMigration/unclassified separate', () => {
    const metric = getDashboardPqcMetric({
      pqc_percentage: 8,
      pqc_ready: 1,
      symmetric_safe: 1,
      non_pqc: 4,
      unclassified: 7,
      total_implementations: 13,
      // This mirrors the old, wrong fallback source. It must not affect the dashboard.
      compliance_percent: 45,
    } as Parameters<typeof getDashboardPqcMetric>[0] & { compliance_percent: number });

    expect(metric).toEqual({
      adoptionPercent: 8,
      pqcReady: 2, // pqc_ready + symmetric_safe
      total: 13,
      needsMigration: 4,
      unclassified: 7,
    });
  });

  // M-2 regression: needsMigration + unclassified must NOT be collapsed into a
  // single "on classical crypto" figure — an implementation with no algorithm
  // data is a data-quality gap, not evidence it uses classical crypto.
  it('never folds unclassified into needsMigration', () => {
    const metric = getDashboardPqcMetric({
      pqc_percentage: 0,
      pqc_ready: 0,
      symmetric_safe: 0,
      non_pqc: 4,
      unclassified: 7,
      total_implementations: 11,
    });

    expect(metric.needsMigration).toBe(4);
    expect(metric.unclassified).toBe(7);
    expect(metric.needsMigration + metric.unclassified).toBe(metric.total - metric.pqcReady);
  });

  // The gauge and the two "PQC configs" tiles are read at a glance, so the
  // percentage is a whole number. /pqc/progress computes ready/total as a
  // float, and 4 of 11 rendered as "36.36363636363637%" inside an 86px ring.
  it('rounds the adoption percentage to a whole percent', () => {
    const at = (pqc_percentage: number) => getDashboardPqcMetric({
      pqc_percentage, pqc_ready: 0, symmetric_safe: 0, non_pqc: 0, unclassified: 0, total_implementations: 11,
    }).adoptionPercent;

    expect(at((4 / 11) * 100)).toBe(36);
    expect(at((1 / 3) * 100)).toBe(33);
    expect(at((2 / 3) * 100)).toBe(67);
    expect(at(99.5)).toBe(100);
    // A non-zero adoption must never round away to a bare 0 on a tenant that
    // has some PQC — but 0.4% of a large estate legitimately reads 0%.
    expect(at(0.4)).toBe(0);
    expect(Number.isInteger(at(12.3456))).toBe(true);
  });

  it('keeps new-tenant and loading states at zero', () => {
    expect(getDashboardPqcMetric(undefined)).toEqual({
      adoptionPercent: 0,
      pqcReady: 0,
      total: 0,
      needsMigration: 0,
      unclassified: 0,
    });
  });
});

describe('dashboard discovery fleet metric', () => {
  // The exact fleet that produced the bug report: 2 sensors + 2 agents reading
  // "3/3 sensors". Three rows come from /sensors (one of which is the seeded
  // platform interrogation AGENT) and one registered agent from /agents was not
  // counted at all.
  const sensorRows = [
    { name: 'Platform Discovery Sensor', status: 'active', profile: 'discovery', sensor_type: 'network', tags: ['system', 'platform', 'discovery'] },
    { name: 'Platform Device Interrogation Agent', status: 'active', profile: 'device_interrogation', sensor_type: 'api', tags: ['system', 'platform', 'device_interrogation'] },
    { name: 'winsensor1', status: 'active', profile: 'datacenter_host', sensor_type: 'network', tags: [] },
  ];
  const agentRows = [{ name: 'win-device-agent-1', status: 'active' }];

  it('counts both fleets and splits sensors from agents', () => {
    const fleet = getDiscoveryFleetMetric(sensorRows, agentRows);

    expect(fleet.all).toEqual({ online: 4, total: 4 });      // was 3/3
    expect(fleet.sensors).toEqual({ online: 2, total: 2 });
    expect(fleet.agents).toEqual({ online: 2, total: 2 });   // platform agent + registered agent
  });

  it('classifies the platform interrogation agent as an agent, not a sensor', () => {
    expect(isAgentRow(sensorRows[1])).toBe(true);
    expect(isAgentRow(sensorRows[0])).toBe(false);
    expect(isAgentRow(sensorRows[2])).toBe(false);
  });

  it('counts only active rows as online, per fleet', () => {
    const fleet = getDiscoveryFleetMetric(
      [{ ...sensorRows[0], status: 'offline' }, sensorRows[1], sensorRows[2]],
      [{ status: 'inactive' }],
    );

    expect(fleet.sensors).toEqual({ online: 1, total: 2 });
    expect(fleet.agents).toEqual({ online: 1, total: 2 });
    expect(fleet.all).toEqual({ online: 2, total: 4 });
  });

  it('is empty-safe while either query is still loading', () => {
    expect(getDiscoveryFleetMetric(undefined, undefined).all).toEqual({ online: 0, total: 0 });
    expect(getDiscoveryFleetMetric(sensorRows, undefined).agents).toEqual({ online: 1, total: 1 });
  });
});
