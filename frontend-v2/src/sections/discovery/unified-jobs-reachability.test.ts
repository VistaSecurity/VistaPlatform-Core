// Reachability for the unified Discovery → Discovery Jobs page (morning-notes
// decision 7b, FEATURE_IMPLEMENTATION_FRAMEWORK).
//
// "A feature is done only when it is reachable by a user and gated correctly,
// and no layer ships without its consumer." Each of these compiles perfectly
// with the wiring deleted:
//
//   - unified-jobs.ts computes the merge/filter/label rules, but jobs-page.tsx
//     never calls mergeJobs — the page renders only device-interrogation rows,
//     same as before this feature (discovery_jobs silently vanish again);
//   - useDiscoveryJobs exists in queries.ts, but nothing calls it — the same
//     "endpoint nothing calls" reachability violation 93edc38b removed once;
//   - the nav entry and route already exist (Discovery → Discovery Jobs), but
//     a route with no new consumer inside it is still dead weight;
//   - the detail modal exists but no row opens it, so a discovery/automatic
//     job's dispatch timeline and findings split are unreachable;
//   - the Go route exists but is not registered in all three of the legacy
//     v1 group, the /api/v2 prefix and the plain /api/v1 group inventory-service
//     actually serves through.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');
const jobsPage = read('./jobs-page.tsx');
const queries = read('./queries.ts');
const nav = read('../../app/nav.ts');
const mainGo = read('../../../../services/inventory-service/cmd/main.go');
const discoveryHandlersGo = read('../../../../services/inventory-service/internal/handlers/discovery_handlers.go');

describe('Discovery → Discovery Jobs — unified page', () => {
  it('has a nav entry (no new route needed — it extends the existing page)', () => {
    expect(nav).toMatch(/path: '\/discovery\/jobs', label: 'Discovery Jobs'/);
  });

  it('fetches both job sources and merges them, not just one', () => {
    expect(jobsPage).toMatch(/useJobs\(\)/);
    expect(jobsPage).toMatch(/useDiscoveryJobs\(\)/);
    expect(jobsPage).toMatch(/mergeJobs\(/);
  });

  it('the discovery-jobs query hook actually calls the list route', () => {
    expect(queries).toMatch(/useDiscoveryJobs/);
    expect(queries).toMatch(/GET\('\/discovery\/jobs'/);
  });

  it('renders Kind/Status/Executor filters wired to filterRows', () => {
    expect(jobsPage).toMatch(/aria-label="Filter by kind"/);
    expect(jobsPage).toMatch(/aria-label="Filter by status"/);
    expect(jobsPage).toMatch(/aria-label="Filter by executor"/);
    expect(jobsPage).toMatch(/filterRows\(/);
  });

  it('opens the discovery-job detail modal from a row click, not just the interrogation one', () => {
    expect(jobsPage).toMatch(/setSelectedDiscovery/);
    expect(jobsPage).toMatch(/<DiscoveryJobDetailModal job=\{selectedDiscovery\}/);
  });

  it('is gated on discovery.update for its write actions, same as the interrogation table', () => {
    expect(jobsPage).toMatch(/TENANT_PERMISSIONS\.discovery\.update/);
  });

  it('the Go list route is registered in the v1, apiv2, and legacy-prefix groups inventory-service actually serves', () => {
    const legs = mainGo.split('\n').filter((l) => l.includes('discovery/jobs"') && l.includes('discoveryHandler.ListJobs'));
    expect(legs.length, 'expected 3 GET .../discovery/jobs routes bound to ListJobs (v1, apiv2, legacy /discovery prefix)').toBe(3);
  });

  it('the Go handler proxies to cluster-sensor-service rather than answering locally', () => {
    expect(discoveryHandlersGo).toMatch(/func \(h \*DiscoveryHandler\) ListJobs/);
    expect(discoveryHandlersGo).toMatch(/GetClusterSensorURL\(\) \+ "\/api\/v1\/discovery\/jobs"/);
  });
});
