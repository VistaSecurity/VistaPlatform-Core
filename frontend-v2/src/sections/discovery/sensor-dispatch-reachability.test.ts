// Reachability for tenant-sensor dispatch, FEATURE_IMPLEMENTATION_FRAMEWORK.
//
// "A feature is done only when it is reachable by a user and gated correctly,
// and no layer ships without its consumer." Each of these compiles perfectly
// with the wiring deleted:
//
//   - the "Run from" helpers exist but the Active Scan page never renders the
//     select or sends `run_from`, so every scan silently runs from the platform;
//   - the job-state helpers exist but the Active Scan page never renders its
//     feedback panel, so a scan handed to a sensor vanishes when the toast
//     fades and "failed: sensor offline" is visible to nobody;
//   - the settings run list carries the executor and failure fields but
//     renders the bare status word, so the same failure is invisible there;
//   - the settings form carries the switch but the page never renders it, so
//     the policy field is written by nothing.
//
// Discovery → Discovery Jobs listed only device interrogations from
// through 93edc38b (same-day correction: a scans table existed but nothing
// else pointed at the endpoint that fed it, so it was removed rather than
// shipped unreachable). Morning-notes decision 7b is the real
// listing page this deferred to: see unified-jobs-reachability.test.ts for
// its own reachability coverage.
//
// The unit tests next door cover what the helpers COMPUTE; this covers whether
// anything reaches them.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');
const activeScanPage = read('./active-scan-page.tsx');
const panel = read('./active-scan-jobs-panel.tsx');
const queries = read('./queries.ts');
const settingsPage = read('../settings/pages-auto-scan.tsx');

describe('Active Scan → Run from', () => {
  it('renders the select and sends the chosen executor with the scan', () => {
    expect(activeScanPage).toMatch(/aria-label="Run from"/);
    expect(activeScanPage).toMatch(/runFromOptions\(/);
    expect(activeScanPage).toMatch(/scanRequestBody\(ids, choice\)/);
  });

  it('says every state out loud: loading disables, error and no-sensors fall back to the platform', () => {
    expect(activeScanPage).toMatch(/disabled=\{runFrom\.loading/);
    expect(activeScanPage).toMatch(/runFrom\.error &&/);
    expect(activeScanPage).toMatch(/runFrom\.noTenantSensors &&/);
    expect(activeScanPage).toMatch(/Sensors &amp; Agents/);
  });

  it('names the executor in the toast rather than a bare "started"', () => {
    expect(activeScanPage).toMatch(/describeScanResult\(r\)/);
  });

  it('is gated on assets.update — the permission follows the action, not the executor', () => {
    expect(activeScanPage).toMatch(/TENANT_PERMISSIONS\.assets\.update/);
    expect(activeScanPage).not.toMatch(/TENANT_PERMISSIONS\.sensors\./);
  });
});

describe("Active Scan → the page's own job feedback", () => {
  it('keeps every job the scan started and renders the panel', () => {
    expect(activeScanPage).toMatch(/setStarted\(/);
    expect(activeScanPage).toMatch(/setSkipped\(/);
    expect(activeScanPage).toMatch(/<ActiveScanJobsPanel scans=\{started\} skipped=\{skipped\} \/>/);
  });

  it('polls the job, and renders executor, state and the dispatch timeline from the existing job route', () => {
    expect(queries).toMatch(/GET\('\/discovery\/jobs\/\{id\}'/);
    expect(queries).toMatch(/refetchInterval/);
    expect(panel).toMatch(/useScanJob\(scan\.jobId\)/);
    expect(panel).toMatch(/scanJobState\(job\)/);
    expect(panel).toMatch(/executorLabel\(job\)/);
    expect(panel).toMatch(/dispatchTimeline\(job\)/);
  });
});

describe('Settings → Active Scanning', () => {
  it('renders the "Prefer the observing sensor" switch and writes it into the policy', () => {
    expect(settingsPage).toMatch(/label="Prefer the observing sensor"/);
    expect(settingsPage).toMatch(/set\('preferObservingSensor', v\)/);
    expect(read('../settings/auto-scan-form.ts')).toMatch(/prefer_observing_sensor: draft\.preferObservingSensor/);
  });

  it('shows the executor and the dispatch state beside each automatic scan', () => {
    expect(settingsPage).toMatch(/job\.executor === 'sensor'/);
    expect(settingsPage).toMatch(/scanJobState\(scanJobFromRecent\(job\)\)/);
    expect(settingsPage).toMatch(/<RunState job=\{job\} \/>/);
  });
});
