// @vitest-environment jsdom
//
// The job history both the sensor and the agent drawer render, MOUNTED: it
// replaced a command list that printed every command's JSON response and grew
// without bound. Pinned here: it shows the last 10 and says how many exist, each
// row is one line until clicked, one click opens that row's detail and a second
// closes it, and the payload is only in the DOM while its row is open.
//
// Follows sensor-extra-tls-ports.jsdom.test.tsx: jsdom + React's own `act`, no
// testing-library.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { JobHistoryList, LogExportPanel, PayloadBlock, recentJobMeta, type LogExportState, type RecentJob } from './runtime-drawer';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const jobs: RecentJob[] = Array.from({ length: 14 }, (_, i) => ({
  id: `job-${i}`,
  title: `Command ${i}`,
  status: i === 0 ? 'failed' : 'completed',
  createdAt: new Date(Date.now() - i * 60_000).toISOString(),
  error: i === 0 ? 'interface eth9 not found' : null,
}));

let host: HTMLDivElement;
let root: Root;

beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});

afterEach(() => {
  act(() => root.unmount());
  host.remove();
});

function render(total?: number) {
  act(() => {
    root.render(
      <JobHistoryList
        jobs={jobs}
        total={total}
        isLoading={false}
        isError={false}
        emptyText="none"
        renderDetail={(id) => <PayloadBlock label="Payload" value={{ job: id }} />}
      />,
    );
  });
}

const rows = () => [...host.querySelectorAll<HTMLButtonElement>('button[aria-expanded]')];

describe('JobHistoryList', () => {
  it('shows the last 10 and how many there are', () => {
    render(31);
    expect(rows()).toHaveLength(10);
    expect(host.textContent).toContain('last 10 of 31');
    expect(host.textContent).toContain('Command 0');
    expect(host.textContent).not.toContain('Command 10');
  });

  it('keeps every row collapsed, with no payload in the DOM, until clicked', () => {
    render();
    expect(rows().every((r) => r.getAttribute('aria-expanded') === 'false')).toBe(true);
    expect(host.querySelector('pre')).toBeNull();
  });

  it('opens one row on click, shows its error and payload, and closes on a second click', () => {
    render();
    act(() => rows()[0].click());
    expect(rows()[0].getAttribute('aria-expanded')).toBe('true');
    expect(host.querySelectorAll('pre')).toHaveLength(1);
    expect(host.querySelector('pre')?.textContent).toContain('"job": "job-0"');
    expect(host.textContent).toContain('interface eth9 not found');

    // Opening another row closes the first.
    act(() => rows()[3].click());
    expect(rows()[0].getAttribute('aria-expanded')).toBe('false');
    expect(host.querySelector('pre')?.textContent).toContain('"job": "job-3"');

    act(() => rows()[3].click());
    expect(host.querySelector('pre')).toBeNull();
  });

  it('labels the in-flight command states instead of printing the raw word', () => {
    expect(recentJobMeta('delivered').l).toBe('Delivered');
    expect(recentJobMeta('acknowledged').l).toBe('Running');
    expect(recentJobMeta('expired').l).toBe('Expired');
    expect(recentJobMeta('pending').l).toBe('Queued');
    expect(recentJobMeta('failed').l).toBe('Failed');
  });

  it('omits an empty payload block rather than drawing {}', () => {
    act(() => root.render(<PayloadBlock label="Payload" value={{}} />));
    expect(host.querySelector('pre')).toBeNull();
  });
});

// The Logs tab both drawers render: the lines read as text, and the fetch
// control matches what can happen next.
describe('LogExportPanel', () => {
  function renderLogs(state: LogExportState, canRequest = true) {
    act(() => {
      root.render(
        <LogExportPanel noun="agent" state={state} canRequest={canRequest} lineCount={200} onLineCount={() => {}} onFetch={() => {}} fetching={false} unsupportedText="cannot send" />,
      );
    });
  }
  const fetchButton = () => [...host.querySelectorAll('button')].find((b) => /Fetch/.test(b.textContent ?? ''));

  it('shows the lines as text, one per line, and offers to fetch again', () => {
    renderLogs({ kind: 'ready', lines: ['first line', 'second line'], receivedAt: '2026-10-23T12:00:00Z' });
    expect(host.querySelector('pre')?.textContent).toBe('first line\nsecond line');
    expect(host.textContent).toContain('2 lines');
    expect(fetchButton()?.textContent).toContain('Fetch again');
    expect(fetchButton()?.disabled).toBe(false);
  });

  it('disables fetching while a request is waiting', () => {
    renderLogs({ kind: 'waiting', requestedAt: new Date().toISOString() });
    expect(host.textContent).toContain('waiting for the agent to check in');
    expect(fetchButton()?.disabled).toBe(true);
  });

  it('offers no fetch to a device that cannot answer, or a viewer who cannot ask', () => {
    renderLogs({ kind: 'unsupported' });
    expect(host.textContent).toContain('cannot send');
    expect(fetchButton()).toBeUndefined();
    renderLogs({ kind: 'none' }, false);
    expect(fetchButton()).toBeUndefined();
  });
});
