// @vitest-environment jsdom
// Discovery → PCAP Upload: a capture whose snapshot length cut its packets
// short completes with almost nothing, and the job row has to say why. A
// 128-byte capture of a busy network once completed with 9 discoveries and no
// hint that 80% of its packets were unreadable.
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ jobs: [] as Record<string, unknown>[] }));
vi.mock('./queries', () => ({ usePcapJobs: () => ({ data: { jobs: mocks.jobs } }) }));
vi.mock('../../lib/clients', () => ({ clients: { sensors: { POST: vi.fn() } } }));
vi.mock('@vistasecurity/primitives/rbac', () => ({
  PermissionGate: ({ children }: { children: ReactNode }) => <>{children}</>,
  TENANT_PERMISSIONS: { pcap: { upload: 'pcap.upload' } },
  usePermissions: () => ({ hasPermission: () => true }),
}));

import { PcapPage, truncationNotice } from './pcap-page';

// Formatted the way the page formats them, so the test holds in any locale.
const cutText = `${(17972).toLocaleString()} of ${(22572).toLocaleString()} packets were cut short to 128 bytes`;

const job = (over: Record<string, unknown>) => ({
  id: 'job-1',
  original_filename: 'br0.pcap',
  file_size_bytes: 3001220,
  status: 'completed',
  discovery_count: 9,
  packet_count: 22572,
  truncated_packet_count: 0,
  created_at: new Date().toISOString(),
  ...over,
});

describe('truncationNotice', () => {
  it('is silent for a full-length capture', () => {
    expect(truncationNotice(job({}))).toBeNull();
  });

  it('names how many packets were cut, of how many, and to what length', () => {
    const n = truncationNotice(job({ truncated_packet_count: 17972, snapshot_length: 128 }));
    expect(n).toContain(cutText);
    expect(n).toContain('tcpdump -s 0');
  });

  it('still warns when the file did not state its snapshot length', () => {
    expect(truncationNotice(job({ truncated_packet_count: 5 }))).toContain('were cut short when captured');
  });
});

describe('PcapPage job row', () => {
  let host: HTMLDivElement;
  let root: Root;
  beforeEach(() => {
    host = document.createElement('div');
    document.body.appendChild(host);
    root = createRoot(host);
  });
  afterEach(() => { act(() => root.unmount()); host.remove(); });

  const render = () => act(async () => {
    root.render(<QueryClientProvider client={new QueryClient()}><PcapPage /></QueryClientProvider>);
  });

  it('shows the truncation notice on a truncated job', async () => {
    mocks.jobs = [job({ truncated_packet_count: 17972, snapshot_length: 128 })];
    await render();
    const note = host.querySelector('[role="note"]');
    expect(note?.textContent).toContain(cutText);
  });

  it('shows no notice on a full-length job', async () => {
    mocks.jobs = [job({})];
    await render();
    expect(host.textContent).toContain('br0.pcap');
    expect(host.querySelector('[role="note"]')).toBeNull();
  });
});
