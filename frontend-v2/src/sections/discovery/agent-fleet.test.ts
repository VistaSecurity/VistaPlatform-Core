import { describe, it, expect } from 'vitest';
import { profileLabel, jobsSummary, hostSummary, addressTooltip } from './agent-fleet';

// A discovery agent used to be rendered through the sensor table, which had no
// column for any of this — so every one of these values existed in the database
// and reached the browser only to be dropped. These tests pin what the dedicated
// Discovery agents table shows instead.

const minutesAgo = (n: number) => new Date(Date.now() - n * 60_000).toISOString();

describe('profileLabel', () => {
  it('renders the one shipped profile in the operator\'s words, not the enum', () => {
    expect(profileLabel('device_interrogation')).toBe('Network devices');
  });

  it('passes an unrecognized profile through rather than blanking the column', () => {
    // A profile added later must be visible, not silently swallowed — the
    // column exists to say what the agent is allowed to interrogate.
    expect(profileLabel('cloud_interrogation')).toBe('cloud_interrogation');
  });

  it('falls back to a dash when the agent carries no profile', () => {
    expect(profileLabel(null)).toBe('—');
    expect(profileLabel(undefined)).toBe('—');
  });
});

describe('jobsSummary', () => {
  it('distinguishes an enrolled-but-never-used agent', () => {
    // The case the old table could not express at all: registered, online,
    // and has never been given a thing to do.
    expect(jobsSummary({ job_count: 0, last_job_at: null })).toEqual({
      last: 'Never run',
      count: '',
    });
  });

  it('reports both when the agent has run work', () => {
    const s = jobsSummary({ job_count: 47, last_job_at: minutesAgo(120) });
    expect(s.count).toBe('47 jobs');
    expect(s.last).not.toBe('Never run');
  });

  it('singularizes a single job', () => {
    expect(jobsSummary({ job_count: 1, last_job_at: minutesAgo(5) }).count).toBe('1 job');
  });

  it('shows an agent that has gone quiet as a stale timestamp, not as never-run', () => {
    // count > 0 with an old timestamp is the "went quiet" signal; neither
    // number alone could tell it apart from "never used".
    const s = jobsSummary({ job_count: 12, last_job_at: minutesAgo(60 * 24 * 30) });
    expect(s.count).toBe('12 jobs');
    expect(s.last).not.toBe('Never run');
  });
});

describe('hostSummary', () => {
  it('prefers the self-reported primary address and counts the rest', () => {
    expect(hostSummary({
      ip_address: '192.0.2.173',
      addresses: [
        { address: '192.0.2.173', is_primary: true },
        { address: '198.51.100.20', is_primary: false },
      ],
      job_count: 0,
    })).toEqual({ primary: '192.0.2.173', extra: '+1 more address' });
  });

  it('pluralizes several extra addresses', () => {
    expect(hostSummary({
      ip_address: '192.0.2.173',
      addresses: [
        { address: '192.0.2.173', is_primary: true },
        { address: '198.51.100.20', is_primary: false },
        { address: '203.0.113.7', is_primary: false },
      ],
      job_count: 0,
    }).extra).toBe('+2 more addresses');
  });

  it('falls back to the inventory primary when the agent reported no ip_address', () => {
    // Older agents predate primary-address self-reporting but still send their
    // address inventory; the column should not go blank for them.
    expect(hostSummary({
      ip_address: null,
      addresses: [
        { address: '198.51.100.20', is_primary: false },
        { address: '192.0.2.173', is_primary: true },
      ],
      job_count: 0,
    })).toEqual({ primary: '192.0.2.173', extra: '+1 more address' });
  });

  it('falls back to any address when none is flagged primary', () => {
    expect(hostSummary({
      ip_address: null,
      addresses: [{ address: '198.51.100.20', is_primary: false }],
      job_count: 0,
    })).toEqual({ primary: '198.51.100.20', extra: '' });
  });

  it('is blank only when the agent has genuinely reported nothing', () => {
    expect(hostSummary({ ip_address: null, addresses: [], job_count: 0 }))
      .toEqual({ primary: '—', extra: '' });
    expect(hostSummary({ job_count: 0 })).toEqual({ primary: '—', extra: '' });
  });

  it('does not count the primary twice when it is absent from the inventory', () => {
    // ip_address is refreshed on every heartbeat; agent_addresses is rebuilt
    // from the same report, but a partial report could leave them disagreeing.
    expect(hostSummary({
      ip_address: '192.0.2.173',
      addresses: [{ address: '198.51.100.20', is_primary: false }],
      job_count: 0,
    })).toEqual({ primary: '192.0.2.173', extra: '+1 more address' });
  });
});

describe('addressTooltip', () => {
  it('renders every address with its interface and prefix', () => {
    // The cell can only show the primary; this is where "which segments is
    // this agent on?" is actually answerable, and the prefix is the part that
    // turns an address into a segment.
    expect(addressTooltip({
      job_count: 0,
      addresses: [
        { address: '192.0.2.173', is_primary: true, interface_name: 'Ethernet', prefix_length: 24 },
        { address: '198.51.100.20', is_primary: false, interface_name: 'Ethernet 2', prefix_length: 24 },
      ],
    })).toBe('Ethernet 192.0.2.173/24 · Ethernet 2 198.51.100.20/24');
  });

  it('omits the prefix when the agent reported a bare address', () => {
    expect(addressTooltip({
      job_count: 0,
      addresses: [{ address: '192.0.2.173', is_primary: true, interface_name: 'eth0', prefix_length: null }],
    })).toBe('eth0 192.0.2.173');
  });

  it('is empty when there is nothing to show, so the caller can omit the attribute', () => {
    expect(addressTooltip({ job_count: 0, addresses: [] })).toBe('');
    expect(addressTooltip({ job_count: 0 })).toBe('');
  });
});
