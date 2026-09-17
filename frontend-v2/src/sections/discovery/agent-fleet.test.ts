import { describe, it, expect } from 'vitest';
import { profileLabel, jobsSummary, hostSummary, addressTooltip, isPlatformManaged, hostInventorySummary, isPlatformInterrogationAgent, partitionSensorFleet } from './agent-fleet';

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

describe('isPlatformManaged', () => {
  // Both polarities matter equally. A false negative offers a delete button that
  // silently cuts this workspace's discovery results off from inventory; a false
  // positive takes away a deletion the tenant is entitled to make. The predicate
  // mirrors the server guard (models.Sensor.IsPlatformManaged) exactly.

  it('recognises the rows the provisioning trigger creates', () => {
    expect(isPlatformManaged({
      platform: 'platform',
      tags: ['system', 'platform', 'device_interrogation'],
    })).toBe(true);
    expect(isPlatformManaged({
      platform: 'platform',
      tags: ['system', 'platform', 'discovery'],
    })).toBe(true);
  });

  it('recognises a row carrying only ONE of the two markers', () => {
    // ORed, not ANDed: either marker alone identifies the row, so a partially
    // stamped row cannot slip past the guard.
    expect(isPlatformManaged({ platform: 'platform', tags: [] })).toBe(true);
    expect(isPlatformManaged({ platform: 'linux', tags: ['system'] })).toBe(true);
  });

  it('leaves an ordinary customer-deployed sensor deletable', () => {
    expect(isPlatformManaged({ platform: 'linux', tags: ['edge', 'dc1'] })).toBe(false);
    expect(isPlatformManaged({ platform: 'windows', tags: [] })).toBe(false);
    expect(isPlatformManaged({})).toBe(false);
    expect(isPlatformManaged({ platform: null, tags: null })).toBe(false);
  });

  it('does not key on profile — those values are legitimate for a tenant sensor', () => {
    expect(isPlatformManaged({ platform: 'linux', tags: ['discovery'] })).toBe(false);
    expect(isPlatformManaged({ platform: 'darwin', tags: ['device_interrogation'] })).toBe(false);
  });
});

describe('hostInventorySummary', () => {
  // A host-inventory collection is the agent describing its OWN host, on its own
  // timer, with nobody having queued it. The jobs column therefore cannot say
  // whether it is happening: an agent busy interrogating firewalls that has
  // never reported its own host reads as perfectly healthy on "47 jobs · 2h ago".

  it('says nothing at all for an agent that has never reported one', () => {
    // Rather than "never": an agent deployed purely to interrogate network
    // devices is not misconfigured, and a permanent "never" on every such row
    // trains people to ignore the line.
    expect(hostInventorySummary({ job_count: 47, last_host_inventory_at: null })).toBeNull();
    expect(hostInventorySummary({ job_count: 0 })).toBeNull();
  });

  it('reports when, and what it found', () => {
    const s = hostInventorySummary({
      job_count: 3,
      last_host_inventory_at: minutesAgo(120),
      host_inventory_packages: 412,
      host_inventory_listeners: 18,
    });
    expect(s).toBe('Last host inventory: 2h ago — 412 packages, 18 listeners');
  });

  it('omits the package count when the package step failed, rather than saying zero', () => {
    // The three-valued rule, at the last place it can still be broken. A host
    // whose dpkg could not be read has NOT been enumerated; rendering "0
    // packages" would make that indistinguishable from a host with none.
    const s = hostInventorySummary({
      job_count: 1,
      last_host_inventory_at: minutesAgo(30),
      host_inventory_packages: null,
      host_inventory_listeners: 18,
    });
    expect(s).toBe('Last host inventory: 30m ago — 18 listeners');
  });

  it('keeps an explicit zero, which is an answer', () => {
    // Zero packages from a step that SUCCEEDED is a real measurement — a
    // minimal container image genuinely has no package-database entries — and
    // it must not be dropped the way an absent count is.
    const s = hostInventorySummary({
      job_count: 1,
      last_host_inventory_at: minutesAgo(5),
      host_inventory_packages: 0,
      host_inventory_listeners: 1,
    });
    expect(s).toBe('Last host inventory: 5m ago — 0 packages, 1 listener');
  });

  it('still reports the time when it has no counts to show', () => {
    expect(hostInventorySummary({ job_count: 1, last_host_inventory_at: minutesAgo(10) }))
      .toBe('Last host inventory: 10m ago');
  });
});

describe('isPlatformInterrogationAgent', () => {
  // The in-cluster interrogation agent has a row in `sensors` only so the
  // interrogation pipeline has something to attribute discoveries to
  // (ResultProcessor.lookupSystemSensor). It is a command-driven agent, and the
  // Sensors table showed it with Type "api" and an empty Segment because it has
  // neither. These pin which rows move and, more importantly, which do not.

  const platformInterrogation = {
    platform: 'platform',
    profile: 'device_interrogation',
    tags: ['system', 'platform', 'device_interrogation'],
  };
  const platformDiscovery = {
    platform: 'platform',
    profile: 'discovery',
    tags: ['system', 'platform', 'discovery'],
  };

  it('moves the platform interrogation agent out of the sensor fleet', () => {
    expect(isPlatformInterrogationAgent(platformInterrogation)).toBe(true);
  });

  it('leaves the platform DISCOVERY sensor where it is — that one really is a sensor', () => {
    // Both rows come from the same provisioning trigger and share
    // platform='platform' and the `system` tag. Only the profile separates
    // them, which is why the predicate cannot be isPlatformManaged alone.
    expect(isPlatformInterrogationAgent(platformDiscovery)).toBe(false);
  });

  it('leaves a CUSTOMER sensor carrying the interrogation profile alone', () => {
    // `device_interrogation` is a legitimate profile for a sensor an operator
    // deployed themselves — sensor-manager accepts it at registration. Keying
    // on the profile alone would silently relocate a row its owner put in the
    // sensor fleet, which is the same bug pointed the other way.
    expect(isPlatformInterrogationAgent({ platform: 'linux', profile: 'device_interrogation', tags: ['edge'] })).toBe(false);
    expect(isPlatformInterrogationAgent({ platform: 'darwin', profile: 'device_interrogation' })).toBe(false);
  });

  it('recognises the row from either platform marker, matching isPlatformManaged', () => {
    // A row stamped with only one of the two markers is still platform-managed
    // everywhere else in the product; it must not read as a customer sensor here.
    expect(isPlatformInterrogationAgent({ platform: 'platform', profile: 'device_interrogation' })).toBe(true);
    expect(isPlatformInterrogationAgent({ tags: ['system'], profile: 'device_interrogation' })).toBe(true);
  });

  it('does not move a platform row that has no profile at all', () => {
    expect(isPlatformInterrogationAgent({ platform: 'platform', tags: ['system'] })).toBe(false);
    expect(isPlatformInterrogationAgent({ platform: 'platform', profile: null })).toBe(false);
  });
});

describe('partitionSensorFleet', () => {
  const rows = [
    { id: 'a', platform: 'platform', profile: 'discovery', tags: ['system'] },
    { id: 'b', platform: 'platform', profile: 'device_interrogation', tags: ['system'] },
    { id: 'c', platform: 'linux', profile: 'datacenter_host', tags: [] },
    { id: 'd', platform: 'linux', profile: 'device_interrogation', tags: [] },
  ];

  it('sends only the platform interrogation agent to the agents table', () => {
    const { sensors, interrogationAgents } = partitionSensorFleet(rows);
    expect(interrogationAgents.map((r) => r.id)).toEqual(['b']);
    expect(sensors.map((r) => r.id)).toEqual(['a', 'c', 'd']);
  });

  it('loses nothing — every row lands in exactly one list', () => {
    // The whole reason this is a partition and not two independent filters: a
    // row that fell through both predicates would vanish from the page with
    // nothing anywhere saying so.
    const { sensors, interrogationAgents } = partitionSensorFleet(rows);
    expect(sensors.length + interrogationAgents.length).toBe(rows.length);
  });

  it('handles an empty fleet without inventing rows', () => {
    expect(partitionSensorFleet([])).toEqual({ sensors: [], interrogationAgents: [] });
  });
});
