import { describe, it, expect } from 'vitest';
import { summariseHostObservations, type HeartbeatRow } from './host-observations';

// The sensor's host_observations_* counters are CUMULATIVE, and the history
// endpoint returns heartbeats newest-first. Everything below is about the two
// ways a reader of cumulative counters gets a plausible-looking wrong number:
// summing them, and differencing across a restart.

function beat(uptime: number, counters: Record<string, number> | null): HeartbeatRow {
  return { uptime_seconds: uptime, extra_counters: counters };
}

const c = (emitted: number, queueDropped = 0, pending = 0) => ({
  host_observations_offered: emitted * 3,
  host_observations_decoded: emitted,
  host_observations_emitted: emitted,
  host_observations_malformed: 0,
  host_observations_queue_dropped: queueDropped,
  host_observations_emit_dropped: 0,
  host_observations_coalesce_dropped: 0,
  host_observations_pending: pending,
});

describe('summariseHostObservations', () => {
  it('differences the window rather than summing it', () => {
    // Five heartbeats, newest first. The totals are 500/400/300/200/100, so the
    // window saw 400 — and summing would say 1500.
    const rows = [
      beat(5000, c(500)),
      beat(4000, c(400)),
      beat(3000, c(300)),
      beat(2000, c(200)),
      beat(1000, c(100)),
    ];
    const got = summariseHostObservations(rows);
    expect(got).not.toBeNull();
    expect(got!.emitted).toBe(400);
    expect(got!.sinceRestart).toBe(false);
  });

  it('sums the three drop counters, which are kept apart on the wire', () => {
    const rows = [
      {
        uptime_seconds: 5000,
        extra_counters: {
          host_observations_emitted: 500,
          host_observations_queue_dropped: 10,
          host_observations_emit_dropped: 5,
          host_observations_coalesce_dropped: 2,
        },
      },
      {
        uptime_seconds: 1000,
        extra_counters: {
          host_observations_emitted: 100,
          host_observations_queue_dropped: 1,
          host_observations_emit_dropped: 0,
          host_observations_coalesce_dropped: 0,
        },
      },
    ];
    expect(summariseHostObservations(rows)!.dropped).toBe(16);
  });

  it('reads pending as a level from the newest row, not as a difference', () => {
    // Subjects currently accumulating in the coalescer. Differencing it would
    // report "how much the backlog grew", labelled as the backlog.
    const rows = [beat(5000, c(500, 0, 12)), beat(1000, c(100, 0, 40))];
    expect(summariseHostObservations(rows)!.pending).toBe(12);
  });

  it('says "since restart" when uptime went backwards inside the window', () => {
    // The counters reset with the process, so the window's own figure is not
    // knowable from these rows. 90 (the newest total) is knowable; 90 - 4000
    // is not a number, and 90 alone labelled "last 24h" is a lie.
    const rows = [
      beat(600, c(90)),
      beat(300, c(40)),
      beat(9000, c(4000)), // before the restart: much higher uptime AND total
      beat(8700, c(3900)),
    ];
    const got = summariseHostObservations(rows)!;
    expect(got.sinceRestart).toBe(true);
    expect(got.emitted).toBe(90);
  });

  it('treats a single heartbeat as a total, not a window', () => {
    // One row is not a span. Differencing it against itself would report 0 for
    // a sensor that has seen 500 hosts.
    const got = summariseHostObservations([beat(5000, c(500))])!;
    expect(got.emitted).toBe(500);
    expect(got.sinceRestart).toBe(true);
  });

  it('is null when no heartbeat reported these counters', () => {
    // An older sensor build, or host observation switched off. Absent, not
    // zero: "not running" and "running and seeing nothing" must not look the
    // same, so the caller renders nothing rather than a row of noughts.
    expect(summariseHostObservations([beat(5000, null), beat(1000, null)])).toBeNull();
    expect(summariseHostObservations([])).toBeNull();
  });

  it('ignores heartbeats that carry no counters when some do', () => {
    // A sensor upgraded mid-window: the older rows have no counters at all, so
    // the span is the reporting ones.
    const rows = [beat(5000, c(500)), beat(4000, c(450)), beat(1000, null)];
    const got = summariseHostObservations(rows)!;
    expect(got.emitted).toBe(50);
    expect(got.sinceRestart).toBe(false);
  });

  it('never renders a negative count', () => {
    // A counter moving backwards without a restart is a producer bug; a
    // negative "observations seen" is a worse thing to put on screen than 0.
    const rows = [beat(5000, c(10)), beat(4000, c(900))];
    expect(summariseHostObservations(rows)!.emitted).toBe(0);
  });
});
