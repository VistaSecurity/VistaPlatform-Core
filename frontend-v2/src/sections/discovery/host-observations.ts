// Passive host observations, as an operator reads them on a sensor.
//
// Kept out of sensor-detail-drawer.tsx so it can be unit-tested directly:
// frontend-v2's vitest runs in the node environment with no jsdom, so a pure
// module is testable where a component is not.
//
// # Why this is not a sum
//
// The sensor's eight `host_observations_*` counters are CUMULATIVE — atomic
// counters incremented since the process started, never reset — and each
// heartbeat carries the running total. Adding them up across a day of
// heartbeats would count every observation once per heartbeat that followed it,
// which on a five-minute interval overstates a day's work by roughly 288×. That
// is not a rounding error; it is a number with no meaning at all, and it would
// look entirely plausible on screen.
//
// So the figure for a window is a DIFFERENCE: the newest total minus the oldest
// one inside it.
//
// # And why the difference needs a restart check
//
// A sensor restart resets the counters to zero, so the newest total can be
// SMALLER than the oldest one in the window and the difference goes negative —
// or, worse, stays positive but undercounts, because the work done before the
// restart is gone from both ends. `uptime_seconds` is on every row and is the
// thing that says a restart happened: uptime only ever increases within one
// process lifetime, so a decrease between two heartbeats is a restart.
//
// When that happens the window's figure is not knowable from these rows, and
// this says so — `sinceRestart: true`, with the newest total, which IS knowable
// — rather than showing a number that means something other than its label.

/** The subset of a health-metrics row this module needs. Structural, so it
 *  accepts the generated API type without importing it. */
export interface HeartbeatRow {
  uptime_seconds: number;
  recorded_at?: string | null;
  extra_counters?: { [key: string]: number } | null;
}

export interface HostObservationSummary {
  /** Observations emitted over the window, or since the restart inside it. */
  emitted: number;
  /** Observations shed rather than emitted, over the same span. Non-zero means
   *  the segment is busier than the sensor is sized for. */
  dropped: number;
  /** Subjects currently accumulating in the coalescer — a LEVEL, not a total,
   *  so it is read from the newest row rather than differenced. */
  pending: number;
  /** True when a restart inside the window makes the window's own figure
   *  unknowable, so the numbers above are "since the restart" instead. */
  sinceRestart: boolean;
}

const EMITTED = 'host_observations_emitted';
const PENDING = 'host_observations_pending';

/** The three ways an observation is shed, summed. They are kept apart on the
 *  wire because they mean different things — ahead of the decoder, behind it,
 *  and at the coalescer's capacity — and summed here because the question this
 *  tile answers is "is this sensor losing hosts", which any of them answers
 *  yes to. The detail is in the raw counters. */
const DROP_KEYS = [
  'host_observations_queue_dropped',
  'host_observations_emit_dropped',
  'host_observations_coalesce_dropped',
];

function counter(row: HeartbeatRow | undefined, key: string): number {
  const v = row?.extra_counters?.[key];
  return typeof v === 'number' ? v : 0;
}

function drops(row: HeartbeatRow | undefined): number {
  return DROP_KEYS.reduce((sum, k) => sum + counter(row, k), 0);
}

/**
 * Summarise host observation activity over a window of heartbeats.
 *
 * `rows` is the history as the API returns it — NEWEST FIRST. Returns null when
 * no row in the window reported these counters at all, which is the honest
 * answer for a sensor running an older build or with host observation switched
 * off: absent, not zero. "Not running" and "running and seeing nothing" must
 * not look the same, so the caller renders nothing rather than a row of noughts.
 */
export function summariseHostObservations(rows: HeartbeatRow[]): HostObservationSummary | null {
  const reporting = rows.filter((r) => r.extra_counters != null && EMITTED in r.extra_counters);
  if (reporting.length === 0) return null;

  const newest = reporting[0];
  const oldest = reporting[reporting.length - 1];
  const pending = counter(newest, PENDING);

  // One heartbeat is a total, not a span. Report it as such rather than
  // differencing a row against itself and calling the result a window.
  if (reporting.length === 1) {
    return { emitted: counter(newest, EMITTED), dropped: drops(newest), pending, sinceRestart: true };
  }

  // Uptime only increases within one process lifetime, so any decrease walking
  // from oldest to newest is a restart — and the counters reset with it.
  let restarted = false;
  for (let i = reporting.length - 1; i > 0; i--) {
    if (reporting[i - 1].uptime_seconds < reporting[i].uptime_seconds) {
      restarted = true;
      break;
    }
  }
  if (restarted) {
    return { emitted: counter(newest, EMITTED), dropped: drops(newest), pending, sinceRestart: true };
  }

  return {
    // Math.max guards the one case uptime cannot see: a counter that moved
    // backwards without a restart would be a producer bug, and a negative
    // "observations seen" is a worse thing to render than a zero.
    emitted: Math.max(0, counter(newest, EMITTED) - counter(oldest, EMITTED)),
    dropped: Math.max(0, drops(newest) - drops(oldest)),
    pending,
    sinceRestart: false,
  };
}
