// Guards for the "Re-evaluate now" control (Risk & Compliance → Posture).
//
// The headline assertion is the first one: the button must be DISABLED for the
// whole cooldown. A control that is clickable and then answers 429 is the exact
// defect this release removed across a dozen surfaces — and it is invisible in a
// screenshot, which is why it needs a test.
import { describe, it, expect } from 'vitest';
import { countdownLabel, reevaluateControlView, relativeSince } from './reevaluate-control';

const NOW = Date.parse('2026-08-16T12:00:00Z');
const iso = (offsetMs: number) => new Date(NOW + offsetMs).toISOString();

describe('reevaluateControlView', () => {
  it('disables the control for the whole cooldown', () => {
    const v = reevaluateControlView(
      { allowed: false, last_requested_at: iso(-10 * 60_000), next_allowed_at: iso(50 * 60_000) },
      NOW,
    );
    expect(v.blocked).toBe(true);
    expect(v.disabled).toBe(true);
    expect(v.subtitle).toBe('Available in 50m');
  });

  it('enables it once the cooldown has elapsed', () => {
    const v = reevaluateControlView(
      { allowed: true, last_requested_at: iso(-3 * 3600_000), next_allowed_at: null },
      NOW,
    );
    expect(v.blocked).toBe(false);
    expect(v.disabled).toBe(false);
    expect(v.subtitle).toBe('Last re-evaluated 3h ago');
  });

  it('re-enables from the timestamp, not the stale `allowed` flag', () => {
    // The state is polled every 30s; between polls `allowed:false` can be up to
    // half a minute out of date. Without this the button stays dead after the
    // hour is genuinely up, which reads as broken.
    const v = reevaluateControlView(
      { allowed: false, last_requested_at: iso(-3600_000), next_allowed_at: iso(-1_000) },
      NOW,
    );
    expect(v.blocked).toBe(false);
    expect(v.disabled).toBe(false);
  });

  it('treats "we have not heard from the server yet" as disabled', () => {
    // Enabling on unknown state is a guess, and a wrong guess is a failed click.
    expect(reevaluateControlView(undefined, NOW, { loading: true }).disabled).toBe(true);
    expect(reevaluateControlView(undefined, NOW).disabled).toBe(true);
  });

  it('disables while a request is in flight so one click cannot become two', () => {
    const v = reevaluateControlView(
      { allowed: true, last_requested_at: null, next_allowed_at: null },
      NOW,
      { pending: true },
    );
    expect(v.disabled).toBe(true);
  });

  it('says "Not re-evaluated yet" rather than inventing a date', () => {
    const v = reevaluateControlView({ allowed: true, last_requested_at: null, next_allowed_at: null }, NOW);
    expect(v.subtitle).toBe('Not re-evaluated yet');
    expect(v.disabled).toBe(false);
  });
});

describe('countdownLabel', () => {
  it('never renders a blocked cooldown as "now"', () => {
    expect(countdownLabel(1)).toBe('1s');
    expect(countdownLabel(59)).toBe('59s');
    expect(countdownLabel(61)).toBe('2m');
    expect(countdownLabel(0)).toBe('now');
  });
});

describe('relativeSince', () => {
  it('returns null for a missing timestamp rather than a fake one', () => {
    expect(relativeSince(null, NOW)).toBeNull();
    expect(relativeSince(undefined, NOW)).toBeNull();
    expect(relativeSince('not-a-date', NOW)).toBeNull();
  });

  it('reads in coarse units', () => {
    expect(relativeSince(iso(-30_000), NOW)).toBe('just now');
    expect(relativeSince(iso(-15 * 60_000), NOW)).toBe('15m ago');
    expect(relativeSince(iso(-5 * 3600_000), NOW)).toBe('5h ago');
    expect(relativeSince(iso(-3 * 24 * 3600_000), NOW)).toBe('3d ago');
  });
});
