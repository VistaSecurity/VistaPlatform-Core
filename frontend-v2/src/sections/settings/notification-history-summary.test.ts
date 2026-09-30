import { expect, it } from 'vitest';
import { deliverySummary } from './notification-history-summary';

const results = (...r: Array<Record<string, unknown>>) => ({ channel_results: r });

it('a fan-out where one channel failed is not shown as a plain success', () => {
  const s = deliverySummary({
    status: 'partial',
    channels_used: ['in_app'],
    metadata: results(
      { channel_id: 'a', channel_type: 'in_app', status: 'sent' },
      { channel_id: 'b', channel_type: 'email', status: 'retrying' },
    ),
  });
  expect(s.text).toBe('in_app ✓, email ✗ (retrying)');
  expect(s.tone).toBe('warn');
  expect(s.attention).toBe(true);
});

it('says a matched-but-failed row FAILED, not "no rule matched"', () => {
  const failed = deliverySummary({
    status: 'failed',
    channels_used: [],
    metadata: results({ channel_id: 'a', channel_type: 'webhook', status: 'failed', retries_exhausted: true }),
  });
  expect(failed.text).toBe('webhook ✗ (gave up)');
  expect(failed.tone).toBe('bad');

  // A row from before channel_results existed still must not claim no rule matched.
  const legacy = deliverySummary({ status: 'failed', channels_used: [], metadata: {} });
  expect(legacy.text).toBe('delivery failed');
});

it('keeps the no-rule-matched wording for a row nothing was attempted for', () => {
  const s = deliverySummary({ status: 'sent', channels_used: [], metadata: { no_matching_channels: true } });
  expect(s.text).toBe('— (no rule matched)');
});

it('a fully delivered row is quiet', () => {
  const s = deliverySummary({
    status: 'sent',
    channels_used: ['in_app', 'email'],
    metadata: results(
      { channel_id: 'a', channel_type: 'in_app', status: 'sent' },
      { channel_id: 'b', channel_type: 'email', status: 'sent' },
    ),
  });
  expect(s).toEqual({ text: 'in_app ✓, email ✓', tone: 'ok', attention: false });
});

it('a recovered retry reads as delivered', () => {
  const s = deliverySummary({
    status: 'sent',
    channels_used: ['in_app', 'email'],
    metadata: results(
      { channel_id: 'a', channel_type: 'in_app', status: 'sent' },
      { channel_id: 'b', channel_type: 'email', status: 'sent' },
    ),
  });
  expect(s.attention).toBe(false);
});

it('tolerates missing / malformed metadata and falls back to channels_used', () => {
  expect(deliverySummary({ status: 'sent', channels_used: ['email'], metadata: null }).text).toBe('email');
  expect(deliverySummary({ status: 'sent', channels_used: ['email'], metadata: { channel_results: 'nope' } }).text).toBe('email');
  expect(deliverySummary({ status: 'partial', channels_used: ['email'] }).attention).toBe(true);
});

// A row routed ONLY to digest channels has nothing sent yet, by design — it used
// to read "no rule matched", the opposite of what happened.
it('a digest-only row reads as queued for digest, not "no rule matched"', () => {
  const s = deliverySummary({ status: 'pending', channels_used: [], metadata: { digest_queued_channels: 2 } });
  expect(s.text).toBe('queued for digest (2 channels)');
  expect(s.text).not.toContain('no rule matched');
  expect(s).toMatchObject({ tone: 'ok', attention: false });
  expect(deliverySummary({ status: 'pending', channels_used: [], metadata: { digest_queued_channels: 1 } }).text).toBe('queued for digest (1 channel)');
});

it('an immediate + digest row keeps the immediate outcome and notes the queued channels', () => {
  const s = deliverySummary({
    status: 'sent',
    channels_used: ['in_app'],
    metadata: { digest_queued_channels: 1, channel_results: [{ channel_id: 'a', channel_type: 'in_app', status: 'sent' }] },
  });
  expect(s.text).toBe('in_app ✓ · 1 queued for digest');
});

it('a pending row with no digest marker still reads as no rule matched', () => {
  expect(deliverySummary({ status: 'pending', channels_used: [], metadata: {} }).text).toBe('— (no rule matched)');
  expect(deliverySummary({ status: 'pending', channels_used: [], metadata: { digest_queued_channels: 0 } }).text).toBe('— (no rule matched)');
});

it("surfaces each failed channel's reason for the cell tooltip", () => {
  const s = deliverySummary({
    status: 'failed',
    channels_used: [],
    metadata: results(
      { channel_id: 'a', channel_type: 'email', status: 'failed', reason: "Email delivery isn't configured by the platform operator." },
      { channel_id: 'b', channel_type: 'webhook', status: 'retrying', reason: 'The destination did not respond in time.' },
      { channel_id: 'c', channel_type: 'in_app', status: 'sent' },
    ),
  });
  expect(s.detail).toBe("email: Email delivery isn't configured by the platform operator.\nwebhook: The destination did not respond in time.");
  // A delivered channel never contributes a reason, and a clean row has no detail at all.
  expect(deliverySummary({ status: 'sent', channels_used: ['in_app'], metadata: results({ channel_id: 'c', channel_type: 'in_app', status: 'sent', reason: 'stale' }) })).not.toHaveProperty('detail');
});
