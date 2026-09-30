// Platform notification channels: no SMS option (the backend has no SMS sender),
// and a failed Test shows the server's sanitized reason.
//
// Vite `?raw` rather than node:fs — this app has no @types/node.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import PAGE from './notification-delivery-page.tsx?raw';
import { PLATFORM_CHANNEL_TYPES, testFailureReason } from './notification-channel-types';

const api = vi.hoisted(() => ({ POST: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { notifications: api } }));

describe('channel types offered to platform admins', () => {
  it('offers only transports notification-service can deliver — never SMS', () => {
    expect([...PLATFORM_CHANNEL_TYPES]).toEqual(['email', 'slack', 'webhook', 'pagerduty']);
    expect(PLATFORM_CHANNEL_TYPES).not.toContain('sms');
  });

  // The list above is only a guard if the page really uses it.
  it('the page builds its Type select from that list, with no literal channel-type array of its own', () => {
    expect(PAGE).toContain('PLATFORM_CHANNEL_TYPES');
    expect(PAGE).not.toMatch(/['"]sms['"]/);
  });
});

describe('testFailureReason', () => {
  it('uses the sanitized reason the server sends', () => {
    expect(testFailureReason({ status: 'test_failed', error: 'Test failed', reason: "Email delivery isn't configured by the platform operator." }))
      .toBe("Email delivery isn't configured by the platform operator.");
  });

  it('falls back when there is none', () => {
    for (const bad of [undefined, null, {}, { reason: '' }, { reason: 7 }, 'boom']) expect(testFailureReason(bad)).toBe('Test failed');
  });
});

// The request itself: a 422 must throw with the reason (before, only `error`
// truthiness was checked and the text was always the literal 'Test failed').
describe('platformChannelTest', () => {
  beforeEach(() => api.POST.mockReset());

  it('rejects with the server reason on a 422', async () => {
    const { platformChannelTest } = await import('./settings-notifications-queries');
    api.POST.mockResolvedValue({ error: { status: 'test_failed', reason: 'The destination did not respond in time.' }, response: { ok: false, status: 422 } });
    await expect(platformChannelTest('c-1')).rejects.toThrow('The destination did not respond in time.');
  });

  it('resolves on success', async () => {
    const { platformChannelTest } = await import('./settings-notifications-queries');
    api.POST.mockResolvedValue({ data: { status: 'test_sent' }, response: { ok: true, status: 200 } });
    await expect(platformChannelTest('c-1')).resolves.toBeUndefined();
  });
});
