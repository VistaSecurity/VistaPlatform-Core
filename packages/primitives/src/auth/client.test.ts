import { afterEach, describe, expect, it, vi } from 'vitest';
import { createAuthClient, PlatformAccountError, PLATFORM_ACCOUNT_CODE } from './client';

function respondWith(status: number, body: unknown) {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })));
}

afterEach(() => vi.unstubAllGlobals());

describe('login: platform credentials at the tenant sign-in (#2458)', () => {
  it('throws PlatformAccountError naming the admin host and carrying the URL', async () => {
    respondWith(403, { error: 'This is a platform account.', code: PLATFORM_ACCOUNT_CODE, admin_url: 'https://admin.example.test' });
    const err = await createAuthClient('http://localhost').login('a@b.test', 'pw').catch((e) => e);
    expect(err).toBeInstanceOf(PlatformAccountError);
    expect(err.message).toBe('This is a platform account. Sign in at admin.example.test instead.');
    expect(err.adminUrl).toBe('https://admin.example.test/');
  });

  it('falls back to the server sentence when no usable admin URL came back', async () => {
    respondWith(403, { error: 'Platform account, use the console.', code: PLATFORM_ACCOUNT_CODE, admin_url: 'javascript:alert(1)' });
    const err = await createAuthClient('http://localhost').login('a@b.test', 'pw').catch((e) => e);
    expect(err).toBeInstanceOf(PlatformAccountError);
    expect(err.adminUrl).toBeNull();
    expect(err.message).toBe('Platform account, use the console.');
  });

  it('leaves every other failure a plain Error', async () => {
    respondWith(401, { error: 'Invalid email or password' });
    const err = await createAuthClient('http://localhost').login('a@b.test', 'pw').catch((e) => e);
    expect(err).not.toBeInstanceOf(PlatformAccountError);
    expect(err.message).toBe('Invalid email or password');
  });
});
