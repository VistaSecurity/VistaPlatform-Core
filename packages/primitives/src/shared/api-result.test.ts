import { describe, expect, it } from 'vitest';
import { ApiError, errorMessage, unwrap } from './api-result';

// openapi-fetch hands back `{ data, error, response }`. These build the shapes
// it really produces: a bodiless failure has a FALSY `error` (the case that
// `if (error) throw` waved through), a bodied one carries the parsed JSON.
const res = (status: number) => new Response(null, { status });

describe('unwrap', () => {
  it('throws on a bodiless 500 — falsy `error` must not pass as success', () => {
    let caught: unknown;
    try {
      unwrap({ data: undefined, error: undefined, response: res(500) }, 'Failed to merge');
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).status).toBe(500);
    expect((caught as ApiError).message).toBe('Failed to merge');
    expect((caught as ApiError).fromServer).toBe(false);
  });

  it('throws on a bodiless 403', () => {
    expect(() => unwrap({ response: res(403) }, 'Forbidden fallback')).toThrow('Forbidden fallback');
  });

  it("surfaces the server's own reason instead of the fallback", () => {
    const body = { error: 'scan dispatch is not authorized: probe target belongs to a collector' };
    try {
      unwrap({ error: body, response: res(400) }, 'Failed to start scan');
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(ApiError);
      expect((e as ApiError).message).toBe(body.error);
      expect((e as ApiError).status).toBe(400);
      expect((e as ApiError).body).toBe(body);
      expect((e as ApiError).fromServer).toBe(true);
    }
  });

  it('still throws when `error` is set on an ok-looking response', () => {
    expect(() => unwrap({ error: { message: 'nope' }, response: res(200) }, 'x')).toThrow('nope');
  });

  it('returns the data on success', () => {
    expect(unwrap({ data: { id: 'a' }, response: res(200) }, 'x')).toEqual({ id: 'a' });
  });

  it('returns undefined for a 204 with no body', () => {
    expect(unwrap<undefined>({ response: res(204) }, 'x')).toBeUndefined();
  });

  it('requireData turns an ok response with no body into a failure', () => {
    expect(() => unwrap({ response: res(200) }, 'No body', { requireData: true })).toThrow('No body');
    expect(unwrap({ data: { ok: true }, response: res(200) }, 'x', { requireData: true })).toEqual({ ok: true });
  });
});

describe('errorMessage', () => {
  it('reads the common shapes and ignores the rest', () => {
    expect(errorMessage({ error: ' boom ' })).toBe('boom');
    expect(errorMessage({ message: 'm' })).toBe('m');
    expect(errorMessage({ detail: 'd' })).toBe('d');
    expect(errorMessage({ problems: ['a', 'b'] })).toBe('a; b');
    expect(errorMessage({ errors: [{ message: 'bad', suggestion: 'try x' }] })).toBe('bad — try x');
    expect(errorMessage(undefined)).toBeNull();
    expect(errorMessage('text')).toBeNull();
    expect(errorMessage({ error: '' })).toBeNull();
  });
});
