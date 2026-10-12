import { describe, expect, it } from 'vitest';
import { safeHttpUrl } from './url';

describe('safeHttpUrl', () => {
  it('allows absolute http(s)', () => {
    expect(safeHttpUrl('https://example.com/a')).toBe('https://example.com/a');
    expect(safeHttpUrl('http://example.com')).toBe('http://example.com/');
  });
  it.each(['javascript:alert(1)', 'data:text/html,x', 'vbscript:x', '/relative', '//host/x', '', null, undefined])(
    'rejects %s', (v) => expect(safeHttpUrl(v as string | null | undefined)).toBeNull());
});
