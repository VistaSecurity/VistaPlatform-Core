import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const caddyfile = readFileSync(new URL('../../Caddyfile', import.meta.url), 'utf8');
const csp = caddyfile.match(/Content-Security-Policy\s+"([^"]+)"/)?.[1];

describe('production browser security headers', () => {
  it('ships a restrictive content security policy', () => {
    expect(csp, 'Caddyfile must define Content-Security-Policy').toBeTruthy();
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("base-uri 'self'");
    expect(csp).toContain("form-action 'self'");
  });

  it('disables the deprecated browser XSS auditor', () => {
    expect(caddyfile).toMatch(/X-XSS-Protection\s+"0"/);
    expect(caddyfile).not.toMatch(/X-XSS-Protection\s+"1/);
  });
});
