// The Discover wizard's Custom port fields against the SAME cases the
// platform's ParsePortSpec is held to (shared/discovery/testdata/port_specs.json,
// read by shared/discovery/scan_ports_vectors_test.go too), error text included
// — so "8000-8100" means the range in both places (hole H8), and a person
// is told the same thing about "http" before Start as the server would after it.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { formatPortSpec, goQuote, parsePortSpec } from './discover-port-spec';

type Case = {
  input?: string;
  repeat?: { unit: string; times: number; suffix: string };
  count?: number;
  canonical?: string;
  error?: string;
};

const repoRoot = fileURLToPath(new URL('../../../../', import.meta.url));
const { cases } = JSON.parse(readFileSync(repoRoot + 'shared/discovery/testdata/port_specs.json', 'utf8')) as { cases: Case[] };
const inputOf = (c: Case) => (c.repeat ? c.repeat.unit.repeat(c.repeat.times) + c.repeat.suffix : c.input ?? '');

describe('port specs (#2170 H8) — shared with the platform', () => {
  it('loads the shared cases', () => {
    // A table that loads nothing passes everything.
    expect(cases.length).toBeGreaterThan(20);
  });

  cases.forEach((c, i) => {
    const input = inputOf(c);
    it(`case ${i}: ${JSON.stringify(input.slice(0, 40))} parses as the platform does`, () => {
      const got = parsePortSpec(input);
      if (c.error !== undefined) {
        expect(got).toEqual({ ok: false, error: c.error });
      } else {
        expect(got.ok).toBe(true);
        if (got.ok) {
          expect(got.ports.length).toBe(c.count);
          expect(got.canonical).toBe(c.canonical);
        }
      }
    });
  });

  it('a range is the range, never its first port', () => {
    const r = parsePortSpec('8000-8100');
    expect(r.ok && r.ports[0]).toBe(8000);
    expect(r.ok && r.ports[r.ports.length - 1]).toBe(8100);
    expect(r.ok && r.ports.length).toBe(101);
  });

  it('formats runs collapsed, like PortSet.String', () => {
    expect(formatPortSpec([22, 80, 81, 82, 443])).toBe('22,80-82,443');
    expect(formatPortSpec([])).toBe('');
  });

  it("quotes like Go's %q", () => {
    expect(goQuote('a"b\\c')).toBe('"a\\"b\\\\c"');
    expect(goQuote('\u0001')).toBe('"\\x01"');
    expect(goQuote('\t')).toBe('"\\t"');
    expect(goQuote('﻿')).toBe('"\\ufeff"');
    expect(goQuote('２ x')).toBe('"２ x"');
  });
});
