// The elevation export (DCIM row 2.5): CSS custom properties resolve to real
// colours so the downloaded SVG/PNG renders without the app's stylesheet.
import { describe, expect, it } from 'vitest';
import { exportFilename, inlineCssVars } from './rack-export';

describe('inlineCssVars', () => {
  const vars: Record<string, string> = { '--danger': '#e5484d', '--accent': ' #7c5cff ' };
  const resolve = (n: string) => vars[n] ?? '';
  it('replaces every var() with its computed value', () => {
    expect(inlineCssVars('<rect fill="var(--danger)" stroke="var(--accent)"/>', resolve)).toBe('<rect fill="#e5484d" stroke="#7c5cff"/>');
  });
  it('falls back to the declared fallback, then to a neutral colour', () => {
    expect(inlineCssVars('fill="var(--missing, #123456)"', resolve)).toBe('fill="#123456"');
    expect(inlineCssVars('fill="var(--missing)"', resolve)).toBe('fill="#888888"');
    expect(inlineCssVars('fill="var(--missing, var(--danger))"', resolve)).toBe('fill="#e5484d"');
  });
  it('leaves no var( behind', () => {
    expect(inlineCssVars('a var(--x) b var(--danger) c', resolve)).not.toContain('var(');
  });
});

it('names the file after the rack and the day', () => {
  expect(exportFilename('R12 / Row 3', 'png', new Date('2026-10-16T09:00:00Z'))).toBe('rack-r12-row-3-2026-10-16.png');
});
