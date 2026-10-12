// Every rule kind the classifier can emit has a human label.
//
// The Go list is the source of truth, so this reads it rather than a copy: the
// next kind added to shared/classify/rule.go fails here instead of showing a
// raw key in the Approvals queue.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { KIND_LABEL, ruleKindLabel } from './class-rule-labels';

const goSource = readFileSync(
  fileURLToPath(new URL('../../../../shared/classify/rule.go', import.meta.url)), 'utf8',
);

/** The values of the identifiers listed in `var Kinds = []string{...}`. */
export function goRuleKinds(src: string): string[] {
  const consts = new Map<string, string>();
  for (const m of src.matchAll(/^\s*(Kind\w+)\s*=\s*"([a-z0-9_]+)"/gm)) consts.set(m[1], m[2]);
  const list = /var Kinds = \[\]string\{([^}]*)\}/.exec(src);
  if (!list) throw new Error('shared/classify/rule.go no longer declares `var Kinds = []string{...}`');
  return list[1].split(/[\s,]+/).filter(Boolean).map((id) => {
    const v = consts.get(id);
    if (v === undefined) throw new Error(`Kinds names ${id}, which has no string constant`);
    return v;
  });
}

describe('rule kind labels', () => {
  const kinds = goRuleKinds(goSource);

  it('reads a plausible Go list', () => {
    expect(kinds.length).toBeGreaterThanOrEqual(14);
    expect(kinds).toContain('os_name');
    expect(kinds).toContain('dhcp_vendor_class');
  });

  it.each(kinds)('%s has a label that is not the raw key', (kind) => {
    const label = ruleKindLabel(kind);
    expect(label).not.toBe(kind);
    expect(label.trim()).not.toBe('');
  });

  it('labels no kind the classifier cannot emit', () => {
    expect(Object.keys(KIND_LABEL).sort()).toEqual([...kinds].sort());
  });
});
