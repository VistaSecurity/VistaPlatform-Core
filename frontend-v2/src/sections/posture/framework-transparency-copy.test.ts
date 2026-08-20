// B-46 regression guard — a rule-less control must never be described as
// passing.
//
// The engine classifies a control with no measurement rules as NOT_ASSESSED
// (reason no_measurements), excluded from both sides of the score fraction
// (rule_evaluator.go, framework_score.go). Four UI copy sites — the tenant
// Framework Transparency drawer, the tenant Custom Policies rule builder, the
// admin measurement-rules modal, and the customer doc for Custom Policies —
// used to say the opposite ("passes by default"), actively encouraging an
// author to leave a control unmeasured believing it was satisfied.
//
// No render harness exists in this repo for frontend-v2/admin-ui-v2, so this
// pins the fix at the source: none of the four sites may claim a rule-less
// control passes, and each must say it is Not assessed instead.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../../../', import.meta.url));
const read = (rel: string) => readFileSync(repoRoot + rel, 'utf8');

const FORBIDDEN = /passes by default/i;

const SITES = [
  'frontend-v2/src/sections/posture/framework-browser.tsx',
  'frontend-v2/src/sections/settings/custom-policy-detail.tsx',
  'admin-ui-v2/src/sections/catalog/measurement-rules-modal.tsx',
  'docsv4/enterprise/features/custom-policies.md',
];

describe.each(SITES)('B-46: %s', (rel) => {
  it('does not claim a rule-less control "passes by default"', () => {
    const src = read(rel);
    expect(src, `${rel} still claims a rule-less control passes by default`).not.toMatch(FORBIDDEN);
  });

  it('says the control is Not assessed instead', () => {
    const src = read(rel);
    expect(src, `${rel} should describe the rule-less state as Not assessed`).toMatch(/not assessed/i);
  });
});
