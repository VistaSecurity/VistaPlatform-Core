// Reachability for workstream 4.6 (FEATURE_IMPLEMENTATION_FRAMEWORK).
//
// "A feature is done only when it is reachable by a user and gated correctly,
// and no layer ships without its consumer." Three layers landed here and each
// can be orphaned in a way nothing else catches, because every file still
// compiles perfectly with the wiring line deleted:
//
//   - the threshold control exists but Settings → Identification rules never
//     renders it, so the one place a tenant can grant the platform permission
//     to merge their assets is unreachable and the endpoint has no caller;
//   - the auto-merged record exists but Approvals never renders it, so the one
//     unattended act in the pipeline reports nowhere — "a capability that acts
//     unasked and reports nowhere is indistinguishable from a bug";
//   - the score's reasons exist on the candidate but the card never shows
//     them, so a reviewer is back to rubber-stamping a number.
//
// So this reads the sources. The unit tests next door cover what the helpers
// COMPUTE; this covers whether anything calls them.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { SETTINGS_NAV } from '../settings/nav';
import { AUTO_MERGED_CAPTION } from './auto-merged-section';

const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');
const approvalsPage = read('./approvals-page.tsx');
const mergeRow = read('./merge-proposal-row.tsx');
const settingsPage = read('../settings/settings-page.tsx');
const identificationPage = read('../settings/pages-classes.tsx');

describe('the auto-accept threshold is reachable', () => {
  const item = SETTINGS_NAV
    .flatMap((s) => s.items.map((i) => ({ ...i, section: s.section })))
    .find((i) => i.key === 'identification-rules');

  it('has a nav entry under Policies, marked built', () => {
    // The negative polarity of the same fact: an entry left `built: false`
    // renders the "arrives in a later release" placeholder over a live
    // endpoint, which is worse than either shipping it or not.
    expect(item).toBeDefined();
    expect(item?.section).toBe('Policies');
    expect(item?.built).toBe(true);
  });

  it('the nav entry SAYS the page decides something, not just displays it', () => {
    // The job line is what a tenant reads before clicking. While the page was
    // read-only it said "See how a discovered thing is matched"; a page that
    // now grants an unattended merge permission and still advertises itself as
    // a viewer is a gate nobody knows is there.
    expect(item?.job).toMatch(/decide|accept/i);
  });

  it('the settings router dispatches that key to the page', () => {
    expect(settingsPage).toMatch(/case 'identification-rules':\s*return <IdentificationRulesPage/);
  });

  it('the page RENDERS the threshold card', () => {
    // The wiring line. Delete `<AutoAcceptCard />` and the control vanishes
    // with everything still compiling, every unit test still green, and the
    // PUT endpoint left with no caller in the product.
    expect(identificationPage).toContain("import { AutoAcceptCard }");
    expect(identificationPage).toMatch(/<AutoAcceptCard\s*\/>/);
  });

  it('RENDERS the scope note, and renders it unconditionally', () => {
    // The constant existing is not the disclosure; showing it is. And it must
    // sit in the always-visible help text rather than inside the `pct > 0`
    // warning block — someone deciding whether to turn the threshold ON is
    // exactly who needs to know what it would not cover.
    const card = read('../settings/auto-accept-card.tsx');
    expect(card).toMatch(/\{THRESHOLD_SCOPE_NOTE\}/);
    const gated = card.slice(card.indexOf('{pct > 0 && ('));
    expect(gated).not.toMatch(/\{THRESHOLD_SCOPE_NOTE\}/);
  });

  it('no longer claims the threshold "arrives in a later release"', () => {
    // It shipped. A page that ships the control and still tells the reader it
    // has not is the same lie as a placeholder over a live endpoint.
    expect(identificationPage).not.toMatch(/auto-merge confidence threshold arrive/i);
  });
});

describe('what the matcher merged unasked is reachable', () => {
  it('Approvals asks for it', () => {
    expect(approvalsPage).toContain('useAutoAcceptedMerges');
  });

  it('Approvals RENDERS the section', () => {
    expect(approvalsPage).toContain("import { AutoMergedSection }");
    expect(approvalsPage).toMatch(/<AutoMergedSection/);
  });

  it('the caption states plainly that a merge cannot be reversed', () => {
    // A tenant reading this list is looking at merges that already happened,
    // and the question the list invites is "can I put that back?". It has to
    // be answered here, not only on the settings page that turned the
    // capability on months ago.
    expect(AUTO_MERGED_CAPTION).toMatch(/no way to reverse|cannot be reversed|cannot be undone/i);
  });
});

describe('a candidate score shows its working', () => {
  it('the card renders the reasons under the bar', () => {
    // Delete `<ScoreReasons candidate={candidate} />` and the score is a bare
    // number again — reviewable only by agreeing with it.
    expect(mergeRow).toMatch(/<ScoreReasons\s+candidate=/);
  });

  it('the reasons come from the candidate explanation, not from a re-derivation', () => {
    expect(mergeRow).toMatch(/topReasons\(candidate\)/);
    expect(mergeRow).toMatch(/c\.explanation \?\? \[\]/);
  });
});
