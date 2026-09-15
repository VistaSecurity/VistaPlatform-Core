// Reachability for the class-history record (seeds part 3, item 1).
//
// "A backend capability with no UI control is a gap, not a feature." The
// `asset_class_history` table, its writer at three call sites, its endpoint and
// its generated client are four layers; without a fifth that a tenant can
// actually look at, the whole thing is invisible to the only people it was
// built for.
//
// This reads the source rather than mounting React, for the reason
// class-proposals-reachability.test.ts does: every assertion below corresponds
// to a deletion that compiles, typechecks and leaves the rest of the suite
// green.
//
//   - drop `<ClassHistoryPanel>` from HistoryTab → the endpoint has no caller
//     and nobody ever sees a reclassification;
//   - drop `useAssetClassHistory` → the panel renders an empty state for ever;
//   - drop the empty-state wording → an asset with no recorded change reads as
//     an asset that has never changed, which is a different claim;
//   - drop the error branch → a failed read renders as "no recorded change".
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');
const assetPage = read('./asset-page.tsx');
const assetQueries = read('./asset-queries.ts');

describe('class history is reachable on the asset page', () => {
  it('the History tab renders the panel', () => {
    // Imported-but-unrendered is the orphan this whole file exists for.
    expect(assetPage).toContain('function ClassHistoryPanel');
    expect(assetPage).toContain('<ClassHistoryPanel asset={asset} />');
  });

  it('the panel reads the endpoint', () => {
    expect(assetQueries).toContain("'/infrastructure-assets/{id}/class-history'");
    expect(assetPage).toContain('useAssetClassHistory(asset.id)');
  });

  it('an empty list is NOT rendered as "never changed"', () => {
    // The distinction the whole record exists to preserve. An asset created
    // before this table has no row, and a panel that said "unchanged" would be
    // asserting something nobody measured.
    expect(assetPage).toContain('No recorded class change');
    expect(assetPage).toContain('not the same as never having changed');
  });

  it('a failed read says so rather than showing an empty timeline', () => {
    const panel = assetPage.slice(
      assetPage.indexOf('function ClassHistoryPanel'),
      assetPage.indexOf('function ClassChangeRow'),
    );
    expect(panel).toContain('ErrorCard');
  });

  it('the creation row does not render as a change from nothing', () => {
    // `from_class_key` is absent on the row an asset's creation writes. "— →
    // Printer" reads as a transition out of some previous state; there was
    // none.
    expect(assetPage).toContain('`Classified as ${to}`');
  });

  it('an absent actor is rendered as the mechanism, never as a person', () => {
    // Absent means NO PERSON — a machine did it — and inventing "unknown user"
    // would put a shrug where a fact belongs.
    expect(assetQueries).toContain('CLASS_CHANGE_SOURCE_LABELS');
    expect(assetPage).toContain('CLASS_CHANGE_SOURCE_LABELS[change.source]');
  });
});
