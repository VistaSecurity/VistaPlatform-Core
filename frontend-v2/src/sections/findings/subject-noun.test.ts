// Every finding subject type has a word for it, on every surface that names one.
//
// A finding carries `(subject_type, subject_id)` and two surfaces render the
// TYPE when the row has no label of its own: the asset page's Findings tab and a
// remediation plan's item list. Both did it through a lookup table with a silent
// fallback — the raw `subject_type` on one, the word "finding" on the other — so
// a type missing from the table produced no error and no blank, just worse
// prose. That is how `key` and `relationship` were still missing months after
// their subject paths were added to findings.AssetSubjects: a `pqc_vulnerable`
// finding on a cryptographic key read "crypto · key", the internal vocabulary
// leaking onto the page, and a plan item on either read only "finding".
//
// So the registry is the authority. `standards/findings-registry.yaml` owns the
// `subject_types` vocabulary; this test reads it and requires a noun per value
// on both surfaces. Adding a subject type to the registry now fails here until
// somebody decides what to call it.
//
// Mutation-proven: delete `key` (or any other) from either map and this goes red.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { SUBJECT_NOUN as ASSET_PAGE_NOUN } from '../inventory/asset-page';
import { SUBJECT_NOUN as PLAN_ITEM_NOUN } from '../remediation/plan-detail';

const repoRoot = fileURLToPath(new URL('../../../../', import.meta.url));

/**
 * The `subject_types` list from standards/findings-registry.yaml.
 *
 * Parsed with a regex rather than a YAML library because the block is a flat
 * list of bare scalars and the repo's other registry-reading frontend tests
 * (phase3.reachability, connectors-catalogue) do the same — a parser dependency
 * for ten lines of one-word entries buys nothing. The slice is anchored on the
 * top-level key and the count is asserted, so a file whose shape changed fails
 * loudly instead of yielding an empty list the assertions would pass over.
 */
function registrySubjectTypes(): string[] {
  const src = readFileSync(repoRoot + 'standards/findings-registry.yaml', 'utf8');
  const start = src.indexOf('\nsubject_types:');
  expect(start, 'could not find the top-level `subject_types:` list in standards/findings-registry.yaml')
    .toBeGreaterThan(-1);
  const body = src.slice(start + 1).split('\n').slice(1);
  const out: string[] = [];
  for (const line of body) {
    const item = /^\s+-\s+([a-z0-9_]+)\s*$/.exec(line);
    if (item) {
      out.push(item[1]);
      continue;
    }
    if (line.trim() === '' || line.trimStart().startsWith('#')) continue;
    break; // the next top-level key ends the list
  }
  return out;
}

describe('finding subject nouns', () => {
  const types = registrySubjectTypes();

  it('reads the registry vocabulary', () => {
    // Anchor: an empty or truncated list would make every assertion below
    // vacuous, which is the failure mode of a source-reading guard.
    expect(types).toContain('asset');
    expect(types).toContain('key');
    expect(types).toContain('relationship');
    expect(types.length).toBeGreaterThanOrEqual(9);
  });

  it.each([
    ["the asset page's Findings tab", () => ASSET_PAGE_NOUN],
    ['a remediation plan item', () => PLAN_ITEM_NOUN],
  ] as const)('%s has a noun for every subject type', (_name, get) => {
    const map = get();
    const missing = types.filter((t) => !map[t]?.trim());
    expect(missing, 'subject types the registry has and this surface has no word for').toEqual([]);
  });

  it.each([
    ["the asset page's Findings tab", () => ASSET_PAGE_NOUN],
    ['a remediation plan item', () => PLAN_ITEM_NOUN],
  ] as const)('%s invents no subject type the registry does not have', (_name, get) => {
    // The other polarity. A noun for a type the registry dropped is dead code
    // that reads as coverage — and the same check catches a typo'd key, which
    // would otherwise present as a missing entry somebody "already added".
    const extra = Object.keys(get()).filter((k) => !types.includes(k));
    expect(extra).toEqual([]);
  });
});
