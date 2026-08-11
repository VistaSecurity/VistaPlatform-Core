// Feature-flag registration parity — the "three registrations" invariant.
//
// A gated surface is only actually gated when the flag exists on EVERY surface
// it travels through. Miss one and the gate is half-wired in a way that is
// invisible until a Core deployment renders a paid page whose calls 404:
//
//   1. auth-service `knownFeatures`     — the server publishes the key at all
//   2. the OpenAPI `FeatureFlags` shape — closed (`additionalProperties: false`),
//                                          so an unlisted key breaks the contract
//   3. the `FeatureName` union / `defaultFeatures` map — the client can name it,
//                                          and defaults it to OFF while loading
//
// A key present in (1) but missing from (3) reads as `undefined` in the client:
// falsy, so a `feature`-gated entry vanishes on EVERY deployment, paid ones
// included. A key in (3) but missing from (1) is never sent, so it is
// permanently off. Both failures are silent. Hence this test.
//
// Reading the two source files rather than importing them is deliberate: they
// are a Go slice and a YAML document, and there is no build step that would
// bring either into TypeScript. Cheap regexes over a flat list beat a
// dependency, and a shape change fails loudly here rather than degrading into a
// vacuous pass (both anchors are asserted non-empty below).
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { defaultFeatures } from '@vistasecurity/primitives/features';

const repoRoot = fileURLToPath(new URL('../../../', import.meta.url));
const read = (rel: string) => readFileSync(repoRoot + rel, 'utf8');

/** The `knownFeatures` string slice in auth-service. */
function knownFeatures(): string[] {
  const src = read('services/auth-service/internal/api/features.go');
  const block = /var knownFeatures = \[\]string\{([\s\S]*?)\n\}/.exec(src);
  expect(block, 'could not locate `var knownFeatures` — has features.go been restructured?').toBeTruthy();
  return [...block![1].matchAll(/"([a-z0-9_]+)"/g)].map((m) => m[1]);
}

/** The `required:` list of the FeatureFlags schema in the auth-service spec. */
function specRequired(): string[] {
  const src = read('api/openapi/auth-service.openapi.yaml');
  const schema = /\n {4}FeatureFlags:\n([\s\S]*?)\n {4}\w/.exec(src);
  expect(schema, 'could not locate the FeatureFlags schema in the auth-service spec').toBeTruthy();
  const req = /\n {6}required:\n((?: {8}- [a-z0-9_]+\n)+)/.exec(schema![1]);
  expect(req, 'FeatureFlags has no `required:` list — the shape is no longer closed').toBeTruthy();
  return [...req![1].matchAll(/- ([a-z0-9_]+)/g)].map((m) => m[1]);
}

describe('feature-flag registration parity', () => {
  const client = Object.keys(defaultFeatures).sort();

  it('reads a non-empty list from each source (the anchors still match)', () => {
    // Guard against the regexes silently matching nothing, which would turn
    // every assertion below into "[] equals []".
    expect(client.length).toBeGreaterThan(5);
    expect(knownFeatures().length).toBeGreaterThan(5);
    expect(specRequired().length).toBeGreaterThan(5);
  });

  it('publishes exactly the same keys server-side as the client knows', () => {
    expect(knownFeatures().sort()).toEqual(client);
  });

  it('requires exactly those keys in the closed OpenAPI shape', () => {
    expect(specRequired().sort()).toEqual(client);
  });

  it('defaults every flag to OFF, so a client that cannot reach the endpoint degrades to Core', () => {
    for (const [key, value] of Object.entries(defaultFeatures)) {
      expect(value, `${key} must default to false`).toBe(false);
    }
  });
});
