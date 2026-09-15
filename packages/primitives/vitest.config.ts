import { defineConfig } from 'vitest/config';

// Minimal vitest setup — pure-TS unit tests, matching frontend-v2 and
// admin-ui-v2. Run with `npm run test -- --run`.
//
// `conformance.test.ts` reads `shared/query/testdata/conformance.json` from the
// repository root with node's `fs`, which the node environment allows; the
// fixture is deliberately not copied into this package, because a copy is a
// cross-language contract that can go stale without anything failing.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.{ts,tsx}'],
  },
});
