import { defineConfig } from 'vitest/config';

// Minimal vitest setup — pure-TS unit tests (no jsdom/react harness yet).
// Tests run in the node environment; anything that needs `document` stubs it
// via vi.stubGlobal. Run with `npm run test -- --run` (the nightly invocation).
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.{ts,tsx}'],
  },
});
