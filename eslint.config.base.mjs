// Shared ESLint flat-config base for the TypeScript workspaces.
//
// Both UIs (frontend-v2, admin-ui-v2) are React 19 + react-router 8 + Vite +
// TypeScript 6 npm-workspace members off the root package.json, so the lint
// toolchain is declared once in the root devDependencies and the config is
// shared from here rather than duplicated per app (ADR-0005).
//
// Each app's eslint.config.js does:
//
//     import baseConfig from '../eslint.config.base.mjs';
//     export default baseConfig(import.meta.dirname);
//
// Type-aware rules (no-floating-promises and friends) need a TS program, so
// `projectService` is switched on and `tsconfigRootDir` is passed in by the
// caller. Only `src/**` is linted — the Vite/Vitest/Tailwind config files sit
// outside each app's tsconfig `include`, so there is no program for them.
//
// ── On the `warn` levels below ──────────────────────────────────────
//
// This config is the first real linter these apps have ever had; the step that
// claimed to run one was `tsc --noEmit`. The first run surfaced a backlog that
// is too large to fix responsibly inside the change that introduces the gate,
// so those rules are demoted to `warn` — reported on every run, never silent,
// never blanket-disabled — with the first-run counts recorded inline and a
// burn-down issue tracking them. Every rule below is either ERROR (enforced,
// currently zero findings) or WARN (visible, counted, tracked). None is off
// except where noted with a reason.
//
// A warning that blocks nothing is the same trap as a lint step that lints
// nothing, so each app's `lint` script pins `--max-warnings` at its current
// count (frontend-v2 639, admin-ui-v2 310). The backlog can shrink but not
// grow: a new floating promise or a new `any` pushes the total over the cap
// and fails the build. Lower the number as findings are burnt down.
//
// Follow-up burn-down: GitHub.

import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import tseslint from 'typescript-eslint';

/**
 * @param {string} tsconfigRootDir absolute path to the app directory
 *   (pass `import.meta.dirname` from the app's eslint.config.js)
 */
export default function baseConfig(tsconfigRootDir) {
  return tseslint.config(
    {
      ignores: [
        'dist/**',
        'coverage/**',
        'node_modules/**',
        'public/**',
        '**/*.config.js',
        '**/*.config.ts',
        '**/*.d.ts',
      ],
    },

    js.configs.recommended,
    ...tseslint.configs.recommendedTypeChecked,
    reactHooks.configs.flat['recommended-latest'],

    {
      files: ['src/**/*.{ts,tsx}'],
      languageOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
        globals: {
          ...globals.browser,
          ...globals.es2022,
        },
        parserOptions: {
          projectService: true,
          tsconfigRootDir,
        },
      },
      rules: {
        // ══ ENFORCED (error) ═══════════════════════════════════════════════
        // Each of these is at zero findings across both apps as of this
        // change. They fail the build.

        // Hooks correctness. A conditionally-called hook is a real runtime
        // bug, and it is the single rule this whole gate most needed to run.
        'react-hooks/rules-of-hooks': 'error',
        // `warn` in the plugin's own recommended set; promoted here because a
        // stale closure in a data-fetching effect is exactly the class of bug
        // that reaches production quietly. The 15 first-run findings (all the
        // same `const all = data ?? []` → `useMemo([all])` identity churn)
        // were fixed rather than downgraded.
        'react-hooks/exhaustive-deps': 'error',
        // tsc's noUnusedLocals/noUnusedParameters already cover most of this;
        // the lint rule adds caught-error and rest-sibling handling and lets
        // `_`-prefixed names opt out deliberately.
        '@typescript-eslint/no-unused-vars': [
          'error',
          {
            argsIgnorePattern: '^_',
            varsIgnorePattern: '^_',
            caughtErrorsIgnorePattern: '^_',
            ignoreRestSiblings: true,
          },
        ],
        // 4 first-run findings, all `cond ? set.delete(x) : set.add(x)` used
        // as a statement. Rewritten as if/else.
        '@typescript-eslint/no-unused-expressions': 'error',
        // Zero findings in app code. (The 5 first-run hits were all `fetch`
        // stubs in tests — see the test-file override at the bottom.)
        '@typescript-eslint/require-await': 'error',

        // ══ REPORTED BUT NOT BLOCKING (warn) — ═══════════════════
        // First-run counts are frontend-v2 + admin-ui-v2.

        // 110 + 28. Dominated by two mechanical patterns: react-router 8's
        // `navigate()` now returns a Promise, and `(async () => {…})()` IIFEs
        // inside effects. Fixing means a `void` prefix on ~138 call sites in
        // 50+ files — a mass rewrite that would bury the gate it ships with.
        '@typescript-eslint/no-floating-promises': 'warn',
        // 44 + 63. Same root cause on the JSX-handler side.
        '@typescript-eslint/no-misused-promises': 'warn',
        // 171 + 51. Redundant `as X` where TS already narrows. Autofixable and
        // harmless, but 222 mechanical deletions is not this change's job.
        '@typescript-eslint/no-unnecessary-type-assertion': 'warn',
        // 17 + 23. Mostly `${obj}` in template literals over API payloads.
        '@typescript-eslint/no-base-to-string': 'warn',
        // 9 + 10. Overwhelmingly test-double and API-client method references.
        '@typescript-eslint/unbound-method': 'warn',
        // 3 + 11. `throw error ?? new Error(...)` where `error` is the typed
        // openapi error body, consumed by a matching TanStack `onError`. Real
        // smell, but "fixing" it changes error-propagation semantics, so it
        // needs a deliberate pass, not a drive-by one.
        '@typescript-eslint/only-throw-error': 'warn',
        // 3 + 2. `${maybeNumber}` / `${maybeNull}` inside template literals.
        '@typescript-eslint/restrict-template-expressions': 'warn',
        // 223 + 34. `a || b` where `a` is a non-nullable string; changing to
        // `??` alters falsy-empty-string behaviour, so each site needs reading.
        '@typescript-eslint/prefer-nullish-coalescing': 'warn',
        // 5 + 59 across the no-unsafe-* family, plus 0 + 20 explicit `any`.
        // Confined to untyped JSON that has not reached the typed client yet.
        '@typescript-eslint/no-unsafe-assignment': 'warn',
        '@typescript-eslint/no-unsafe-member-access': 'warn',
        '@typescript-eslint/no-unsafe-argument': 'warn',
        '@typescript-eslint/no-unsafe-call': 'warn',
        '@typescript-eslint/no-unsafe-return': 'warn',
        '@typescript-eslint/no-explicit-any': 'warn',
        // 6 + 0, every one a `let x = <seed>` before a do/while that assigns
        // before the condition reads it. Deleting the initializer would trade
        // a lint warning for worse readability, so this stays advisory.
        'no-useless-assignment': 'warn',

        // React Compiler-era rules from eslint-plugin-react-hooks v7. These
        // are advisory-by-nature: they describe what blocks the compiler from
        // optimising, not what is broken. Kept visible, not blocking.
        //   set-state-in-effect          26 + 6
        //   static-components             8 + 0
        //   purity                        4 + 0  (Date.now() during render;
        //                                         one site quantises to the
        //                                         hour on purpose)
        //   immutability                  3 + 1  (mostly `window.location.href
        //                                         = …` in event handlers,
        //                                         which is a false positive)
        //   preserve-manual-memoization   3 + 0
        'react-hooks/set-state-in-effect': 'warn',
        'react-hooks/static-components': 'warn',
        'react-hooks/purity': 'warn',
        'react-hooks/immutability': 'warn',
        'react-hooks/preserve-manual-memoization': 'warn',

        // ══ DELIBERATELY OFF ═══════════════════════════════════════════════
        // Not a defect class in this codebase and extremely noisy against
        // optional-chained API payloads.
        '@typescript-eslint/no-unnecessary-condition': 'off',
      },
    },

    // Test files: the type-aware strictness around mocks and fixtures says
    // nothing about product correctness.
    {
      files: ['src/**/*.{test,spec}.{ts,tsx}', 'src/**/__tests__/**/*.{ts,tsx}'],
      languageOptions: {
        globals: {
          ...globals.node,
        },
      },
      rules: {
        '@typescript-eslint/no-non-null-assertion': 'off',
        '@typescript-eslint/unbound-method': 'off',
        // `fetch` stubs must be declared `async` to match the real fetch
        // signature (Promise<Response>) even though they never await. Making
        // them non-async and wrapping in Promise.resolve would satisfy the
        // rule and read worse.
        '@typescript-eslint/require-await': 'off',
      },
    },
  );
}
