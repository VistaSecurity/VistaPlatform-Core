#!/usr/bin/env node
/**
 * Release tag-namespace split (-adjacent, see CHANGELOG).
 *
 * Two independent release lines now share one repository:
 *
 *   core-vX.Y.Z  → publish-public-tree.yml  (export → public repo, tagged vX.Y.Z)
 *   vX.Y.Z       → release-customer.yml     (promote Harbor → Docker Hub)
 *
 * They must not overlap. Before the split a single `v*.*.*` tag fired both, so
 * every Core publish rehearsal left a failed release-customer run behind it —
 * it tried to promote Harbor images that did not exist for that tag.
 *
 * The whole thing rests on one assumption: GitHub's `v*.*.*` tag filter does
 * NOT match `core-v0.1.0`. That is true because ref globs are anchored, but
 * "obviously anchored" is exactly the kind of assumption that is wrong once and
 * costs an afternoon — so it is asserted here against a real glob matcher
 * rather than trusted.
 *
 * Run: node scripts/test-release-tag-split.mjs
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const WF = path.join(ROOT, '.github', 'workflows');

let failures = 0;
const check = (desc, ok, detail = '') => {
  if (ok) console.log(`  ✓ ${desc}`);
  else { failures++; console.error(`  ✗ ${desc}${detail ? `\n      ${detail}` : ''}`); }
};

/**
 * GitHub ref-glob → RegExp, matching the documented semantics: patterns are
 * anchored at both ends, `*` matches any character except `/`, `**` matches
 * across `/`. Everything else is literal.
 */
function refGlobToRegExp(glob) {
  let out = '^';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') { out += '.*'; i++; }
      else out += '[^/]*';
    } else if ('\\^$.|?+()[]{}'.includes(c)) {
      out += '\\' + c;
    } else {
      out += c;
    }
  }
  return new RegExp(out + '$');
}

const matches = (glob, ref) => refGlobToRegExp(glob).test(ref);

const triggersOf = (file) => {
  const doc = yaml.parse(fs.readFileSync(path.join(WF, file), 'utf8'));
  // `on` is parsed as the boolean true by YAML 1.1 semantics in some parsers;
  // read both spellings so this cannot silently find nothing and pass.
  const on = doc.on ?? doc[true];
  if (!on) throw new Error(`${file}: could not read the \`on:\` block`);
  const tags = on.push?.tags;
  if (!tags) throw new Error(`${file}: has no push.tags trigger`);
  return tags;
};

console.log('Release tag namespaces');

// ─── The glob semantics everything else depends on ─────────────────────────
check('`v*.*.*` does not match a core tag',
  !matches('v*.*.*', 'core-v0.1.0'),
  'if this ever becomes true, every Core release also fires release-customer');
check('`core-v*.*.*` does not match a commercial tag',
  !matches('core-v*.*.*', 'v3.7.0'));
check('each glob matches its own line',
  matches('v*.*.*', 'v3.7.0') && matches('core-v*.*.*', 'core-v0.1.0'));

// ─── Workflow triggers ─────────────────────────────────────────────────────
const publish = triggersOf('publish-public-tree.yml');
const customer = triggersOf('release-customer.yml');
const core = triggersOf('release-core.yml');

check('publish-public-tree fires on the core line only',
  publish.every((g) => matches(g, 'core-v0.1.0')) && !publish.some((g) => matches(g, 'v3.7.0')),
  `got ${JSON.stringify(publish)}`);
check('release-customer fires on the commercial line only',
  customer.some((g) => matches(g, 'v3.7.0')) && !customer.some((g) => matches(g, 'core-v0.1.0')),
  `got ${JSON.stringify(customer)}`);

// release-core is the exception and it is deliberate: it ships IN the export,
// so it triggers on the `vX.Y.Z` tag that publish pushes to the PUBLIC repo.
// In this repo it also matches, and no-ops — its guard job skips any tree
// containing services/*/ee. That guard is what makes the overlap safe, so its
// absence must fail here rather than being noticed in production.
check('release-core fires on the public repo\'s v tag',
  core.some((g) => matches(g, 'v0.1.0')),
  `got ${JSON.stringify(core)}`);

const coreSrc = fs.readFileSync(path.join(WF, 'release-core.yml'), 'utf8');
check('release-core still guards on the absence of services/*/ee',
  /compgen -G "services\/\*\/ee"/.test(coreSrc) && /is_core=false/.test(coreSrc),
  'without this guard, a commercial tag would build a second Core image line from the private tree');
check('every build job is gated on that guard',
  (coreSrc.match(/needs\.guard\.outputs\.is_core == 'true'/g) || []).length >= 2);

// ─── The prefix strip ──────────────────────────────────────────────────────
//
// The public repo is tagged with the STRIPPED version, because over there the
// repo is Core and a `core-` prefix would be noise — and because release-core
// there triggers on `v*.*.*`. Getting this wrong publishes a tag nothing builds.
const pubSrc = fs.readFileSync(path.join(WF, 'publish-public-tree.yml'), 'utf8');
check('the public tag is the source tag with `core-` stripped',
  /V="\$\{SRC#core-\}"/.test(pubSrc),
  'the public repo must be tagged vX.Y.Z, not core-vX.Y.Z');
check('the checkout ref is the UNstripped source tag',
  /REF="\$SRC"/.test(pubSrc),
  'checking out the stripped name would look for a tag that does not exist in this repo');
check('a bare commercial tag is rejected with an explanation, not silently accepted',
  /is a COMMERCIAL tag/.test(pubSrc));

// Shell-verify the strip rather than trusting the regex above.
const stripped = 'core-v0.1.0'.replace(/^core-/, '');
check('core-v0.1.0 → v0.1.0', stripped === 'v0.1.0', `got ${stripped}`);

// Self-hosted runners reuse $RUNNER_TEMP, and the exporter refuses to write
// into a non-empty directory. Without an explicit clear, a publish that lands
// on a runner holding a leftover export fails — intermittently, depending which
// runner picks the job up. It happened on the core-v0.1.0 tag replay.
check('publish clears any leftover export directory before building',
  /rm -rf "\$\{RUNNER_TEMP\}\/public-tree"/.test(pubSrc),
  'self-hosted runners reuse RUNNER_TEMP; a leftover tree fails the export');

if (failures) {
  console.error(`\n❌ ${failures} release-tag check(s) failed`);
  process.exit(1);
}
console.log('✅ Release tag namespaces are disjoint and correctly wired');
