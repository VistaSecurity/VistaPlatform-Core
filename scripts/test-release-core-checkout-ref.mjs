#!/usr/bin/env node
// Static regression test for release-core.yml. A manual workflow dispatch accepts
// a tag input, so every checkout must use that resolved release ref rather than
// the branch the operator happened to dispatch from.

import { readFileSync } from 'node:fs';

const workflow = readFileSync('.github/workflows/release-core.yml', 'utf8');
const lines = workflow.split('\n');

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

assert(
  workflow.includes('RELEASE_REF: ${{ github.event.inputs.tag || github.ref_name }}'),
  'release-core.yml must compute RELEASE_REF from the dispatch tag or pushed ref',
);

const checkoutBlocks = [];
for (let i = 0; i < lines.length; i += 1) {
  if (!lines[i].includes('uses: actions/checkout@')) {
    continue;
  }

  const block = [lines[i]];
  for (let j = i + 1; j < lines.length; j += 1) {
    if (/^\s{6}-\s/.test(lines[j])) {
      break;
    }
    block.push(lines[j]);
  }
  checkoutBlocks.push(block.join('\n'));
}

// The property that matters is that EVERY checkout pins a release ref — not
// that there are exactly N of them. An exact count made adding a job (the
// binaries + release jobs) fail this test for the wrong reason, which teaches
// people to bump the number rather than check the new job.
//
// `guard` resolves and validates the ref; everything downstream builds
// guard.outputs.version, so a malformed tag is rejected once rather than
// trusted by each consumer.
assert(checkoutBlocks.length >= 3, `expected at least 3 release-core checkouts, found ${checkoutBlocks.length}`);

for (const [i, block] of checkoutBlocks.entries()) {
  assert(
    block.includes('ref: ${{ env.RELEASE_REF }}') ||
      block.includes('ref: ${{ needs.guard.outputs.version }}'),
    `release-core checkout #${i + 1} does not pin a release ref — it would build the branch the operator dispatched from:\n${block}`,
  );
}

const [guardCheckout, imagesCheckout, chartCheckout] = checkoutBlocks;
assert(
  guardCheckout.includes('ref: ${{ env.RELEASE_REF }}'),
  'guard checkout must inspect the resolved release ref',
);
assert(
  imagesCheckout.includes('ref: ${{ needs.guard.outputs.version }}'),
  'image build checkout must build the validated release ref',
);
assert(
  chartCheckout.includes('ref: ${{ needs.guard.outputs.version }}'),
  'chart packaging checkout must package the validated release ref',
);

console.log('✅ release-core checkout refs are pinned to the release version');
