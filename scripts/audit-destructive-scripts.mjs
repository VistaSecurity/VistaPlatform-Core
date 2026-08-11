#!/usr/bin/env node
/**
 * Blast-radius audit for shipped shell scripts.
 *
 * Several teardown scripts reached for host-wide Docker commands — `docker ps
 * -aq` piped into `docker rm`, `docker volume prune`, `docker image prune -a`,
 * `docker network prune`. None of those know what a compose project is. On a
 * machine running one stack they look correct; on a shared machine, or a
 * Kubernetes node, or a developer's laptop with a second project open, they
 * delete other people's containers, volumes and images. These scripts ship in
 * the public tree, so the machine on the other end is one we know nothing
 * about.
 *
 * The rule this enforces: a script may only remove Docker resources it has
 * first filtered by compose project. In practice that means going through
 * scripts/lib/docker-scope.sh, or writing the label filter inline.
 *
 * Two escape hatches, both deliberate:
 *   - `docker builder prune` cannot be scoped (BuildKit's cache is per-daemon).
 *     Allowed only in a file that also gates it behind a confirmation.
 *   - A line ending in `# docker-scope: ok <reason>` is exempted, so a genuine
 *     exception is visible in review rather than invisible in a helper.
 *
 *   node scripts/audit-destructive-scripts.mjs [--strict]
 *
 * Mutation-test it: add `docker ps -aq | xargs docker rm -f` to any script here
 * and check it fails.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const STRICT = process.argv.includes('--strict');

// Patterns that operate on the whole daemon.
const UNSCOPED = [
  {
    re: /docker\s+(volume|network|image|container|system)\s+prune/,
    what: 'host-wide prune — hits every project on the daemon',
  },
  {
    re: /docker\s+(ps|volume\s+ls|network\s+ls|images)\b[^\n|]*\|[^\n]*docker\s+(rm|rmi|stop|volume\s+rm|network\s+rm)/,
    what: 'unfiltered list piped into a remove',
    // A `--filter` on the listing side narrows it to something. By label is
    // ideal; by name prefix is weaker but still a deliberate choice, not a
    // whole-daemon sweep. Only a listing with no filter at all is the bug.
    unless: (line) => /--filter/.test(line),
  },
  {
    re: /docker\s+(rm|rmi|stop)\s+(-f\s+)?\$\((docker\s+ps|docker\s+images)/,
    what: 'unfiltered command substitution into a remove',
    unless: (line) => /--filter/.test(line),
  },
];

// `docker builder prune` is unscopeable. A file may call it only if it also
// asks first — require_confirmation() from the shared lib, an interactive
// read, or an explicit opt-in env var.
const BUILDER_PRUNE = /docker\s+builder\s+prune/;
const GATED = /require_confirmation|read -r? *-?p|CLEAN_DOCKER_CACHE|ASSUME_YES|DRY_RUN/;

const EXEMPT = /#\s*docker-scope:\s*ok\b/;

// Scoping evidence: the shared helpers, or a hand-written project-label filter.
const SCOPED_HINT = /com\.docker\.compose\.project|project_containers|project_volumes|project_networks|project_built_images/;

const files = fs
  .readdirSync(path.join(ROOT, 'scripts'), { withFileTypes: true })
  .filter((e) => e.isFile() && e.name.endsWith('.sh'))
  .map((e) => path.join('scripts', e.name))
  .sort();

const problems = [];
let scanned = 0;
let scopedFiles = 0;

for (const rel of files) {
  const text = fs.readFileSync(path.join(ROOT, rel), 'utf8');
  const lines = text.split('\n');
  scanned++;
  if (SCOPED_HINT.test(text)) scopedFiles++;

  lines.forEach((line, i) => {
    if (line.trim().startsWith('#')) return; // a comment describing the old bug is not the bug
    if (EXEMPT.test(line)) return;

    for (const { re, what, unless } of UNSCOPED) {
      if (re.test(line) && !(unless && unless(line))) {
        problems.push(`${rel}:${i + 1} — ${what}\n    ${line.trim()}`);
      }
    }

    if (BUILDER_PRUNE.test(line) && !GATED.test(text)) {
      problems.push(
        `${rel}:${i + 1} — 'docker builder prune' cannot be scoped to a project, and this file ` +
          `never asks before running it.\n    ${line.trim()}`
      );
    }
  });
}

console.log('Destructive-script audit');
console.log(`  ${scanned} shell script(s) scanned, ${scopedFiles} using compose-project scoping`);

if (problems.length) {
  console.error(
    '\nFAIL: host-wide Docker operation(s) in shipped scripts. Scope them to the compose ' +
      'project (see scripts/lib/docker-scope.sh), or annotate the line `# docker-scope: ok <reason>`:\n\n' +
      problems.map((p) => `  ${p}`).join('\n\n')
  );
  process.exit(STRICT ? 1 : 0);
}
console.log('OK: no unscoped container/volume/network/image removal in scripts/.');
