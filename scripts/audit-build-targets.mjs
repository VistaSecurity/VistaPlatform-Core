#!/usr/bin/env node
// Audit: no build command may compile a single `main.go` instead of its package.
//
// `go build ./cmd/main.go` compiles ONE FILE. Every sibling file in the same
// `package main` — edition.go, hooks.go, logbuffer.go — is excluded, so the
// build fails with `undefined: edition` the moment a service grows a second
// file in cmd/. That is exactly how `make build-services` came to be broken in
// a tree the public README told strangers to build, and it stayed
// broken because nothing could catch it:
//
//   - `go build ./...` (the export's verification gate, CI, `go vet`) uses the
//     PACKAGE form and therefore always succeeded.
//   - The bug lives in the Makefile and in shell scripts, which no Go tool reads.
//
// So this guard reads the build recipes as text. It is the only check in the
// repo that looks at HOW the binaries are invoked rather than whether the
// source compiles.
//
// Run strict (`--strict`) from `make audit`; without the flag it warns.

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const strict = process.argv.includes('--strict');

// `go build ... <path>/main.go` — with or without a leading ./, and regardless
// of what flags sit between `go build` and the path.
const SINGLE_FILE_BUILD = /go build\b[^\n]*?(?<![\w./-])\.?\/?(?:[\w./-]*\/)?main\.go(?![\w.])/;

const targets = ['Makefile'];
for (const f of readdirSync('scripts')) {
  if (f.endsWith('.sh')) targets.push(join('scripts', f));
}

const findings = [];
for (const file of targets) {
  let lines;
  try {
    lines = readFileSync(file, 'utf8').split('\n');
  } catch {
    continue;
  }
  lines.forEach((line, i) => {
    // Comments explain the trap on purpose (the SENSOR_MAIN note, and this
    // script's own header). Skip them, or the guard flags its own rationale.
    const code = line.replace(/^\s*[#]/, '');
    if (code !== line) return;
    // Likewise skip lines that only PRINT a build command — the audit's own
    // progress echo, and the hints install-sensor.sh prints to the operator.
    // A recipe that merely describes a build does not run one.
    if (/^\s*@?(echo|printf)\b/.test(line)) return;
    if (!SINGLE_FILE_BUILD.test(line)) return;
    findings.push(`${file}:${i + 1}: ${line.trim()}`);
  });
}

// --- coverage: build-services must build every service it claims to ----------
//
// The single-file bug was one way this target lied. The other was simpler: its
// help text says "all Go backend services" while it named 11 of the 16 in the
// registry and exited 0 — audit, notification, discovery-processor and
// device-interrogation were absent, so the documented "build everything" command
// produced an incomplete tree and reported success.
//
// pcap-processor is the one legitimate omission: CGO + libpcap headers, which
// would make this target fail on any machine without libpcap-dev.
const BUILD_EXEMPT = new Set(['pcap-processor']);

// `services:` is a LIST of maps (`  - key: <name>`). Parsing it as a map of keys
// yields zero services, which would leave this half of the audit inert while
// still printing a reassuring line — so a zero parse is a hard failure.
const reg = readFileSync(join('standards', 'service-registry.yaml'), 'utf8');
const regBody = reg.split(/^services:\s*$/m)[1] ?? '';
const registryServices = [...regBody.matchAll(/^ {2}- key:\s*([a-z][a-z0-9-]*)\s*$/gm)].map(
  (m) => m[1],
);
if (registryServices.length === 0) {
  console.error(
    'audit-build-targets: parsed ZERO services from standards/service-registry.yaml — ' +
      'the coverage half of this audit would be inert. Fix the parser.',
  );
  process.exit(1);
}

const recipe =
  readFileSync('Makefile', 'utf8').split(/^build-services:/m)[1]?.split(/^\w[\w-]*:/m)[0] ?? '';
const built = new Set([...recipe.matchAll(/-o \.\.\/\.\.\/bin\/([a-z][a-z0-9-]*)/g)].map((m) => m[1]));
const uncovered = registryServices.filter((s) => !BUILD_EXEMPT.has(s) && !built.has(s));
const expected = registryServices.filter((s) => !BUILD_EXEMPT.has(s)).length;

console.log('Build-target audit (no single-file `go build .../main.go`)');
console.log(`  ${targets.length} file(s) scanned`);
console.log(
  `  build-services covers ${expected - uncovered.length}/${expected} registry service(s) ` +
    `(${[...BUILD_EXEMPT].join(', ')} exempt)`,
);

for (const svc of uncovered) {
  console.log(`  \u2717 build-services does not build ${svc}, but the registry declares it`);
}
if (uncovered.length > 0) {
  console.log(
    `\n${uncovered.length} service(s) missing from build-services. Add them, or add to ` +
      'BUILD_EXEMPT with the reason.',
  );
}

if (findings.length === 0 && uncovered.length === 0) {
  console.log('OK: every build command compiles a package, and build-services is complete.');
  process.exit(0);
}
if (findings.length === 0) process.exit(strict ? 1 : 0);

for (const f of findings) console.log(`  ✗ ${f}`);
console.log(
  `\n${findings.length} single-file build command(s). Use the package form ` +
    '(`./cmd`) so sibling files in `package main` are included.',
);
process.exit(strict ? 1 : 0);
