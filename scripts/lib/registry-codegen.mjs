// Shared helpers for the standards-registry code generators
// (generate-findings-registry.mjs, generate-fact-keys.mjs,
// generate-connectors.mjs). Kept small and dependency-free on purpose: these
// run inside `make generate` and `make audit` on every commit.

// Initialisms that should stay upper-case in generated Go identifiers, so the
// constants read the way hand-written Go would (OSEndOfLife, not OsEndOfLife).
const INITIALISMS = new Set([
  'api', 'aws', 'cdp', 'cmdb', 'cpe', 'cpu', 'cvss', 'dns', 'edr', 'eol', 'gcp',
  'hw', 'http', 'https', 'id', 'ip', 'itsm', 'json', 'lldp', 'mac', 'mdm', 'os',
  'oui', 'pqc', 'sbom', 'siem', 'snmp', 'ssh', 'sw', 'tls', 'url', 'uuid',
  'vlan', 'vpc', 'xml',
]);

/**
 * Converts a lower_snake or dotted registry key into an exported Go
 * identifier: `os.eol_date` -> `OSEOLDate`, `weak_certificate` ->
 * `WeakCertificate`.
 */
export function goConst(key) {
  return String(key)
    .split(/[._\-/]+/)
    .filter(Boolean)
    .map((part) => {
      const lower = part.toLowerCase();
      if (INITIALISMS.has(lower)) return lower.toUpperCase();
      return lower.charAt(0).toUpperCase() + lower.slice(1);
    })
    .join('');
}

/** Quotes a value as a Go string literal. */
export function goStr(s) {
  return JSON.stringify(String(s ?? ''));
}

/**
 * Quotes a value as a TypeScript string literal, single-quoted house style.
 * Newlines are escaped, not passed through: a YAML block scalar (`|`, or a
 * folded scalar with a blank line in it) would otherwise put a raw line break
 * inside a single-quoted literal and the generated file would not parse. The
 * Go side gets this for free from JSON.stringify.
 */
export function tsStr(s) {
  return `'${String(s ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')}'`;
}

/**
 * Renders `name = value` lines with the names padded to a common width, the
 * way gofmt aligns a const block. Generated Go has to come out gofmt-clean on
 * the first write: CI's format check runs on it, and the --check drift audit
 * compares bytes, so a re-run of gofmt would read as drift.
 *
 * @param {Array<{name: string, value: string}>} entries
 */
export function goConstBlock(entries) {
  assertNoIdentifierCollision(entries);
  const width = entries.reduce((n, e) => Math.max(n, e.name.length), 0);
  return entries.map((e) => `\t${e.name.padEnd(width)} = ${e.value}`).join('\n');
}

/**
 * goConst folds `.`, `_`, `-` and `/` to nothing, so two distinct registry keys
 * can land on one Go identifier — `os.eol_date` and `os.eol.date` both become
 * `OSEOLDate`. Without this the generator writes a file that only fails later,
 * at `go build` (and at `tsc`, on the duplicate object key), with an error that
 * names the identifier rather than the two YAML entries that produced it.
 *
 * @param {Array<{name: string, value: string}>} entries
 */
function assertNoIdentifierCollision(entries) {
  const byName = new Map();
  for (const e of entries) {
    const prev = byName.get(e.name);
    if (prev !== undefined && prev !== e.value) {
      fail(
        'registry-codegen',
        `two registry keys generate the same identifier ${e.name}: ` +
        `${prev} and ${e.value} — rename one of them`);
    }
    byName.set(e.name, e.value);
  }
}

/** Prints a namespaced failure and exits non-zero. */
export function fail(scope, msg) {
  console.error(`${scope}: ${msg}`);
  process.exit(1);
}
