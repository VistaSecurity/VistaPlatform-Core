// The normalised version sort key (§5.5).
//
// This is a byte-for-byte port of Go's `ast.VersionSortKey`, which is the
// definition of `software_products.version_sort` and of every other `*_sort`
// column a version-typed field points at. It lives here so the editor can tell
// a user whether a version literal will compare at all — `looksLikeVersion` is
// the validator's type check — and so the two languages agree about which
// strings have no sort key.

/** How many numeric components the key holds. */
const VERSION_SLOTS = 6;

/** The largest component the padding can represent. */
const MAX_VERSION_COMPONENT = 99999999;

/**
 * Sorts above every alphanumeric byte, which is what makes a release sort above
 * its own pre-releases.
 */
const RELEASE_SENTINEL = '~';

/**
 * Normalises a version string into a text key that sorts component-wise, which
 * is what `version < 3.0` must compare on (§5.5: `1.1.1w` < `3.0.2`, never
 * lexically).
 *
 * The shape is `<slot1>.<slot2>.….<slot6>|<pre>`:
 *
 * - Six fixed slots, missing ones zero-filled, so a shorter version compares
 *   against the longer one component by component: `3.0` must be BELOW `3.0.2`.
 * - Each slot is the component's leading digits zero-padded to eight
 *   characters, so `1.10` sorts after `1.9` rather than before it.
 * - A letter glued to a component's digits is kept in the slot, so OpenSSL's
 *   `1.1.1w` sorts just after `1.1.1` — a glued letter is a patch release.
 * - Anything after the first `-` or `+` is a pre-release tag and goes in the
 *   final field, where a release's `~` makes `1.0.0-rc1` sort BELOW `1.0.0`.
 *
 * Returns null when the string carries no numeric component at all. A version
 * that does not parse has no sort key, the column is NULL, and every comparison
 * against it is UNKNOWN — which is the point (§5.2).
 */
export function versionSortKey(input: string): string | null {
  let v = input.trim();
  if (v === '') return null;
  if (v.startsWith('v') || v.startsWith('V')) v = v.slice(1);

  let core = v;
  let pre = '';
  const sep = firstIndexOfAny(v, '-+');
  if (sep >= 0) {
    core = v.slice(0, sep);
    pre = v.slice(sep + 1).toLowerCase();
  }

  const slots: string[] = new Array<string>(VERSION_SLOTS).fill(padNumber(0));
  let sawNumber = false;
  const parts = core.split('.');
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    if (p === '') continue;
    let d = 0;
    while (d < p.length && p[d] >= '0' && p[d] <= '9') d++;
    const digits = p.slice(0, d);
    const suffix = p.slice(d).toLowerCase();
    if (digits === '') {
      // A component with no digits at all inside the core (say "1.x.3") is not
      // a version component; fold it into the pre-release field so it still
      // compares, rather than pretending it is a number.
      pre = trimPrefix(suffix + '.' + pre, '.');
      continue;
    }
    const n = Number.parseInt(digits, 10);
    if (!Number.isSafeInteger(n) || n > MAX_VERSION_COMPONENT) return null;
    sawNumber = true;
    if (i < VERSION_SLOTS) {
      slots[i] = padNumber(n) + suffix;
      continue;
    }
    // Beyond the sixth component the value is vanishingly rare; keep it in the
    // trailing field so it is not silently dropped.
    pre = trimSuffix(pre + '.' + padNumber(n) + suffix, '.');
  }
  if (!sawNumber) return null;
  if (pre === '') pre = RELEASE_SENTINEL;
  return slots.join('.') + '|' + pre;
}

/**
 * Reports whether v could be a version literal, which is the validator's type
 * check for a version-typed field.
 */
export function looksLikeVersion(v: string): boolean {
  return versionSortKey(v) !== null;
}

function padNumber(n: number): string {
  const s = String(n);
  return s.length >= 8 ? s : '0'.repeat(8 - s.length) + s;
}

function firstIndexOfAny(s: string, chars: string): number {
  for (let i = 0; i < s.length; i++) if (chars.includes(s[i])) return i;
  return -1;
}

function trimPrefix(s: string, prefix: string): string {
  return s.startsWith(prefix) ? s.slice(prefix.length) : s;
}

function trimSuffix(s: string, suffix: string): string {
  return s.endsWith(suffix) ? s.slice(0, s.length - suffix.length) : s;
}
