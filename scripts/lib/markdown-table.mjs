// Escaping for values interpolated into a GitHub-Flavored-Markdown table cell.
//
// Why this is its own module rather than an inline `.replace()`: escaping a
// delimiter with a backslash is only correct if the backslash itself is escaped
// FIRST. `s.replace(/\|/g, '\\|')` looks complete — the regex is global, so it
// does hit every pipe — but it is not, because it also manufactures a backslash
// in front of each pipe without accounting for backslashes the input already
// carried.
//
// Concretely, for an input of `C:\` followed by `|`:
//
//   pipe-only escape → `C:\\|`   GFM reads `\\` as an escaped backslash, so the
//                                `|` that follows is a LIVE cell delimiter: the
//                                row silently grows a column and the table
//                                mis-renders from that row on.
//   escape both      → `C:\\\|`  renders as `C:\|`, one cell, correct.
//
// Same class of bug as an escaper that only replaces the first occurrence
// (CodeQL js/incomplete-sanitization flags both). Here the generated file is
// documentation rather than a security boundary, so the damage is wrong output
// — but wrong output from a generator nobody hand-checks is exactly what this
// repository has been bitten by before.
//
// Order is load-bearing: backslashes first, then pipes. Reversing it would
// double-escape the backslashes this function just introduced.

/**
 * Escape a value for safe interpolation into a Markdown table cell.
 *
 * @param {unknown} value raw cell content
 * @returns {string} content safe to place between two `|` delimiters
 */
export function escapeTableCell(value) {
  return String(value ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|');
}
