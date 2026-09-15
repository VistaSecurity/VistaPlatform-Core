// The regex dialect: the common subset of RE2 and Postgres ARE (§13 A6).
//
// §2 says `~` is "case-sensitive RE2", and §6 says the validator checks the
// pattern compiles as RE2. Both are true and neither is enough, because the
// pattern is not run by the client — it is handed to Postgres `~`, which is ARE
// (Spencer). The two dialects agree on most of what anyone writes and diverge
// on a handful of constructs, in the two worst ways:
//
//   - SILENTLY. In ARE `\b` is a BACKSPACE character, not a word boundary. So
//     `hostname ~ "\bweb\b"` compiles as RE2, validates, reaches Postgres, and
//     returns the wrong rows — no error anywhere. (Verified against PG 17:
//     `'word' ~ '\bword\b'` is FALSE.)
//   - LOUDLY, at query time. `(?i)` mid-pattern, `\z`, `\p{L}`, `(?i:…)` and
//     named groups all raise "invalid regular expression" from the database,
//     which surfaces as a 500 rather than as a validation error with a span.
//
// So the language's regex is the intersection, checked by the scanner below.
// Allowed, and nothing else:
//
//	literals; "."
//	bracket classes [...] with ranges and a leading "^"
//	the escapes \d \D \w \W \s \S
//	the escaped metacharacters \. \\ \( \) \[ \] \{ \} \* \+ \? \| \^ \$ \-
//	anchors ^ $
//	groups (...) and (?:...)
//	quantifiers * + ? {n} {n,} {n,m}
//	alternation |
//	the flag group (?i), as a PREFIX only
//
// The Go side runs an RE2 compile as a second check and a live-Postgres probe
// over every accepted construct. This port has neither RE2 nor a database, so
// the scanner is the whole check here — see `compileCheck` for the narrow thing
// JavaScript's own RegExp can still be asked, and what it deliberately is not.

/** The shorthand classes both dialects spell the same way. */
const CLASS_ESCAPES = 'dDwWsS';

/** The metacharacters an escape may make literal. */
const LITERAL_ESCAPES = '.\\()[]{}*+?|^$-';

/**
 * The largest count a SINGLE repetition may carry.
 *
 * It is Postgres's own limit (DUPMAX, 255), not a number chosen here: `a{256}`
 * raises "invalid regular expression: invalid repetition count(s)" from the
 * database. §6 capped repetition at 1000, so every count from 256 to 1000
 * validated and then failed at query time (§13 A9).
 *
 * The cap on the PRODUCT across nesting (`Options.maxRepetition`) is separate
 * and still earns its place: two nested bounds of 100 are each legal and their
 * product is not.
 */
export const MAX_REPETITION_BOUND = 255;

/**
 * Caps the scanner's own recursion. A pattern is at most maxRegexLen code
 * points, so nesting cannot exceed that — but the scanner recurses per group,
 * and a cap is cheaper than trusting the caller's cap to be small.
 */
const MAX_REGEX_NESTING = 64;

/**
 * Clamps the running repetition product so a deeply nested pattern cannot
 * overflow before the cap is compared.
 */
const REPETITION_CEILING = 1 << 30;

/**
 * The one description of the dialect, so every regex error points at the same
 * rules.
 */
export const REGEX_SUBSET_HELP =
  'the regex dialect is the common subset of RE2 and Postgres: ' +
  'literals, ".", [...] classes, \\d \\D \\w \\W \\s \\S, escaped metacharacters, ' +
  '"^" and "$", (...) and (?:...) groups, * + ? {n} {n,} {n,m}, "|", ' +
  'and "(?i)" at the START of the pattern';

/** What the subset scanner found. */
export interface RegexCheck {
  /**
   * The largest effective repetition count in the pattern — the PRODUCT along
   * the nesting, so `(a{100}){100}` counts as 10,000 rather than 100.
   */
  maxRepetition: number;
  /**
   * Empty when the pattern is inside the subset; otherwise it names the
   * construct, for a message a user can act on.
   */
  problem: string;
}

/**
 * Validates pattern against the common subset of RE2 and Postgres ARE, and
 * returns the largest effective repetition count in it.
 */
export function checkRegexSubset(pattern: string): RegexCheck {
  const s = new ReScanner([...pattern]);
  // (?i) is the one flag group, and only as a prefix: ARE rejects it anywhere
  // else, so accepting it mid-pattern would be storing a query the database
  // refuses to run.
  if (pattern.startsWith('(?i)')) s.pos = 4;
  const max = s.alt(0);
  if (s.problem !== '') return { maxRepetition: 0, problem: s.problem };
  if (s.pos < s.src.length) {
    return { maxRepetition: 0, problem: 'unbalanced ' + JSON.stringify(s.src[s.pos]) };
  }
  return { maxRepetition: max, problem: '' };
}

/**
 * The second check, after the subset scanner: does the pattern compile at all?
 *
 * Go runs `regexp.Compile`, which is the "no backtracking by construction"
 * guarantee AND a syntax check. JavaScript's RegExp is a backtracking engine
 * with a different dialect, so it is NOT a stand-in for RE2 and this port must
 * not pretend otherwise — a pattern JS accepts may still be refused by RE2, and
 * the server is the authority.
 *
 * What it is still worth asking is the narrow question the subset scanner does
 * not look for: whether a bracket range is well formed (`[z-a]` is an error in
 * every engine). Anything the scanner already accepted and JS then rejects for
 * a dialect reason would be a false positive, so only a range error is
 * reported.
 */
export function compileCheck(pattern: string): string {
  try {
    // eslint-disable-next-line no-new
    new RegExp(pattern, 'u');
    return '';
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (/range/i.test(message) && /class|character/i.test(message)) {
      return 'character class has an out-of-order range';
    }
    return '';
  }
}

class ReScanner {
  readonly src: string[];
  pos = 0;
  problem = '';

  constructor(src: string[]) {
    this.src = src;
  }

  private fail(message: string): void {
    if (this.problem === '') this.problem = message;
  }

  private peek(): string {
    if (this.pos >= this.src.length) return '';
    return this.src[this.pos];
  }

  /** Reads `seq { "|" seq }` and returns the largest repetition product in it. */
  alt(depth: number): number {
    if (depth > MAX_REGEX_NESTING) {
      this.fail(`pattern nests more than ${MAX_REGEX_NESTING} groups deep`);
      return 1;
    }
    let max = this.seq(depth);
    while (this.problem === '' && this.peek() === '|') {
      this.pos++;
      const n = this.seq(depth);
      if (n > max) max = n;
    }
    return max;
  }

  /** Reads a run of quantified atoms. */
  private seq(depth: number): number {
    let max = 1;
    while (this.problem === '' && this.pos < this.src.length) {
      const c = this.peek();
      if (c === '|' || c === ')') return max;
      const inside = this.atom(depth);
      if (this.problem !== '') return max;
      const bound = this.quantifier();
      if (this.problem !== '') return max;
      const n = clampProduct(inside, bound);
      if (n > max) max = n;
    }
    return max;
  }

  /**
   * Reads one atom and returns the largest repetition product inside it (1 for
   * anything but a group).
   */
  private atom(depth: number): number {
    const c = this.src[this.pos];
    switch (c) {
      case '(':
        return this.group(depth);
      case '[':
        this.charClass();
        return 1;
      case '.':
      case '^':
      case '$':
      case '}':
        // "}" with no "{" to close is an ordinary character in both dialects.
        this.pos++;
        return 1;
      case '\\':
        this.escape();
        return 1;
      case '*':
      case '+':
      case '?':
        this.fail('quantifier ' + JSON.stringify(c) + ' with nothing to repeat');
        return 1;
      case '{':
        // A "{" that does not open a valid repetition is a literal brace in
        // both dialects today, but only by accident of two different parsers
        // agreeing. Say what to write instead.
        this.fail('"{" must open a repetition like {2} or {2,5}; write \\{ for a literal brace');
        return 1;
      default:
        this.pos++;
        return 1;
    }
  }

  /** Reads "(...)" or "(?:...)", and rejects every other "(?" form. */
  private group(depth: number): number {
    this.pos++; // "("
    if (this.peek() === '?') {
      const rest = this.src.slice(this.pos).join('');
      if (rest.startsWith('?:')) {
        this.pos += 2;
      } else if (rest.startsWith('?i)')) {
        this.fail('the "(?i)" flag is only allowed at the start of the pattern');
        return 1;
      } else {
        this.fail('only "(...)" and "(?:...)" groups are allowed');
        return 1;
      }
    }
    const inside = this.alt(depth + 1);
    if (this.problem !== '') return inside;
    if (this.peek() !== ')') {
      this.fail('unterminated group');
      return inside;
    }
    this.pos++;
    return inside;
  }

  /**
   * Reads a bracket expression. Escapes and nested "[" are refused inside one:
   * ARE reads `[[:alpha:]]` as a POSIX class and `[]]` as a class containing
   * "]", and RE2 does not agree about either.
   */
  private charClass(): void {
    this.pos++; // "["
    if (this.peek() === '^') this.pos++;
    while (this.pos < this.src.length) {
      switch (this.src[this.pos]) {
        case ']':
          this.pos++;
          return;
        case '\\':
          this.fail(
            'a "\\" is not allowed inside a character class; the characters in one are already literal',
          );
          return;
        case '[':
          this.fail('a "[" is not allowed inside a character class');
          return;
        default:
          break;
      }
      this.pos++;
    }
    this.fail('unterminated character class');
  }

  /** Reads a backslash escape and rejects everything outside the subset. */
  private escape(): void {
    this.pos++; // "\"
    if (this.pos >= this.src.length) {
      this.fail('pattern ends in a "\\"');
      return;
    }
    const c = this.src[this.pos];
    if (CLASS_ESCAPES.includes(c) || LITERAL_ESCAPES.includes(c)) {
      this.pos++;
      return;
    }
    this.fail(
      'the escape "\\' + c + '" is not in the common subset of RE2 and Postgres' + escapeHint(c),
    );
  }

  /**
   * Reads an optional quantifier and returns its upper bound (1 when there is
   * none). A lazy quantifier is refused: both dialects accept `a+?` and they do
   * not agree on what it means.
   */
  private quantifier(): number {
    let bound = 1;
    const c = this.peek();
    if (c === '*' || c === '+' || c === '?') {
      this.pos++;
    } else if (c === '{') {
      bound = this.repetition();
      if (this.problem !== '') return bound;
    } else {
      return bound;
    }
    if (this.peek() === '?') {
      this.fail('a non-greedy quantifier means different things in RE2 and in Postgres');
    }
    return bound;
  }

  /** Reads `{n}`, `{n,}` or `{n,m}` and returns the largest count. */
  private repetition(): number {
    const start = this.pos;
    this.pos++; // "{"
    const lo = this.number();
    if (lo === null) {
      this.pos = start;
      this.fail('a repetition is written {n}, {n,} or {n,m}; write \\{ for a literal brace');
      return 1;
    }
    let max = lo;
    if (this.peek() === ',') {
      this.pos++;
      const hi = this.number();
      if (hi !== null) max = hi;
    }
    if (this.peek() !== '}') {
      this.pos = start;
      this.fail('a repetition is written {n}, {n,} or {n,m}; write \\{ for a literal brace');
      return 1;
    }
    this.pos++;
    if (max > MAX_REPETITION_BOUND) {
      this.fail(
        `a single repetition count may not exceed ${MAX_REPETITION_BOUND}; ` +
          'Postgres refuses a larger one outright',
      );
      return 1;
    }
    return max;
  }

  /**
   * Reads a run of digits. It returns null for an absent number, and the
   * ceiling for one too large to be a repetition count —
   * `a{99999999999999999999}` is not a malformed brace, it is a count nobody
   * meant, and the repetition cap is what should reject it.
   */
  private number(): number | null {
    const start = this.pos;
    while (this.pos < this.src.length && this.src[this.pos] >= '0' && this.src[this.pos] <= '9') {
      this.pos++;
    }
    if (this.pos === start) return null;
    const n = Number.parseInt(this.src.slice(start, this.pos).join(''), 10);
    if (!Number.isSafeInteger(n)) return REPETITION_CEILING;
    return n;
  }
}

/**
 * Adds the specific reason for the escapes people actually reach for, because
 * "not in the subset" alone does not tell them what to do.
 */
function escapeHint(c: string): string {
  switch (c) {
    case 'b':
    case 'B':
      return ': Postgres reads "\\b" as a backspace character, not a word boundary';
    case 'A':
    case 'z':
    case 'Z':
      return ': use "^" and "$"';
    case 'p':
    case 'P':
      return ': write the characters out in a [...] class';
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      return ': RE2 has no backreferences';
    case 'n':
    case 't':
    case 'r':
      return ': put the character itself in the pattern, or write it as \\uXXXX in the query string';
    default:
      return '';
  }
}

/**
 * Multiplies without overflowing, so a deeply nested pattern is compared
 * against the cap rather than wrapping past it.
 */
function clampProduct(a: number, b: number): number {
  if (a <= 0 || b <= 0) return 0;
  if (a > REPETITION_CEILING / b) return REPETITION_CEILING;
  return a * b;
}
