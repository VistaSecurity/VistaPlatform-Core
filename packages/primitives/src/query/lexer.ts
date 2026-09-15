// Scans query text into tokens.
//
// The scanner is mode-driven, because the language is: after a field separator
// or an operator, a bare value may contain `:` `/` `*` and friends (§2), so
// `id.mac:aa:bb:*` is a field, a separator and one value — not five tokens. The
// parser therefore asks for the next token in the mode it expects, which is the
// smallest mechanism that makes §2's rule true without a second grammar.

import type { Span } from './ast';
import { isBareValueChar } from './literal';

/** The lexical class of a token. */
export type TokenKind =
  /** The end of input. */
  | 'eof'
  /** An identifier: `[A-Za-z_][A-Za-z0-9_]*`. */
  | 'ident'
  /** A quoted string; `value` holds the decoded text. */
  | 'string'
  /** A run of bare-value characters, scanned in value mode. */
  | 'bare'
  | '('
  | ')'
  | '['
  | ']'
  | ','
  /** `:` used as a field separator. */
  | ':'
  /** `.` between field segments. */
  | '.'
  /** A comparison operator: `=` `:=` `!=` `<` `<=` `>` `>=` `~`. */
  | 'op'
  /** A leading `-` negation. */
  | '-'
  /** A character that starts no token in the current mode, or a malformed string. */
  | 'illegal';

/** Selects the scanning rules for one token. */
export type Mode =
  /** Scans structure: identifiers, punctuation and operators. */
  | 'default'
  /** Scans a value position: a quoted string, a bare run, or the punctuation that opens a group, a list or a range. */
  | 'value';

/** One lexeme. */
export interface Token {
  kind: TokenKind;
  /** The raw source text of the token, or the reason for an `illegal` token. */
  text: string;
  /** The decoded value; it differs from `text` only for strings. */
  value: string;
  span: Span;
}

/** What `peekChar` returns at end of input. */
export const EOF = null;

/**
 * Scans a query string. It holds no state beyond a position, so the parser can
 * save and restore it to re-scan a term in another mode.
 */
export class Lexer {
  private readonly src: string;
  private pos = 0;

  constructor(src: string) {
    this.src = src;
  }

  /** Returns the source text. */
  source(): string {
    return this.src;
  }

  /** Returns the current position, for `reset`. */
  mark(): number {
    return this.pos;
  }

  /** Moves the scanner back to a position returned by `mark`. */
  reset(pos: number): void {
    this.pos = pos;
  }

  /** Advances past whitespace and returns the new offset. */
  skipSpace(): number {
    while (this.pos < this.src.length) {
      const c = this.src[this.pos];
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r') {
        this.pos++;
        continue;
      }
      return this.pos;
    }
    return this.pos;
  }

  /**
   * Returns the next character after any whitespace, without consuming it, or
   * EOF at end of input. A NUL in the middle of a query is a character like any
   * other and is never mistaken for the end of the text.
   */
  peekChar(): string | null {
    const p = this.pos;
    this.skipSpace();
    let r: string | null = EOF;
    if (this.pos < this.src.length) r = charAt(this.src, this.pos);
    this.pos = p;
    return r;
  }

  /** Scans the next token in the given mode without consuming it. */
  peek(mode: Mode): Token {
    const p = this.pos;
    const tok = this.next(mode);
    this.pos = p;
    return tok;
  }

  /** Scans and consumes the next token in the given mode. */
  next(mode: Mode): Token {
    this.skipSpace();
    const start = this.pos;
    if (this.pos >= this.src.length) {
      return { kind: 'eof', text: '', value: '', span: { start, end: start } };
    }
    const c = this.src[this.pos];

    // Punctuation that means the same thing in both modes.
    switch (c) {
      case '(':
      case ')':
      case '[':
      case ']':
      case ',':
        this.pos++;
        return this.tok(c, start);
      case '"':
      case "'":
        return this.scanString();
      default:
        break;
    }

    if (mode === 'value') return this.scanBare(start);

    if (isIdentStart(c)) {
      this.pos++;
      while (this.pos < this.src.length && isIdentPart(this.src[this.pos])) this.pos++;
      return this.tok('ident', start);
    }
    switch (c) {
      case '.':
        this.pos++;
        return this.tok('.', start);
      case ':':
        // ":=" is the accepted alias for "=" (§3 cheat sheet).
        if (this.pos + 1 < this.src.length && this.src[this.pos + 1] === '=') {
          this.pos += 2;
          return this.tok('op', start);
        }
        this.pos++;
        return this.tok(':', start);
      case '-':
        this.pos++;
        return this.tok('-', start);
      case '=':
      case '~':
        this.pos++;
        return this.tok('op', start);
      case '!':
        if (this.pos + 1 < this.src.length && this.src[this.pos + 1] === '=') {
          this.pos += 2;
          return this.tok('op', start);
        }
        this.pos++;
        return illegal('expected "!="', start, this.pos);
      case '<':
      case '>':
        this.pos++;
        if (this.pos < this.src.length && this.src[this.pos] === '=') this.pos++;
        return this.tok('op', start);
      default:
        break;
    }

    this.pos += charLen(this.src, this.pos);
    return illegal(
      'unexpected character ' + quoteRune(this.src.slice(start, this.pos)),
      start,
      this.pos,
    );
  }

  /** Scans a run of bare-value characters (§2). */
  private scanBare(start: number): Token {
    while (this.pos < this.src.length) {
      const r = charAt(this.src, this.pos);
      if (!isBareValueChar(r)) break;
      this.pos += r.length;
    }
    if (this.pos === start) {
      this.pos += charLen(this.src, this.pos);
      return illegal(
        'expected a value, found ' + quoteRune(this.src.slice(start, this.pos)),
        start,
        this.pos,
      );
    }
    return this.tok('bare', start);
  }

  /** Scans a quoted string and decodes §2's escapes. */
  private scanString(): Token {
    const start = this.pos;
    const quoteChar = this.src[this.pos];
    this.pos++;
    let b = '';
    while (this.pos < this.src.length) {
      const c = this.src[this.pos];
      if (c === quoteChar) {
        this.pos++;
        return {
          kind: 'string',
          text: this.src.slice(start, this.pos),
          value: b,
          span: { start, end: this.pos },
        };
      }
      if (c === '\\') {
        this.pos++;
        if (this.pos >= this.src.length) return this.unterminated(start);
        const e = this.src[this.pos];
        switch (e) {
          case '\\':
          case '"':
          case "'":
            b += e;
            this.pos++;
            continue;
          case 'n':
            b += '\n';
            this.pos++;
            continue;
          case 't':
            b += '\t';
            this.pos++;
            continue;
          case 'r':
            b += '\r';
            this.pos++;
            continue;
          case 'u': {
            if (this.pos + 4 >= this.src.length) {
              return this.badEscape(start, '\\u needs four hex digits');
            }
            const hex = this.src.slice(this.pos + 1, this.pos + 5);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
              return this.badEscape(start, '\\u needs four hex digits');
            }
            const n = Number.parseInt(hex, 16);
            if (n >= 0xd800 && n <= 0xdfff) {
              // A surrogate is half of a UTF-16 pair and is not a character.
              // Go's WriteRune would silently substitute U+FFFD, so \ud800 and
              // \udfff would decode to the SAME value — two different queries,
              // one stored predicate. Refuse it rather than quietly changing
              // what was written. (JavaScript would keep the lone surrogate,
              // which is a different wrong answer for the same reason.)
              return this.badEscape(
                start,
                '\\u' + hex + ' is an unpaired surrogate, not a character',
              );
            }
            b += String.fromCodePoint(n);
            this.pos += 5;
            continue;
          }
          default:
            return this.badEscape(start, 'unknown escape \\' + e);
        }
      }
      const r = charAt(this.src, this.pos);
      b += r;
      this.pos += r.length;
    }
    return this.unterminated(start);
  }

  private unterminated(start: number): Token {
    this.pos = this.src.length;
    return illegal('unterminated string', start, this.pos);
  }

  private badEscape(start: number, reason: string): Token {
    this.pos = this.src.length;
    return illegal(reason, start, this.pos);
  }

  private tok(kind: TokenKind, start: number): Token {
    const text = this.src.slice(start, this.pos);
    return { kind, text, value: text, span: { start, end: this.pos } };
  }
}

function illegal(reason: string, start: number, end: number): Token {
  return { kind: 'illegal', text: reason, value: reason, span: { start, end } };
}

function isIdentStart(c: string): boolean {
  return c === '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

function isIdentPart(c: string): boolean {
  return isIdentStart(c) || (c >= '0' && c <= '9');
}

/** Returns the whole code point at i, so a surrogate pair is never split. */
function charAt(s: string, i: number): string {
  const cp = s.codePointAt(i);
  return cp === undefined ? '' : String.fromCodePoint(cp);
}

function charLen(s: string, i: number): number {
  if (i >= s.length) return 1;
  return charAt(s, i).length;
}

/** Renders a character the way Go's strconv.QuoteRune does, for a message. */
function quoteRune(s: string): string {
  const cp = s.codePointAt(0);
  if (cp === undefined) return "''";
  if (cp === 0x27) return "'\\''";
  if (cp === 0x5c) return "'\\\\'";
  if (cp < 0x20 || cp === 0x7f) {
    const named: Record<number, string> = {
      0x07: '\\a', 0x08: '\\b', 0x09: '\\t', 0x0a: '\\n',
      0x0b: '\\v', 0x0c: '\\f', 0x0d: '\\r',
    };
    const n = named[cp];
    return "'" + (n ?? '\\x' + cp.toString(16).padStart(2, '0')) + "'";
  }
  return "'" + String.fromCodePoint(cp) + "'";
}
