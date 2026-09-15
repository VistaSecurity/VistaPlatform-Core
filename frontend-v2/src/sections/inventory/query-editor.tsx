// The query editor.
//
// QUERY_LANGUAGE §1: "Learnable by reading. The facet rail writes the query and
// shows it; a user learns the language by watching the UI produce it."
// Autocomplete is the other half of that, and the inline error is the third:
// a query that is wrong must say WHERE it is wrong and WHAT to write instead,
// because "invalid query" teaches nothing.
//
// Everything the editor knows about the language comes from
// `@vistasecurity/primitives/query`. There is no parsing, no field list and no
// value list written out here — the vocabulary is generated from the class
// registry, the fact registry and the schema's own enums, and a second copy in
// this file would be a copy that goes stale (the package README has the long
// version of why).
import { useMemo, useRef, useState } from 'react';
import {
  CVSS_LADDER, check, defaultOptions, newRegistryCatalog, parse, suggest, walkFields, withLadder,
  type Completion, type QueryError,
} from '@vistasecurity/primitives/query';
import { Icon } from '../../components/ui';

/** The production catalogue and options, built once. Both are pure data. */
const CATALOG = newRegistryCatalog();
const OPTIONS = withLadder(defaultOptions(), CVSS_LADDER);

/** Validate a query against the `asset` target. Exported so the tests and the
 *  saved-view dialog can ask the same question the editor asks. */
export function checkAssetQuery(text: string): { ok: boolean; canonical: string; errors: QueryError[] } {
  if (text.trim() === '') return { ok: true, canonical: '', errors: [] };
  const out = check(text, 'asset', CATALOG, OPTIONS);
  return out.ok
    ? { ok: true, canonical: out.value.canonical, errors: [] }
    : { ok: false, canonical: '', errors: out.errors };
}

/** Completions at a cursor, against the same catalogue. */
export function suggestAssetQuery(text: string, cursor: number): ReturnType<typeof suggest> {
  return suggest(text, cursor, CATALOG, { target: 'asset', ladder: CVSS_LADDER, limit: 12 });
}

const KIND_ICON: Record<Completion['kind'], string> = {
  field: 'tag',
  namespace: 'folder-tree',
  operator: 'equal',
  value: 'circle-dot',
  class: 'box',
  relationship: 'waypoints',
  collection: 'layers',
  keyword: 'type',
};

/** The shape both diagnostic sources agree on — the local validator's
 *  `QueryError` and the API's `QueryDiagnostic` are the same four fields
 *  (QUERY_LANGUAGE §10). They differ ONLY in how the span is measured, which is
 *  `byteSpanToStringSpan`'s job. */
export interface Diagnostic {
  code: string;
  message: string;
  span: { start: number; end: number };
  suggestion?: string;
}

/** The UTF-8 encoded length of one code point. */
function utf8Len(cp: number): number {
  if (cp < 0x80) return 1;
  if (cp < 0x800) return 2;
  if (cp < 0x10000) return 3;
  return 4;
}

/**
 * Converts a SERVER span into a JavaScript string span.
 *
 * `QueryDiagnostic.span` carries "a byte span into the submitted text" — Go
 * measures in UTF-8 bytes. A JavaScript string is indexed in UTF-16 code units,
 * so `source.slice(span.start, span.end)` on a raw server span underlines the
 * wrong characters the moment the query contains anything outside ASCII: every
 * accented letter in a hostname or a business unit shifts the highlight one
 * place further left, and a CJK or emoji value shifts it two or three. The
 * message would still be right and the caret would point at an innocent word —
 * which teaches the user something false about their own query.
 *
 * The LOCAL validator's spans are already UTF-16 (see the query package's
 * README: "Spans are UTF-16 code units, not UTF-8 bytes"), so this is applied
 * to server diagnostics ONLY. Running it over a local span would corrupt the
 * one that was correct.
 *
 * Out-of-range and inverted spans clamp rather than throw: a diagnostic is a
 * message about a mistake, and it must not become a second one.
 */
export function byteSpanToStringSpan(source: string, span: { start: number; end: number }): { start: number; end: number } {
  let start: number | null = null;
  let end: number | null = null;
  let bytes = 0;
  let i = 0;
  for (;;) {
    if (start === null && bytes >= span.start) start = i;
    if (end === null && bytes >= span.end) end = i;
    if ((start !== null && end !== null) || i >= source.length) break;
    const cp = source.codePointAt(i) as number;
    bytes += utf8Len(cp);
    i += cp > 0xffff ? 2 : 1;
  }
  const s = Math.max(0, start ?? source.length);
  return { start: s, end: Math.max(s, end ?? source.length) };
}

/** Server diagnostics, with their byte spans translated into the string the
 *  editor is rendering. `query` is the text the server echoed back, which is
 *  what those spans index into — not necessarily what is in the box now. */
export function serverDiagnosticsForDisplay(query: string, errors: Diagnostic[]): Diagnostic[] {
  return errors.map((e) => ({ ...e, span: byteSpanToStringSpan(query, e.span) }));
}

/**
 * Renders one error with the offending span highlighted in the query text.
 *
 * The span is the point of the structured error: a message that names a field
 * is useful, but a message that POINTS at the field in what the user typed is
 * the difference between reading an error and seeing one. `errors.ts` renders
 * this as a caret line for a terminal; this is the same information in a
 * browser.
 */
function ErrorLine({ source, error }: { source: string; error: Diagnostic | QueryError }) {
  const start = Math.max(0, Math.min(error.span.start, source.length));
  const end = Math.max(start + 1, Math.min(error.span.end, source.length));
  return (
    <div data-testid="query-error" style={{ padding: '7px 11px', borderTop: '1px solid var(--app-border)' }}>
      <div className="mono" style={{ fontSize: 11.5, whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: 'var(--app-t3)' }}>
        {source.slice(0, start)}
        <span
          data-testid="query-error-span"
          style={{ color: 'var(--danger-text)', background: 'color-mix(in srgb, var(--danger) 18%, transparent)', borderRadius: 3, textDecoration: 'underline wavy var(--danger)', textUnderlineOffset: 3 }}
        >
          {source.slice(start, end)}
        </span>
        {source.slice(end)}
      </div>
      <div style={{ fontSize: 12, color: 'var(--danger-text)', marginTop: 4 }}>
        <span className="mono" style={{ fontSize: 10.5, opacity: 0.8 }}>{error.code}</span>{' '}
        {error.message}
      </div>
      {error.suggestion && (
        <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 2 }}>{error.suggestion}</div>
      )}
    </div>
  );
}

/**
 * The server's own diagnostics for a query it refused, rendered the same way
 * the editor renders its own.
 *
 * The two validators are held to one fixture file but they are not the same
 * program, and the codes only the server can raise are exactly the ones a user
 * most needs pointed at: `untranslatable` (the language accepts it, the SQL
 * shape does not) and a value set the client's generated catalogue is one
 * release behind on. Flattening those into a sentence in an error card is the
 * "invalid query" the language exists to avoid, one layer further out.
 *
 * `query` is the text the server echoed, which is what its spans index into.
 */
export function ServerQueryErrors({ query, errors }: { query: string; errors: Diagnostic[] }) {
  const display = useMemo(() => serverDiagnosticsForDisplay(query, errors), [query, errors]);
  if (display.length === 0) return null;
  return (
    <div
      role="alert"
      data-testid="server-query-errors"
      style={{ textAlign: 'left', maxWidth: 560, borderRadius: 10, border: '1px solid var(--danger)', background: 'var(--app-panel)', overflow: 'hidden' }}
    >
      {display.map((e, i) => <ErrorLine key={`${e.code}-${e.span.start}-${i}`} source={query} error={e} />)}
    </div>
  );
}

/**
 * The query field itself: the input, its completion list, and its diagnostics.
 *
 * Split out of `QueryEditor` so the other places a query is authored get the
 * same editor rather than a bare text box. A scope and an auto-approval rule
 * carry the same language as the Inventory rail — that unification is the whole
 * of ADR-0006 D2 — so they deserve the same autocomplete and the same
 * caret-under-the-error, not a field that only finds out it is wrong on save.
 *
 * It reports the draft on EVERY keystroke (`onDraftChange`) and nothing else. A
 * caller that owns a Save button asks `checkAssetQuery` about the value it is
 * already holding — validity is a pure function of that string, so deriving it
 * is both simpler and correct on the same frame.
 *
 * It deliberately does NOT push validity back up. This used to take an
 * `onValidityChange` and call it during render, which is a setState on a
 * DIFFERENT component mid-render: React logs "Cannot update a component while
 * rendering a different component" and the update is not guaranteed to be
 * batched with the render that caused it. There was never a reason for the
 * callback — the parent has the text.
 */
export function QueryInput({
  value, onDraftChange, onCommit, placeholder, inputId, ariaLabel, autoFocus,
}: {
  value: string;
  onDraftChange: (draft: string) => void;
  /** Enter with no completion highlighted. */
  onCommit?: (canonical: string) => void;
  placeholder?: string;
  inputId?: string;
  ariaLabel?: string;
  autoFocus?: boolean;
}) {
  const [cursor, setCursor] = useState(0);
  const [open, setOpen] = useState(false);
  const [highlight, setHighlight] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const outcome = useMemo(() => checkAssetQuery(value), [value]);

  const completions = useMemo(() => {
    if (!open) return null;
    return suggestAssetQuery(value, cursor);
  }, [open, value, cursor]);
  const list = completions ? completions.completions : [];

  const apply = (c: Completion) => {
    const res = completions;
    if (!res) return;
    const next = value.slice(0, res.span.start) + c.text + value.slice(res.span.end);
    onDraftChange(next);
    // Put the caret straight after what was inserted so the next completion
    // (a value after a field's colon) is one keystroke away.
    const at = res.span.start + c.text.length;
    requestAnimationFrame(() => {
      inputRef.current?.focus();
      inputRef.current?.setSelectionRange(at, at);
      setCursor(at);
    });
    setHighlight(0);
  };

  const syncCursor = (e: { currentTarget: HTMLInputElement }) => {
    setCursor(e.currentTarget.selectionStart ?? 0);
    setHighlight(0);
  };

  return (
    <div style={{ position: 'relative', flex: 1, minWidth: 0 }}>
      <Icon name="search-code" size={14} style={{ position: 'absolute', left: 11, top: 9, color: 'var(--app-t3)', pointerEvents: 'none' }} />
      <input
        ref={inputRef}
        id={inputId}
        className="mono"
        aria-label={ariaLabel ?? 'Query'}
        aria-invalid={!outcome.ok}
        spellCheck={false}
        autoComplete="off"
        autoFocus={autoFocus}
        value={value}
        placeholder={placeholder ?? 'class:server and risk >= high'}
        onChange={(e) => { onDraftChange(e.target.value); setCursor(e.target.selectionStart ?? 0); setHighlight(0); setOpen(true); }}
        onClick={syncCursor}
        // ArrowUp/ArrowDown deliberately excluded: they move the COMPLETION
        // highlight, not the caret, and syncing on them would reset the
        // selection the user is making with them.
        onKeyUp={(e) => { if (e.key === 'ArrowLeft' || e.key === 'ArrowRight' || e.key === 'Home' || e.key === 'End') syncCursor(e); }}
        onFocus={() => setOpen(true)}
        onBlur={() => { window.setTimeout(() => setOpen(false), 140); }}
        onKeyDown={(e) => {
          if (e.key === 'Escape') { setOpen(false); return; }
          if (open && list.length > 0) {
            if (e.key === 'ArrowDown') { e.preventDefault(); setHighlight((h) => (h + 1) % list.length); return; }
            if (e.key === 'ArrowUp') { e.preventDefault(); setHighlight((h) => (h - 1 + list.length) % list.length); return; }
            if (e.key === 'Tab') { e.preventDefault(); apply(list[highlight]); return; }
          }
          if (e.key === 'Enter') {
            e.preventDefault();
            if (open && list.length > 0 && highlight >= 0 && e.currentTarget.selectionStart !== value.length) {
              apply(list[highlight]);
              return;
            }
            setOpen(false);
            if (outcome.ok) onCommit?.(outcome.canonical);
          }
        }}
        style={{
          width: '100%', height: 33, padding: '0 12px 0 33px', borderRadius: 9,
          border: `1px solid ${outcome.ok ? 'var(--app-border2)' : 'var(--danger)'}`,
          background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12.5, outline: 'none',
        }}
      />

      {/* Errors — every one of them, with its span highlighted. */}
      {!outcome.ok && (
        <div
          role="alert"
          style={{ position: 'absolute', zIndex: 40, top: 38, left: 0, right: 0, borderRadius: 10, border: '1px solid var(--danger)', background: 'var(--app-panel)', boxShadow: '0 10px 30px rgba(0,0,0,.22)', overflow: 'hidden' }}
        >
          {outcome.errors.map((e, i) => <ErrorLine key={`${e.code}-${e.span.start}-${i}`} source={value} error={e} />)}
        </div>
      )}

      {/* Completions. Only ever what the validator would accept — see the
          package README: an editor that suggests a field the server rejects has
          taught the user something false. */}
      {outcome.ok && open && list.length > 0 && (
        <ul
          role="listbox"
          aria-label="Query completions"
          style={{ position: 'absolute', zIndex: 40, top: 38, left: 0, minWidth: 320, maxWidth: 460, maxHeight: 280, overflowY: 'auto', margin: 0, padding: 4, listStyle: 'none', borderRadius: 10, border: '1px solid var(--app-border2)', background: 'var(--app-panel)', boxShadow: '0 10px 30px rgba(0,0,0,.22)' }}
        >
          {list.map((c, i) => (
            <li key={`${c.kind}-${c.text}`} role="option" aria-selected={i === highlight}>
              <button
                onMouseDown={(e) => { e.preventDefault(); apply(c); }}
                onMouseEnter={() => setHighlight(i)}
                style={{ display: 'flex', alignItems: 'center', gap: 9, width: '100%', padding: '6px 9px', border: 'none', borderRadius: 7, cursor: 'pointer', textAlign: 'left', background: i === highlight ? 'var(--app-panel2)' : 'transparent', color: 'var(--app-t1)' }}
              >
                <Icon name={KIND_ICON[c.kind] ?? 'circle-dot'} size={13} style={{ color: 'var(--app-t3)', flex: 'none' }} />
                <span className="mono" style={{ fontSize: 12.5 }}>{c.text}</span>
                {c.detail && (
                  <span style={{ fontSize: 11, color: 'var(--app-t3)', marginLeft: 'auto', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 220 }}>{c.detail}</span>
                )}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/**
 * The Inventory toolbar's editor: a `QueryInput` plus Run and Clear.
 *
 * It holds a DRAFT and commits on Enter or Run, because the committed value goes
 * into the URL and refetches the page — running a query on every keystroke would
 * be a request per character.
 */
export function QueryEditor({ value, onChange, onSubmit, placeholder, busy }: {
  /** The query text currently in the URL. */
  value: string;
  /** Called when the user commits a VALID query (Enter, or the Run button). */
  onChange: (query: string) => void;
  onSubmit?: () => void;
  placeholder?: string;
  busy?: boolean;
}) {
  const [draft, setDraft] = useState(value);
  const [lastValue, setLastValue] = useState(value);

  // The URL is the source of truth: a facet click rewrites the query, and the
  // editor must show what the rail just wrote.
  //
  // Adjusted DURING RENDER rather than in an effect, which is React's own
  // recommendation for resetting state when a prop changes: an effect would
  // paint the stale draft for one frame first, and a `key` would remount the
  // input and take the caret with it mid-typing.
  if (value !== lastValue) {
    setLastValue(value);
    setDraft(value);
  }

  const outcome = useMemo(() => checkAssetQuery(draft), [draft]);
  const dirty = draft.trim() !== value.trim();

  const commit = () => {
    if (!outcome.ok) return;
    // Store the CANONICAL form (§10), not what was typed: it is what a saved
    // view carries and what makes two spellings of one predicate one cache key.
    onChange(outcome.canonical);
    onSubmit?.();
  };

  return (
    <div style={{ position: 'relative', flex: 1, minWidth: 260, display: 'flex', alignItems: 'center', gap: 6 }}>
      <QueryInput
        value={draft}
        onDraftChange={setDraft}
        onCommit={(canonical) => { onChange(canonical); onSubmit?.(); }}
        placeholder={placeholder}
      />
      <button
        className={'ui-btn' + (dirty && outcome.ok ? ' accent' : '')}
        disabled={!outcome.ok || busy}
        onClick={commit}
        title={outcome.ok ? 'Run this query' : 'Fix the query first'}
        style={{ height: 33, padding: '0 11px', fontSize: 12.5, opacity: outcome.ok ? 1 : 0.5, flex: 'none' }}
      >
        <Icon name="play" size={13} />Run
      </button>
      {value && (
        <button
          className="ui-btn ghost"
          onClick={() => { setDraft(''); onChange(''); }}
          title="Clear the query"
          style={{ height: 33, padding: '0 9px', fontSize: 12.5, flex: 'none' }}
        >
          <Icon name="x" size={13} />Clear
        </button>
      )}
    </div>
  );
}

/**
 * A query rendered read-only, with its FIELD NAMES picked out.
 *
 * Used wherever a stored query is shown rather than edited — a scope row, a rule
 * row. The highlighting comes from the real parser's resolved field spans, not
 * from a regex over the text, so it cannot disagree with what the query means:
 * a word that looks like a field but is a quoted value is not highlighted,
 * because the parser says it is not one.
 */
export function QueryChip({ query, empty = 'All assets' }: { query?: string | null; empty?: string }) {
  const text = (query ?? '').trim();
  const parts = useMemo(() => splitFieldSpans(text), [text]);
  if (text === '') {
    return <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{empty}</span>;
  }
  return (
    <span className="mono" title={text} style={{ fontSize: 11.5, color: 'var(--app-t2)', wordBreak: 'break-word' }}>
      {parts.map((part, i) => (
        <span key={i} style={part.field ? { color: 'var(--accent)', fontWeight: 600 } : undefined}>{part.text}</span>
      ))}
    </span>
  );
}

/** Splits a query into runs, marking the ones the parser resolved as FIELD
 *  references. A query that does not parse is one unmarked run — highlighting a
 *  guess at a broken query would be inventing structure that is not there. */
export function splitFieldSpans(text: string): { text: string; field: boolean }[] {
  if (text === '') return [];
  const parsed = parse(text);
  if (!parsed.ok) return [{ text, field: false }];
  const spans: { start: number; end: number }[] = [];
  walkFields(parsed.value.root, (f) => { spans.push({ start: f.span.start, end: f.span.end }); });
  spans.sort((a, b) => a.start - b.start);
  const out: { text: string; field: boolean }[] = [];
  let at = 0;
  for (const s of spans) {
    if (s.start < at) continue;
    if (s.start > at) out.push({ text: text.slice(at, s.start), field: false });
    out.push({ text: text.slice(s.start, s.end), field: true });
    at = s.end;
  }
  if (at < text.length) out.push({ text: text.slice(at), field: false });
  return out;
}
