#!/usr/bin/env node
// Vocabulary guard (asset-inventory ADR-0010 D2; DCIM BUILD_PLAN row 0.1).
//
// Reads standards/vocabulary.yaml and fails when
//   1. a forbidden synonym appears where a canonical noun belongs, in the scopes
//      the YAML names (audit.scopes), minus audit.allow_files; or
//   2. the schema and the registry disagree about tables (structural parity).
//
// Phase awareness: a `forbidden` entry with no `after_phase` is enforced from
// day one; one with `after_phase: N` is enforced only when the top-level
// `current_phase` >= N, i.e. once the replacement noun has shipped.
//
// Matching is whole-word and case-insensitive. A multi-word term ("network
// segment") matches with spaces or hyphens between the words. A
// trailing plural (s / es) is allowed. Per scope:
//   ui_strings     String literals and JSX text only. Heuristic, not a parser:
//                  comments and `import ... from '...'` statements are blanked,
//                  then the contents of '...' / "..." / `...` literals and the
//                  text between `>` and `<` are scanned. A word embedded in an
//                  identifier (camelCase, snake_case, digits on either side)
//                  never matches, so `labelFor` does not trip `label` and
//                  `subnetMask` does not trip `subnet`.
//   openapi        Schema names (components.schemas keys), property names and
//                  `title` / `description` text. Names are split on `_`, `-`
//                  and camelCase boundaries and matched as a word sequence.
//   schema         Table and column identifiers only: comments and string
//                  literals are blanked, then each identifier is split on `_`
//                  and matched as a word sequence.
//   customer_docs  Markdown prose; fenced code blocks and `inline code` are
//                  skipped.
//
// A forbidden entry may also carry
//   names_only: true     (openapi) judge schema names only, not properties or prose;
//   paths: [globs]       enforce the entry only in those files;
//   allow_paths: [globs] exempt those files (the connected system's own term).
//   except: [phrases]    real terms that merely contain the word (subnet-router anycast);
//                        blanked before matching, joined on space / hyphen / underscore.
//
// Structural parity (against audit.scopes.schema[0]'s file, usually
// scripts/database/schema.sql):
//   - every objects[].table present in the schema is the plural of its key
//     (and the key is a generated ObjectKind constant);
//   - a schema table named with the SINGULAR key where the registry says plural
//     (`rack` for `racks`) fails;
//   - every table carrying a `custom_fields` column — the DCIM object substrate
//     (ADR-0010 D5) — must be a vocabulary table, so a new object cannot ship
//     without its registry row;
//   - the two reserved ObjectKind tables (assets, asset_endpoints) exist.
//
// `--root <dir>` audits another tree (the tests do). Exit 1 with a report
// grouped by word -> file:line -> matched text; one OK line otherwise.
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';
import { loadVocabulary, pascal, pluralKey, RESERVED_KINDS } from './generate-vocabulary.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// globbing (small, dependency-free; Node 22's fs.glob is still experimental)
// ---------------------------------------------------------------------------

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.claude']);

function expandBraces(p) {
  const m = p.match(/\{([^{}]+)\}/);
  if (!m) return [p];
  return m[1].split(',').flatMap((alt) => expandBraces(p.slice(0, m.index) + alt + p.slice(m.index + m[0].length)));
}

function globToRegex(p) {
  let re = '';
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === '*') {
      if (p[i + 1] === '*') {
        i += 1;
        if (p[i + 1] === '/') { i += 1; re += '(?:.*/)?'; } else re += '.*';
      } else re += '[^/]*';
    } else if (c === '?') re += '[^/]';
    else re += c.replace(/[.+^$()|\\[\]]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}

export function globFiles(root, patterns) {
  const out = new Set();
  for (const pat of patterns.flatMap(expandBraces)) {
    const segs = pat.split('/');
    const staticSegs = [];
    for (const s of segs) { if (/[*?]/.test(s)) break; staticSegs.push(s); }
    const base = path.join(root, ...staticSegs.slice(0, segs.length - 1 === staticSegs.length ? -1 : undefined));
    const re = globToRegex(pat);
    const walk = (dir) => {
      let ents;
      try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
      for (const e of ents) {
        const full = path.join(dir, e.name);
        if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(full); } else {
          const rel = path.relative(root, full).split(path.sep).join('/');
          if (re.test(rel)) out.add(rel);
        }
      }
    };
    if (fs.existsSync(base) && fs.statSync(base).isDirectory()) walk(base);
    else if (fs.existsSync(path.join(root, pat))) out.add(pat);
  }
  return [...out].sort();
}

// ---------------------------------------------------------------------------
// matching
// ---------------------------------------------------------------------------

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Free-text matcher: words separated by space / hyphen runs, optional plural,
// bounded by non-identifier characters. Underscore is an identifier character,
// so snake_case keys (tables, enum values, API keys) are technical identifiers
// and never match here; the openapi and schema scopes check names separately.
export function textMatcher(term) {
  const words = term.trim().split(/\s+/).map(escapeRe);
  return new RegExp(`(?<![A-Za-z0-9_])${words.join('[\\s-]+')}(?:e?s)?(?![A-Za-z0-9_])`, 'gi');
}

// Identifier tokens: split on non-alphanumerics and camelCase boundaries.
export function identTokens(id) {
  return id
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((t) => t.toLowerCase());
}

export function identMatches(id, term) {
  const toks = identTokens(id);
  const want = term.trim().toLowerCase().split(/\s+/);
  for (let i = 0; i + want.length <= toks.length; i++) {
    let ok = true;
    for (let j = 0; j < want.length; j++) {
      const t = toks[i + j];
      const w = want[j];
      const last = j === want.length - 1;
      if (!(t === w || (last && (t === `${w}s` || t === `${w}es`)))) { ok = false; break; }
    }
    if (ok) return true;
  }
  return false;
}

// `except: [phrases]` on a forbidden entry: real terms that merely contain the
// word ("subnet-router anycast", IPv6). Each phrase is blanked (same length, so
// offsets survive) before matching; words in a phrase join on space, hyphen or
// underscore, case-insensitively.
export function exceptMatcher(phrases) {
  if (!phrases || !phrases.length) return null;
  const alts = phrases.map((ph) => ph.trim().split(/[\s_-]+/).map(escapeRe).join('[\\s_-]+'));
  return new RegExp(`(?<![A-Za-z0-9])(?:${alts.join('|')})(?![A-Za-z0-9])`, 'gi');
}
export function applyExcept(str, ex) {
  return ex ? str.replace(ex, (m) => ' '.repeat(m.length)) : str;
}

function lineOf(text, offset) {
  let n = 1;
  for (let i = 0; i < offset && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

// Replace every non-newline character of [a,b) with a space (keeps offsets).
function blank(s, a, b) {
  return s.slice(0, a) + s.slice(a, b).replace(/[^\n]/g, ' ') + s.slice(b);
}

// ---------------------------------------------------------------------------
// per-scope extractors: each returns [{ line, text, kind }] units to test
// ---------------------------------------------------------------------------

function stripJsComments(src) {
  // Walks the source so comment markers inside string literals survive.
  let out = src;
  let i = 0;
  while (i < out.length) {
    const c = out[i];
    const n = out[i + 1];
    if (c === '/' && n === '/') {
      let j = out.indexOf('\n', i); if (j < 0) j = out.length;
      out = blank(out, i, j); i = j;
    } else if (c === '/' && n === '*') {
      let j = out.indexOf('*/', i + 2); j = j < 0 ? out.length : j + 2;
      out = blank(out, i, j); i = j;
    } else if (c === '"' || c === "'" || c === '`') {
      let j = i + 1;
      while (j < out.length && out[j] !== c) { if (out[j] === '\\') j++; if (c !== '`' && out[j] === '\n') break; j++; }
      i = j + 1;
    } else i++;
  }
  return out;
}

export function uiUnits(src) {
  let s = stripJsComments(src);
  // import / export-from statements: module specifiers are not UI strings.
  s = s.replace(/^[ \t]*import\b[^;'"`=]*?['"][^'"\n]*['"];?/gm, (m) => m.replace(/[^\n]/g, ' '));
  s = s.replace(/^[ \t]*export\b[^;'"`=]*?\bfrom\s*['"][^'"\n]*['"];?/gm, (m) => m.replace(/[^\n]/g, ' '));
  const units = [];
  const lit = /(['"`])((?:\\.|(?!\1)[^\\\n])*)\1/g;
  let m;
  while ((m = lit.exec(s))) units.push({ off: m.index + 1, text: m[2] });
  // Template literals may span lines.
  const tpl = /`((?:\\.|[^`\\])*)`/g;
  while ((m = tpl.exec(s))) if (m[1].includes('\n')) units.push({ off: m.index + 1, text: m[1] });
  const jsx = />([^<>{}\n][^<>{}]*)</g;
  while ((m = jsx.exec(s))) units.push({ off: m.index + 1, text: m[1] });
  return { s, units };
}

function scanText(rel, text, units, matcher, f, hits) {
  const ex = exceptMatcher(f.except);
  for (const u of units) {
    matcher.lastIndex = 0;
    let m;
    const ut = applyExcept(u.text, ex);
    while ((m = matcher.exec(ut))) {
      hits.push({ word: f.word, object: f.object, file: rel, line: lineOf(text, u.off + m.index), match: m[0] });
    }
  }
}

function sqlIdentifiers(src) {
  let s = src;
  s = s.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '));
  s = s.replace(/--[^\n]*/g, (m) => ' '.repeat(m.length));
  s = s.replace(/\$([A-Za-z_]*)\$[\s\S]*?\$\1\$/g, (m) => m.replace(/[^\n]/g, ' '));
  s = s.replace(/'(?:[^']|'')*'/g, (m) => m.replace(/[^\n]/g, ' '));
  const ids = [];
  const re = /[A-Za-z_][A-Za-z0-9_]*/g;
  let m;
  while ((m = re.exec(s))) ids.push({ id: m[0], off: m.index });
  return { s, ids };
}

function openapiUnits(rel, text) {
  const doc = yaml.parseDocument(text, { keepSourceTokens: false });
  const lc = new yaml.LineCounter();
  yaml.parseDocument(text, { lineCounter: lc });
  const names = []; // {name, line}
  const texts = []; // {text, line}
  const lineAt = (node) => (node && node.range ? lc.linePos(node.range[0]).line : 1);
  yaml.visit(doc, {
    Pair(_, pair, pth) {
      const key = pair.key && pair.key.value !== undefined ? String(pair.key.value) : null;
      if (key === null) return;
      const parent = pth[pth.length - 2]; // the Pair that owns the map we sit in
      const owner = parent && parent.key && parent.key.value;
      const grand = pth[pth.length - 4];
      const grandOwner = grand && grand.key && grand.key.value;
      if (owner === 'properties') names.push({ name: key, line: lineAt(pair.key), schema: false });
      else if (owner === 'schemas' && grandOwner === 'components') names.push({ name: key, line: lineAt(pair.key), schema: true });
      else if ((key === 'title' || key === 'description') && pair.value && typeof pair.value.value === 'string') {
        texts.push({ text: pair.value.value, line: lineAt(pair.value) });
      }
    },
  });
  return { names, texts };
}

function markdownProse(src) {
  const lines = src.split('\n');
  const out = [];
  let fence = null;
  let generated = false;
  lines.forEach((ln, i) => {
    // The glossary region is generated FROM the registry that defines these
    // words; it is the registry's own text, not prose to police.
    if (/<!--\s*BEGIN GENERATED: vocabulary/.test(ln)) { generated = true; return; }
    if (/<!--\s*END GENERATED: vocabulary/.test(ln)) { generated = false; return; }
    if (generated) return;
    const f = ln.match(/^\s*(```+|~~~+)/);
    if (f) {
      if (!fence) fence = f[1][0]; else if (f[1][0] === fence) fence = null;
      return;
    }
    if (fence) return;
    out.push({ line: i + 1, text: ln.replace(/`[^`\n]*`/g, (m) => ' '.repeat(m.length)) });
  });
  return out;
}

// ---------------------------------------------------------------------------
// forbidden-word audit
// ---------------------------------------------------------------------------

export function collectForbidden(reg, currentPhase) {
  const list = [];
  for (const o of reg.objects || []) {
    for (const f of o.forbidden || []) {
      const after = f.after_phase === undefined ? null : Number(f.after_phase);
      if (after === null || after <= currentPhase) list.push({ object: o.key, ...f });
    }
  }
  for (const r of reg.reserved || []) {
    // `forbidden_in_ui` are retired synonyms of a reserved noun (UI/docs only).
    // `forbidden_as` ("a business unit is never a tenant") names a semantic
    // misuse of a CANONICAL word, which no word hunt can see; it is not scanned.
    // An item is a bare word, or { word, after_phase, note } to defer it.
    for (const item of r.forbidden_in_ui || []) {
      const e = typeof item === 'string' ? { word: item } : item;
      const after = e.after_phase === undefined ? null : Number(e.after_phase);
      if (after === null || after <= currentPhase) list.push({ object: r.key, where: ['ui_strings', 'customer_docs'], ...e });
    }
  }
  return list;
}

export function auditForbidden(root, reg, currentPhase) {
  const hits = [];
  const scopes = reg.audit?.scopes || {};
  const allow = globToSet(root, reg.audit?.allow_files || []);
  const forbidden = collectForbidden(reg, currentPhase);
  const cache = new Map();
  const read = (rel) => { if (!cache.has(rel)) cache.set(rel, fs.readFileSync(path.join(root, rel), 'utf8')); return cache.get(rel); };

  for (const [scope, patterns] of Object.entries(scopes)) {
    const allWords = forbidden.filter((f) => (f.where || []).includes(scope));
    if (!allWords.length) continue;
    const files = globFiles(root, patterns).filter((f) => !allow.has(f));
    // Per-entry narrowing: `paths` limits an entry to those globs, `allow_paths`
    // exempts globs (a connected system's own term, e.g. the CMDB connectors).
    const only = new Map(allWords.map((f) => [f, f.paths ? globToSet(root, f.paths) : null]));
    const skip = new Map(allWords.map((f) => [f, f.allow_paths ? globToSet(root, f.allow_paths) : null]));
    for (const rel of files) {
      const text = read(rel);
      const words = allWords.filter((f) => (!only.get(f) || only.get(f).has(rel)) && !(skip.get(f) && skip.get(f).has(rel)));
      if (!words.length) continue;
      if (scope === 'ui_strings') {
        const { s, units } = uiUnits(text);
        for (const f of words) scanText(rel, s, units, textMatcher(f.word), f, hits);
      } else if (scope === 'customer_docs') {
        const prose = markdownProse(text);
        for (const f of words) {
          const re = textMatcher(f.word);
          const ex = exceptMatcher(f.except);
          for (const p of prose) { re.lastIndex = 0; let m; const pt = applyExcept(p.text, ex); while ((m = re.exec(pt))) hits.push({ word: f.word, object: f.object, file: rel, line: p.line, match: m[0] }); }
        }
      } else if (scope === 'openapi') {
        const { names, texts } = openapiUnits(rel, text);
        for (const f of words) {
          // `names_only`: judge schema names (components.schemas keys) only, not
          // property names or description prose.
          const ex = exceptMatcher(f.except);
          for (const n of names) if ((!f.names_only || n.schema) && identMatches(applyExcept(n.name, ex).replace(/ +/g, '_'), f.word)) hits.push({ word: f.word, object: f.object, file: rel, line: n.line, match: n.name });
          if (f.names_only) continue;
          const re = textMatcher(f.word);
          for (const t of texts) { re.lastIndex = 0; let m; const tt = applyExcept(t.text, ex); while ((m = re.exec(tt))) hits.push({ word: f.word, object: f.object, file: rel, line: t.line, match: m[0] }); }
        }
      } else if (scope === 'schema') {
        const { ids } = sqlIdentifiers(text);
        for (const f of words) { const ex = exceptMatcher(f.except); for (const id of ids) if (identMatches(applyExcept(id.id, ex).replace(/ +/g, '_'), f.word)) hits.push({ word: f.word, object: f.object, file: rel, line: lineOf(text, id.off), match: id.id }); }
      }
    }
  }
  return hits;
}

function globToSet(root, patterns) {
  return new Set(globFiles(root, patterns));
}

// ---------------------------------------------------------------------------
// structural parity
// ---------------------------------------------------------------------------

export function schemaTables(sqlSrc) {
  const { s } = sqlIdentifiers(sqlSrc);
  const out = new Map(); // table -> { line, columns:Set }
  const re = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:(?:public)\.)?([A-Za-z_][A-Za-z0-9_]*)\s*\(/gi;
  let m;
  while ((m = re.exec(s))) {
    // Only the public schema's unqualified tables; audit.* etc. are other schemas.
    const prefix = s.slice(m.index, m.index + m[0].length);
    if (/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[A-Za-z_]+\./i.test(prefix) && !/\bpublic\./i.test(prefix)) continue;
    // body = balanced parentheses from the opening one
    let depth = 1; let i = re.lastIndex;
    const start = i;
    while (i < s.length && depth) { if (s[i] === '(') depth++; else if (s[i] === ')') depth--; i++; }
    const body = s.slice(start, i - 1);
    const cols = new Set();
    let d = 0; let cur = '';
    for (const ch of body) {
      if (ch === '(') d++; if (ch === ')') d--;
      if (ch === ',' && d === 0) { cols.add(cur.trim().split(/\s+/)[0]?.toLowerCase()); cur = ''; } else cur += ch;
    }
    cols.add(cur.trim().split(/\s+/)[0]?.toLowerCase());
    out.set(m[1].toLowerCase(), { line: lineOf(s, m.index), columns: cols });
  }
  return out;
}

export function auditStructure(root, reg, kinds) {
  const issues = [];
  const schemaRel = (reg.audit?.scopes?.schema || [])[0];
  if (!schemaRel) return issues;
  const schemaFile = path.join(root, schemaRel);
  if (!fs.existsSync(schemaFile)) return [{ file: schemaRel, line: 1, msg: 'schema file not found' }];
  const tables = schemaTables(fs.readFileSync(schemaFile, 'utf8'));

  const genRel = 'shared/dcim/objectkind_gen.go';
  const genFile = path.join(root, genRel);
  const goConsts = new Map();
  if (fs.existsSync(genFile)) {
    const g = fs.readFileSync(genFile, 'utf8');
    for (const m of g.matchAll(/^\s*(ObjectKind\w+)\s+ObjectKind\s*=\s*"([^"]+)"/gm)) goConsts.set(m[2], m[1]);
  }

  const vocabTables = new Set(kinds.filter((k) => k.table).map((k) => k.table));
  for (const k of kinds) {
    if (!k.table) continue;
    const want = `ObjectKind${pascal(k.key)}`;
    const inSchema = tables.get(k.table);
    if (inSchema && goConsts.get(k.key) !== want) {
      issues.push({ file: genRel, line: 1, msg: `table "${k.table}" exists but ${genRel} has no constant ${want} = "${k.key}"` });
    }
    // singular where the registry says plural
    const singular = tables.get(k.key);
    if (singular && k.key !== k.table) {
      issues.push({ file: schemaRel, line: singular.line, msg: `table "${k.key}" must be named "${k.table}" (the plural of the key; VOCABULARY.md rule 5)` });
    }
  }
  for (const [name, t] of tables) {
    if (t.columns.has('custom_fields') && !vocabTables.has(name)) {
      issues.push({ file: schemaRel, line: t.line, msg: `table "${name}" carries custom_fields (the object substrate) but has no row in standards/vocabulary.yaml` });
    }
  }
  for (const [key, table] of Object.entries(RESERVED_KINDS)) {
    if (!tables.has(table)) issues.push({ file: schemaRel, line: 1, msg: `reserved kind "${key}" expects table "${table}", which is not in the schema` });
  }
  return issues;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

export function runAudit(root) {
  const { reg, kinds, errors, currentPhase } = loadVocabulary(root);
  const hits = errors.length ? [] : auditForbidden(root, reg, currentPhase);
  const issues = errors.map((msg) => ({ file: 'standards/vocabulary.yaml', line: 1, msg }));
  if (!errors.length) issues.push(...auditStructure(root, reg, kinds));
  return { hits, issues, currentPhase };
}

export function formatReport({ hits, issues, currentPhase }) {
  const lines = [];
  const byWord = new Map();
  for (const h of hits) { if (!byWord.has(h.word)) byWord.set(h.word, []); byWord.get(h.word).push(h); }
  for (const [word, hs] of byWord) {
    lines.push(`forbidden word "${word}" (${hs.length}):`);
    for (const h of hs) lines.push(`  ${h.file}:${h.line}  ${JSON.stringify(h.match)}`);
  }
  if (issues.length) {
    lines.push('structural parity:');
    for (const i of issues) lines.push(`  ${i.file}:${i.line}  ${i.msg}`);
  }
  lines.push(`vocabulary audit FAILED at current_phase ${currentPhase}: ${hits.length} forbidden-word finding(s), ${issues.length} structural finding(s). Fix the text, or advance the registry (see docsv4/internal/developer/design/dcim/VOCABULARY.md); never add an allow-list path.`);
  return lines.join('\n');
}

function main() {
  const argv = process.argv.slice(2);
  const ri = argv.indexOf('--root');
  const root = ri >= 0 ? path.resolve(argv[ri + 1]) : path.resolve(__dirname, '..');
  const res = runAudit(root);
  if (res.hits.length || res.issues.length) {
    console.error(formatReport(res));
    process.exitCode = 1; // not process.exit(): it truncates a large report on a pipe
    return;
  }
  console.log(`vocabulary audit OK (current_phase ${res.currentPhase}, 0 findings)`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
