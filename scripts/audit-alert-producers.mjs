#!/usr/bin/env node
// Audits standards/alert-registry.yaml against the Go source: every
// `status: live` alert type must actually have a PRODUCER — a site that
// constructs an events.AlertRaiseEvent naming that type.
//
// Why this exists: the registry's own generator only checks YAML ↔ generated-Go
// drift, so the catalog could claim `status: live` (which the product reads as
// "a detector is active and this forms a real alert in the alerts table with
// dedupe/escalation/auto-resolve, visible at Remediation → Alerts") for a type
// nothing ever raises. That is exactly what happened to failed_login_burst and
// metric_threshold: both were detected, both notified, neither ever reached the
// alerts table — and every gate stayed green.
//
// The producer set is DERIVED from the source on every run. There is
// deliberately no hand-maintained list of live types here: a second copy of the
// answer is a copy that drifts, and the drift would be invisible precisely
// because this file is what is supposed to notice it.
//
// Run via `make audit` (strict). Mutation-test any change to it: flip a
// `planned` type to `live` (must FAIL), comment out a raise site (must FAIL),
// delete ONE branch of a helper that routes two types — the
// `hygiene_score_drop` arm of `alertTypeForFramework` — (must FAIL naming
// hygiene_score_drop, not compliance_score_drop), clean tree (must PASS).
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

// Directories scanned for producers. The rail is deliberately open to any
// service, so scan them all plus shared/.
const SCAN_DIRS = ['services', 'shared'];

function fail(msg) {
  console.error(`alert-producers: ${msg}`);
  process.exit(1);
}

async function goFiles(dir) {
  const out = [];
  async function walk(d) {
    let entries;
    try {
      entries = await fs.readdir(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) {
        if (e.name === 'node_modules' || e.name === 'vendor' || e.name === '.git') continue;
        await walk(p);
      } else if (e.name.endsWith('.go') && !e.name.endsWith('_test.go')) {
        // The generated catalog names every id but produces nothing.
        if (e.name === 'registry_gen.go') continue;
        out.push(p);
      }
    }
  }
  await walk(dir);
  return out;
}

// stripComments removes Go line and block comments (string literals preserved).
// Without this the audit is INERT against the commonest way a producer dies:
// commenting the raise site out leaves the text `AlertRaiseEvent{` in the file,
// and a text scan happily credits a producer that no longer runs. Verified by
// mutation test — see the header.
function stripComments(src) {
  let out = '';
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === '"' || c === '`' || c === "'") {
      const quote = c;
      out += c;
      i++;
      for (; i < src.length; i++) {
        out += src[i];
        if (src[i] === '\\' && quote !== '`') {
          i++;
          if (i < src.length) out += src[i];
          continue;
        }
        if (src[i] === quote) break;
      }
      continue;
    }
    if (c === '/' && src[i + 1] === '/') {
      while (i < src.length && src[i] !== '\n') i++;
      out += '\n';
      continue;
    }
    if (c === '/' && src[i + 1] === '*') {
      i += 2;
      while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) i++;
      i++;
      out += ' ';
      continue;
    }
    out += c;
  }
  return out;
}

// extractRaiseBlocks returns the source text of every AlertRaiseEvent composite
// literal in `src`, by brace matching from the opening `{`.
function extractRaiseBlocks(src) {
  const blocks = [];
  const marker = 'AlertRaiseEvent{';
  let from = 0;
  for (;;) {
    const i = src.indexOf(marker, from);
    if (i === -1) break;
    let depth = 0;
    let j = i + marker.length - 1; // at the '{'
    let end = -1;
    for (; j < src.length; j++) {
      const c = src[j];
      if (c === '"') {
        // skip string literal
        j++;
        while (j < src.length && !(src[j] === '"' && src[j - 1] !== '\\')) j++;
        continue;
      }
      if (c === '{') depth++;
      else if (c === '}') {
        depth--;
        if (depth === 0) {
          end = j;
          break;
        }
      }
    }
    if (end === -1) break;
    blocks.push(src.slice(i, end + 1));
    from = end + 1;
  }
  return blocks;
}

// --- alert-type resolution ---------------------------------------------------
//
// The RHS of an `AlertType:` field is rarely a literal. It is a const, a struct
// field (`j.spec.alertType`), or a value a helper returned (`fs.alertType()`),
// so crediting a producer means following the value back to the string(s) it can
// carry.
//
// This used to end in a FILE-LEVEL FALLBACK: a value the resolver could not
// trace credited every registry id appearing as a literal anywhere in the same
// file. That is what made the audit unable to tell `compliance_score_drop` and
// `hygiene_score_drop` apart — one job serves both, the RHS is a local bound
// from a method call, and the fallback handed it both ids whether or not either
// was still reachable. Delete the hygiene branch of `alertTypeForFramework` and
// the audit stayed green while nothing could raise `hygiene_score_drop` again.
//
// The fallback is gone. Resolution follows the value: identifier → the things
// bound to that NAME → the expressions those hold → the bodies of the functions
// they name, transitively. A value that still cannot be traced is reported as an
// UNRESOLVED blind spot (which fails the audit) rather than papered over with
// every id in the file.
//
// Only literals that are REGISTRY IDS are collected while following a chain,
// because a helper's body legitimately contains other strings (log formats, SQL)
// and crediting those would resurrect the same looseness pointed the other way.
// A DIRECT literal at the `AlertType:` field is not filtered, so a typo there is
// still caught by the unknown-type check below.

const IDENT_RE = /[A-Za-z_][A-Za-z0-9_]*/g;

// skipString returns the index of the closing quote of the Go string or rune
// literal that starts at src[i].
function skipString(src, i) {
  const quote = src[i];
  i++;
  for (; i < src.length; i++) {
    if (src[i] === '\\' && quote !== '`') {
      i++;
      continue;
    }
    if (src[i] === quote) return i;
  }
  return src.length;
}

// balancedExpr reads the expression starting at `from`, ending at the first
// newline reached with every bracket closed. That is what lets a multi-line
// composite literal (`var m = map[uuid.UUID]string{\n  k: v,\n}`) be read as ONE
// expression instead of being truncated at its first line — which is where the
// audit-service rule→type map lives.
function balancedExpr(src, from) {
  let depth = 0;
  let i = from;
  for (; i < src.length; i++) {
    const c = src[i];
    if (c === '"' || c === '`' || c === "'") {
      i = skipString(src, i);
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      if (depth === 0) break;
      depth--;
    } else if (c === '\n' && depth === 0) break;
  }
  return src.slice(from, i);
}

// funcBody returns the body of the function declaration whose `func` keyword is
// at `from`, or '' when it cannot be delimited.
function funcBody(src, from) {
  let paren = 0;
  let bracket = 0;
  let i = from + 4;
  for (; i < src.length; i++) {
    const c = src[i];
    if (c === '"' || c === '`' || c === "'") {
      i = skipString(src, i);
      continue;
    }
    if (c === '(') paren++;
    else if (c === ')') paren--;
    else if (c === '[') bracket++;
    else if (c === ']') bracket--;
    else if (c === '{' && paren === 0 && bracket === 0) break;
  }
  if (i >= src.length) return '';
  let depth = 0;
  for (let j = i; j < src.length; j++) {
    const c = src[j];
    if (c === '"' || c === '`' || c === "'") {
      j = skipString(src, j);
      continue;
    }
    if (c === '{') depth++;
    else if (c === '}') {
      depth--;
      if (depth === 0) return src.slice(i, j + 1);
    }
  }
  return '';
}

// funcReturns lists the expressions a function body can hand back.
function funcReturns(body) {
  const out = [];
  const re = /\breturn\b/g;
  let m;
  while ((m = re.exec(body)) !== null) {
    const expr = balancedExpr(body, m.index + m[0].length).trim();
    if (expr) out.push(expr);
  }
  return out;
}

// buildSymbols indexes one file: per NAME, the string literals bound to it, the
// expressions bound to it, and the bodies of functions declared with it. A file
// is still the unit (as it was before), but a name now only contributes what is
// actually bound to THAT name.
function buildSymbols(src) {
  const literals = new Map(); // name -> Set(literal)
  const exprs = new Map(); // name -> [expression source]
  const funcs = new Map(); // name -> [body source]
  const add = (map, key, value) => {
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(value);
  };

  // `name = expr`, `name := expr`, `name: expr` (a composite-literal field) and
  // the multi-value `name, other := expr`. The identifier must sit immediately
  // before the operator, which is what keeps `==`, `!=`, `>=` and `+=` out.
  const bind = /([A-Za-z_][A-Za-z0-9_]*)\s*(?:,\s*[A-Za-z_][A-Za-z0-9_]*\s*)?(:=|=|:)(?![=:])\s*/g;
  let m;
  while ((m = bind.exec(src)) !== null) {
    const name = m[1];
    const rhs = balancedExpr(src, m.index + m[0].length).trim();
    if (!rhs) continue;
    const lit = rhs.match(/^"([^"\\]*)"$/);
    if (lit) {
      if (!literals.has(name)) literals.set(name, new Set());
      literals.get(name).add(lit[1]);
    } else {
      add(exprs, name, rhs);
    }
  }

  const fn = /\bfunc\b/g;
  while ((m = fn.exec(src)) !== null) {
    // `func Name(` or `func (r T) Name(`.
    const named = src.slice(m.index, m.index + 240).match(/^func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(/);
    if (!named) continue;
    const body = funcBody(src, m.index);
    // Only the RETURN expressions, never the whole body. A body mentions all
    // sorts of names — loop variables, the type consts it compares against, log
    // arguments — and following every one of them re-creates the file-level
    // fallback by a longer route: with the whole body in play, deleting the
    // `hygiene_score_drop` branch of `alertTypeForFramework` still left the id
    // reachable through an unrelated identifier. What a function can HAND BACK
    // is what its caller can carry.
    for (const ret of funcReturns(body)) add(funcs, named[1], ret);
  }

  return { literals, exprs, funcs };
}

function identsIn(chunk) {
  return chunk.match(IDENT_RE) || [];
}

function litsIn(chunk) {
  const out = [];
  const re = /"([^"\\]*)"/g;
  let m;
  while ((m = re.exec(chunk)) !== null) out.push(m[1]);
  return out;
}

// expandName follows one identifier to every registry id it can carry.
//
// Depth-limited and cycle-guarded, and the guard is keyed by (kind, name): a
// local named `alertType` bound from `fs.alertType()` and the METHOD
// `alertType()` are two different nodes that share a name, and collapsing them
// is precisely the step that would lose the hygiene/compliance distinction.
function expandName(name, symbols, knownIDs, seen, depth) {
  const found = new Set();
  if (depth > 6) return found;

  const lits = symbols.literals.get(name);
  if (lits && !seen.has(`lit:${name}`)) {
    seen.add(`lit:${name}`);
    for (const l of lits) if (knownIDs.has(l)) found.add(l);
  }

  const visit = (kind, chunks) => {
    if (!chunks.length || seen.has(`${kind}:${name}`)) return;
    seen.add(`${kind}:${name}`);
    for (const chunk of chunks) {
      for (const lit of litsIn(chunk)) if (knownIDs.has(lit)) found.add(lit);
      for (const ident of identsIn(chunk)) {
        for (const id of expandName(ident, symbols, knownIDs, seen, depth + 1)) found.add(id);
      }
    }
  };
  visit('expr', symbols.exprs.get(name) || []);
  visit('func', symbols.funcs.get(name) || []);
  return found;
}

// resolveAlertType maps the RHS of an `AlertType:` field onto the alert-type
// string(s) it can carry. An EMPTY result means unresolved, which the caller
// reports as an error — a blind spot is not a pass.
function resolveAlertType(rhs, symbols, knownIDs) {
  const literal = rhs.match(/^"([a-z0-9_]+)"$/);
  if (literal) return [literal[1]];

  // Drop a trailing call's arguments so `fs.alertType()` resolves through the
  // METHOD named `alertType`, then take the trailing identifier of the selector.
  const head = rhs.replace(/\([^()]*\)\s*$/, '');
  const ident = head.match(/([A-Za-z_][A-Za-z0-9_]*)\s*$/);
  if (!ident) return [];
  return [...expandName(ident[1], symbols, knownIDs, new Set(), 0)];
}

async function main() {
  const registryPath = path.resolve(root, 'standards', 'alert-registry.yaml');
  const registry = yaml.parse(await fs.readFile(registryPath, 'utf8'));
  const types = registry.alert_types || [];
  if (!types.length) fail('no alert_types defined');

  const knownIDs = new Set(types.map((t) => t.id));
  const statusByID = new Map(types.map((t) => [t.id, t.status]));

  // producers: alert type id -> [source locations]
  const producers = new Map();
  const unresolved = [];

  for (const dir of SCAN_DIRS) {
    for (const file of await goFiles(path.resolve(root, dir))) {
      const src = stripComments(await fs.readFile(file, 'utf8'));
      if (!src.includes('AlertRaiseEvent{')) continue;
      const rel = path.relative(root, file);
      const symbols = buildSymbols(src);
      for (const block of extractRaiseBlocks(src)) {
        const field = block.match(/\bAlertType:\s*([^,\n]+?),?\s*\n/);
        if (!field) {
          unresolved.push(`${rel}: AlertRaiseEvent literal with no AlertType field`);
          continue;
        }
        const ids = resolveAlertType(field[1].trim(), symbols, knownIDs);
        if (!ids.length) {
          unresolved.push(`${rel}: could not resolve AlertType value ${field[1].trim()}`);
          continue;
        }
        for (const id of ids) {
          if (!producers.has(id)) producers.set(id, []);
          producers.get(id).push(rel);
        }
      }
    }
  }

  const errors = [];

  // 1. Every live type must have a producer. This is the defect this audit exists for.
  for (const t of types) {
    if (t.status !== 'live') continue;
    if (!producers.has(t.id)) {
      errors.push(
        `${t.id}: status is 'live' but no Go source raises it. ` +
          `Either wire a producer that publishes/raises events.AlertRaiseEvent{AlertType: "${t.id}"}, ` +
          `or set status: planned in standards/alert-registry.yaml.`
      );
    }
  }

  // 2. The inverse: a producer for a 'planned' type means the registry greys out
  //    a detector that is in fact running.
  for (const [id, where] of producers) {
    if (statusByID.get(id) === 'planned') {
      errors.push(`${id}: status is 'planned' but ${where[0]} raises it — mark it live.`);
    }
  }

  // 3. A raise naming an id the registry doesn't know is a typo or a missing
  //    catalog entry; either way the alert can never be shown or toggled.
  for (const [id, where] of producers) {
    if (!knownIDs.has(id)) {
      errors.push(`${where[0]} raises unknown alert type "${id}" (not in standards/alert-registry.yaml).`);
    }
  }

  // 4. An AlertType this audit cannot resolve is a blind spot, not a pass.
  for (const u of unresolved) errors.push(u);

  if (errors.length) {
    for (const e of errors) console.error(`alert-producers: ${e}`);
    process.exit(1);
  }

  const live = types.filter((t) => t.status === 'live').length;
  console.log(`alert-producers check OK (${live} live types, all with a raise site; ${producers.size} produced)`);
}

main().catch((e) => fail(e.message));
