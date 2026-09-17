#!/usr/bin/env node
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import ts from 'typescript';
import YAML from 'yaml';
const words = new Set(['critical', 'high', 'medium', 'med', 'low', 'info', 'informational', 'excellent', 'good', 'fair', 'poor', 'failing', 'weak', 'acceptable', 'strong', 'recommended']);
const compare = new Set([ts.SyntaxKind.GreaterThanToken, ts.SyntaxKind.GreaterThanEqualsToken, ts.SyntaxKind.LessThanToken, ts.SyntaxKind.LessThanEqualsToken]);

export function inspectTypeScript(filename, source) {
  const file = ts.createSourceFile(filename, source, ts.ScriptTarget.Latest, true, filename.endsWith('x') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  if (file.parseDiagnostics.length) throw new Error(`${filename}: TypeScript parse failed`);
  const results = [];
  function check(node, symbol) {
    const found = new Set(); let comparisons = 0; let ranks = 0; let numericResults = 0; let table = false; let constructor = false;
    const word = n => {
      const text = ts.isStringLiteral(n) || ts.isIdentifier(n) ? n.text : ts.isPropertyAccessExpression(n) ? n.name.text : '';
      const normalized = text.toLowerCase();
      return words.has(normalized) ? normalized : null;
    };
    const numeric = n => ts.isNumericLiteral(n) || ts.isIdentifier(n) || ts.isPropertyAccessExpression(n);
    function tableEntry(entry) {
      let hasGrade = false; let hasNumber = false;
      function scan(n) {
        if (word(n)) hasGrade = true;
        if (ts.isNumericLiteral(n)) hasNumber = true;
        // Named bounds are meaningful only in a range/rank field, not any identifier.
        if (ts.isPropertyAssignment(n) && /^(min|max|rank|threshold|score|value)$/i.test(n.name.getText(file).replaceAll(/['"]/g, '')) && numeric(n.initializer)) hasNumber = true;
        ts.forEachChild(n, scan);
      }
      scan(entry); return hasGrade && hasNumber;
    }
    function inspect(n) {
      if (word(n)) found.add(word(n));
      if (ts.isReturnStatement(n) && n.expression && ts.isNumericLiteral(n.expression)) numericResults++;
      if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isNumericLiteral(n.right)) numericResults++;
      if (ts.isArrayLiteralExpression(n) && n.elements.filter(tableEntry).length >= 3) table = true;
      if (ts.isCallExpression(n) && /(?:FromRungs|fromRungs)$/.test(n.expression.getText(file)) && n.arguments.filter(numeric).length >= 3) constructor = true;
      if (ts.isBinaryExpression(n) && compare.has(n.operatorToken.kind)) comparisons++;
      if (ts.isPropertyAssignment(n) && words.has(n.name.getText(file).replaceAll(/['"]/g, '').toLowerCase()) && (ts.isNumericLiteral(n.initializer) || ts.isIdentifier(n.initializer))) ranks++;
      if (ts.isCaseClause(n) && word(n.expression)) {
        for (const statement of n.statements) if (ts.isReturnStatement(statement) && statement.expression && ts.isNumericLiteral(statement.expression)) ranks++;
      }
      ts.forEachChild(n, inspect);
    }
    inspect(node);
    const reason = table ? 'local rating table' : constructor ? 'local ladder constructor' : ranks >= 3 || (found.size >= 3 && numericResults >= 3) ? 'local rating rank' : found.size >= 3 && comparisons >= 2 ? 'local numeric rating ladder' : null;
    if (reason) results.push({ path: filename, line: file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1, symbol, reason, fingerprint: createHash('sha256').update(ts.createPrinter({removeComments: true}).printNode(ts.EmitHint.Unspecified, node, file)).digest('hex') });
  }
  function visit(node) {
    if ((ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) && node.name) { check(node, node.name.getText(file)); return; }
    if (ts.isVariableDeclaration(node) && node.initializer) { check(node.initializer, node.name.getText(file)); return; }
    ts.forEachChild(node, visit);
  }
  visit(file);
  return results;
}

function sources(root, dir) {
  const results = [];
  for (const entry of fs.readdirSync(path.join(root, dir), { withFileTypes: true })) {
    const name = `${dir}/${entry.name}`;
    if (entry.isDirectory()) {
      if (!['node_modules', 'testdata', 'dist', '__tests__'].includes(entry.name)) results.push(...sources(root, name));
    } else if (/\.tsx?$/.test(name) && !/\.(?:test|spec|gen|d)\.tsx?$/.test(name)) results.push(name);
  }
  return results;
}
export function auditExceptions(results, exceptions) {
  const errors = []; const seen = new Set();
  for (const result of results) {
    const key = `${result.path}#${result.symbol}`;
    seen.add(key);
    if (!exceptions[key]?.reason || !exceptions[key]?.concept || exceptions[key]?.fingerprint !== result.fingerprint) errors.push(`${key}:${result.line}: ${result.reason}; use the canonical owner or document a distinct policy`);
  }
  for (const key of Object.keys(exceptions)) if (!seen.has(key)) errors.push(`${key}: stale exception; remove or update it`);
  return errors;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const goPin = fs.readFileSync(path.join(root, 'go.work'), 'utf8').match(/^go (\S+)/m)?.[1];
  if (!goPin) throw new Error('go.work toolchain pin missing');
  const go = JSON.parse(execFileSync('go', ['run', './shared/ratingsguard/cmd/audit-ratings', root], { cwd: root, env: { ...process.env, GOTOOLCHAIN: `go${goPin}` }, encoding: 'utf8' }));
  const files = ['frontend-v2/src', 'admin-ui-v2/src', 'packages/primitives/src'].flatMap(dir => sources(root, dir));
  if (!files.length) throw new Error('no TypeScript files scanned');
  const results = [...go, ...files.flatMap(file => inspectTypeScript(file, fs.readFileSync(path.join(root, file), 'utf8')))];
  if (process.argv.includes('--inventory')) console.log(JSON.stringify(results, null, 2));
  else {
    const exceptions = YAML.parse(fs.readFileSync(path.join(root, 'standards/rating-ladder-exceptions.yaml'), 'utf8'));
    const errors = auditExceptions(results, exceptions);
    if (errors.length) { for (const error of errors) console.error(error); process.exitCode = 1; }
    else console.log(`Rating ladders: Go and ${files.length} TypeScript sources checked; ${results.length} documented domain policies.`);
  }
}
