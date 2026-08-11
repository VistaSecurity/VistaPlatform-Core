#!/usr/bin/env node
import fs from 'fs';
import path from 'path';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const uiDirs = [path.resolve(root, 'web-ui'), path.resolve(root, 'admin-ui')];

const disallowedPatterns = [
  /http:\/\/localhost:808[0-9]/i, // Direct service ports
  /\b\/api\/(?!v1\b)/,           // Missing /api/v1
];

const mustUseServicePrefix = [
  /\/auth\//, // bare /auth should be /auth-service/auth/
];

function walk(dir, arr = []) {
  for (const entry of fs.readdirSync(dir)) {
    const full = path.join(dir, entry);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) {
      if (entry === 'node_modules' || entry === 'dist' || entry === 'build') continue;
      walk(full, arr);
    } else if (full.endsWith('.ts') || full.endsWith('.tsx') || full.endsWith('.js')) {
      arr.push(full);
    }
  }
  return arr;
}

let errors = [];

for (const dir of uiDirs) {
  if (!fs.existsSync(dir)) continue;
  const files = walk(path.join(dir, 'src'));
  for (const file of files) {
    const text = fs.readFileSync(file, 'utf8');
    for (const pat of disallowedPatterns) {
      if (pat.test(text)) {
        errors.push(`${file}: contains disallowed pattern ${pat}`);
      }
    }
    // Allow runtime config accessor
    if (text.includes('getRuntimeConfig().apiGatewayUrl')) {
      // ok
    }
    // Check for missing service prefix when hitting auth endpoints
    const authCalls = text.match(/['"`]\/api\/v1\/[a-zA-Z0-9\-]*auth[^'"`]*/g) || [];
    for (const call of authCalls) {
      if (!call.includes('/auth-service/')) {
        errors.push(`${file}: auth path should use /api/v1/auth-service/... (${call})`);
      }
    }
  }
}

if (errors.length > 0) {
  console.error('Frontend API usage violations found:');
  for (const e of errors) console.error(' -', e);
  process.exit(1);
} else {
  console.log('Frontend API usage OK');
}


