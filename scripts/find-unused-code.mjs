#!/usr/bin/env node
/**
 * Find Unused Code Script
 * 
 * Scans TypeScript/JavaScript files for unused functions, variables, and imports
 * to help maintain clean code and prevent build failures.
 */

import fs from 'fs';
import path from 'path';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const uiDirs = [path.resolve(root, 'web-ui'), path.resolve(root, 'admin-ui')];

// Patterns to detect unused code
const unusedPatterns = [
  // Unused function declarations (prefixed with _)
  /^[\s]*const\s+_[a-zA-Z][a-zA-Z0-9_]*\s*=/gm,
  /^[\s]*function\s+_[a-zA-Z][a-zA-Z0-9_]*\s*\(/gm,
  /^[\s]*const\s+_[a-zA-Z][a-zA-Z0-9_]*\s*:\s*\(/gm,
  
  // Unused variable declarations (prefixed with _)
  /^[\s]*const\s+_[a-zA-Z][a-zA-Z0-9_]*\s*=/gm,
  /^[\s]*let\s+_[a-zA-Z][a-zA-Z0-9_]*\s*=/gm,
  /^[\s]*var\s+_[a-zA-Z][a-zA-Z0-9_]*\s*=/gm,
];

// Patterns to detect potentially unused imports
const importPatterns = [
  /import\s*{([^}]+)}\s*from\s*['"][^'"]+['"]/g,
  /import\s+([a-zA-Z][a-zA-Z0-9_]*)\s+from\s*['"][^'"]+['"]/g,
];

function walk(dir, arr = []) {
  for (const entry of fs.readdirSync(dir)) {
    const full = path.join(dir, entry);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) {
      if (entry === 'node_modules' || entry === 'dist' || entry === '__tests__' || entry === '.git') continue;
      walk(full, arr);
    } else if (stat.isFile() && (full.endsWith('.ts') || full.endsWith('.tsx') || full.endsWith('.js') || full.endsWith('.jsx'))) {
      arr.push(full);
    }
  }
  return arr;
}

function findUnusedInFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const issues = [];
  
  // Check for unused patterns
  for (const pattern of unusedPatterns) {
    const matches = content.match(pattern);
    if (matches) {
      for (const match of matches) {
        const lineNumber = content.substring(0, content.indexOf(match)).split('\n').length;
        issues.push({
          type: 'unused_code',
          line: lineNumber,
          content: match.trim(),
          file: filePath
        });
      }
    }
  }
  
  // Check for potentially unused imports
  for (const pattern of importPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const importLine = match[0];
      const importedItems = match[1] ? match[1].split(',').map(item => item.trim()) : [];
      
      for (const item of importedItems) {
        const cleanItem = item.replace(/\s+as\s+\w+/, '').trim();
        if (cleanItem && !content.includes(cleanItem) && !content.includes(`_${cleanItem}`)) {
          const lineNumber = content.substring(0, content.indexOf(importLine)).split('\n').length;
          issues.push({
            type: 'unused_import',
            line: lineNumber,
            content: `Unused import: ${cleanItem}`,
            file: filePath
          });
        }
      }
    }
  }
  
  return issues;
}

function main() {
  console.log('🔍 Scanning for unused code...\n');
  
  let totalIssues = 0;
  const allIssues = [];
  
  for (const uiDir of uiDirs) {
    console.log(`📁 Scanning ${path.basename(uiDir)}...`);
    const files = walk(uiDir);
    let dirIssues = 0;
    
    for (const file of files) {
      const issues = findUnusedInFile(file);
      if (issues.length > 0) {
        allIssues.push(...issues);
        dirIssues += issues.length;
      }
    }
    
    console.log(`   Found ${dirIssues} potential issues\n`);
    totalIssues += dirIssues;
  }
  
  if (totalIssues === 0) {
    console.log('✅ No unused code found!');
    return;
  }
  
  console.log(`⚠️  Found ${totalIssues} potential issues:\n`);
  
  // Group by file
  const issuesByFile = {};
  for (const issue of allIssues) {
    if (!issuesByFile[issue.file]) {
      issuesByFile[issue.file] = [];
    }
    issuesByFile[issue.file].push(issue);
  }
  
  // Display issues
  for (const [file, issues] of Object.entries(issuesByFile)) {
    const relativePath = path.relative(root, file);
    console.log(`📄 ${relativePath}:`);
    
    for (const issue of issues) {
      console.log(`   Line ${issue.line}: ${issue.content}`);
    }
    console.log('');
  }
  
  console.log('💡 Recommendations:');
  console.log('   - Remove unused functions and variables');
  console.log('   - Remove unused imports');
  console.log('   - Consider if code is truly unused before removing');
  console.log('   - Use TypeScript strict mode to catch these at compile time');
  
  process.exit(1);
}

main();
