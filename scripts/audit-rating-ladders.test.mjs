import assert from 'node:assert/strict';
import fs from 'node:fs';
import YAML from 'yaml';
import { test } from 'node:test';
import { inspectTypeScript, auditExceptions } from './audit-rating-ladders.mjs';

test('renamed variables, constants, ternaries and rank maps cannot hide ladders', () => {
  for (const source of [
    `function grade(x:number) { return x>=critical ? 'Critical' : x>=high ? 'High' : 'Medium' }`,
    `const grade=(renamed:number)=>renamed>=90?'Critical':renamed>=70?'High':'Low'`,
    `const order={critical:5, high:4, medium:3, low:2, info:1}`,
    `const bands=[{min:90,label:'Critical'},{min:70,label:'High'},{min:40,label:'Medium'}]`,
    `const bands=[[90,'Critical'],[70,'High'],[40,'Medium']]`,
    `const bands=[{min:CRITICAL_MIN,label:Severity.Critical},{min:HIGH_MIN,label:Severity.High},{min:MEDIUM_MIN,label:Severity.Medium}]`,
    `const grade=(x:number)=>x>=90?Severity.Critical:x>=70?Severity.High:Severity.Medium`,
    `function order(s:Severity){switch(s){case Severity.Critical:return 5;case Severity.High:return 4;case Severity.Medium:return 3}}`,
    `const bands=FromRungs(90,70,40,1)`,
    `class Ratings{static band(x:number){return x>=90?'Critical':x>=70?'High':'Medium'}}`,
    `function rank(x:string){if(x==='critical')return 5;if(x==='high')return 4;if(x==='medium')return 3;return 0}`,
    `function rank(x:string){let r=0;switch(x){case 'critical':r=5;break;case 'high':r=4;break;case 'medium':r=3};return r}`,
    `function order(s:string) {switch(s){case 'critical':return 5;case 'high':return 4;case 'medium':return 3}}`,
  ]) assert.ok(inspectTypeScript('fixture.ts', source).length, source);
});
test('attainment colours, workflow labels and delegation are not numeric risk ladders', () => {
  for (const source of [
    `const colors={critical:'red',high:'orange',medium:'amber'}`,
    `function hygiene(p:number){return p>=90?'green':p>=70?'amber':'red'}`,
    `const level=(x:number)=>riskLevelFromScore(x)`,
    `type Priority='critical'|'high'|'medium'|'low'; const priority:Priority='high'`,
  ]) assert.deepEqual(inspectTypeScript('fixture.ts', source), [], source);
});
test('new offenders and stale or unexplained exceptions fail closed', () => {
  const result = { path:'fixture.ts',symbol:'grade',line:1,reason:'local ladder',fingerprint:'current' };
  assert.match(auditExceptions([result], {}).join('\n'), /canonical owner/);
  assert.match(auditExceptions([result], {'fixture.ts#grade':{reason:'CVSS source'}}).join('\n'), /canonical owner/);
  assert.deepEqual(auditExceptions([result], {'fixture.ts#grade':{reason:'CVSS source mapping',concept:'external_cvss',fingerprint:'current'}}), []);
  assert.match(auditExceptions([{...result,fingerprint:'changed'}], {'fixture.ts#grade':{reason:'source',concept:'external',fingerprint:'current'}}).join('\n'), /canonical owner/);
  assert.match(auditExceptions([], {'fixture.ts#grade':{reason:'old',concept:'external_cvss'}}).join('\n'), /stale/);
});

export function assertWiring(makefile, workflow) {
  const auditRecipe = makefile.match(/^audit:[^\n]*\n((?:\t[^\n]*\n|\n)*)/m)?.[1] ?? '';
  assert.match(auditRecipe, /node \.\/scripts\/audit-rating-ladders\.mjs/);
  assert.match(makefile, /^standards-check:.*\brating-ladder-test\b/m);
  assert.match(makefile, /^rating-ladder-test:[\s\S]*?go test \.\/shared\/ratingsguard\/\.\.\./m);
  assert.match(makefile, /^rating-ladder-test:[\s\S]*?node --test \.\/scripts\/audit-rating-ladders\.test\.mjs/m);
  const parsed = YAML.parse(workflow);
  const steps = Object.values(parsed.jobs).flatMap(job => job.steps ?? []);
  assert.ok(steps.some(step => /make audit/.test(step.run ?? '')));
  assert.ok(steps.some(step => /make rating-ladder-test/.test(step.run ?? '')));
  for (const event of ['push', 'pull_request']) {
    assert.ok(parsed.on[event].paths.includes('scripts/audit-rating-*.mjs'));
    assert.ok(parsed.on[event].paths.includes('shared/**'));
    assert.ok(parsed.on[event].paths.includes('.github/workflows/standards.yml'));
  }
}
test('actual Make and CI enforcement cannot be removed silently', () => {
  const makefile = fs.readFileSync(new URL('../Makefile', import.meta.url), 'utf8');
  const workflow = fs.readFileSync(new URL('../.github/workflows/standards.yml', import.meta.url), 'utf8');
  assertWiring(makefile, workflow);
  for (const token of ['node ./scripts/audit-rating-ladders.mjs', 'rating-ladder-test: ', 'go test ./shared/ratingsguard/...', 'node --test ./scripts/audit-rating-ladders.test.mjs']) {
    assert.throws(() => assertWiring(makefile.replace(token, 'REMOVED'), workflow), token);
  }
  assert.throws(() => assertWiring(makefile, workflow.replace('make rating-ladder-test', 'true')));
  assert.throws(() => assertWiring(makefile, workflow.replaceAll("      - '.github/workflows/standards.yml'\n", '')));
});
