import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { runCases } from '../src/architect-runner.js';
import { architectCases } from '../src/architect-cases.js';
test('every exercise has an explicit expected decision',()=>{assert.equal(architectCases.length,31);for(const s of architectCases)assert.ok(['allow','approve','deny'].includes(s.expected));});
test('runner provides feedback and does not mutate fixtures',()=>{const before=JSON.stringify(architectCases);const results=runCases();assert.equal(results.length,31);assert.equal(JSON.stringify(architectCases),before);assert.ok(results.every(x=>x.passed));});
test('evaluator exceptions are reported as failures',()=>{const res=runCases(architectCases.slice(0,1),()=>{throw Error('bug')});assert.equal(res[0].actual,'error');assert.match(res[0].reason,/bug/);});
