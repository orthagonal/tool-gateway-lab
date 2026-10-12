import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluate, scoreDecision } from '../src/engine.js';
import { scenarios } from '../src/scenarios.js';
const expected = ['allow', 'deny', 'approve', 'deny', 'deny', 'approve'];
for (const [i, s] of scenarios.entries()) test(`${s.id}: ${s.title}`, () => assert.equal(evaluate(s.call, s.policy).decision, expected[i]));
test('missing tool denies', () => assert.equal(evaluate({tool:'shell.exec',scope:'read'}, {allowedTools:[],allowedScopes:['read'],approvalTools:[]}).decision, 'deny'));
test('scope checked before approval', () => assert.equal(evaluate({tool:'db.migrate',scope:'prod:write',requiresApproval:true},{allowedTools:['db.migrate'],allowedScopes:[],approvalTools:['db.migrate']}).decision,'deny'));
test('score distinguishes overblocking', () => assert.equal(scoreDecision('deny','allow'),20));
