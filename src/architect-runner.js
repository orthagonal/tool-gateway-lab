import { architectCases } from './architect-cases.js';
import { decide } from './player-policy.js';

export function runCases(cases = architectCases, evaluator = decide) {
  return cases.map(s => {
    try {
      const response = evaluator(structuredClone(s.context));
      const actual = response?.decision;
      if (!['allow', 'approve', 'deny'].includes(actual) || typeof response?.reason !== 'string') throw new Error('Return { decision, reason }');
      return { ...s, actual, reason: response.reason, passed: actual === s.expected };
    } catch (e) {
      return { ...s, actual: 'error', reason: String(e?.message ?? e), passed: false };
    }
  });
}
