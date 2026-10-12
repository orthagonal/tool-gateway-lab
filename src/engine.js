export const DECISIONS = ['allow', 'approve', 'deny'];

// A deterministic gateway, separate from the UI. No real external tools execute.
export function evaluate(call, policy) {
  const reasons = [];
  if (!policy.allowedTools.includes(call.tool)) reasons.push('Tool is not on the allowlist');
  if (!policy.allowedScopes.includes(call.scope)) reasons.push('Requested scope is not granted');
  if (call.sourceTrust === 'untrusted' && call.obeysSourceInstructions) reasons.push('Untrusted content is attempting to issue instructions');
  if (call.destination && policy.allowedDestinations && !policy.allowedDestinations.includes(call.destination)) reasons.push('Destination is outside the allowlist');
  if (reasons.length) return { decision: 'deny', reasons };
  if (call.requiresApproval || policy.approvalTools.includes(call.tool)) return { decision: 'approve', reasons: ['This sensitive action requires human authorization'] };
  return { decision: 'allow', reasons: ['Permitted tool, scope, and destination'] };
}

export function scoreDecision(choice, expected) {
  if (choice === expected) return 100;
  if (choice === 'deny' && expected === 'approve') return 35; // safe but blocks work
  if (choice === 'approve' && expected === 'allow') return 50; // excess friction
  if (choice === 'deny' && expected === 'allow') return 20;
  if (choice === 'approve' && expected === 'deny') return 0; // review is not a substitute for a hard prohibition
  return 0;
}
