/**
 * Builds the object passed to the player's decide(context).
 * This module records facts. It does not allow or deny the call.
 *
 * riskLevel, sourceTrust, and requiresApproval are advisory labels from the
 * runtime. They are not authorization decisions. origin.inducedByUntrustedContent
 * stays false; the player policy has to decide what untrusted text means.
 *
 * The legacy userIntent, call, grant, origin, and approval fields are filled so
 * an existing decide() implementation can read them. permissions is the same
 * grant, cloned so the policy cannot change the mission.
 */

const SCOPE = {
  'files.read': 'files:read',
  'files.write': 'files:write',
  'http.post': 'http:post',
  'email.send': 'email:send',
  'database.query': 'db:read',
  'database.execute': 'db:write'
};

const ADVISORY_RISK = {
  'files.read': 'low',
  'database.query': 'low',
  'files.write': 'high',
  'http.post': 'high',
  'email.send': 'high',
  'database.execute': 'high'
};

const ADVISORY_APPROVAL = new Set(['files.write', 'email.send', 'database.execute']);

function hostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

export const policyContract = {
  function: 'decide(context) -> { decision, reason }',
  decisions: ['allow', 'deny', 'approve'],
  aliases: { approval: 'approve' },
  examples: [
    { decision: 'allow', reason: 'The call matches the authorized scope.' },
    { decision: 'deny', reason: 'The path is outside the granted root.' },
    { decision: 'approve', reason: 'A person must confirm this side effect.' }
  ],
  notes: [
    'Throwing, timing out, or returning any other decision fails closed and does not run the tool.',
    'approve and approval both suspend the tool until a person chooses. The runtime asks decide() again with approval.status set to approved. The tool runs only if that second result is allow.',
    'permissions and grant are the mission authorization. sourceTrust, riskLevel, and requiresApproval are hints.'
  ]
};

export function buildContext(mission, proposal) {
  const args = proposal.arguments && typeof proposal.arguments === 'object' && !Array.isArray(proposal.arguments)
    ? proposal.arguments
    : {};
  const resource = firstString(args.path, args.file, args.table, args.sql);
  let target = resource || proposal.name;
  let destination;
  if (proposal.name === 'http.post' && typeof args.url === 'string') {
    target = args.url;
    destination = hostname(args.url) || args.url;
  } else if (proposal.name === 'email.send' && typeof args.to === 'string') {
    target = args.to;
    destination = args.to;
  }
  const grant = structuredClone(mission.grant);
  return {
    userRequest: mission.userRequest,
    toolName: proposal.name,
    arguments: structuredClone(args),
    permissions: grant,
    resource,
    destination: destination ?? null,
    action: actionFor(proposal.name),
    riskLevel: ADVISORY_RISK[proposal.name] ?? 'unknown',
    sourceTrust: proposal.sourceTrust === 'tool-output' ? 'tool-output' : 'user',
    requiresApproval: ADVISORY_APPROVAL.has(proposal.name),
    missionId: mission.id,
    userIntent: structuredClone(mission.userIntent),
    call: {
      id: proposal.id,
      tool: proposal.name,
      scope: SCOPE[proposal.name] ?? 'unknown',
      target: String(target ?? ''),
      destination,
      intentId: mission.userIntent.id,
      highImpact: false,
      arguments: structuredClone(args)
    },
    grant,
    origin: {
      kind: proposal.sourceTrust === 'tool-output' ? 'tool-output' : 'user',
      inducedByUntrustedContent: false
    },
    approval: { status: 'none', callId: null }
  };
}

function actionFor(name) {
  if (name === 'files.read' || name === 'database.query') return 'read';
  if (name === 'files.write' || name === 'database.execute') return 'write';
  if (name === 'http.post') return 'post';
  if (name === 'email.send') return 'send';
  return 'call';
}

function firstString(...values) {
  return values.find(value => typeof value === 'string' && value.length > 0) ?? null;
}
