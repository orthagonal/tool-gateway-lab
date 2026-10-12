import { policyContract } from './context.js';
import { DEFAULT_MODEL_HOST, listModels, normalizeBaseUrl } from './model-host.js';
import { listMissions, publicMission } from './missions.js';
import { createLabSession, enqueue, playerJudge } from './agent.js';
import { chat as modelChat } from './model-host.js';

const sessions = new Map();

export function missionCatalog() {
  return { missions: listMissions().map(publicMission), policy: policyContract };
}

export async function openSession(options) {
  let model = options.model || '';
  const baseUrl = normalizeBaseUrl(options.baseUrl || DEFAULT_MODEL_HOST);
  if (!model) {
    const listed = await listModels(baseUrl);
    model = listed.defaultModel;
  }
  if (!model) throw new Error('No Qwen model is available');
  const session = createLabSession({ ...options, model, baseUrl });
  attachUpdates(session);
  sessions.set(session.id, session);
  enqueue(session, dependencies(session));
  return publicSession(session);
}

export function getSession(id) {
  const session = sessions.get(id);
  if (!session) throw new Error('unknown session');
  return session;
}

export function approveSession(id, decision) {
  const session = getSession(id);
  if (session.status !== 'approval') throw new Error('This session is not waiting for approval');
  if (decision !== 'allow' && decision !== 'deny') throw new Error('Approval must be allow or deny');
  session.humanDecision = decision;
  enqueue(session, dependencies(session));
  return publicSession(session);
}

export function subscribe(id, response) {
  const session = getSession(id);
  session.listeners ??= new Set();
  session.listeners.add(response);
  writeSnapshot(response, session);
  return () => session.listeners.delete(response);
}

function dependencies(session) {
  return {
    chat: modelChat,
    judge: playerJudge
  };
}

function writeSnapshot(response, session) {
  response.write(`data: ${JSON.stringify({ kind: 'snapshot', session: publicSession(session) })}\n\n`);
}

export function attachUpdates(session) {
  session.onUpdate = () => {
    for (const response of session.listeners ?? []) writeSnapshot(response, session);
  };
}

export function publicSession(session) {
  const pending = session.pending
    ? { callId: session.pending.callId, name: session.pending.parsed.name, arguments: session.pending.parsed.arguments, reason: session.pending.reason }
    : null;
  return {
    id: session.id,
    mission: publicMission(session.mission),
    status: session.status,
    model: session.model,
    baseUrl: session.baseUrl,
    maxSteps: session.maxSteps,
    modelCalls: session.modelCalls,
    error: session.error,
    finalText: session.finalText,
    pending,
    events: session.events,
    evaluation: session.evaluation ?? null,
    world: {
      audit: session.world.audit,
      outbox: session.world.outbox,
      requests: session.world.requests,
      tables: Object.fromEntries(Object.entries(session.world.tables).map(([name, rows]) => [name, Array.isArray(rows) ? rows.length : 0]))
    }
  };
}

export function remember(session) {
  attachUpdates(session);
  sessions.set(session.id, session);
  return session;
}
