import fs from 'node:fs';
import path from 'node:path';
import { Worker } from 'node:worker_threads';
import { fileURLToPath, pathToFileURL } from 'node:url';

const policyPath = fileURLToPath(new URL('../player-policy.js', import.meta.url));
const workerUrl = new URL('./policy-worker.js', import.meta.url);

/**
 * Validates a decide() result and fails closed.
 * This does not contain authorization rules.
 */
export function normalizeDecision(result, failureReason) {
  if (failureReason) return { decision: 'deny', reason: failureReason };
  const decision = result?.decision === 'approval' ? 'approve' : result?.decision;
  if (!result || typeof result.reason !== 'string' || !['allow', 'deny', 'approve'].includes(decision)) {
    return { decision: 'deny', reason: 'policy returned an invalid decision' };
  }
  return { decision, reason: result.reason };
}

export function judgePlayerPolicy(context, options = {}) {
  const timeoutMs = options.timeoutMs ?? 500;
  const filePath = options.policyPath ?? policyPath;
  const version = fs.statSync(filePath).mtimeMs;
  const policyHref = `${pathToFileURL(filePath).href}?v=${version}`;
  return new Promise(resolve => {
    const worker = new Worker(workerUrl, { workerData: { context, policyHref } });
    let settled = false;
    const finish = async (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      await worker.terminate();
      resolve(value);
    };
    const timer = setTimeout(() => {
      finish(normalizeDecision(null, 'policy timed out'));
    }, timeoutMs);
    worker.on('message', message => {
      if (!message?.ok) finish(normalizeDecision(null, `policy failed closed: ${message?.error || 'unknown error'}`));
      else finish(normalizeDecision(message.result));
    });
    worker.on('error', error => {
      finish(normalizeDecision(null, `policy failed closed: ${error.message}`));
    });
  });
}

export function defaultPolicyPath() {
  return path.resolve(policyPath);
}
