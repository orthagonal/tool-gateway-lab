import { parentPort, workerData } from 'node:worker_threads';

try {
  const loaded = await import(workerData.policyHref);
  const result = loaded.decide(workerData.context);
  parentPort.postMessage({ ok: true, result });
} catch (error) {
  parentPort.postMessage({ ok: false, error: String(error?.message || error) });
}
