export const DEFAULT_MODEL_HOST = 'http://127.0.0.1:8765';

export function normalizeBaseUrl(input) {
  const url = new URL(input || DEFAULT_MODEL_HOST);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new Error('Model host URL must be http or https');
  return url.origin;
}

export function chooseDefaultModel(models) {
  const names = (models ?? []).map(model => model.name || model.model).filter(Boolean);
  const qwen = names.filter(name => /qwen/i.test(name));
  const small = qwen.find(name => /1\.5b|1\.5|0\.5b|0\.5|3b/i.test(name));
  return small || qwen[0] || names[0] || '';
}

export async function listModels(baseUrl, timeoutMs = 4000) {
  const origin = normalizeBaseUrl(baseUrl);
  let response;
  try {
    response = await fetch(`${origin}/api/tags`, { signal: AbortSignal.timeout(timeoutMs) });
  } catch (error) {
    const detail = error?.cause?.message || error?.message || 'connection failed';
    throw new Error(`Cannot reach the Qwen host at ${origin} (${detail})`);
  }
  if (!response.ok) throw new Error(`Qwen host model list failed (${response.status})`);
  const body = await response.json();
  const models = body.models ?? [];
  return { baseUrl: origin, models, defaultModel: chooseDefaultModel(models) };
}

export async function chat({ baseUrl, model, messages, tools, timeoutMs = 60000 }) {
  const origin = normalizeBaseUrl(baseUrl);
  if (!model) throw new Error('No Qwen model is selected');
  let response;
  try {
    response = await fetch(`${origin}/api/chat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model, messages, tools, stream: false }),
      signal: AbortSignal.timeout(timeoutMs)
    });
  } catch (error) {
    const detail = error?.cause?.message || error?.message || 'connection failed';
    throw new Error(`Cannot reach the Qwen host at ${origin} (${detail})`);
  }
  if (!response.ok) {
    let detail = '';
    try { detail = (await response.json()).error || ''; } catch { detail = ''; }
    throw new Error(detail || `Qwen host chat failed (${response.status})`);
  }
  const body = await response.json();
  if (!body.message) throw new Error('Qwen host returned no message');
  return body;
}
