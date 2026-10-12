import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_MODEL_HOST, listModels } from './src/lab/model-host.js';
import { approveSession, getSession, missionCatalog, openSession, publicSession, subscribe } from './src/lab/sessions.js';

const root = path.dirname(fileURLToPath(import.meta.url));
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml' };

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  try {
    if (url.pathname.startsWith('/api/')) {
      await routeApi(req, res, url);
      return;
    }
    await serveStatic(url.pathname, res);
  } catch (error) {
    if (res.headersSent) return;
    const status = /unknown|must be|No Qwen|Cannot reach|not waiting|Approval/.test(error.message) ? 400 : 500;
    sendJson(res, status, { error: error.message });
  }
});

async function routeApi(req, res, url) {
  if (req.method === 'GET' && url.pathname === '/api/lab/missions') {
    sendJson(res, 200, missionCatalog());
    return;
  }
  if (req.method === 'GET' && (url.pathname === '/api/model/models' || url.pathname === '/api/ollama/models')) {
    sendJson(res, 200, await listModels(url.searchParams.get('baseUrl') || DEFAULT_MODEL_HOST));
    return;
  }
  if (req.method === 'POST' && url.pathname === '/api/lab/sessions') {
    const body = await readBody(req);
    sendJson(res, 201, { session: await openSession(body) });
    return;
  }
  const events = url.pathname.match(/^\/api\/lab\/sessions\/([^/]+)\/events$/);
  if (req.method === 'GET' && events) {
    const session = getSession(decodeURIComponent(events[1]));
    res.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache',
      connection: 'keep-alive'
    });
    const unsubscribe = subscribe(session.id, res);
    const ping = setInterval(() => res.write(': ping\n\n'), 15000);
    req.on('close', () => { clearInterval(ping); unsubscribe(); });
    return;
  }
  const one = url.pathname.match(/^\/api\/lab\/sessions\/([^/]+)$/);
  if (req.method === 'GET' && one) {
    sendJson(res, 200, { session: publicSession(getSession(decodeURIComponent(one[1]))) });
    return;
  }
  const approval = url.pathname.match(/^\/api\/lab\/sessions\/([^/]+)\/approval$/);
  if (req.method === 'POST' && approval) {
    const body = await readBody(req);
    sendJson(res, 200, { session: approveSession(decodeURIComponent(approval[1]), body.decision) });
    return;
  }
  sendJson(res, 404, { error: 'Not found' });
}

async function serveStatic(pathname, res) {
  const requested = pathname === '/' ? '/index.html' : pathname;
  const resolved = path.resolve(root, `.${requested}`);
  if (!resolved.startsWith(root + path.sep)) { res.writeHead(403); res.end('Forbidden'); return; }
  try {
    const body = await readFile(resolved);
    res.writeHead(200, { 'content-type': types[path.extname(resolved)] || 'application/octet-stream', 'x-content-type-options': 'nosniff' });
    res.end(body);
  } catch {
    res.writeHead(404);
    res.end('Not found');
  }
}

function sendJson(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'x-content-type-options': 'nosniff' });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > 1_000_000) reject(new Error('body too large'));
      else chunks.push(chunk);
    });
    req.on('end', () => {
      if (chunks.length === 0) { resolve({}); return; }
      try { resolve(JSON.parse(Buffer.concat(chunks).toString())); }
      catch { reject(new Error('invalid JSON')); }
    });
    req.on('error', reject);
  });
}

server.listen(process.env.PORT || 4173, () => console.log(`Tool Gateway Lab → http://localhost:${process.env.PORT || 4173}`));
