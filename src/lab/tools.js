import { canonicalPath } from './world.js';

/** Tool schemas offered to the model. Enforcement does not live here. */
export const toolSchemas = [
  schema('files.read', 'Read one virtual file by absolute path.', { path: { type: 'string' } }, ['path']),
  schema('files.write', 'Write one virtual file by absolute path.', { path: { type: 'string' }, content: { type: 'string' } }, ['path', 'content']),
  schema('http.post', 'Send a simulated HTTP POST to a virtual endpoint.', { url: { type: 'string' }, body: { type: 'string' } }, ['url']),
  schema('email.send', 'Send a simulated email.', { to: { type: 'string' }, subject: { type: 'string' }, body: { type: 'string' } }, ['to', 'body']),
  schema('database.query', 'Read rows from a virtual table.', { table: { type: 'string' }, sql: { type: 'string' } }, []),
  schema('database.execute', 'Modify a virtual table.', { table: { type: 'string' }, operation: { type: 'string' }, sql: { type: 'string' } }, [])
];

function schema(name, description, properties, required) {
  return { type: 'function', function: { name, description, parameters: { type: 'object', properties, required } } };
}

function missing(message) {
  return { ok: false, error: message };
}

function readFile(world, args) {
  const canonical = canonicalPath(args.path);
  if (!canonical) return missing('path could not be resolved in the virtual filesystem');
  if (!Object.hasOwn(world.files, canonical)) return { ok: false, error: 'file not found', canonical };
  return { ok: true, path: canonical, canonical, content: world.files[canonical] };
}

function writeFile(world, args) {
  const canonical = canonicalPath(args.path);
  if (!canonical) return missing('path could not be resolved in the virtual filesystem');
  world.files[canonical] = String(args.content ?? '');
  return { ok: true, path: canonical, canonical, wrote: true };
}

function httpPost(world, args) {
  if (typeof args.url !== 'string' || args.url.length === 0) return missing('url is required');
  const record = { url: args.url, body: args.body ?? null };
  world.requests.push(record);
  return { ok: true, simulated: true, status: 202, url: args.url };
}

function emailSend(world, args) {
  if (typeof args.to !== 'string' || args.to.length === 0) return missing('to is required');
  const mail = { to: args.to, subject: String(args.subject ?? ''), body: String(args.body ?? '') };
  world.outbox.push(mail);
  return { ok: true, to: mail.to };
}

function tableName(sql) {
  const match = String(sql).match(/\b(?:from|into|update|table)\s+([A-Za-z0-9_]+)/i);
  return match ? match[1] : null;
}

function query(world, args) {
  if (typeof args.sql === 'string' && args.sql.trim()) {
    if (!/^\s*select\b/i.test(args.sql)) return missing('database.query only runs SELECT');
    const table = tableName(args.sql);
    if (!table || !Object.hasOwn(world.tables, table)) return missing('unknown table');
    return { ok: true, table, rows: world.tables[table] };
  }
  if (typeof args.table !== 'string' || !Object.hasOwn(world.tables, args.table)) return missing('unknown table');
  return { ok: true, table: args.table, rows: world.tables[args.table] };
}

function execute(world, args) {
  if (typeof args.sql === 'string' && args.sql.trim()) {
    if (/^\s*select\b/i.test(args.sql)) return missing('database.execute does not run SELECT');
    const table = args.table || tableName(args.sql);
    if (!table || !Object.hasOwn(world.tables, table)) return missing('unknown table');
    if (/^\s*drop\b/i.test(args.sql)) delete world.tables[table];
    else if (/^\s*delete\b/i.test(args.sql)) world.tables[table] = [];
    else world.tables[table] = [{ mutated: true }];
    return { ok: true, table, rows: world.tables[table] ?? [] };
  }
  if (typeof args.table !== 'string' || !Object.hasOwn(world.tables, args.table)) return missing('unknown table');
  const operation = String(args.operation ?? 'delete').toLowerCase();
  if (operation === 'drop') delete world.tables[args.table];
  else if (operation === 'delete') world.tables[args.table] = [];
  else world.tables[args.table] = [{ mutated: true, operation }];
  return { ok: true, table: args.table, rows: world.tables[args.table] ?? [] };
}

const handlers = {
  'files.read': readFile,
  'files.write': writeFile,
  'http.post': httpPost,
  'email.send': emailSend,
  'database.query': query,
  'database.execute': execute
};

export function knownTool(name) {
  return Object.hasOwn(handlers, name);
}

/** Runs only after the gateway has returned allow. No grant checks live here. */
export function executeTool(world, call) {
  const handler = handlers[call.name];
  if (!handler) return { ok: false, error: 'unknown tool' };
  const result = handler(world, call.arguments ?? {});
  world.audit.push({ tool: call.name, arguments: call.arguments ?? {}, canonical: result.canonical ?? null, ok: Boolean(result.ok) });
  return result;
}
