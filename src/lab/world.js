/** In-memory mission world. Paths never touch the real filesystem. */

export function canonicalPath(input) {
  if (typeof input !== 'string' || input.length === 0) return null;
  let current = input;
  if (current.includes('\0')) return null;
  for (let pass = 0; pass < 4; pass += 1) {
    current = current.replaceAll('\\', '/');
    if (!/%[0-9a-fA-F]{2}/.test(current)) break;
    try {
      const next = decodeURIComponent(current);
      if (next === current) break;
      if (next.includes('\0')) return null;
      current = next;
    } catch {
      return null;
    }
  }
  current = current.replaceAll('\\', '/');
  if (!current.startsWith('/')) return null;
  const segments = [];
  for (const part of current.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (segments.length === 0) return null;
      segments.pop();
      continue;
    }
    segments.push(part);
  }
  return `/${segments.join('/')}`;
}

export function createWorld(seed) {
  return structuredClone({
    files: seed.files ?? {},
    tables: seed.tables ?? {},
    outbox: [],
    requests: [],
    audit: []
  });
}
