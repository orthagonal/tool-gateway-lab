/**
 * decide(context) -> { decision: 'allow'|'approve'|'deny', reason: string }
 *
 * Returns a decision for one proposed tool call. It never executes the tool.
 *
 * Trusted inputs are grant (server permissions), userIntent (the verified user
 * request), origin (gateway provenance), and approval (the approval service).
 * call is only a proposal. Its highImpact flag can add an approval hold; it
 * cannot remove one the grant requires.
 *
 * Denials are decided before approval. An approval record cannot repair a call
 * that fails any policy below, and it cannot authorize different arguments
 * than the ones it attests.
 *
 * 1. Capability. call.tool must be in grant.tools, and call.scope in grant.scopes.
 * 2. Resource path. Email addresses and http(s) URLs are not filesystem paths.
 *    A file: URL is judged by its pathname. Every other target that contains a
 *    slash, a backslash, or a ".." segment is a filesystem path. Backslashes are
 *    separators. Percent-encoding is decoded until the path stops changing, then
 *    "." and ".." are resolved. The result must be absolute and must sit inside
 *    some grant.resourceRoots entry by segment, so "/workspace-secret" is not
 *    inside "/workspace". A relative path is denied: this function has no trusted
 *    base directory to resolve it against. An empty root list denies every
 *    filesystem target.
 * 3. Origin. inducedByUntrustedContent true means tool output or page text induced
 *    the call, so it is denied. The same kind of source with that flag false is
 *    still allowed.
 * 4. Destination. The hostname of an http(s) target is parsed from the URL.
 *    Userinfo before "@" is not the host. That hostname must exactly match a
 *    grant.destinations entry after trim, lowercase, and stripping one trailing
 *    dot. When call.destination is also set, it must be that same host. Omitting
 *    call.destination does not skip the URL check.
 * 5. Intent. call.intentId must equal userIntent.id. When userIntent.resources is
 *    a non-empty list, the canonical filesystem path must equal one of those
 *    resources. Repeating the intent id does not authorize a different path.
 *
 * A conflicting attested approval field (tool, scope, target, destination, or
 * intentId) is a deny. Otherwise a tool in grant.approvalTools, a scope in
 * grant.approvalScopes, or call.highImpact returns "approve" until
 * approval.status is "approved" and approval.callId is this call's id.
 */

const APPROVAL_FIELDS = ['tool', 'scope', 'target', 'destination', 'intentId'];

function pathSegments(path) {
  const segments = [];
  for (const part of String(path).split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (segments.length === 0) return null;
      segments.pop();
      continue;
    }
    segments.push(part);
  }
  return segments;
}

function decodePath(input) {
  let current = String(input);
  if (current.includes('\0')) return null;
  for (let i = 0; i < 4; i++) {
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
  if (current.includes('\0')) return null;
  return current;
}

function canonicalAbsolute(target) {
  const decoded = decodePath(target);
  if (decoded == null || !decoded.startsWith('/')) return null;
  const segments = pathSegments(decoded);
  if (!segments) return null;
  return `/${segments.join('/')}`;
}

function insideRoot(canonical, root) {
  const base = canonicalAbsolute(root);
  if (!canonical || !base) return false;
  return canonical === base || canonical.startsWith(`${base}/`);
}

function filesystemTarget(target) {
  if (typeof target !== 'string' || target.length === 0) return null;
  if (/^https?:\/\//i.test(target)) return null;
  if (/^file:/i.test(target)) {
    try {
      return new URL(target).pathname;
    } catch {
      return false;
    }
  }
  if (target.includes('@') && !/[\\/]/.test(target)) return null;
  if (target.startsWith('/') || /[\\/]/.test(target) || target.split(/[\\/]/).includes('..')) return target;
  return null;
}

function normalizeHost(host) {
  return String(host).trim().toLowerCase().replace(/\.$/, '');
}

function httpHostname(target) {
  if (typeof target !== 'string' || !/^https?:\/\//i.test(target)) return undefined;
  try {
    return normalizeHost(new URL(target).hostname);
  } catch {
    return null;
  }
}

function deny(reason) {
  return { decision: 'deny', reason };
}

export function decide(context) {
  const { call, grant, userIntent, origin, approval } = context;

  if (!grant.tools.includes(call.tool)) return deny('tool not granted');
  if (!grant.scopes.includes(call.scope)) return deny('scope not granted');

  const filesystemPath = filesystemTarget(call.target);
  if (filesystemPath === false) return deny('filesystem target is malformed');
  if (filesystemPath !== null) {
    const canonical = canonicalAbsolute(filesystemPath);
    const contained = (grant.resourceRoots ?? []).some(root => insideRoot(canonical, root));
    if (!contained) return deny('path is outside granted resource roots');
    if (Array.isArray(userIntent?.resources) && userIntent.resources.length) {
      const allowed = userIntent.resources.map(resource => canonicalAbsolute(resource));
      if (!allowed.includes(canonical)) return deny('path is outside the verified user intent');
    }
  }

  if (origin?.inducedByUntrustedContent) return deny('call was induced by untrusted content');

  const host = httpHostname(call.target);
  if (host === null) return deny('destination url is malformed');
  if (host) {
    const allowed = (grant.destinations ?? []).map(normalizeHost);
    if (!allowed.includes(host)) return deny('destination host is not granted');
    if (call.destination && normalizeHost(call.destination) !== host) return deny('destination does not match the target host');
  } else if (call.destination) {
    const destination = normalizeHost(call.destination);
    const allowed = (grant.destinations ?? []).map(normalizeHost);
    if (!allowed.includes(destination)) return deny('destination host is not granted');
  }

  if (call.intentId !== userIntent?.id) return deny('call does not match the verified user intent');

  if (approval && APPROVAL_FIELDS.some(key => approval[key] != null && approval[key] !== call[key])) {
    return deny('approval does not match this call');
  }

  const needsApproval = (grant.approvalTools ?? []).includes(call.tool)
    || (grant.approvalScopes ?? []).includes(call.scope)
    || call.highImpact;
  if (needsApproval) {
    if (approval?.status === 'approved' && approval.callId === call.id) {
      return { decision: 'allow', reason: 'valid approval for this call' };
    }
    return { decision: 'approve', reason: 'human authorization required' };
  }
  return { decision: 'allow', reason: 'capability, path, origin, destination, and intent checks passed' };
}
