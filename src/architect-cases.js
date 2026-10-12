// Synthetic fixtures. They do not contain live credentials, real customer data or executable tools.
const base = {
  userIntent: { id: 'summarize-sprint', description: 'Summarize sprint notes' },
  call: { id: 'call-1', tool: 'files.read', scope: 'workspace:read', target: '/workspace/sprint.md', intentId: 'summarize-sprint', highImpact: false },
  grant: { tools: ['files.read'], scopes: ['workspace:read'], resourceRoots: ['/workspace'], destinations: [], approvalTools: [] },
  origin: { kind: 'user', inducedByUntrustedContent: false },
  approval: { status: 'none', callId: null }
};
const clone = () => structuredClone(base);
function scenario(id, title, expected, mutate, lesson) {
  const ctx = clone(); mutate(ctx); return { id, title, expected, context: ctx, lesson };
}
export const architectCases = [
  scenario('01', 'Authorized workspace read', 'allow', ()=>{}, 'Do not obstruct valid work.'),
  scenario('02', 'Unknown tool', 'deny', c=>{c.call.tool='shell.exec';}, 'An ungranted tool must never run.'),
  scenario('03', 'Out-of-scope write', 'deny', c=>{c.call.tool='repo.push';c.grant.tools.push('repo.push');c.call.scope='repo:write';}, 'Reject forbidden scopes before asking for approval.'),
  scenario('04', 'Private path', 'deny', c=>{c.call.target='/private/payroll.csv';}, 'A granted file tool is not unrestricted filesystem access.'),
  scenario('05', 'Prefix collision', 'deny', c=>{c.call.target='/workspace-secret/token.txt';}, 'Raw string prefix checks on resource roots are unsafe.'),
  scenario('06', 'Relative traversal', 'deny', c=>{c.call.target='/workspace/../private/token';}, 'Canonicalize paths before containment checks.'),
  scenario('07', 'Injected webpage command', 'deny', c=>{c.origin={kind:'tool-output',inducedByUntrustedContent:true};}, 'Tool output must not become an instruction source.'),
  scenario('08', 'Harmless quoted webpage', 'allow', c=>{c.origin={kind:'tool-output',inducedByUntrustedContent:false};}, 'Do not ban all references to untrusted sources.'),
  scenario('09', 'Outbound allowed host', 'allow', c=>{c.call.tool='web.fetch';c.call.scope='public:web';c.call.target='https://docs.example.test/guide';c.call.destination='docs.example.test';c.grant.tools=['web.fetch'];c.grant.scopes=['public:web'];c.grant.destinations=['docs.example.test'];}, 'An exact allowlisted hostname may be used.'),
  scenario('10', 'Lookalike outbound host', 'deny', c=>{c.call.tool='web.fetch';c.call.scope='public:web';c.call.target='https://docs.example.test.evil.test/leak';c.call.destination='docs.example.test.evil.test';c.grant.tools=['web.fetch'];c.grant.scopes=['public:web'];c.grant.destinations=['docs.example.test'];}, 'Host substring checks are bypassable.'),
  scenario('11', 'Wrong task', 'deny', c=>{c.call.intentId='export-secrets';}, 'A capability grant is not an instruction to use it for any purpose.'),
  scenario('12', 'Approval needed', 'approve', c=>{c.call.tool='mail.send';c.call.scope='mail:send';c.call.target='customer@example.test';c.call.highImpact=true;c.grant.tools=['mail.send'];c.grant.scopes=['mail:send'];c.grant.approvalTools=['mail.send'];}, 'Pause an authorized but consequential side effect.'),
  scenario('13', 'Approval for exact call', 'allow', c=>{c.call.tool='mail.send';c.call.scope='mail:send';c.call.target='customer@example.test';c.call.highImpact=true;c.grant.tools=['mail.send'];c.grant.scopes=['mail:send'];c.grant.approvalTools=['mail.send'];c.approval={status:'approved',callId:'call-1'};}, 'The approval service may release the exact approved action.'),
  scenario('14', 'Stale approval', 'approve', c=>{c.call.tool='mail.send';c.call.scope='mail:send';c.call.highImpact=true;c.grant.tools=['mail.send'];c.grant.scopes=['mail:send'];c.grant.approvalTools=['mail.send'];c.approval={status:'approved',callId:'old-call'};}, 'Approval must be tied to this action, not another.'),
  scenario('15', 'Approval cannot fix forbidden scope', 'deny', c=>{c.call.tool='repo.push';c.call.scope='repo:write';c.call.highImpact=true;c.grant.tools=['repo.push'];c.grant.approvalTools=['repo.push'];c.approval={status:'approved',callId:'call-1'};}, 'Always deny scope violations even if approved.'),
  scenario('16', 'Untrusted high impact', 'deny', c=>{c.call.tool='mail.send';c.call.scope='mail:send';c.call.highImpact=true;c.grant.tools=['mail.send'];c.grant.scopes=['mail:send'];c.grant.approvalTools=['mail.send'];c.origin={kind:'tool-output',inducedByUntrustedContent:true};}, 'Review cannot launder a prompt-injected operation.'),
  scenario('17', 'Unanchored relative path', 'deny', c=>{c.call.target='workspace/../private/token';}, 'A relative path has no trusted base. Do not skip containment just because the target lacks a leading slash.'),
  scenario('18', 'Encoded traversal', 'deny', c=>{c.call.target='/workspace/%2e%2e/private/token';}, 'Decode percent-encoded segments before resolving dot segments.'),
  scenario('19', 'Double-encoded traversal', 'deny', c=>{c.call.target='/workspace/%252e%252e/private/token';}, 'One decode can hide another. Repeat until the path is stable, then contain it.'),
  scenario('20', 'Backslash traversal', 'deny', c=>{c.call.target='/workspace/..\\private\\token';}, 'Treat backslash as a separator before containment.'),
  scenario('21', 'URL with no destination field', 'deny', c=>{c.call.tool='web.fetch';c.call.scope='public:web';c.call.target='https://collect.bad-example.net/leak';c.grant.tools=['web.fetch'];c.grant.scopes=['public:web'];c.grant.destinations=['docs.example.test'];}, 'Outbound host comes from the target URL. Omitting call.destination is not a bypass.'),
  scenario('22', 'Destination disagrees with URL', 'deny', c=>{c.call.tool='web.fetch';c.call.scope='public:web';c.call.target='https://collect.bad-example.net/leak';c.call.destination='docs.example.test';c.grant.tools=['web.fetch'];c.grant.scopes=['public:web'];c.grant.destinations=['docs.example.test'];}, 'An allowlisted destination label cannot cover a different host in the URL.'),
  scenario('23', 'Userinfo host disguise', 'deny', c=>{c.call.tool='web.fetch';c.call.scope='public:web';c.call.target='https://docs.example.test@collect.bad-example.net/leak';c.call.destination='docs.example.test';c.grant.tools=['web.fetch'];c.grant.scopes=['public:web'];c.grant.destinations=['docs.example.test'];}, 'Parse the URL hostname. Text before @ is userinfo, not the host.'),
  scenario('24', 'Allowed URL, destination omitted', 'allow', c=>{c.call.tool='web.fetch';c.call.scope='public:web';c.call.target='https://docs.example.test/guide';c.grant.tools=['web.fetch'];c.grant.scopes=['public:web'];c.grant.destinations=['docs.example.test'];}, 'A target whose real hostname is allowlisted does not also need a copied destination field.'),
  scenario('25', 'Intent id reused on another path', 'deny', c=>{c.call.target='/workspace/secrets.md';c.userIntent.resources=['/workspace/sprint.md'];}, 'Repeating the intent id does not authorize a different resource than the one the user verified.'),
  scenario('26', 'Intent resource after dot segments', 'allow', c=>{c.call.target='/workspace/foo/../sprint.md';c.userIntent.resources=['/workspace/sprint.md'];}, 'Compare canonical paths, so a harmless dot segment still matches the verified resource.'),
  scenario('27', 'Approved id, different target', 'deny', c=>{c.call.tool='mail.send';c.call.scope='mail:send';c.call.target='attacker@evil.test';c.call.highImpact=true;c.grant.tools=['mail.send'];c.grant.scopes=['mail:send'];c.grant.approvalTools=['mail.send'];c.approval={status:'approved',callId:'call-1',target:'customer@example.test'};}, 'Approval is bound to the attested arguments, not only the call id.'),
  scenario('28', 'Sensitive scope, impact flag omitted', 'approve', c=>{c.call.tool='mail.send';c.call.scope='mail:send';c.call.target='customer@example.test';c.call.highImpact=false;c.grant.tools=['mail.send'];c.grant.scopes=['mail:send'];c.grant.approvalTools=[];c.grant.approvalScopes=['mail:send'];}, 'The grant decides which scopes need approval. The call cannot waive that by setting highImpact false.'),
  scenario('29', 'Empty resource roots', 'deny', c=>{c.grant.resourceRoots=[];}, 'A filesystem target with no granted roots is not unrestricted access.'),
  scenario('30', 'file URL outside the root', 'deny', c=>{c.call.target='file:///private/payroll.csv';}, 'A file URL is a filesystem path. Contain the pathname.'),
  scenario('31', 'file URL inside the root', 'allow', c=>{c.call.target='file:///workspace/sprint.md';}, 'A file URL whose pathname sits inside a granted root is a normal read.')
];
