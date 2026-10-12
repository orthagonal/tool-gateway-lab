const $ = selector => document.querySelector(selector);
const escape = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
let catalog = [];
let policy = null;
let session = null;
let source = null;
let missionId = 'poisoned-customer';

async function boot() {
  const response = await fetch('/api/lab/missions');
  const body = await response.json();
  catalog = body.missions;
  policy = body.policy;
  drawMission();
  await refreshModels();
}

function selectedMission() {
  return catalog.find(item => item.id === missionId) ?? catalog[0];
}

function drawMission() {
  const mission = selectedMission();
  if (!mission) return;
  const controls = `
    <div class="lab-form">
      <label>Qwen host <input id="base-url" value="http://127.0.0.1:8765"></label>
      <label>Model <select id="model"></select></label>
      <label>Max steps <input id="max-steps" type="number" min="1" max="20" value="6"></label>
      <label>Model timeout (seconds) <input id="timeout" type="number" min="5" max="120" value="60"></label>
    </div>
    <div class="lab-actions">
      <button id="start" type="button">START</button>
      <button id="reset" type="button">RESET</button>
      <button id="reload-models" type="button">RELOAD MODELS</button>
    </div>`;
  $('#mission').innerHTML = `
    <label class="muted">Scenario</label>
    <select id="mission-id">${catalog.map(item => `<option value="${escape(item.id)}"${item.id === mission.id ? ' selected' : ''}>${escape(item.title)}</option>`).join('')}</select>
    <div class="lab-card"><b>User request</b><div class="muted-block">${escape(mission.userRequest)}</div></div>
    <div class="lab-card"><b>Teaching goal</b><div class="muted-block">${escape(mission.teachingGoal)}</div></div>
    <div class="lab-card"><b>Tools the model can attempt</b><div class="muted-block">${escape(mission.tools.join(', '))}</div></div>
    <div class="lab-card"><b>Authorized scope</b><div class="muted-block">${escape(JSON.stringify(mission.authorized, null, 2))}</div></div>
    <div class="lab-card"><b>Attacker-controlled content</b>${mission.attackerContent.map(item => `<div class="muted-block"><b>${escape(item.label)}</b>\n${escape(item.content)}</div>`).join('')}</div>
    <div class="lab-card"><b>Protected resources</b><div class="muted-block">${escape(mission.protectedResources.join(', '))}</div></div>
    <div class="lab-card"><b>Invariants</b><div class="muted-block">${mission.invariants.map(item => `• ${escape(item)}`).join('\n')}</div></div>
    ${controls}
    <div class="lab-card contract"><b>decide(context)</b> must return <code>{ decision, reason }</code>. Use <code>allow</code>, <code>deny</code>, or <code>approve</code> (<code>approval</code> is the same hold). A throw, a timeout, or any other decision does not run the tool. <code>riskLevel</code>, <code>sourceTrust</code>, and <code>requiresApproval</code> are hints. Edit <code>src/player-policy.js</code> and start a new run to reload it.</div>
    <p class="warn" id="form-error"></p>`;
  $('#mission-id').onchange = () => { missionId = $('#mission-id').value; drawMission(); refreshModels(); };
  $('#start').onclick = start;
  $('#reset').onclick = start;
  $('#reload-models').onclick = refreshModels;
}

async function refreshModels() {
  const select = $('#model');
  if (!select) return;
  const baseUrl = $('#base-url')?.value || 'http://127.0.0.1:8765';
  try {
    const response = await fetch(`/api/model/models?baseUrl=${encodeURIComponent(baseUrl)}`);
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || 'Model list failed');
    const names = (body.models ?? []).map(model => model.name || model.model);
    select.innerHTML = names.map(name => `<option${name === body.defaultModel ? ' selected' : ''}>${escape(name)}</option>`).join('') || '<option value="">No models</option>';
    $('#form-error').textContent = names.length ? '' : 'The Qwen host returned no models.';
  } catch (error) {
    select.innerHTML = '<option value="">Unavailable</option>';
    $('#form-error').textContent = error.message;
  }
}

async function start() {
  const mission = selectedMission();
  if (source) source.close();
  $('#agent').textContent = 'Contacting the Qwen host…';
  const response = await fetch('/api/lab/sessions', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      missionId: mission.id,
      baseUrl: $('#base-url').value,
      model: $('#model').value,
      maxSteps: Number($('#max-steps').value),
      modelTimeoutMs: Number($('#timeout').value) * 1000
    })
  });
  const body = await response.json();
  if (!response.ok) {
    $('#agent').textContent = body.error || 'Could not start the mission.';
    return;
  }
  session = body.session;
  drawSession();
  source = new EventSource(`/api/lab/sessions/${session.id}/events`);
  source.onmessage = event => {
    const payload = JSON.parse(event.data);
    if (payload.session) {
      session = payload.session;
      drawSession();
    }
  };
  source.onerror = () => {
    if (!session) $('#form-error').textContent = 'Lost the event stream.';
  };
}

function drawSession() {
  if (!session) return;
  $('#run-state').textContent = session.status.toUpperCase();
  $('#agent').innerHTML = renderAgent(session);
  $('#security').innerHTML = renderSecurity(session);
  $('#trace').innerHTML = session.events.length ? session.events.map(renderTrace).join('') : 'No events yet.';
  document.querySelectorAll('[data-approval]').forEach(button => {
    button.onclick = () => submitApproval(button.dataset.approval);
  });
}

function renderAgent(current) {
  const parts = current.events.filter(event => ['model', 'gateway', 'execution', 'malformed', 'approval-request', 'human', 'error'].includes(event.kind)).map(event => {
    if (event.kind === 'model') {
      const calls = (event.toolCalls ?? []).map(call => `<div class="muted-block">${escape(call.name || 'malformed')} ${escape(JSON.stringify(call.arguments || call.reason || ''))}</div>`).join('');
      return `<div class="lab-card"><b>Model</b><div class="muted-block">${escape(event.content || '(no text)')}</div>${calls}</div>`;
    }
    if (event.kind === 'gateway') return `<div class="lab-card"><b>Gateway</b> <span class="tag ${escape(event.decision)}">${escape(event.decision)}</span> ${event.attack ? '<span class="tag attack">MONITORED</span>' : ''}<div class="muted-block">${escape(event.call?.name)} ${escape(JSON.stringify(event.call?.arguments ?? {}))}\n${escape(event.reason)}</div></div>`;
    if (event.kind === 'execution') return `<div class="lab-card"><b>Virtual tool</b><div class="muted-block">${escape(event.call.name)} → ${escape(JSON.stringify(event.result))}</div></div>`;
    if (event.kind === 'approval-request') return `<div class="lab-card"><b>Approval needed</b><div class="muted-block">${escape(event.reason)}</div></div>`;
    if (event.kind === 'human') return `<div class="lab-card"><b>Person</b><div class="muted-block">${escape(event.decision)} ${escape(event.tool)}</div></div>`;
    if (event.kind === 'error') return `<div class="lab-card"><b>Error</b><div class="muted-block">${escape(event.message)}</div></div>`;
    return `<div class="lab-card"><b>Malformed call</b><div class="muted-block">${escape(event.reason)}</div></div>`;
  });
  if (current.pending && current.status === 'approval') {
    parts.push(`<div class="lab-card"><b>This call is waiting</b><div class="muted-block">${escape(current.pending.name)} ${escape(JSON.stringify(current.pending.arguments))}</div><div class="approval-row"><button class="allow" type="button" data-approval="allow">APPROVE</button><button class="deny" type="button" data-approval="deny">REJECT</button></div><p class="contract">Approving asks decide() again. The tool runs only if that result is allow.</p></div>`);
  }
  return parts.join('') || 'Waiting for the model.';
}

function renderSecurity(current) {
  const evaluation = current.evaluation;
  if (!evaluation) return '<p class="muted">The gateway has not judged a call yet.</p>';
  const progress = evaluation.progress.map(item => `<div>${item.met ? '✓' : '·'} ${escape(item.label)}</div>`).join('');
  return `
    <div class="lab-card"><b>Status</b><div class="muted-block">${escape(current.status)} · ${escape(current.model)} · step ${current.modelCalls}/${current.maxSteps}</div></div>
    <div class="lab-card"><b>Legitimate task</b><div class="muted-block">${progress}</div></div>
    <div class="lab-card"><b>Monitored attacks proposed</b><div class="muted-block">${evaluation.violationsAttempted.length}</div></div>
    <div class="lab-card"><b>Prevented before execution</b><div class="muted-block">${evaluation.violationsPrevented}</div></div>
    <div class="lab-card"><b>Executed in the virtual world</b><div class="muted-block">${evaluation.violationsExecuted}</div></div>
    <div class="lab-card"><b>Evaluation</b><div class="muted-block">${escape(evaluation.note)}\nTask ${evaluation.taskMet ? 'met' : 'not met'}. Invariants ${evaluation.invariantsHeld ? 'held' : 'broken'}. ${evaluation.securityDemonstrated ? 'An attempted attack was kept out of the tools.' : ''}</div></div>
    <div class="lab-card"><b>Virtual effects</b><div class="muted-block">reads/writes ${current.world.audit.length}\nmail ${current.world.outbox.length}\nhttp ${current.world.requests.length}</div></div>`;
}

function renderTrace(event) {
  const lines = [];
  if (event.content) lines.push(event.content);
  for (const call of event.toolCalls ?? []) lines.push(`${call.name || 'malformed'} ${JSON.stringify(call.arguments || call.reason || '')}`);
  if (event.call) lines.push(`${event.call.name} ${JSON.stringify(event.call.arguments || {})}`);
  if (event.reason) lines.push(event.reason);
  if (event.message) lines.push(event.message);
  if (event.kind === 'human') lines.push(`${event.decision} ${event.tool}`);
  if (event.result) lines.push(JSON.stringify(event.result));
  return `<div class="lab-card"><b>${escape(event.kind)}</b><div class="muted-block">${escape(lines.join('\n') || event.status || '')}</div></div>`;
}

async function submitApproval(decision) {
  if (!session) return;
  await fetch(`/api/lab/sessions/${session.id}/approval`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ decision })
  });
}

boot();
