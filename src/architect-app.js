import { runCases } from './architect-runner.js';
const results = runCases();
let active = results.findIndex(x=>!x.passed); if (active<0) active=0;
const $ = s=>document.querySelector(s);
const escape = s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const passed=results.filter(x=>x.passed).length;
$('#score').textContent=`${passed}/${results.length}`;
$('#count').textContent=`${results.length} SCENARIOS`;
$('#bar').style.width=`${100*passed/results.length}%`;
function draw(){
 $('#missions').innerHTML=results.map((r,i)=>`<div class="mission ${i===active?'selected':''}" data-case="${i}"><span class="${r.passed?'ok':'fail'}">${r.passed?'✓':'✕'}</span> &nbsp;${escape(r.id)} / ${escape(r.title)}</div>`).join('');
 const r=results[active];
 $('#detail').innerHTML=`<div class="eyebrow">CASE ${escape(r.id)} / ${escape(r.title)}</div><h2 class="${r.passed?'ok':'fail'}">${r.passed?'PASSED':'FAILED'}</h2><p>EXPECTED: <b>${escape(r.expected.toUpperCase())}</b> &nbsp; YOUR POLICY: <b>${escape(r.actual.toUpperCase())}</b></p><p><b>Reason returned:</b> ${escape(r.reason)}</p><p><b>Security principle:</b> ${escape(r.lesson)}</p><div class="panelhead" style="padding-left:0">INTERCEPTED CONTEXT</div><pre class="code">${escape(JSON.stringify(r.context,null,2))}</pre>`;
 document.querySelectorAll('[data-case]').forEach(el=>el.onclick=()=>{active=Number(el.dataset.case);draw()});
}
draw();
