/* Project Sentinel — shared JS utilities */

// ── Clock ──────────────────────────────────────────────────────────
function startClock(id) {
  const el = document.getElementById(id);
  if (!el) return;
  const tick = () => el.textContent = new Date().toLocaleTimeString('en-GB',{hour12:false});
  tick();
  setInterval(tick, 1000);
}

// ── Toast ──────────────────────────────────────────────────────────
function showToast(ok, title, body='') {
  const box = document.getElementById('toast-box');
  if (!box) return;
  const div = document.createElement('div');
  div.className = 'toast' + (ok ? ' toast-ok' : '');
  div.innerHTML = `
    <button class="toast-close" onclick="this.closest('.toast').remove()">✕</button>
    <div class="toast-title" style="color:${ok?'var(--g300)':'var(--r300)'};">
      ${ok ? '✓' : '⚠'} ${title}
    </div>
    ${body ? `<div style="color:var(--tx-mid);font-size:12px;margin-top:3px;">${body}</div>` : ''}`;
  box.prepend(div);
  setTimeout(() => div.remove(), 7000);
}

// ── SSE ────────────────────────────────────────────────────────────
function connectSSE(onMessage) {
  const es = new EventSource('/stream');
  es.onmessage = e => {
    try { onMessage(JSON.parse(e.data)); } catch(_){}
  };
  es.onerror = () => setTimeout(() => connectSSE(onMessage), 5000);
}

// ── Risk colour ───────────────────────────────────────────────────
function riskColor(level) {
  return level==='High' ? 'var(--r300)' : level==='Medium' ? 'var(--a300)' : 'var(--g300)';
}
function riskRowClass(level) {
  return level==='High' ? 'row-high' : level==='Medium' ? 'row-med' : 'row-low';
}
function riskBadgeClass(level) {
  return level==='High' ? 'badge-high' : level==='Medium' ? 'badge-medium' : 'badge-low';
}

// ── Threat bar ─────────────────────────────────────────────────────
function updateThreatBar(high, total) {
  const bar = document.getElementById('threat-bar');
  const txt = document.getElementById('threat-level-txt');
  if (!bar || !txt) return;
  const pct = total>0 ? Math.min((high/total)*120,100) : 0;
  bar.style.width = pct + '%';
  if (high === 0) { txt.textContent = 'LOW'; txt.style.color = 'var(--g400)'; }
  else if (pct < 40) { txt.textContent = 'MEDIUM'; txt.style.color = 'var(--a400)'; }
  else { txt.textContent = 'HIGH'; txt.style.color = 'var(--r400)'; }
}