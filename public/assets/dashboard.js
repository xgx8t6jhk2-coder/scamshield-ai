import { BRANDS, SCAM_PLAYBOOKS } from '/engine/scamshield.js';

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const brandName = (id) => BRANDS.find((b) => b.id === id)?.en || (id === 'unknown' ? 'Unknown' : id);
const pbName = (id) => SCAM_PLAYBOOKS.find((p) => p.id === id)?.en || ({ phishing_link: 'Phishing link', unknown: 'Other' }[id] || id);
const fmt = (n) => new Intl.NumberFormat('en-AE').format(n || 0);
const short = (d) => (d ? d.slice(5, 16).replace(' ', ' · ') : '—');
const riskCls = (s) => (s >= 65 ? 'h' : s >= 35 ? 'm' : 'l');
let key = (() => { try { return localStorage.getItem('ss_key') || ''; } catch { return ''; } })();
let data = null;

async function load() {
  const days = $('#range').value;
  const demo = $('#demo').checked ? 1 : 0;
  try {
    const r = await fetch(`/api/stats?days=${days}&demo=${demo}`);
    data = await r.json();
    render(data);
  } catch (e) { toast('Could not load stats'); }
}

function render(d) {
  const t = d.totals || {};
  const active = (d.campaigns || []).filter((c) => c.status === 'active').length;
  const kpis = [
    ['Reports', 'بلاغات', t.reports, 'rgba(214,178,94,.25)'],
    ['Victims who lost money', 'ضحايا خسروا مالاً', t.victims, 'rgba(244,63,94,.3)'],
    ['Active campaigns', 'حملات نشطة', active, 'rgba(251,191,36,.25)'],
    ['Scam domains', 'نطاقات احتيال', t.domains, 'rgba(59,130,246,.3)'],
    ['Residents warned', 'سكان تم تحذيرهم', t.warned, 'rgba(52,211,153,.25)'],
    ['Hunted pre-emptively', 'مرصودة استباقياً', (d.hunts || []).length, 'rgba(34,211,238,.25)'],
  ];
  $('#kpis').innerHTML = kpis.map(([en, ar, n, c]) => `<div class="kpi" style="--kc:${c}"><small>${en}</small><small class="ar">${ar}</small><b data-n="${n || 0}">0</b></div>`).join('');
  document.querySelectorAll('.kpi b').forEach(countUp);

  $('#alerts').innerHTML = (d.alerts || []).slice(0, 3).map((a) => `<div class="alert"><b>×${a.factor}</b><div class="t"><strong>Surge:</strong> ${esc(brandName(a.brand))} · ${esc(pbName(a.playbook))} — ${a.today} reports in the last 24 h vs ${a.avg.toFixed(1)}/day average. <span class="muted">Consider a public warning on official channels.</span></div><button class="mini" data-brand="${esc(a.brand)}">Hunt domains</button></div>`).join('');
  document.querySelectorAll('.alert .mini').forEach((b) => (b.onclick = () => { $('#huntBrand').value = b.dataset.brand; hunt(); $('#huntBrand').scrollIntoView({ behavior: 'smooth', block: 'center' }); }));

  timeline(d.timeline || [], Number(d.days));
  emirates(d.byEmirate || []);
  hbars('#brands', (d.byBrand || []).map((b) => [brandName(b.brand), b.n]));
  hbars('#channels', (d.byChannel || []).map((b) => [b.channel.toUpperCase(), b.n]));
  donut(d.byPlaybook || []);

  $('#campaigns tbody').innerHTML = (d.campaigns || []).map((c) => `<tr>
      <td>${c.id}</td><td><b>${esc(brandName(c.brand))}</b></td><td>${esc(pbName(c.playbook))}</td><td>.${esc(c.tld || '—')}</td>
      <td class="risk">${c.reports}</td><td class="risk ${c.victims ? 'h' : ''}">${c.victims}</td>
      <td>${(c.domains || []).slice(0, 4).map((x) => `<span class="chip" data-d="${esc(x)}">${esc(x)}</span>`).join('')}${(c.domains || []).length > 4 ? `<span class="muted">+${c.domains.length - 4}</span>` : ''}</td>
      <td class="muted">${short(c.first_seen)} → ${short(c.last_seen)}</td><td><span class="status ${c.status}">${c.status.replace('_', ' ')}</span></td></tr>`).join('') || '<tr><td colspan="9" class="empty">No campaigns in this window.</td></tr>';

  $('#domains tbody').innerHTML = (d.topDomains || []).map((x) => `<tr><td><code>${esc(x.domain)}</code></td><td>${esc(brandName(x.brand))}</td><td>${esc(pbName(x.playbook))}</td><td class="risk">${x.n}</td><td class="risk ${x.victims ? 'h' : ''}">${x.victims || 0}</td><td class="risk ${riskCls(x.score)}">${x.score}</td><td class="muted">${short(x.first_seen)}</td><td><button class="mini" data-d="${esc(x.domain)}">Takedown pack</button></td></tr>`).join('') || '<tr><td colspan="8" class="empty">No domains yet.</td></tr>';

  renderHunts(d.hunts || []);
  document.querySelectorAll('[data-d]').forEach((el) => (el.onclick = () => takedown(el.dataset.d)));
}

function renderHunts(list) {
  $('#hunts tbody').innerHTML = list.map((h) => `<tr><td><code>${esc(h.domain)}</code></td><td>${esc(brandName(h.brand))}</td><td>${h.source === 'ct' ? 'Cert. Transparency' : 'DNS sweep'}</td><td class="muted">${esc(h.detail || '')}</td><td class="risk ${riskCls(h.score)}">${h.score}</td><td class="muted">${short(h.first_seen)}</td><td><span class="status ${h.status}">${h.status.replace('_', ' ')}</span></td><td><button class="mini" data-d="${esc(h.domain)}">Takedown pack</button></td></tr>`).join('') || '<tr><td colspan="8" class="empty">Nothing on the watch-list yet — run a hunt.</td></tr>';
  document.querySelectorAll('#hunts [data-d]').forEach((el) => (el.onclick = () => takedown(el.dataset.d)));
}

function countUp(el) {
  const n = Number(el.dataset.n); const t0 = performance.now();
  const step = (t) => { const p = Math.min(1, (t - t0) / 900); el.textContent = fmt(Math.round(n * (1 - Math.pow(1 - p, 3)))); if (p < 1) requestAnimationFrame(step); };
  requestAnimationFrame(step);
}

function timeline(rows, days) {
  const W = 900, H = 260, P = { l: 36, r: 26, t: 14, b: 26 };
  const map = new Map(rows.map((r) => [r.day, r]));
  const pts = [];
  for (let i = days - 1; i >= 0; i--) { const day = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10); const r = map.get(day); pts.push({ day, n: r?.n || 0, v: r?.victims || 0 }); }
  const max = Math.max(4, ...pts.map((p) => p.n));
  const x = (i) => P.l + (i * (W - P.l - P.r)) / Math.max(1, pts.length - 1);
  const y = (v) => H - P.b - (v / max) * (H - P.t - P.b);
  const line = (k) => pts.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p[k]).toFixed(1)}`).join('');
  const area = `${line('n')}L${x(pts.length - 1)},${H - P.b}L${x(0)},${H - P.b}Z`;
  const grid = [0, .25, .5, .75, 1].map((f) => `<line x1="${P.l}" x2="${W - P.r}" y1="${y(max * f)}" y2="${y(max * f)}" stroke="rgba(148,178,230,.08)"/><text x="${P.l - 8}" y="${y(max * f) + 4}" text-anchor="end">${Math.round(max * f)}</text>`).join('');
  const every = Math.ceil(pts.length / 7);
  const labels = pts.map((p, i) => (i % every === 0 || i === pts.length - 1 ? `<text x="${x(i)}" y="${H - 6}" text-anchor="middle">${p.day.slice(5)}</text>` : '')).join('');
  const dots = pts.map((p, i) => `<circle cx="${x(i)}" cy="${y(p.n)}" r="3.5" fill="#d6b25e"><title>${p.day}: ${p.n} reports, ${p.v} victims</title></circle>`).join('');
  $('#timeline').innerHTML = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none"><defs><linearGradient id="ga" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#d6b25e" stop-opacity=".35"/><stop offset="1" stop-color="#d6b25e" stop-opacity="0"/></linearGradient></defs>${grid}<path d="${area}" fill="url(#ga)"/><path d="${line('n')}" fill="none" stroke="#d6b25e" stroke-width="2.5"/><path d="${line('v')}" fill="none" stroke="#f43f5e" stroke-width="2" stroke-dasharray="5 4"/>${dots}${labels}</svg>`;
}

function emirates(rows) {
  const E = [['AD', 'Abu Dhabi', 'أبوظبي'], ['DXB', 'Dubai', 'دبي'], ['SHJ', 'Sharjah', 'الشارقة'], ['AJM', 'Ajman', 'عجمان'], ['UAQ', 'Umm Al Quwain', 'أم القيوين'], ['RAK', 'Ras Al Khaimah', 'رأس الخيمة'], ['FUJ', 'Fujairah', 'الفجيرة']];
  const m = new Map(rows.map((r) => [r.emirate, r.n]));
  const max = Math.max(1, ...rows.map((r) => r.n));
  $('#emirates').innerHTML = `<div class="tiles">${E.map(([k, en, ar]) => `<div class="tile" style="--a:${(0.06 + 0.5 * (m.get(k) || 0) / max).toFixed(2)}"><b>${fmt(m.get(k) || 0)}</b><span>${en}<br>${ar}</span></div>`).join('')}</div>`;
}

function hbars(sel, rows) {
  const max = Math.max(1, ...rows.map((r) => r[1]));
  $(sel).innerHTML = rows.slice(0, 8).map(([k, n]) => `<div class="hbar"><span>${esc(k)}</span><b>${fmt(n)}</b><div class="track"><i style="width:${(n / max) * 100}%"></i></div></div>`).join('') || '<p class="empty">No data</p>';
}

function donut(rows) {
  const colors = ['#f43f5e', '#fbbf24', '#d6b25e', '#3b82f6', '#22d3ee', '#34d399', '#a78bfa', '#f472b6', '#94a3b8'];
  const total = rows.reduce((a, b) => a + b.n, 0) || 1;
  let acc = 0; const R = 60, C = 2 * Math.PI * R;
  const segs = rows.slice(0, 9).map((r, i) => { const len = (r.n / total) * C; const s = `<circle r="${R}" cx="75" cy="75" fill="none" stroke="${colors[i]}" stroke-width="22" stroke-dasharray="${len} ${C - len}" stroke-dashoffset="${-acc}"/>`; acc += len; return s; }).join('');
  $('#playbooks').innerHTML = `<div class="donut"><svg viewBox="0 0 150 150" style="transform:rotate(-90deg)">${segs}</svg><ul>${rows.slice(0, 9).map((r, i) => `<li><i style="background:${colors[i]}"></i><span>${esc(pbName(r.playbook))}</span><b>${Math.round((r.n / total) * 100)}%</b></li>`).join('')}</ul></div>`;
}

/* ---------------- hunting ---------------- */
$('#huntBrand').innerHTML = BRANDS.map((b) => `<option value="${b.id}">${esc(b.en)} — ${esc(b.domains[0])}</option>`).join('');
$('#huntBrand').value = 'rta';
async function hunt() {
  const btn = $('#huntBtn'); btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Hunting…';
  $('#huntOut').innerHTML = '<p class="muted">Querying Certificate Transparency logs and sweeping look-alike domains over DNS…</p>';
  try {
    const r = await fetch(`/api/hunt?brand=${$('#huntBrand').value}`);
    const j = await r.json();
    $('#huntOut').innerHTML = `<p class="muted">Checked ${j.checked} permutations · CT logs ${j.ctAvailable ? 'queried' : 'unavailable (timeout) — DNS sweep only'} · <b style="color:var(--text)">${j.found.length} suspicious live domains</b> targeting ${esc(j.brand.en)} (official: ${esc(j.brand.official)})</p>
      <div class="found">${j.found.map((f) => `<div class="f"><code>${esc(f.host)}</code><small>${f.source === 'ct' ? '📜 New certificate' : '🌐 Live DNS'} · ${esc(f.detail)}</small><div style="display:flex;justify-content:space-between;align-items:center"><span class="risk ${riskCls(f.score)}">risk ${f.score}</span><button class="mini" data-d="${esc(f.domain)}">Takedown pack</button></div></div>`).join('') || '<p class="empty">No live look-alikes found right now. 👍</p>'}</div>`;
    document.querySelectorAll('#huntOut [data-d]').forEach((el) => (el.onclick = () => takedown(el.dataset.d)));
    load();
  } catch { $('#huntOut').innerHTML = '<p class="empty">Hunt failed — try again.</p>'; }
  finally { btn.disabled = false; btn.textContent = 'Hunt now'; }
}
$('#huntBtn').onclick = hunt;

/* ---------------- takedown pack ---------------- */
let pack = null;
async function takedown(domain) {
  const dlg = $('#tdDlg'); $('#tdBody').innerHTML = `<h3>Building evidence for ${esc(domain)}…</h3><p class="muted">RDAP registration lookup, DNS, engine findings, community reports.</p>`; dlg.showModal();
  try {
    pack = await (await fetch(`/api/takedown?domain=${encodeURIComponent(domain)}`)).json();
    const r = pack.registration || {};
    $('#tdBody').innerHTML = `<h3>Takedown pack · <code>${esc(pack.domain)}</code></h3>
      <p class="muted">Ref ${esc(pack.ref)} · risk <span class="risk ${riskCls(pack.score)}">${pack.score}</span> ${pack.impersonates ? `· impersonates <b>${esc(pack.impersonates.en)}</b>` : ''}</p>
      <div class="evid">
        <div><small>Registrar</small>${esc(r.registrar || 'unknown')}</div>
        <div><small>Registered</small>${r.registered ? `${esc(r.registered.slice(0, 10))} (${r.ageDays} d)` : r.found === false ? 'not registered / removed' : 'unknown'}</div>
        <div><small>Abuse contact</small>${esc(r.abuseEmail || '—')}</div>
        <div><small>IP / A records</small>${esc((pack.dns.a || []).join(', ') || 'none')}</div>
        <div><small>Community reports</small>${pack.community?.reports || 0} (${pack.community?.victims || 0} victims)</div>
        <div><small>Detected by hunt</small>${pack.hunt ? esc(pack.hunt.source + ' · ' + pack.hunt.first_seen) : '—'}</div>
      </div>
      <pre id="tdNotice">${esc(pack.notice)}</pre>
      <p class="muted">Send to: ${pack.sendTo.map((s) => esc(s.who) + (s.email ? ` &lt;${esc(s.email)}&gt;` : '') + (s.url ? ` (<a href="${esc(s.url)}" target="_blank" rel="noopener">form</a>)` : '')).join(' · ')}</p>`;
  } catch { $('#tdBody').innerHTML = '<p class="empty">Could not build the pack.</p>'; }
}
$('#tdCopy').onclick = async () => { if (!pack) return; try { await navigator.clipboard.writeText(pack.notice); toast('Notice copied'); } catch { toast('Copy failed'); } };
$('#tdJson').onclick = () => { if (!pack) return; const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([JSON.stringify(pack, null, 2)], { type: 'application/json' })); a.download = `${pack.ref}-${pack.domain}.json`; a.click(); };
$('#tdMark').onclick = async () => {
  if (!pack) return;
  if (!key) { $('#keyDlg').showModal(); return; }
  const r = await fetch('/api/hunt', { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${key}` }, body: JSON.stringify({ domain: pack.domain, status: 'takedown_requested' }) });
  toast(r.ok ? 'Marked as takedown requested' : 'Analyst key rejected');
  if (r.ok) load();
};

/* ---------------- misc ---------------- */
$('#keyBtn').onclick = () => { $('#keyInput').value = key; $('#keyDlg').showModal(); };
$('#keyDlg').addEventListener('close', () => { if ($('#keyDlg').returnValue === 'save') { key = $('#keyInput').value.trim(); try { localStorage.setItem('ss_key', key); } catch {} toast('Key saved on this device'); } });
$('#range').onchange = load; $('#demo').onchange = load;
function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.remove('show'), 3200); }
load();
setInterval(load, 30000);
