import { analyzeMessage, analyzeUrl, fingerprint, BRANDS, SCAM_PLAYBOOKS, TACTICS } from '/engine/scamshield.js';
import { splitWords, startDemo } from '/assets/fx.js';

/* ---------------- i18n ---------------- */
const EN = {
  tagline: 'UAE scam detector', nav_how: 'How it works', nav_live: 'Live in the UAE', nav_quiz: 'Test yourself', nav_police: 'Police dashboard',
  eyebrow: 'Runs on your phone · Arabic & English · Free',
  h1a: 'Suspicious message?', h1b: 'Check before you click.',
  lead: 'Paste the message or link, upload a screenshot or scan a QR code. ScamShield spots fake UAE government, bank and delivery messages in a second — and tells you why.',
  tab_msg: 'Message', tab_url: 'Link', tab_shot: 'Screenshot', tab_qr: 'QR code',
  ph_msg: 'Paste the SMS, WhatsApp or email text here…', ph_sender: 'Sender (optional): e.g. RTA or +971…', ph_url: 'https://…',
  hint_url: 'We open the link for you in an isolated sandbox — the scammer never reaches your phone.',
  shot_title: 'Upload a screenshot of the message', shot_sub: 'Arabic and English text is read on your device — the image is never uploaded.',
  qr_cam: 'Open camera', qr_up: 'Upload QR photo',
  hint_qr: 'QR scams (“quishing”) are spreading on parking meters and posters. Scan the code here before you pay.',
  mode_deep: 'Deep check: safely open the link + AI analyst (text is never stored)', mode_local: 'On-device only: nothing leaves your phone',
  scan: 'Check now',
  how_t: 'Not just another link checker.', how_s: 'Three layers working together — from a resident’s phone to the police operations room.',
  f1t: 'On-device engine', f1p: 'Reads Arabic, English and Arabizi and knows {N} UAE entities. Works offline in under 5 ms — your messages never leave your phone.',
  f2t: 'Safe link detonation', f2p: 'We follow shorteners and redirects, check the domain’s age and inspect the page: does it ask for your card or OTP? Does it send data to Telegram?',
  f3t: 'AI second opinion', f3p: 'A language model catches new wording the rules have not seen yet, and explains the verdict in one plain sentence for elderly users.',
  f4t: 'Proactive hunting', f4p: 'We watch new SSL certificates and look-alike domains of RTA, Salik, Emirates Post and more — to find the scam site before the first SMS is sent.',
  f5t: 'From report to takedown', f5p: 'Anonymous reports cluster into campaigns, police see surges live, and an evidence pack to shut the domain down is generated in minutes.',
  f6t: 'Private by design', f6p: 'We never store message text, phone numbers or IP addresses. A report is only a structural fingerprint: impersonated brand, scam type, domain.',
  live_t: 'Happening now in the UAE', live_s: 'Most impersonated organisations this week, from anonymous community reports.',
  quiz_t: 'Can you spot it?', quiz_s: 'Five realistic messages. Scam or real? Share it with your parents.', q_scam: '🚩 Scam', q_real: '✅ Real',
  foot: 'Prototype for the 2026 AI Cyber-Crime Hackathon, Abu Dhabi Police × 42 Abu Dhabi. Not an official Abu Dhabi Police app.',
  api: 'API', privacy: 'Privacy',
  rep_t: 'Report anonymously', rep_s: 'We send only the scam fingerprint (impersonated brand, scam type, domain). Never the message text or your number.',
  rep_ch: 'Where did you get it?', rep_em: 'Emirate (optional)', rep_lost: 'I lost money or entered my card details', rep_send: 'Send report', cancel: 'Cancel',
  sos_t: 'Paid or typed your details? Act now',
  sos1: 'Call your bank immediately to block the card and dispute the payment (number on the back of your card).',
  sos2: 'Change the password of the linked account or UAE PASS and turn on two-factor authentication.',
  sos3: 'Do not delete the message — screenshot it as evidence.',
  sos4: 'Report to police: emergency 999, Aman 8002626, ecrime.ae or the Abu Dhabi Police app.',
  sos5: 'If anyone offers to “recover your money” for a fee — that is a second scam.', close: 'Close',
  v_dangerous: 'Dangerous', v_suspicious: 'Suspicious', v_safe: 'Looks safe',
  t_dangerous: 'This is very likely a scam.', t_suspicious: 'Be careful — this has scam warning signs.', t_safe: 'No strong scam signs found.',
  why: 'Why we think so', live_checks: 'Live checks', ai_t: 'AI analyst', what_do: 'What to do',
  they_used: 'They used', real_one: 'The real one', imp: 'Pretends to be', report: 'Report anonymously', warn_family: 'Warn my family', paid: 'I already paid', again: 'Check another',
  age: 'Domain age', registrar: 'Registrar', lands: 'Really opens', page_asks: 'Page asks for', redirects: 'Redirect path', community: 'Community reports', days: 'days',
  nothing: 'Paste a message, link, screenshot or QR first.', scanning: 'Analysing…', reported: 'Thank you — report sent. It joined campaign #{id} ({n} reports).',
  ocr_loading: 'Loading the Arabic + English reader (first time only)…', ocr_reading: 'Reading the text on your device…', ocr_done: 'Text extracted on your device. Review it, then check.', ocr_fail: 'Could not read the image. Try a clearer screenshot.',
  qr_found: 'QR code contains:', qr_none: 'No QR code found in that image.', cam_fail: 'Camera not available — upload a photo instead.',
  share_text: '⚠️ Scam alert (checked with ScamShield AI): a {brand} message is going around linking to {domain}. Do not open it or pay. Real site: {official}.',
  copied: 'Warning copied — paste it in your family group.',
  card: 'card details', otp: 'OTP code', password: 'password', eid: 'Emirates ID', telegram: 'sends data to Telegram',
  s1: 'messages checked', s2: 'people warned', s3: 'scam domains tracked', s4: 'UAE entities protected',
  quiz_right: 'Correct! ', quiz_wrong: 'Not quite. ', quiz_next: 'Next message →', quiz_done: 'You scored {s}/5. Share this page with someone who needs it.',
  no_data: 'No reports yet this week.', reports: 'reports',
  demo_t: 'Watch it catch a scam', demo_s: 'A real message, a scam and a genuine bank OTP — ScamShield tells them apart in under a second.',
  st1t: 'A message arrives', st1p: 'SMS, WhatsApp or email — in Arabic, English or Arabizi.',
  st2t: 'Instant on-device check', st2p: '{N} UAE entities, {P} scam playbooks, {T} manipulation tactics — in milliseconds.',
  st3t: 'Impersonation exposed', st3p: '“salik-uae-pay.top” is not salik.ae — we show you the difference letter by letter.',
  st4t: 'Warn and report in one tap', st4p: 'Clear advice, a family warning, and an anonymous report that reaches the police operations room.',
  unknown: 'Unknown number', dt_b: 'ScamShield: fake Salik message', dt_s: 'The real site is salik.ae. Don’t pay — link blocked.',
};
const AR = Object.fromEntries([...document.querySelectorAll('[data-t]')].map((el) => [el.dataset.t, el.textContent]));
Object.assign(AR, {
  ph_msg: 'الصق نص الرسالة هنا (SMS أو واتساب أو بريد)…', ph_sender: 'المرسل (اختياري): مثل RTA أو ‎+971…', ph_url: 'https://…',
  mode_deep: 'فحص معمّق: فتح الرابط بأمان + ذكاء اصطناعي (لا نحفظ النص)', mode_local: 'على الجهاز فقط: لا يغادر شيء هاتفك',
  f1p: 'يقرأ العربية والإنجليزية والعربيزي ويعرف {N} جهة إماراتية. يعمل دون إنترنت وخلال أقل من 5 ميلي ثانية — رسائلك لا تغادر هاتفك.',
  st2p: '{N} جهة إماراتية، {P} نمط احتيال، {T} أساليب تلاعب — خلال أجزاء من الثانية.',
  v_dangerous: 'خطير', v_suspicious: 'مشبوه', v_safe: 'يبدو آمناً',
  t_dangerous: 'هذا احتيال على الأرجح.', t_suspicious: 'انتبه — توجد مؤشرات احتيال.', t_safe: 'لا توجد مؤشرات احتيال قوية.',
  why: 'لماذا نعتقد ذلك', live_checks: 'فحوص مباشرة', ai_t: 'المحلل الذكي', what_do: 'ماذا تفعل',
  they_used: 'استخدموا', real_one: 'الموقع الحقيقي', imp: 'ينتحل صفة', report: 'بلّغ بشكل مجهول', warn_family: 'حذّر عائلتي', paid: 'دفعت بالفعل', again: 'افحص شيئاً آخر',
  age: 'عمر النطاق', registrar: 'جهة التسجيل', lands: 'يفتح فعلياً', page_asks: 'الصفحة تطلب', redirects: 'مسار التحويل', community: 'بلاغات المجتمع', days: 'يوم',
  nothing: 'الصق رسالة أو رابطاً أو ارفع صورة أولاً.', scanning: 'جارٍ التحليل…', reported: 'شكراً — تم إرسال البلاغ وانضم إلى الحملة رقم {id} ({n} بلاغ).',
  ocr_loading: 'تحميل قارئ النصوص العربية والإنجليزية (أول مرة فقط)…', ocr_reading: 'قراءة النص على جهازك…', ocr_done: 'تم استخراج النص على جهازك. راجعه ثم افحص.', ocr_fail: 'تعذّرت قراءة الصورة. جرّب لقطة أوضح.',
  qr_found: 'رمز QR يحتوي على:', qr_none: 'لم نجد رمز QR في الصورة.', cam_fail: 'الكاميرا غير متاحة — ارفع صورة بدلاً منها.',
  share_text: '⚠️ تنبيه احتيال (تم الفحص عبر ScamShield AI): تنتشر رسالة باسم {brand} برابط إلى {domain}. لا تفتحه ولا تدفع. الموقع الرسمي: {official}.',
  copied: 'تم نسخ التحذير — الصقه في مجموعة العائلة.',
  card: 'بيانات البطاقة', otp: 'رمز التحقق', password: 'كلمة المرور', eid: 'رقم الهوية', telegram: 'ترسل البيانات إلى تيليجرام',
  s1: 'رسالة تم فحصها', s2: 'شخص تم تحذيره', s3: 'نطاق احتيال مرصود', s4: 'جهة إماراتية محمية',
  quiz_right: 'صحيح! ', quiz_wrong: 'ليس تماماً. ', quiz_next: 'الرسالة التالية ←', quiz_done: 'نتيجتك {s}/5. شارك الصفحة مع من يحتاجها.',
  no_data: 'لا توجد بلاغات هذا الأسبوع بعد.', reports: 'بلاغ',
});

let lang = (() => { try { return localStorage.getItem('ss_lang') || (navigator.language.startsWith('ar') ? 'ar' : 'en'); } catch { return 'ar'; } })();
const T = (k, vars = {}) => ((lang === 'ar' ? AR : EN)[k] || EN[k] || k).replace(/\{(\w+)\}/g, (_, v) => vars[v] ?? '');
const $ = (s, r = document) => r.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function applyLang() {
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
  document.querySelectorAll('[data-t]').forEach((el) => { el.textContent = T(el.dataset.t, { N: BRANDS.length, P: SCAM_PLAYBOOKS.length, T: TACTICS.length }); });
  splitWords();
  if (startDemo.restart) startDemo.restart(lang); else startDemo(lang);
  document.querySelectorAll('[data-tp]').forEach((el) => { el.placeholder = T(el.dataset.tp); });
  $('#langBtn').textContent = lang === 'ar' ? 'English' : 'العربية';
  $('#modeLabel').textContent = T($('#deepMode').checked ? 'mode_deep' : 'mode_local');
  renderExamples();
  if (lastResult) renderResult(lastResult);
  renderQuiz();
  if (statsCache) renderLive(statsCache);
}
$('#langBtn').onclick = () => { lang = lang === 'ar' ? 'en' : 'ar'; try { localStorage.setItem('ss_lang', lang); } catch {} applyLang(); };
$('#deepMode').onchange = () => { $('#modeLabel').textContent = T($('#deepMode').checked ? 'mode_deep' : 'mode_local'); };

/* ---------------- tabs ---------------- */
let activePane = 'message';
function setPane(name) {
  activePane = name;
  document.querySelectorAll('.tabs button').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.pane === name)));
  document.querySelectorAll('.pane').forEach((p) => { p.hidden = p.dataset.pane !== name; });
  if (name !== 'qr') stopCam();
}
document.querySelectorAll('.tabs button').forEach((b) => (b.onclick = () => setPane(b.dataset.pane)));

/* ---------------- examples ---------------- */
const EXAMPLES = [
  { en: 'Fake Salik fine', ar: 'مخالفة سالك مزيفة', sender: '+639171234567', text: 'Salik: Your toll account has an unpaid balance of AED 12.50. Pay within 24 hours to avoid a AED 400 fine and black points: https://salik-uae.cfd/pay' },
  { en: 'Emirates Post parcel', ar: 'طرد بريد الإمارات', sender: 'EmiratesPost', text: 'بريد الإمارات: شحنتك معلقة في المستودع بسبب عدم اكتمال العنوان. يرجى تحديث العنوان ودفع رسوم إعادة التوصيل 5 درهم خلال 24 ساعة عبر الرابط: emiratespost-ae.top/track' },
  { en: 'Fake police threat', ar: 'تهديد باسم الشرطة', sender: '+923001234567', text: 'شرطة أبوظبي: يوجد بلاغ مسجل ضدك بقضية غسيل أموال. لتجنب القبض تواصل فوراً مع الضابط عبر واتساب +923001234567' },
  { en: 'Real bank OTP', ar: 'رمز بنكي حقيقي', sender: 'EmiratesNBD', text: 'Your Emirates NBD OTP for the transaction of AED 245.00 at CARREFOUR is 482911. Never share this code with anyone, including bank staff.' },
];
function renderExamples() {
  $('#examples').innerHTML = EXAMPLES.map((e, i) => `<button type="button" data-i="${i}">${esc(lang === 'ar' ? e.ar : e.en)}</button>`).join('');
  $('#examples').querySelectorAll('button').forEach((b) => (b.onclick = () => { const e = EXAMPLES[b.dataset.i]; $('#msgInput').value = e.text; $('#senderInput').value = e.sender; scan(); }));
}

/* ---------------- scanning ---------------- */
let lastResult = null;
let lastInput = null;

async function scan(source) {
  let type, input, sender = '';
  if (activePane === 'url') { type = 'url'; input = $('#urlInput').value.trim(); }
  else { type = 'message'; input = $('#msgInput').value.trim(); sender = $('#senderInput').value.trim(); }
  if (!input) { toast(T('nothing')); return; }
  if (type === 'message' && /^\S+$/.test(input) && /[.\/]/.test(input)) type = 'url';
  lastInput = { type, input, sender, source: source || (activePane === 'shot' ? 'screenshot' : activePane === 'qr' ? 'qr' : 'paste') };

  // 1) instant on-device verdict
  const local = type === 'url' ? analyzeUrl(input) : analyzeMessage(input, { sender });
  local.mode = 'local';
  renderResult(local, true);

  // 2) optional deep scan (live checks + AI) — content analysed then discarded server-side
  if (!$('#deepMode').checked) { lastResult = local; renderResult(local); return; }
  const btn = $('#scanBtn');
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span><span>${T('scanning')}</span>`;
  try {
    const res = await fetch('/api/scan', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type, input, sender, source: lastInput.source }) });
    if (!res.ok) throw new Error(await res.text());
    const deep = await res.json();
    deep.mode = 'deep';
    lastResult = deep;
    renderResult(deep);
  } catch (e) {
    lastResult = local;
    renderResult(local);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<span>${T('scan')}</span><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M5 12h14M13 5l7 7-7 7"/></svg>`;
  }
}
$('#scanBtn').onclick = () => scan();
$('#msgInput').addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) scan(); });
$('#urlInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') scan(); });

/* Highlight the characters that differ between the fake domain and the real one. */
function diffMark(fake, real) {
  const label = real.split('.')[0];
  const idx = fake.indexOf(label);
  if (idx >= 0) return esc(fake.slice(0, idx)) + esc(label) + `<mark>${esc(fake.slice(idx + label.length))}</mark>`;
  let out = '', j = 0;
  for (let i = 0; i < fake.length; i++) { if (fake[i] === label[j]) { out += esc(fake[i]); j++; } else out += `<mark>${esc(fake[i])}</mark>`; }
  return out;
}

function renderResult(r, pending = false) {
  const L = lang;
  const v = r.verdict;
  const color = v === 'dangerous' ? 'var(--bad)' : v === 'suspicious' ? 'var(--warn)' : 'var(--ok)';
  const C = 2 * Math.PI * 64;
  const brand = r.impersonatedBrand;
  const link = r.kind === 'url' ? r : (r.links || []).reduce((a, b) => (!a || b.score > a.score ? b : a), null);
  const live = r.live;
  const signals = (r.signals || []).filter((s) => s.weight !== 0 || s.severity === 'good').slice(0, 9);
  const srcLabel = (s) => (s.source === 'page' ? (L === 'ar' ? 'الصفحة' : 'page') : s.source === 'live' ? (L === 'ar' ? 'مباشر' : 'live') : s.source === 'ai' ? 'AI' : s.source === 'community' ? (L === 'ar' ? 'المجتمع' : 'community') : (L === 'ar' ? 'المحرك' : 'engine'));

  let liveHtml = '';
  if (live) {
    const asks = live.page ? ['card', 'otp', 'password', 'eid', 'telegram'].filter((k) => live.page[k]).map((k) => T(k)).join('، ') : '';
    liveHtml = `<div class="card"><h3>🛰️ ${T('live_checks')}</h3><div class="kv">
      ${live.rdap?.ageDays != null ? `<div><span>${T('age')}</span><span>${live.rdap.ageDays} ${T('days')}</span></div>` : ''}
      ${live.rdap?.registrar ? `<div><span>${T('registrar')}</span><span>${esc(live.rdap.registrar)}</span></div>` : ''}
      ${link && link.url ? `<div><span>${T('lands')}</span><span dir="ltr">${esc(link.registrable || '')}</span></div>` : ''}
      ${asks ? `<div><span>${T('page_asks')}</span><span style="color:var(--bad)">${esc(asks)}</span></div>` : ''}
      ${r.community?.reports ? `<div><span>${T('community')}</span><span>${r.community.reports}</span></div>` : ''}
      </div>
      ${live.chain?.length ? `<h3 style="margin-top:14px">${T('redirects')}</h3><ol class="chain">${live.chain.map((c) => `<li>${esc(c.url.slice(0, 90))} <b>${esc(c.status)}</b></li>`).join('')}</ol>` : ''}
    </div>`;
  }

  const adv = (r.advice?.[L] || []).map((a) => `<li>${esc(a)}</li>`).join('');
  $('#result').innerHTML = `
    <div class="card verdict ${v} ${pending ? 'scanline' : ''}">
      <div class="dial">
        <svg viewBox="0 0 150 150"><circle cx="75" cy="75" r="64" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="12"/>
          <circle id="arc" cx="75" cy="75" r="64" fill="none" stroke="${color}" stroke-width="12" stroke-linecap="round" stroke-dasharray="${C}" stroke-dashoffset="${C}" style="transition:stroke-dashoffset 1s cubic-bezier(.2,.8,.2,1)"/></svg>
        <div class="num"><div><b id="scoreNum">0</b><small>${L === 'ar' ? 'خطورة' : 'risk'}</small></div></div>
      </div>
      <div>
        <span class="vtag">● ${T('v_' + v)} ${r.mode === 'local' && !pending ? (L === 'ar' ? '· على الجهاز' : '· on-device') : ''}</span>
        <h2 class="vtitle">${T('t_' + v)}</h2>
        <p class="vsub">${brand ? `${T('imp')} <b>${esc(L === 'ar' ? brand.ar : brand.en)}</b>.` : ''} ${r.ai && L === 'ar' ? esc(r.ai.ar) : r.ai ? esc(r.ai.en) : ''}</p>
        ${brand && link?.registrable && v !== 'safe' ? `<div class="compare"><div class="fake"><small>${T('they_used')}</small><code>${diffMark(link.displayHost || link.registrable, brand.official)}</code></div><div class="real"><small>${T('real_one')}</small><code>${esc(brand.official)}</code></div></div>` : ''}
      </div>
    </div>
    <div class="grid2">
      <div class="card"><h3>🔎 ${T('why')}</h3><ul class="signals">${signals.map((s, i) => `<li class="${s.severity}" style="animation-delay:${i * 60}ms"><span>${esc(L === 'ar' ? s.ar : s.en)}</span><span class="src">${srcLabel(s)}</span></li>`).join('') || `<li class="good"><span>${T('t_safe')}</span><span></span></li>`}</ul>
        ${r.ai ? `<div class="ai"><b>✦ ${T('ai_t')}</b> · ${Math.round(r.ai.probability * 100)}% — ${esc(L === 'ar' ? r.ai.ar : r.ai.en)}</div>` : ''}
      </div>
      <div style="display:grid;gap:16px;align-content:start">
        ${liveHtml}
        <div class="card"><h3>🛡️ ${T('what_do')}</h3><ol class="advice">${adv}</ol></div>
      </div>
    </div>
    <div class="actions">
      ${v !== 'safe' ? `<button class="cta" id="repBtn">🚩 ${T('report')}</button><button class="ghost" id="shareBtn">👨‍👩‍👧 ${T('warn_family')}</button><button class="ghost bad" id="sosBtn">🆘 ${T('paid')}</button>` : ''}
      <button class="ghost" id="againBtn">↺ ${T('again')}</button>
    </div>`;

  requestAnimationFrame(() => {
    const arc = $('#arc');
    if (arc) arc.style.strokeDashoffset = String(C * (1 - r.score / 100));
    const num = $('#scoreNum');
    const t0 = performance.now();
    const step = (t) => { const p = Math.min(1, (t - t0) / 900); num.textContent = String(Math.round(r.score * (1 - Math.pow(1 - p, 3)))); if (p < 1) requestAnimationFrame(step); };
    requestAnimationFrame(step);
  });
  $('#repBtn') && ($('#repBtn').onclick = () => $('#reportDlg').showModal());
  $('#sosBtn') && ($('#sosBtn').onclick = () => $('#sosDlg').showModal());
  $('#shareBtn') && ($('#shareBtn').onclick = shareWarning);
  $('#againBtn').onclick = () => { $('#result').innerHTML = ''; $('#msgInput').value = ''; $('#urlInput').value = ''; $('#senderInput').value = ''; lastResult = null; $('#scanner').scrollIntoView({ behavior: 'smooth', block: 'center' }); };
  if (!pending) $('#result').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* Defanged share text: the scam link is written as domain[.]top so nobody can tap it. */
async function shareWarning() {
  const r = lastResult;
  const link = r.kind === 'url' ? r : (r.links || []).reduce((a, b) => (!a || b.score > a.score ? b : a), null);
  const brand = r.impersonatedBrand;
  const text = T('share_text', {
    brand: brand ? (lang === 'ar' ? brand.ar : brand.en) : (lang === 'ar' ? 'جهة رسمية' : 'an official body'),
    domain: (link?.registrable || '—').replace(/\./g, '[.]'),
    official: brand?.official || 'u.ae',
  }) + ' https://scamshield-ai-eaj.pages.dev';
  if (navigator.share) { try { await navigator.share({ text }); return; } catch {} }
  try { await navigator.clipboard.writeText(text); toast(T('copied')); } catch { prompt('', text); }
}

$('#reportForm').addEventListener('submit', async (e) => {
  if (e.submitter?.value !== 'send' || !lastResult) return;
  const fp = lastResult.fingerprint || fingerprint(lastResult);
  try {
    const res = await fetch('/api/report', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ fingerprint: fp, channel: $('#repChannel').value, emirate: $('#repEmirate').value || null, lostMoney: $('#repLost').checked }) });
    const j = await res.json();
    if (j.ok) toast(T('reported', { id: j.campaignId, n: j.campaignReports }));
    else toast(j.error || 'Error');
    if ($('#repLost').checked) setTimeout(() => $('#sosDlg').showModal(), 400);
  } catch { toast('Network error'); }
});

/* ---------------- screenshot OCR (on-device, Tesseract.js) ---------------- */
let tesseractLoading = null;
function loadScript(src) { return new Promise((res, rej) => { const s = document.createElement('script'); s.src = src; s.onload = res; s.onerror = rej; document.head.appendChild(s); }); }
async function ocr(file) {
  const prog = $('#ocrProg'); const bar = prog.querySelector('i'); const status = $('#ocrStatus');
  prog.hidden = false; bar.style.width = '5%'; status.textContent = T('ocr_loading');
  try {
    tesseractLoading ||= loadScript('https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/tesseract.min.js');
    await tesseractLoading;
    const { data } = await window.Tesseract.recognize(file, 'ara+eng', {
      logger: (m) => { if (m.status === 'recognizing text') { bar.style.width = `${10 + m.progress * 90}%`; status.textContent = T('ocr_reading'); } },
    });
    const text = data.text.replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
    if (!text) throw new Error('empty');
    bar.style.width = '100%'; status.textContent = T('ocr_done');
    $('#msgInput').value = text;
    setPane('message');
    scan('screenshot');
  } catch { status.textContent = T('ocr_fail'); }
  finally { setTimeout(() => { prog.hidden = true; }, 800); }
}
$('#shotFile').onchange = (e) => e.target.files[0] && ocr(e.target.files[0]);
const drop = $('#shotDrop');
['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
drop.addEventListener('drop', (e) => e.dataTransfer.files[0] && ocr(e.dataTransfer.files[0]));
window.addEventListener('paste', (e) => {
  const img = [...(e.clipboardData?.items || [])].find((i) => i.type.startsWith('image/'));
  if (img) { e.preventDefault(); setPane('shot'); ocr(img.getAsFile()); }
});

/* ---------------- QR (on-device, jsQR) ---------------- */
let jsqrLoading = null, stream = null, raf = 0;
async function ensureJsQR() { jsqrLoading ||= loadScript('https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js'); await jsqrLoading; }
function decodeFrom(source, w, h) {
  const c = document.createElement('canvas'); c.width = w; c.height = h;
  const ctx = c.getContext('2d', { willReadFrequently: true }); ctx.drawImage(source, 0, 0, w, h);
  return window.jsQR(ctx.getImageData(0, 0, w, h).data, w, h, { inversionAttempts: 'attemptBoth' });
}
function onQr(data) {
  stopCam();
  toast(`${T('qr_found')} ${data.slice(0, 80)}`);
  if (/^(https?:\/\/|www\.)/i.test(data) || /^[\w-]+(\.[\w-]+)+(\/\S*)?$/.test(data)) { $('#urlInput').value = data; setPane('url'); }
  else { $('#msgInput').value = data; setPane('message'); }
  scan('qr');
}
$('#qrFile').onchange = async (e) => {
  const f = e.target.files[0]; if (!f) return;
  await ensureJsQR();
  const img = new Image(); img.src = URL.createObjectURL(f); await img.decode();
  const scale = Math.min(1, 1400 / Math.max(img.width, img.height));
  const code = decodeFrom(img, Math.round(img.width * scale), Math.round(img.height * scale));
  code ? onQr(code.data) : toast(T('qr_none'));
};
$('#camBtn').onclick = async () => {
  try {
    await ensureJsQR();
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
    const v = $('#cam'); v.srcObject = stream; v.hidden = false; await v.play();
    const tick = () => { if (!stream) return; if (v.videoWidth) { const code = decodeFrom(v, v.videoWidth, v.videoHeight); if (code?.data) return onQr(code.data); } raf = requestAnimationFrame(tick); };
    tick();
  } catch { toast(T('cam_fail')); }
};
function stopCam() { if (stream) { stream.getTracks().forEach((t) => t.stop()); stream = null; } cancelAnimationFrame(raf); const v = $('#cam'); if (v) v.hidden = true; }

/* ---------------- live trends + counters ---------------- */
let statsCache = null;
async function loadStats() {
  try { const r = await fetch('/api/stats?days=7'); statsCache = await r.json(); renderLive(statsCache); } catch {}
}
function renderLive(s) {
  const nameOf = (id) => { const b = BRANDS.find((x) => x.id === id); return b ? (lang === 'ar' ? b.ar : b.en) : id; };
  const max = Math.max(1, ...(s.byBrand || []).map((b) => b.n));
  $('#liveGrid').innerHTML = (s.byBrand || []).filter((b) => b.brand !== 'unknown').slice(0, 6).map((b) => {
    const official = BRANDS.find((x) => x.id === b.brand)?.domains[0] || '';
    return `<div class="trend"><div class="t"><span>${esc(nameOf(b.brand))}</span><span class="n">${b.n}</span></div><div class="bar"><i style="width:${(b.n / max) * 100}%"></i></div><small>${T('real_one')}: <span dir="ltr">${esc(official)}</span> · ${b.n} ${T('reports')}</small></div>`;
  }).join('') || `<p class="vsub">${T('no_data')}</p>`;
  const t = s.totals || {};
  const fmt = (n) => new Intl.NumberFormat(lang === 'ar' ? 'ar-AE' : 'en-AE').format(n || 0);
  $('#strip').innerHTML = [[t.scans, 's1'], [t.warned, 's2'], [t.domains, 's3'], [BRANDS.length, 's4']].map(([n, k]) => `<div class="stat"><b>${fmt(n)}</b><span>${T(k)}</span></div>`).join('');
}

/* ---------------- quiz ---------------- */
const QUIZ = [
  { scam: true, sender: '+447700900123', text: 'RTA: Your vehicle has 2 unpaid parking violations. Pay AED 15 today to avoid impound: rta-parking-ae.top/pay', en: 'RTA never texts from a UK number, and its only site is rta.ae.', ar: 'هيئة الطرق لا ترسل من رقم بريطاني وموقعها الوحيد rta.ae.' },
  { scam: false, sender: 'ADPOLICE', text: 'Abu Dhabi Police: Beware of fraudulent calls claiming to be from the police. We never ask for bank details by phone. Report on 8002626.', en: 'An awareness message with no link and no request — this is real.', ar: 'رسالة توعوية بلا رابط ولا طلب — هذه حقيقية.' },
  { scam: true, sender: '+971 52 000 1111', text: 'مرحبا ماما هذا رقمي الجديد، تلفوني انكسر. محتاج احول 1800 درهم ضروري اليوم ممكن تساعديني؟', en: 'Classic “new number” scam — call your child on their old number first.', ar: 'احتيال “رقمي الجديد” — اتصل بابنك على رقمه القديم أولاً.' },
  { scam: false, sender: 'Aramex', text: 'Your Aramex shipment 4410293381 is out for delivery today. Track: https://www.aramex.com/track/results?ShipmentNumber=4410293381', en: 'Links to the real aramex.com and asks for no payment.', ar: 'الرابط إلى aramex.com الحقيقي ولا يطلب أي دفع.' },
  { scam: true, sender: 'HR Recruit', text: 'Part-time job! Like YouTube videos and earn AED 300-1500 daily. No experience. Contact our HR manager on WhatsApp wa.me/62812345678', en: 'Task scams start with small payouts, then ask you to “deposit” to unlock earnings.', ar: 'احتيال المهام يبدأ بأرباح صغيرة ثم يطلب منك “إيداعاً” لفتح الأرباح.' },
];
let qi = 0, qs = 0;
function renderQuiz() {
  if (qi >= QUIZ.length) { $('#qOut').innerHTML = `<div class="quiz-result card">${T('quiz_done', { s: qs })}</div>`; return; }
  const q = QUIZ[qi];
  $('#qSender').textContent = q.sender; $('#qText').textContent = q.text;
}
function answer(saidScam) {
  if (qi >= QUIZ.length) return;
  const q = QUIZ[qi];
  const ok = saidScam === q.scam; if (ok) qs++;
  const r = analyzeMessage(q.text, { sender: q.sender });
  $('#qOut').innerHTML = `<div class="quiz-result card" style="border-color:${ok ? 'var(--ok)' : 'var(--bad)'}"><b>${ok ? T('quiz_right') : T('quiz_wrong')}</b>${esc(lang === 'ar' ? q.ar : q.en)}<br><small style="color:var(--muted)">ScamShield: ${T('v_' + r.verdict)} (${r.score}/100)</small><div class="actions"><button class="ghost" id="qNext">${T('quiz_next')}</button></div></div>`;
  $('#qNext').onclick = () => { qi++; $('#qOut').innerHTML = ''; renderQuiz(); };
}
$('#qScam').onclick = () => answer(true);
$('#qReal').onclick = () => answer(false);

/* ---------------- misc ---------------- */
function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.remove('show'), 3800); }
const io = new IntersectionObserver((es) => es.forEach((e) => e.isIntersecting && e.target.classList.add('in')), { threshold: 0.12 });
document.querySelectorAll('.reveal').forEach((el) => io.observe(el));

/* Android share-target / deep links: /?text=...  or /?url=... */
const qp = new URLSearchParams(location.search);
applyLang();
loadStats();
if (qp.get('text') || qp.get('url')) {
  const shared = [qp.get('title'), qp.get('text'), qp.get('url')].filter(Boolean).join('\n');
  if (/^\S+$/.test(shared.trim())) { $('#urlInput').value = shared.trim(); setPane('url'); } else { $('#msgInput').value = shared; }
  scan('paste');
}
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
