// Visual effects: intro, constellation background, headline reveal, live phone demo, tilt cards, ticker.
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
const $ = (s) => document.querySelector(s);

/* intro */
const intro = $('#intro');
if (intro) {
  const done = () => intro.classList.add('done');
  if (reduce || sessionStorage.getItem('ss_intro')) done();
  else { setTimeout(done, 1900); try { sessionStorage.setItem('ss_intro', '1'); } catch {} }
  intro.addEventListener('click', done);
}

/* headline word-by-word reveal (re-run after language switch) */
export function splitWords() {
  document.querySelectorAll('.hero h1 > span').forEach((el, li) => {
    const words = el.textContent.split(/(\s+)/);
    el.innerHTML = words.map((w, i) => (/^\s+$/.test(w) ? w : `<span class="w" style="animation-delay:${(reduce ? 0 : 0.25 + li * 0.25 + i * 0.06).toFixed(2)}s">${w.replace(/[&<>]/g, '')}</span>`)).join('');
  });
}

/* constellation background */
const cv = $('#fxbg');
if (cv && !reduce) {
  const ctx = cv.getContext('2d');
  let W, H, pts, mx = 0.5, my = 0.5;
  const DPR = Math.min(2, devicePixelRatio || 1);
  const resize = () => {
    W = cv.width = innerWidth * DPR; H = cv.height = innerHeight * DPR;
    cv.style.width = innerWidth + 'px'; cv.style.height = innerHeight + 'px';
    const n = Math.min(90, Math.round((innerWidth * innerHeight) / 18000));
    pts = Array.from({ length: n }, () => ({ x: Math.random() * W, y: Math.random() * H, vx: (Math.random() - 0.5) * 0.25 * DPR, vy: (Math.random() - 0.5) * 0.25 * DPR, r: (Math.random() * 1.6 + 0.6) * DPR, g: Math.random() < 0.3 }));
  };
  resize(); addEventListener('resize', resize);
  addEventListener('pointermove', (e) => { mx = e.clientX / innerWidth; my = e.clientY / innerHeight; });
  const link = 130 * DPR;
  const tick = () => {
    ctx.clearRect(0, 0, W, H);
    const ox = (mx - 0.5) * 30 * DPR, oy = (my - 0.5) * 30 * DPR;
    for (const p of pts) { p.x += p.vx; p.y += p.vy; if (p.x < 0 || p.x > W) p.vx *= -1; if (p.y < 0 || p.y > H) p.vy *= -1; }
    for (let i = 0; i < pts.length; i++) {
      const a = pts[i];
      for (let j = i + 1; j < pts.length; j++) {
        const b = pts[j], dx = a.x - b.x, dy = a.y - b.y, d = Math.hypot(dx, dy);
        if (d < link) { ctx.strokeStyle = `rgba(148,178,230,${0.12 * (1 - d / link)})`; ctx.lineWidth = DPR; ctx.beginPath(); ctx.moveTo(a.x + ox, a.y + oy); ctx.lineTo(b.x + ox, b.y + oy); ctx.stroke(); }
      }
      ctx.fillStyle = a.g ? 'rgba(243,217,139,.8)' : 'rgba(147,197,253,.55)';
      ctx.beginPath(); ctx.arc(a.x + ox, a.y + oy, a.r, 0, Math.PI * 2); ctx.fill();
    }
    requestAnimationFrame(tick);
  };
  tick();
}

/* scroll progress */
const prog = $('#progress');
if (prog) addEventListener('scroll', () => { prog.style.width = `${(scrollY / Math.max(1, document.documentElement.scrollHeight - innerHeight)) * 100}%`; }, { passive: true });

/* tilt cards */
if (!reduce && matchMedia('(hover: hover)').matches) {
  document.querySelectorAll('.feature').forEach((c) => {
    c.addEventListener('pointermove', (e) => {
      const r = c.getBoundingClientRect(), x = (e.clientX - r.left) / r.width, y = (e.clientY - r.top) / r.height;
      c.style.transform = `perspective(700px) rotateX(${(0.5 - y) * 10}deg) rotateY(${(x - 0.5) * 12}deg) translateY(-4px)`;
      c.style.setProperty('--mx', `${x * 100}%`); c.style.setProperty('--my', `${y * 100}%`);
    });
    c.addEventListener('pointerleave', () => { c.style.transform = ''; });
  });
}

/* ticker of demo blocked domains (defanged, never clickable) */
const ticker = $('#ticker .track');
if (ticker) {
  const items = [['salik-pay-demo1[.]top', 'Salik'], ['rta-fines-demo1[.]cfd', 'RTA'], ['emirtespost-demo[.]icu', 'Emirates Post'], ['uaepass-verify-demo[.]pages[.]dev', 'UAE PASS'], ['enbd-secure-demo[.]online', 'Emirates NBD'], ['etisalat-points-demo[.]live', 'e&'], ['aramex-redeliver-demo[.]xyz', 'Aramex'], ['dewa-refund-demo[.]shop', 'DEWA'], ['usdt-profit-demo[.]vip', 'crypto'], ['adpolice-gov-demo[.]ae[.]com', 'AD Police']];
  const html = items.map(([d, b]) => `<span><b>BLOCKED</b>${d} <i>· fake ${b}</i></span>`).join('');
  ticker.innerHTML = html + html;
}

/* live phone demo: messages arrive, get scanned, get stamped */
let demoLang = 'ar';
export function startDemo(lang) {
  demoLang = lang;
  const box = $('#demoMsgs'), toastp = $('#demoToast'), steps = [...document.querySelectorAll('.step')];
  if (!box) return;
  const mk = (AR) => [
    { t: AR ? 'مرحبا، الاجتماع الساعة 3 في المكتب 👍' : 'Hey, meeting moved to 3pm at the office 👍', ok: true },
    { t: AR ? 'سالك: لديك رصيد غير مدفوع 12.50 درهم. ادفع خلال 24 ساعة لتجنب غرامة 400 درهم: ' : 'Salik: unpaid balance AED 12.50. Pay within 24h to avoid a AED 400 fine: ', link: 'salik-uae-pay.top/settle', ok: false },
    { t: AR ? 'رمز التحقق من بنك الإمارات دبي الوطني 482911. لا تشاركه مع أحد.' : 'Emirates NBD OTP 482911. Never share this code with anyone.', ok: true },
  ];
  let run = 0;
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const setStep = (i) => steps.forEach((s, k) => s.classList.toggle('on', k === i));
  const loop = async () => {
    const my = ++run;
    box.innerHTML = ''; toastp.classList.remove('show'); setStep(-1);
    const AR = demoLang === 'ar';
    for (const m of mk(AR)) {
      if (my !== run) return;
      const el = document.createElement('div');
      el.className = 'sms';
      el.innerHTML = `<span class="stamp">${m.ok ? (AR ? 'آمن' : 'SAFE') : (AR ? 'احتيال' : 'SCAM')}</span>${m.t}${m.link ? `<span class="lk">${m.link}</span>` : ''}`;
      box.appendChild(el);
      await wait(60); el.classList.add('show'); setStep(0);
      await wait(900); el.classList.add('scanning'); setStep(1);
      await wait(1000); el.classList.add(m.ok ? 'good' : 'bad'); setStep(m.ok ? 1 : 2);
      if (!m.ok) { await wait(500); toastp.classList.add('show'); setStep(3); await wait(3200); toastp.classList.remove('show'); }
      await wait(900);
    }
    await wait(1600);
    if (my === run) loop();
  };
  const io = new IntersectionObserver((es) => { if (es[0].isIntersecting) { io.disconnect(); loop(); } }, { threshold: 0.3 });
  io.observe(box);
  startDemo.restart = (l) => { demoLang = l || demoLang; loop(); };
}
