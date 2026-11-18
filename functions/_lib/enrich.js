/* Server-side enrichment: things a phone cannot safely do on its own.
 * - unroll redirect chains (shorteners, cloakers) without the user ever visiting
 * - domain age + registrar from RDAP
 * - inspect the landing page HTML for credential / card harvesting (no JS executed)
 * - DNS over HTTPS lookups
 * Nothing here stores the scanned content. */
import { analyzeUrl, registrableDomain, BRANDS } from '../../public/engine/scamshield.js';

const UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1';

export async function withTimeout(promise, ms) {
  let t;
  const timeout = new Promise((_, rej) => { t = setTimeout(() => rej(new Error('timeout')), ms); });
  try { return await Promise.race([promise, timeout]); } finally { clearTimeout(t); }
}

const isPrivateHost = (h) => /^(localhost|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.|\[)/.test(h) || h.endsWith('.local') || h.endsWith('.internal');

export async function unroll(startUrl, maxHops = 6) {
  const chain = [];
  let current = startUrl;
  for (let i = 0; i < maxHops; i++) {
    let u;
    try { u = new URL(current); } catch { break; }
    if (!/^https?:$/.test(u.protocol) || isPrivateHost(u.hostname)) { chain.push({ url: current, status: 'blocked' }); break; }
    try {
      const res = await withTimeout(fetch(current, { method: 'GET', redirect: 'manual', headers: { 'user-agent': UA, accept: 'text/html,*/*' } }), 5000);
      const loc = res.headers.get('location');
      chain.push({ url: current, status: res.status });
      if (res.status >= 300 && res.status < 400 && loc) { current = new URL(loc, current).href; continue; }
      // meta-refresh / JS location cloaking in a tiny body
      if (res.status === 200 && (res.headers.get('content-type') || '').includes('html')) {
        const html = (await readLimited(res, 120_000)) || '';
        const meta = html.match(/http-equiv=["']?refresh["']?[^>]*content=["']?\d+;\s*url=([^"'>\s]+)/i) || html.match(/(?:window\.)?location(?:\.href)?\s*=\s*["'](https?:\/\/[^"']+)["']/i);
        if (meta && i < maxHops - 1) { current = new URL(meta[1], current).href; continue; }
        return { chain, finalUrl: current, html };
      }
      return { chain, finalUrl: current, html: null };
    } catch (e) {
      chain.push({ url: current, status: e.message === 'timeout' ? 'timeout' : 'unreachable' });
      return { chain, finalUrl: current, html: null, error: e.message };
    }
  }
  return { chain, finalUrl: current, html: null };
}

async function readLimited(res, limit) {
  if (!res.body) return '';
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let out = '', size = 0;
  while (size < limit) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    out += dec.decode(value, { stream: true });
  }
  try { reader.cancel(); } catch {}
  return out;
}

export async function rdap(domain) {
  try {
    const res = await withTimeout(fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { headers: { accept: 'application/rdap+json' }, redirect: 'follow' }), 5000);
    if (res.status === 404) return { found: false };
    if (!res.ok) return null;
    const j = await res.json();
    const ev = (name) => (j.events || []).find((e) => e.eventAction === name)?.eventDate || null;
    const registrarEnt = (j.entities || []).find((e) => (e.roles || []).includes('registrar'));
    const vcard = (ent) => Object.fromEntries(((ent?.vcardArray || [])[1] || []).map((v) => [v[0], v[3]]));
    let abuseEmail = null, abusePhone = null;
    for (const e of registrarEnt?.entities || []) {
      if ((e.roles || []).includes('abuse')) { const v = vcard(e); abuseEmail = v.email || null; abusePhone = v.tel || null; }
    }
    const registered = ev('registration');
    const ageDays = registered ? Math.floor((Date.now() - Date.parse(registered)) / 86400000) : null;
    return {
      found: true,
      registered,
      expires: ev('expiration'),
      ageDays,
      registrar: vcard(registrarEnt).fn || registrarEnt?.handle || null,
      abuseEmail,
      abusePhone,
      nameservers: (j.nameservers || []).map((n) => (n.ldhName || '').toLowerCase()).filter(Boolean),
      status: j.status || [],
    };
  } catch { return null; }
}

export async function doh(name, type = 'A') {
  try {
    const res = await withTimeout(fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, { headers: { accept: 'application/dns-json' } }), 3500);
    const j = await res.json();
    return { status: j.Status, answers: (j.Answer || []).map((a) => a.data) };
  } catch { return null; }
}

/** Static inspection of landing-page HTML. Returns weighted signals like the engine does. */
export function inspectHtml(html, finalHost) {
  const out = [];
  if (!html) return { signals: out, page: null };
  const lower = html.toLowerCase();
  const title = (html.match(/<title[^>]*>([^<]{0,140})/i) || [])[1]?.trim() || '';
  const has = (re) => re.test(lower);
  const password = has(/<input[^>]+type=["']?password/);
  const card = has(/(cardnumber|card_number|cc-number|ccnum|card-number|رقم البطاقة|autocomplete=["']cc-)/);
  const cvv = has(/(cvv|cvc|csc|security code|رمز الأمان)/);
  const otp = has(/(one[- ]time (password|code)|\botp\b|verification code|رمز التحقق|autocomplete=["']one-time-code)/);
  const eid = has(/(emirates id|رقم الهوية|784-?\d{4})/);
  const telegram = has(/api\.telegram\.org\/bot/);
  const formActions = [...html.matchAll(/<form[^>]+action=["']?([^"'\s>]+)/gi)].map((m) => m[1]);
  const offsiteForm = formActions.find((a) => /^https?:\/\//i.test(a) && !a.toLowerCase().includes(finalHost));
  const obfuscated = (lower.match(/eval\(|atob\(|unescape\(|fromcharcode/g) || []).length >= 3;
  const brandNamed = BRANDS.find((b) => [b.en.toLowerCase(), ...b.arWords].some((w) => w && title.toLowerCase().includes(w.toLowerCase())) || b.domains.some((d) => lower.includes(`/${d}/`) && lower.includes('logo')));
  const hostBrand = BRANDS.find((b) => b.domains.some((d) => finalHost === d || finalHost.endsWith('.' + d)));

  const S = (id, weight, en, ar) => out.push({ id, weight, en, ar, severity: weight >= 35 ? 'high' : weight >= 15 ? 'medium' : 'low', source: 'page' });
  if (card || cvv) S('page_card_form', 35, 'The page asks for card number / CVV.', 'الصفحة تطلب رقم البطاقة أو رمز CVV.');
  if (otp) S('page_otp_form', 25, 'The page asks for a one-time code (OTP).', 'الصفحة تطلب رمز تحقق لمرة واحدة.');
  if (password) S('page_password', 12, 'The page has a password box.', 'الصفحة تحتوي خانة كلمة مرور.');
  if (eid) S('page_eid', 15, 'The page asks for your Emirates ID number.', 'الصفحة تطلب رقم الهوية الإماراتية.');
  if (telegram) S('page_telegram_exfil', 60, 'Typed data is sent straight to a Telegram bot — a classic phishing kit.', 'البيانات تُرسل مباشرة إلى بوت تيليجرام — أداة تصيّد معروفة.');
  if (offsiteForm) S('page_offsite_form', 25, `The form sends your data to another site (${safeHost(offsiteForm)}).`, `النموذج يرسل بياناتك إلى موقع آخر (${safeHost(offsiteForm)}).`);
  if (obfuscated) S('page_obfuscated', 15, 'The page hides its code (obfuscation).', 'الصفحة تخفي شيفرتها البرمجية.');
  if (brandNamed && !hostBrand && (password || card || otp || eid)) S('page_brand_mismatch', 40, `Looks like ${brandNamed.en} and asks for details, but is not on ${brandNamed.domains[0]}.`, `تبدو كصفحة ${brandNamed.ar} وتطلب بياناتك لكنها ليست على ${brandNamed.domains[0]}.`);
  return { signals: out, page: { title, password, card: card || cvv, otp, eid, telegram, offsiteForm: offsiteForm ? safeHost(offsiteForm) : null, imitates: brandNamed?.id || null } };
}

function safeHost(u) { try { return new URL(u).hostname; } catch { return 'unknown'; } }

/** Full deep scan for one URL: local engine + unroll + RDAP + page. */
export async function deepScanUrl(rawUrl) {
  const first = analyzeUrl(rawUrl);
  if (!first.host) return { local: first, final: first, chain: [], rdap: null, page: null, extra: [] };
  if (first.signals.some((s) => s.id === 'official_domain' || s.id === 'trusted_domain') && !first.shortener) {
    return { local: first, final: first, chain: [{ url: first.url, status: 'skipped (official)' }], rdap: null, page: null, extra: [] };
  }
  const un = await unroll(first.url);
  const final = un.finalUrl && un.finalUrl !== first.url ? analyzeUrl(un.finalUrl) : first;
  const reg = final.registrable || first.registrable;
  const [r, dns] = await Promise.all([rdap(reg), doh(final.host || first.host)]);
  const extra = [];
  const S = (id, weight, en, ar) => extra.push({ id, weight, en, ar, severity: weight >= 35 ? 'high' : weight >= 15 ? 'medium' : weight > 0 ? 'low' : 'good', source: 'live' });
  if (un.chain.length > 2) S('redirect_chain', 12, `Bounces through ${un.chain.length - 1} redirects.`, `يمر عبر ${un.chain.length - 1} تحويلات.`);
  if (final !== first && final.registrable !== first.registrable) S('lands_elsewhere', 8, `Really opens ${final.registrable}.`, `يفتح فعلياً ${final.registrable}.`);
  if (r?.ageDays != null && r.ageDays < 30) S('new_domain', 35, `Domain registered only ${r.ageDays} day(s) ago.`, `تم تسجيل النطاق قبل ${r.ageDays} يوم فقط.`);
  else if (r?.ageDays != null && r.ageDays < 180) S('young_domain', 15, `Domain is only ${Math.round(r.ageDays / 30)} month(s) old.`, `عمر النطاق ${Math.round(r.ageDays / 30)} شهر فقط.`);
  else if (r?.ageDays != null && r.ageDays > 5 * 365 && final.score < 65) S('old_domain', -12, `Domain has existed for ${Math.floor(r.ageDays / 365)} years.`, `النطاق موجود منذ ${Math.floor(r.ageDays / 365)} سنوات.`);
  if (dns && dns.status === 3) S('nxdomain', 5, 'Domain no longer resolves (possibly already taken down).', 'النطاق لم يعد يعمل (ربما تم إيقافه).');
  const insp = inspectHtml(un.html, final.host || '');
  extra.push(...insp.signals);
  return { local: first, final, chain: un.chain, rdap: r, dns, page: insp.page, extra };
}

export { registrableDomain };
