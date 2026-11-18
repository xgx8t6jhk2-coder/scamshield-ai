/*!
 * ScamShield AI — on-device scam detection engine
 * Runs identically in the browser, the browser extension and the Cloudflare edge.
 * No network calls, no dependencies: a message or link analysed here never leaves the device.
 *
 * analyzeUrl(url)        -> verdict for a single link
 * analyzeMessage(text)   -> verdict for an SMS / WhatsApp / email body (extracts and scores every link)
 * fingerprint(result)    -> privacy-safe campaign key (no message text, no personal data)
 */

export const ENGINE_VERSION = '1.0.0';

/* ------------------------------------------------------------------ */
/* 1. UAE trusted-entity registry                                      */
/* Each entry: official registrable domains + words scammers borrow.   */
/* ------------------------------------------------------------------ */
export const BRANDS = [
  { id: 'adpolice', en: 'Abu Dhabi Police', ar: 'شرطة أبوظبي', sector: 'police',
    domains: ['adpolice.gov.ae'], words: ['adpolice', 'abudhabipolice', 'ad-police', 'adp-'], arWords: ['شرطة أبوظبي', 'شرطة ابوظبي'] },
  { id: 'dubaipolice', en: 'Dubai Police', ar: 'شرطة دبي', sector: 'police',
    domains: ['dubaipolice.gov.ae'], words: ['dubaipolice', 'dxbpolice', 'dubai-police'], arWords: ['شرطة دبي'] },
  { id: 'moi', en: 'Ministry of Interior', ar: 'وزارة الداخلية', sector: 'government',
    domains: ['moi.gov.ae'], words: ['moi-uae', 'moiuae', 'moi-gov'], arWords: ['وزارة الداخلية'] },
  { id: 'uaepass', en: 'UAE PASS', ar: 'الهوية الرقمية', sector: 'government',
    domains: ['uaepass.ae'], words: ['uaepass', 'uae-pass'], arWords: ['الهوية الرقمية', 'يو اي اي باس'] },
  { id: 'icp', en: 'ICP (Identity & Citizenship)', ar: 'الهيئة الاتحادية للهوية والجنسية', sector: 'government',
    domains: ['icp.gov.ae'], words: ['icp-uae', 'icpuae', 'emiratesid', 'emirates-id', 'eida'], arWords: ['الهوية والجنسية', 'الهوية الإماراتية', 'بطاقة الهوية'] },
  { id: 'tamm', en: 'TAMM', ar: 'تم', sector: 'government',
    domains: ['tamm.abudhabi', 'abudhabi.ae'], words: ['tamm'], arWords: ['منصة تم'] },
  { id: 'uaegov', en: 'UAE Government portal', ar: 'البوابة الرسمية لحكومة الإمارات', sector: 'government',
    domains: ['u.ae', 'government.ae'], words: ['uaegov', 'gov-ae', 'govae'], arWords: [] },
  { id: 'rta', en: 'RTA Dubai', ar: 'هيئة الطرق والمواصلات', sector: 'transport',
    domains: ['rta.ae'], words: ['rta', 'rtadubai', 'rta-dubai'], arWords: ['هيئة الطرق', 'الطرق والمواصلات'] },
  { id: 'salik', en: 'Salik', ar: 'سالك', sector: 'transport',
    domains: ['salik.ae'], words: ['salik'], arWords: ['سالك'] },
  { id: 'darb', en: 'Darb (ITC Abu Dhabi)', ar: 'درب', sector: 'transport',
    domains: ['itc.gov.ae', 'darb.ae'], words: ['darb', 'itc-ad', 'itcabudhabi'], arWords: ['بوابة درب', 'درب'] },
  { id: 'emiratespost', en: 'Emirates Post', ar: 'بريد الإمارات', sector: 'delivery',
    domains: ['emiratespost.ae', 'epg.ae'], words: ['emiratespost', 'emirates-post', 'empost', 'epost-ae', 'uaepost'], arWords: ['بريد الإمارات', 'بريد الامارات'] },
  { id: 'aramex', en: 'Aramex', ar: 'أرامكس', sector: 'delivery',
    domains: ['aramex.com'], words: ['aramex', 'armex'], arWords: ['أرامكس', 'ارامكس'] },
  { id: 'dhl', en: 'DHL', ar: 'دي إتش إل', sector: 'delivery',
    domains: ['dhl.com', 'dhl.ae'], words: ['dhl'], arWords: [] },
  { id: 'fedex', en: 'FedEx', ar: 'فيديكس', sector: 'delivery',
    domains: ['fedex.com'], words: ['fedex'], arWords: [] },
  { id: 'etisalat', en: 'e& (Etisalat)', ar: 'اتصالات', sector: 'telecom',
    domains: ['etisalat.ae', 'eand.com', 'eand.ae'], words: ['etisalat', 'etisalt', 'eand-', 'etislat'], arWords: ['اتصالات'] },
  { id: 'du', en: 'du', ar: 'دو', sector: 'telecom', ambiguous: true,
    domains: ['du.ae'], words: ['du-uae', 'du-ae', 'duuae', 'du-telecom'], arWords: [] },
  { id: 'enbd', en: 'Emirates NBD', ar: 'الإمارات دبي الوطني', sector: 'bank',
    domains: ['emiratesnbd.com', 'emiratesnbd.ae'], words: ['emiratesnbd', 'enbd', 'emirates-nbd'], arWords: ['الإمارات دبي الوطني', 'الامارات دبي الوطني'] },
  { id: 'fab', en: 'First Abu Dhabi Bank', ar: 'بنك أبوظبي الأول', sector: 'bank',
    domains: ['bankfab.com', 'fab.ae'], words: ['bankfab', 'fab-bank', 'fabbank'], arWords: ['بنك أبوظبي الأول', 'بنك ابوظبي الاول'] },
  { id: 'adcb', en: 'ADCB', ar: 'بنك أبوظبي التجاري', sector: 'bank',
    domains: ['adcb.com'], words: ['adcb'], arWords: ['بنك أبوظبي التجاري', 'بنك ابوظبي التجاري'] },
  { id: 'adib', en: 'ADIB', ar: 'مصرف أبوظبي الإسلامي', sector: 'bank',
    domains: ['adib.ae'], words: ['adib'], arWords: ['مصرف أبوظبي الإسلامي', 'مصرف ابوظبي الاسلامي'] },
  { id: 'dib', en: 'Dubai Islamic Bank', ar: 'بنك دبي الإسلامي', sector: 'bank',
    domains: ['dib.ae'], words: ['dib-', 'dubaiislamic'], arWords: ['بنك دبي الإسلامي'] },
  { id: 'mashreq', en: 'Mashreq', ar: 'المشرق', sector: 'bank',
    domains: ['mashreq.com', 'mashreqbank.com'], words: ['mashreq'], arWords: ['بنك المشرق'] },
  { id: 'cbd', en: 'Commercial Bank of Dubai', ar: 'بنك دبي التجاري', sector: 'bank',
    domains: ['cbd.ae'], words: ['cbd-', 'cbdbank'], arWords: ['بنك دبي التجاري'] },
  { id: 'rakbank', en: 'RAKBANK', ar: 'راك بنك', sector: 'bank',
    domains: ['rakbank.ae'], words: ['rakbank'], arWords: ['راك بنك'] },
  { id: 'cbuae', en: 'Central Bank of the UAE', ar: 'مصرف الإمارات المركزي', sector: 'bank',
    domains: ['centralbank.ae'], words: ['centralbank', 'cbuae'], arWords: ['المصرف المركزي', 'مصرف الإمارات المركزي'] },
  { id: 'dewa', en: 'DEWA', ar: 'هيئة كهرباء ومياه دبي', sector: 'utility',
    domains: ['dewa.gov.ae'], words: ['dewa'], arWords: ['ديوا', 'كهرباء ومياه دبي'] },
  { id: 'addc', en: 'ADDC / TAQA', ar: 'أبوظبي للتوزيع', sector: 'utility',
    domains: ['addc.ae', 'taqa.com', 'aadc.ae'], words: ['addc', 'taqa'], arWords: ['شركة أبوظبي للتوزيع', 'طاقة'] },
  { id: 'sewa', en: 'SEWA', ar: 'هيئة كهرباء ومياه وغاز الشارقة', sector: 'utility',
    domains: ['sewa.gov.ae'], words: ['sewa'], arWords: [] },
  { id: 'adnoc', en: 'ADNOC', ar: 'أدنوك', sector: 'energy',
    domains: ['adnoc.ae', 'adnocdistribution.ae'], words: ['adnoc'], arWords: ['أدنوك', 'ادنوك'] },
  { id: 'emirates', en: 'Emirates airline', ar: 'طيران الإمارات', sector: 'travel',
    domains: ['emirates.com'], words: ['emirates-air', 'emiratesair', 'fly-emirates', 'flyemirates'], arWords: ['طيران الإمارات'] },
  { id: 'etihad', en: 'Etihad Airways', ar: 'الاتحاد للطيران', sector: 'travel',
    domains: ['etihad.com'], words: ['etihad'], arWords: ['الاتحاد للطيران'] },
  { id: 'mohre', en: 'MOHRE', ar: 'وزارة الموارد البشرية والتوطين', sector: 'government',
    domains: ['mohre.gov.ae'], words: ['mohre'], arWords: ['وزارة الموارد البشرية'] },
  { id: 'fta', en: 'Federal Tax Authority', ar: 'الهيئة الاتحادية للضرائب', sector: 'government',
    domains: ['tax.gov.ae'], words: ['fta-uae', 'uaetax', 'tax-refund'], arWords: ['الهيئة الاتحادية للضرائب', 'استرداد ضريبة'] },
  { id: 'gdrfa', en: 'GDRFA Dubai', ar: 'الإدارة العامة للإقامة', sector: 'government',
    domains: ['gdrfad.gov.ae'], words: ['gdrfa'], arWords: ['الإقامة وشؤون الأجانب'] },
  { id: 'noon', en: 'noon', ar: 'نون', sector: 'retail', ambiguous: true,
    domains: ['noon.com'], words: ['noon-'], arWords: [] },
  { id: 'amazon', en: 'Amazon', ar: 'أمازون', sector: 'retail',
    domains: ['amazon.ae', 'amazon.com', 'amazon.sa'], words: ['amazon', 'amaz0n'], arWords: ['أمازون', 'امازون'] },
  { id: 'careem', en: 'Careem', ar: 'كريم', sector: 'retail',
    domains: ['careem.com'], words: ['careem'], arWords: [] },
  { id: 'talabat', en: 'talabat', ar: 'طلبات', sector: 'retail',
    domains: ['talabat.com'], words: ['talabat'], arWords: [] },
  { id: 'apple', en: 'Apple', ar: 'آبل', sector: 'tech',
    domains: ['apple.com', 'icloud.com'], words: ['apple-id', 'appleid', 'icloud'], arWords: [] },
  { id: 'microsoft', en: 'Microsoft', ar: 'مايكروسوفت', sector: 'tech',
    domains: ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com', 'outlook.com'], words: ['microsoft', 'office365', 'outlook-'], arWords: [] },
  { id: 'google', en: 'Google', ar: 'جوجل', sector: 'tech',
    domains: ['google.com', 'google.ae', 'goo.gl', 'youtube.com', 'gmail.com'], words: ['google-', 'gmail-'], arWords: [] },
  { id: 'meta', en: 'Meta / WhatsApp / Instagram', ar: 'ميتا / واتساب / إنستغرام', sector: 'tech',
    domains: ['facebook.com', 'instagram.com', 'whatsapp.com', 'wa.me', 'meta.com', 'fb.com', 'whatsapp.net'], words: ['whatsapp', 'instagram', 'facebook', 'meta-support', 'meta-verify'], arWords: ['واتساب', 'انستغرام', 'فيسبوك'] },
  { id: 'paypal', en: 'PayPal', ar: 'باي بال', sector: 'payments',
    domains: ['paypal.com'], words: ['paypal', 'paypa1'], arWords: [] },
];

/* Domains we never flag (besides brand domains). */
const ALWAYS_TRUSTED = new Set([
  'ecrime.ae', 'aman.gov.ae', 'tdra.gov.ae', 'ded.ae', 'dubai.ae', 'sharjah.ae', 'mofa.gov.ae', 'mof.gov.ae',
  'wikipedia.org', 'github.com', 'linkedin.com', 'x.com', 'twitter.com', 'tiktok.com', 'snapchat.com',
  'bbc.com', 'thenationalnews.com', 'khaleejtimes.com', 'gulfnews.com', 'wam.ae', 'alkhaleej.ae', 'emaratalyoum.com',
]);

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'rb.gy', 'is.gd', 'ow.ly', 'shorturl.at', 'tiny.cc', 'rebrand.ly',
  'buff.ly', 'shorte.st', 'v.gd', 'qrco.de', 's.id', 'lnkd.in', 'bl.ink', 'short.io', 't.ly', 'tny.im', 'urlz.fr',
  'shrtco.de', 'gg.gg', 'u.to', 'clck.ru', 'surl.li', 'hyperurl.co', '2u.pm', 'linktr.ee',
]);

/* Free builders / hosting / tunnels — perfectly legal, but no bank or ministry hosts its login page there. */
const FREE_HOSTS = [
  'pages.dev', 'workers.dev', 'netlify.app', 'vercel.app', 'github.io', 'gitlab.io', 'firebaseapp.com', 'web.app',
  'weebly.com', 'wixsite.com', 'wix.com', 'glitch.me', 'repl.co', 'replit.app', '000webhostapp.com', 'blogspot.com',
  'sites.google.com', 'forms.gle', 'ngrok.io', 'ngrok-free.app', 'trycloudflare.com', 'herokuapp.com', 'onrender.com',
  'webflow.io', 'framer.app', 'myshopify.com', 'square.site', 'godaddysites.com', 'wordpress.com', 'carrd.co',
  'surge.sh', 'r2.dev', 'appspot.com', 'azurewebsites.net', 'web.core.windows.net', 'ipfs.io', 'dweb.link',
  'typedream.app', 'notion.site', 'telegra.ph', 'jimdosite.com', 'mystrikingly.com', 'yolasite.com', 'duckdns.org', 'serveo.net',
];

/* TLDs heavily abused for SMS phishing in the GCC (cheap / bulk registration). Not proof — a weight. */
const RISKY_TLDS = new Set([
  'top', 'xyz', 'icu', 'buzz', 'sbs', 'cfd', 'click', 'link', 'live', 'shop', 'online', 'site', 'vip', 'bond',
  'rest', 'monster', 'cyou', 'lol', 'today', 'support', 'help', 'win', 'loan', 'work', 'fit', 'gq', 'ml', 'cf', 'tk',
  'ga', 'cam', 'mom', 'quest', 'beauty', 'hair', 'skin', 'makeup', 'boats', 'yachts', 'autos', 'homes', 'motorcycles',
  'pics', 'zip', 'mov', 'cc', 'ws', 'su', 'pw', 'store', 'fun', 'space', 'website', 'info', 'club', 'asia', 'bar',
]);

/* Multi-part public suffixes we need to compute the registrable domain correctly. */
const MULTI_SUFFIXES = new Set([
  'gov.ae', 'ac.ae', 'co.ae', 'net.ae', 'org.ae', 'sch.ae', 'mil.ae', 'pro.ae', 'name.ae',
  'com.sa', 'gov.sa', 'net.sa', 'org.sa', 'edu.sa', 'com.qa', 'gov.qa', 'com.kw', 'com.bh', 'com.om', 'gov.om',
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'com.pk', 'com.eg', 'com.tr', 'co.in', 'com.cn', 'com.br',
  'co.za', 'com.ng', 'co.jp', 'com.hk', 'com.sg', 'com.my', 'co.id', 'com.ph', 'com.vn', 'com.ru', 'com.ua',
  ...FREE_HOSTS,
]);

/* Visual look-alike folding (Latin digits/ligatures + Cyrillic/Greek confusables). */
const CONFUSABLES = {
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g', '$': 's', '@': 'a', '!': 'i', '|': 'l',
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ԁ': 'd', 'ӏ': 'l', 'ѕ': 's',
  'ο': 'o', 'α': 'a', 'ν': 'v', 'ρ': 'p', 'τ': 't', 'ι': 'i', 'κ': 'k', 'μ': 'm', 'η': 'n',
};

/* ------------------------------------------------------------------ */
/* 2. Helpers                                                          */
/* ------------------------------------------------------------------ */
function foldConfusables(s) {
  let out = '';
  for (const ch of s.toLowerCase()) out += CONFUSABLES[ch] ?? ch;
  return out.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/cl/g, 'd');
}

function levenshtein(a, b) {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > 3) return 99;
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0];
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j];
      prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = tmp;
    }
  }
  return prev[b.length];
}

/** Decode punycode (RFC 3492) so we can show the real characters of an xn-- label. */
function punyDecode(input) {
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  let n = 128, i = 0, bias = 72;
  const out = [];
  let basic = input.lastIndexOf('-');
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; j++) out.push(input.charCodeAt(j));
  const adapt = (delta, numPoints, first) => {
    delta = first ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((base - tMin) * tMax) >> 1) { delta = Math.floor(delta / (base - tMin)); k += base; }
    return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
  };
  for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
    const oldi = i;
    for (let w = 1, k = base; ; k += base) {
      if (idx >= input.length) return null;
      const c = input.charCodeAt(idx++);
      const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
      if (digit >= base) return null;
      i += digit * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (digit < t) break;
      w *= base - t;
    }
    bias = adapt(i - oldi, out.length + 1, oldi === 0);
    n += Math.floor(i / (out.length + 1));
    i %= out.length + 1;
    out.splice(i++, 0, n);
  }
  try { return String.fromCodePoint(...out); } catch { return null; }
}

export function registrableDomain(host) {
  const parts = host.toLowerCase().replace(/\.$/, '').split('.');
  for (let take = Math.min(parts.length, 4); take >= 2; take--) {
    const suffix = parts.slice(parts.length - take + 1).join('.');
    if (take >= 3 && MULTI_SUFFIXES.has(suffix)) return parts.slice(parts.length - take).join('.');
  }
  return parts.slice(-2).join('.');
}

function hostMatches(host, domain) {
  return host === domain || host.endsWith('.' + domain);
}

function brandForHost(host) {
  for (const b of BRANDS) if (b.domains.some((d) => hostMatches(host, d))) return b;
  return null;
}

function isIp(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[') || /^0x[0-9a-f]+$/i.test(host) || /^\d{8,10}$/.test(host);
}

const clamp = (n, lo, hi) => Math.max(lo, Math.min(hi, n));

/** Normalise free text into something URL() accepts. */
export function normaliseUrl(raw) {
  let s = String(raw || '').trim().replace(/[​-‏‪-‮⁦-⁩]/g, '');
  s = s.replace(/^[<("'\[]+|[>)"'\],.;!؟،]+$/g, '');
  s = s.replace(/hxxps?/i, (m) => m.toLowerCase().replace('hxxp', 'http')).replace(/\[\.\]|\(\.\)|\{\.\}/g, '.');
  if (!/^[a-z][a-z0-9+.-]*:/i.test(s)) s = 'http://' + s;
  return s;
}

/* ------------------------------------------------------------------ */
/* 3. Link analysis                                                    */
/* ------------------------------------------------------------------ */
function sig(id, weight, en, ar, severity) {
  return { id, weight, en, ar, severity: severity || (weight >= 35 ? 'high' : weight >= 15 ? 'medium' : weight > 0 ? 'low' : 'good') };
}

export function analyzeUrl(rawUrl) {
  const signals = [];
  const input = String(rawUrl || '').trim();
  let url;
  try { url = new URL(normaliseUrl(input)); } catch {
    return finalise({ kind: 'url', input, signals: [sig('unparseable', 20, 'This does not look like a valid web address.', 'هذا لا يبدو عنواناً إلكترونياً صالحاً.')] });
  }

  const scheme = url.protocol.replace(':', '');
  if (scheme === 'javascript' || scheme === 'data' || scheme === 'vbscript') {
    signals.push(sig('script_uri', 80, 'The link runs code instead of opening a page.', 'الرابط يشغّل شيفرة بدلاً من فتح صفحة.'));
    return finalise({ kind: 'url', input, url: input, signals });
  }
  if (scheme === 'tel' || scheme === 'sms' || scheme === 'mailto') {
    return finalise({ kind: 'url', input, url: input, signals: [sig('contact_link', 5, 'This link opens a call, SMS or email — check who it goes to.', 'الرابط يفتح اتصالاً أو رسالة — تأكد من الجهة.')] });
  }

  let host = url.hostname.toLowerCase().replace(/\.$/, '');
  const displayHost = host.split('.').map((l) => (l.startsWith('xn--') ? punyDecode(l.slice(4)) || l : l)).join('.');
  const reg = registrableDomain(host);
  const regLabel = reg.split('.')[0];
  const tld = host.split('.').pop();
  let path = (url.pathname + url.search).toLowerCase();
  try { path = decodeURIComponent(path); } catch { /* malformed escape — keep raw */ }
  path = path.slice(0, 600);
  const trustedBrand = brandForHost(host);

  const result = { kind: 'url', input, url: url.href, host, displayHost, registrable: reg, tld, brand: null, impersonates: null };

  /* ---- trusted domains short-circuit ---- */
  if (trustedBrand) {
    result.brand = trustedBrand.id;
    signals.push(sig('official_domain', -70, `Official ${trustedBrand.en} domain.`, `نطاق رسمي لـ ${trustedBrand.ar}.`, 'good'));
    if (scheme !== 'https') signals.push(sig('no_https', 10, 'Official site, but the link is not encrypted (http).', 'موقع رسمي لكن الرابط غير مشفّر (http).'));
    if (url.username || url.password) signals.push(sig('userinfo', 45, 'Hidden text before “@” hides the real destination.', 'نص مخفي قبل “@” يخفي الوجهة الحقيقية.'));
    return finalise({ ...result, signals });
  }
  if (ALWAYS_TRUSTED.has(reg) || reg.endsWith('.gov.ae')) {
    signals.push(sig('trusted_domain', -50, 'Known legitimate domain.', 'نطاق معروف وموثوق.', 'good'));
    return finalise({ ...result, signals });
  }

  /* ---- structural tricks ---- */
  if (isIp(host)) signals.push(sig('ip_host', 35, 'Uses a raw IP address instead of a name — real organisations never do this.', 'يستخدم رقم IP بدلاً من اسم — الجهات الرسمية لا تفعل ذلك.'));
  if (url.username || url.password || /@/.test(input.split('/')[2] || ''))
    signals.push(sig('userinfo', 45, 'Text before “@” disguises where the link really goes.', 'النص قبل “@” يخفي وجهة الرابط الحقيقية.'));
  if (host.includes('xn--')) {
    const mixed = /[a-z]/.test(displayHost) && /[^\x00-\x7F]/.test(displayHost);
    signals.push(sig('punycode', mixed ? 45 : 25, `Uses look-alike international characters (shows as “${displayHost}”).`, `يستخدم حروفاً دولية مشابهة (يظهر كـ “${displayHost}”).`));
  }
  if (url.port && !['80', '443'].includes(url.port)) signals.push(sig('odd_port', 15, `Connects on unusual port ${url.port}.`, `يتصل عبر منفذ غير معتاد ${url.port}.`));
  if (scheme === 'http') signals.push(sig('no_https', 8, 'Not encrypted (http) — anything you type can be read.', 'غير مشفّر (http) — يمكن قراءة ما تكتبه.'));
  const subCount = host.split('.').length - reg.split('.').length;
  if (subCount >= 3) signals.push(sig('deep_subdomain', 15, `${subCount} stacked sub-domains — a trick to push the real domain out of view.`, `${subCount} نطاقات فرعية متراكمة — حيلة لإخفاء النطاق الحقيقي.`));
  if (host.length > 45) signals.push(sig('long_host', 8, 'Unusually long address.', 'عنوان طويل بشكل غير معتاد.'));
  const hyphens = (regLabel.match(/-/g) || []).length;
  if (hyphens >= 2) signals.push(sig('many_hyphens', 10, 'Domain made of hyphenated words (e.g. “pay-fine-uae”).', 'نطاق مكوّن من كلمات بشرطات (مثل “pay-fine-uae”).'));
  if (/\d{4,}/.test(regLabel)) signals.push(sig('digit_run', 8, 'Random-looking numbers in the domain name.', 'أرقام عشوائية في اسم النطاق.'));
  if (RISKY_TLDS.has(tld)) signals.push(sig('risky_tld', 15, `“.${tld}” is a cheap ending heavily used in UAE SMS scams.`, `النطاق “.${tld}” رخيص ويُستخدم كثيراً في رسائل الاحتيال.`));
  if (SHORTENERS.has(reg) || SHORTENERS.has(host)) {
    result.shortener = true;
    signals.push(sig('shortener', 14, 'Shortened link hides the final destination.', 'رابط مختصر يخفي الوجهة النهائية.'));
  }
  const freeHost = FREE_HOSTS.find((f) => hostMatches(host, f));
  if (freeHost) { result.freeHost = freeHost; signals.push(sig('free_host', 12, `Hosted on a free website builder (${freeHost}).`, `مستضاف على منصة مواقع مجانية (${freeHost}).`)); }
  if (/(^|[.-])(gov|govt|government)([.-]|$)/.test(host) && !reg.endsWith('.gov.ae')) {
    signals.push(sig('fake_gov', 45, 'Pretends to be a government site, but it is not on .gov.ae.', 'يدّعي أنه موقع حكومي لكنه ليس على .gov.ae.'));
  }
  if (/(^|[.-])ae([.-])/.test(host.replace(/\.ae$/, '')) && !host.endsWith('.ae')) {
    signals.push(sig('fake_ae', 20, '“ae” is placed in the name to look Emirati, but the site is not a .ae domain.', 'تمت إضافة “ae” لتبدو إماراتية لكن النطاق ليس ‎.ae.'));
  }

  /* ---- brand impersonation ---- */
  const folded = foldConfusables(displayHost);
  const hostWords = folded.replace(/\.[^.]+$/, '');
  const pathWords = foldConfusables(path);
  let best = null;
  for (const b of BRANDS) {
    let hit = null;
    for (const w of b.words) {
      const ww = w.replace(/-$/, '');
      if (ww.length < 3) continue;
      if (hostWords.includes(ww)) { hit = { how: 'name', score: 50 }; break; }
    }
    if (!hit) {
      for (const d of b.domains) {
        const label = d.split('.')[0];
        if (label.length < 4) continue;
        const parts = hostWords.split(/[.-]/);
        for (const p of parts) {
          if (p.length < 4) continue;
          const dist = levenshtein(p, label);
          if (dist > 0 && dist <= (label.length >= 8 ? 2 : 1)) { hit = { how: 'typo', score: 55, part: p, label }; break; }
        }
        if (hit) break;
      }
    }
    if (!hit && b.words.some((w) => w.replace(/-$/, '').length >= 4 && pathWords.includes(w.replace(/-$/, '')))) hit = { how: 'path', score: 30 };
    if (hit && (!best || hit.score > best.hit.score)) best = { b, hit };
  }
  if (best) {
    result.impersonates = best.b.id;
    const { b, hit } = best;
    if (hit.how === 'typo')
      signals.push(sig('lookalike', hit.score, `Look-alike of ${b.en}: “${hit.part}” vs the real “${hit.label}”.`, `اسم مشابه لـ ${b.ar}: “${hit.part}” بدلاً من “${hit.label}”.`));
    else if (hit.how === 'name')
      signals.push(sig('brand_in_domain', hit.score, `Uses the name “${b.en}” but is NOT an official ${b.en} domain (official: ${b.domains[0]}).`, `يستخدم اسم “${b.ar}” لكنه ليس نطاقاً رسمياً (الرسمي: ${b.domains[0]}).`));
    else
      signals.push(sig('brand_in_path', hit.score, `Mentions ${b.en} in the link path on an unrelated site.`, `يذكر ${b.ar} داخل مسار الرابط على موقع غير تابع لها.`));
    if (freeHost) signals.push(sig('brand_on_free_host', 25, `${b.en} would never host a page on ${freeHost}.`, `${b.ar} لا تستضيف صفحاتها على ${freeHost}.`));
  }

  /* ---- intent words in the path ---- */
  const intents = [
    ['pay', 'دفع'], ['fine', 'مخالفة'], ['violation', 'مخالفة'], ['verify', 'تحقق'], ['login', 'دخول'], ['signin', 'دخول'],
    ['update', 'تحديث'], ['otp', 'رمز'], ['card', 'بطاقة'], ['refund', 'استرداد'], ['parcel', 'طرد'], ['delivery', 'توصيل'],
    ['track', 'تتبع'], ['customs', 'جمارك'], ['unlock', 'فتح'], ['suspend', 'إيقاف'], ['reward', 'مكافأة'], ['claim', 'مطالبة'],
    ['wallet', 'محفظة'], ['kyc', 'تحديث بيانات'], ['secure', 'آمن'], ['account', 'حساب'], ['billing', 'فاتورة'],
    ['shipment', 'شحنة'], ['confirm', 'تأكيد'], ['استرداد', 'استرداد'], ['تحقق', 'تحقق'], ['دفع', 'دفع'],
  ];
  if (/hxxp|\[\.\]|\(\.\)/i.test(input)) signals.push(sig('defanged', 0, 'This link was written “defanged” (hxxp / [.]) — someone already flagged it as dangerous.', 'كُتب هذا الرابط بصيغة معطّلة (hxxp / [.]) — أي أن أحداً صنّفه خطيراً.', 'low'));
  const hits = intents.filter(([w]) => path.includes(w) || hostWords.includes(w));
  if (hits.length) {
    const w = Math.min(6 * hits.length, 20);
    signals.push(sig('intent_words', w, `Action words scammers use: ${hits.slice(0, 4).map((h) => h[0]).join(', ')}.`, `كلمات يستخدمها المحتالون: ${hits.slice(0, 4).map((h) => h[1]).join('، ')}.`));
  }
  if (/\.(apk|exe|scr|msi|bat|cmd|js|vbs|iso|dmg|zip|rar|7z)(\?|$)/.test(url.pathname.toLowerCase()))
    signals.push(sig('download', 40, 'Downloads an app or file directly — a common way to install banking malware.', 'يحمّل تطبيقاً أو ملفاً مباشرة — طريقة شائعة لتثبيت برامج خبيثة.'));
  const nested = (url.search.match(/(?:redirect|url|next|goto|target|dest|continue|return)[^=]*=(https?(?::|%3a)[^&]+)/i) || [])[1];
  if (nested) {
    let nestedHost = '';
    try { nestedHost = new URL(decodeURIComponent(nested)).hostname; } catch {}
    if (nestedHost && registrableDomain(nestedHost) !== reg) {
      const inner = analyzeUrl(decodeURIComponent(nested));
      signals.push(sig('open_redirect', 16 + Math.round(inner.score / 5), `Bounces through this site to ${nestedHost}.`, `يمر عبر هذا الموقع إلى ${nestedHost}.`));
    }
  }

  return finalise({ ...result, signals });
}

/* ------------------------------------------------------------------ */
/* 4. Message analysis (SMS / WhatsApp / email) — Arabic + English     */
/* ------------------------------------------------------------------ */
export const SCAM_PLAYBOOKS = [
  { id: 'fake_fine', en: 'Fake traffic fine / toll', ar: 'مخالفة مرورية أو رسوم طريق مزيفة', weight: 30,
    re: [/violation notice|e-?fine|outstanding (fine|toll|balance|amount)|toll (due|payment|account)|penalt(y|ies)|impound|(number )?plate (blocked|suspended)|vehicle (registration|file) (suspend|block)|mulkiya|traffic (fine|violation)|unpaid (fine|toll)|salik|parking (fine|violation)|toll (balance|charge)|vehicle (has|is) .*?(fine|blocked)|black ?point/i,
      /مخالفات|غرامات|المبلغ المستحق|رسوم مستحقة|حجز المركبة|اللوحة|تسجيل المركبة|الملكية|مخالف[ةه]|غرام[ةه]|سالك|درب|رسوم (الطريق|التعرفة)|نقاط سوداء|حجز (المركبة|السيارة)/] },
  { id: 'parcel', en: 'Fake parcel / delivery fee', ar: 'شحنة أو رسوم توصيل مزيفة', weight: 28,
    re: [/courier|dispatch|on hold|held at|custom(s)? clearance|reschedule (your )?delivery|delivery slot|parcel|package|shipment|delivery (attempt|failed|fee)|could not be delivered|redeliver|customs (fee|duty|charge)|incomplete address|warehouse/i,
      /المندوب|التخليص الجمركي|إعادة جدولة|موعد التوصيل|محجوزة|شحن[ةهت]|طرد|الطرد|طلبيت|توصيل|التوصيل|العنوان غير (مكتمل|صحيح)|(عدم )?اكتمال العنوان|تحديث العنوان|رسوم (الجمارك|الشحن|التوصيل)|إعادة (التسليم|الإرسال)|المستودع/] },
  { id: 'bank_block', en: 'Bank / card “blocked” alert', ar: 'تنبيه إيقاف حساب أو بطاقة', weight: 30,
    re: [/(account|card) (has been |is |will be )?(blocked|suspended|locked|deactivated|frozen|restricted)|update (your )?(kyc|details|emirates id)|reactivate|unusual (activity|sign.?in)/i,
      /(حسابك|بطاقتك|الحساب|البطاقة) (تم )?(إيقاف|ايقاف|تجميد|حظر|تعليق|موقوف|مجمد)|تحديث (البيانات|بياناتك|الهوية)|إعادة تفعيل|نشاط غير (معتاد|اعتيادي)/] },
  { id: 'prize', en: 'Prize / lottery / gift', ar: 'جائزة أو سحب أو هدية', weight: 28,
    re: [/you (have )?(won|been selected)|winner|lucky draw|prize|reward points? (expire|redeem)|gift card|congratulations!?.{0,40}(won|selected|reward)|free iphone|cashback of/i,
      /(ربحت|فزت|مبروك|تهانينا).{0,40}(جائزة|سحب|مبلغ|هدية)|السحب (الكبير|الشهري)|نقاط.{0,15}(ستنتهي|تنتهي)|استبدال النقاط|جائزة نقدية/] },
  { id: 'job', en: 'Task / part-time job scam', ar: 'وظيفة أو مهام بأرباح يومية', weight: 30,
    re: [/recruit(er|ing|ment)|hiring|vacanc(y|ies)|commission|per task|rating tasks|review (hotels|products|apps)|onboarding|earn (daily|weekly|extra)|work from (home|your phone)|job offer|part.?time (job|work)|earn (aed|dhs?|\$|usd)? ?\d+.{0,20}(per|a|\/) ?(day|hour)|daily (income|salary|commission)|like (videos|posts)|simple tasks?|work from home.{0,30}(aed|dhs|earn)|hr manager.{0,30}(whatsapp|telegram)/i,
      /توظيف|مطلوب موظفين|عرض عمل|عمولة|مهام|تقييم (الفنادق|المنتجات)|دخل إضافي|اربح|(وظيفة|عمل) (بدوام جزئي|من المنزل)|(دخل|ربح|راتب) يومي|أرباح يومية|مهام بسيطة|الإعجاب (بالفيديوهات|بالمنشورات)|عمولة يومية/] },
  { id: 'investment', en: 'Investment / crypto “guaranteed profit”', ar: 'استثمار أو عملات رقمية بأرباح مضمونة', weight: 32,
    re: [/guaranteed (profit|return)|double your (money|investment)|\d{2,3}% (profit|return).{0,15}(daily|weekly|monthly)|crypto (trading|signals|mining) (group|platform)|forex signals|risk.?free investment|recover (your )?(lost|scammed) (funds|money)/i,
      /أرباح مضمونة|عائد مضمون|ضاعف (أموالك|استثمارك)|بدون مخاطر|تداول (العملات|الكريبتو)|استرداد (الأموال|أموالك) المسروقة|منصة استثمار/] },
  { id: 'police_impersonation', en: 'Fake police / legal threat', ar: 'تهديد باسم الشرطة أو القضاء', weight: 38,
    re: [/(arrest|warrant|case|court|criminal|money laundering|travel ban).{0,40}(against you|your name|filed|registered|pending)|police (case|report) (against|on) you|(pay|settle).{0,20}(to avoid|or face).{0,20}(arrest|legal)/i,
      /(قضية|بلاغ|مذكرة (اعتقال|قبض)|منع سفر|غسيل أموال|أمر قبض).{0,40}(ضدك|باسمك|بحقك|مسجل)|سيتم (القبض|اتخاذ الإجراءات القانونية)|ادفع.{0,20}(لتجنب|قبل).{0,20}(القبض|الإجراءات)/] },
  { id: 'id_expiry', en: 'Emirates ID / UAE PASS / visa “expired”', ar: 'انتهاء الهوية أو التأشيرة أو الهوية الرقمية', weight: 26,
    re: [/uae ?pass|digital identity|re-?verif(y|ication)|biometric|face (verification|scan)|visa (status|renewal)|emirates id (renewal|update)|emirates id.{0,30}(expired|expire|update|blocked|suspend)|uae ?pass.{0,30}(suspend|expire|verify|update|deactivat)|visa.{0,25}(cancel|expire|overstay).{0,40}(click|pay|link)/i,
      /الهوية الرقمية|يو ?ايه ?اي ?باس|تجديد الهوية|التحقق من الوجه|البصمة|(الهوية|بطاقة الهوية|الإقامة|التأشيرة).{0,30}(منتهية|انتهت|ستنتهي|موقوفة|إيقاف|تحديث|إلغاء)/] },
  { id: 'utility', en: 'Utility disconnection / refund', ar: 'قطع خدمة أو استرداد فاتورة', weight: 24,
    re: [/meter (reading|crew|technician)|reconnect(ion)?|overcharg|bill (adjust|correction)|(electricity|water|dewa|addc|sewa|internet|line).{0,30}(disconnect|cut off|suspend|overpaid|refund)|bill (refund|overpayment)/i,
      /العداد|إعادة (ربط|الربط) (الحساب|العداد|الخدمة)|فصل الخدمة|(الكهرباء|المياه|الماء|الإنترنت|الخط).{0,30}(قطع|فصل|إيقاف|استرداد)|استرداد (مبلغ|الفاتورة|رسوم)/] },
  { id: 'family_emergency', en: '“Hi Mum/Dad, new number” emergency', ar: 'رسالة “رقمي الجديد” وطلب مال عاجل', weight: 30, needsAction: true,
    re: [/(new number|lost my (phone|mobile)|broke my (phone|mobile)|(phone|mobile) (is )?(broken|dead|died)|mobile e5t|use this (chat|number)|don.?t call (my )?old number)/i,
      /رقمي الجديد|ضاع (تلفوني|هاتفي|جوالي)|انكسر (تلفوني|هاتفي|جوالي)|(تلفوني|جوالي|هاتفي) (طفى|خرب|انكسر)|لا تتصل على (رقمي|الرقم) القديم/] },
  { id: 'romance_sextortion', en: 'Blackmail / sextortion', ar: 'ابتزاز', weight: 34,
    re: [/(video|photos?|pictures?|pics?|clips?|screenshots?|recording|chat) (of|with|mn|from) (you|u|call|our)|i (will|'ll) (share|publish|leak|send|post|forward)|(leak|publish|expose|post) (the |your |it |them |this )?(video|photos?|pics?|clips?|chats?)/i,
      /(سأنشر|راح انشر|بنشر|سأرسل|بفضحك|بفضحك|بنزلها|بنزله|بنشرها)|(الصور|الفيديو|المقطع|صورك|الملف).{0,40}(قروب|أهلك|عائلتك|الدوام|بمسحه|بحذفه)|ba7ot|bansher|bafda7/i] },
  { id: 'charity', en: 'Fake charity / donation', ar: 'تبرع أو جمع أموال وهمي', weight: 18, needsAction: true,
    re: [/donat(e|ion)|charity|orphans?|zakat|relief (box|fund|campaign)|sadaqa/i,
      /تبرع|التبرع|صدقة|زكاة|اليتيم|الأيتام|جمعية خيرية|حساب الجمعية/] },
];

/* Manipulation tactics: HOW the scammer operates, independent of the story.
 * These catch call-centre and chat scams that contain no link at all. */
export const TACTICS = [
  { id: 'credential_request', weight: 40, en: 'Asks you to give a code, PIN, password or bank SMS number — no real organisation ever does.', ar: 'يطلب منك رمزاً أو رقماً سرياً أو كلمة مرور أو رقم رسالة البنك — لا تفعل ذلك أي جهة حقيقية.',
    re: [/(send|share|tell|give|provide|reply with|read( me)?|forward|need|needs|requires?|confirm|type|enter|say).{0,40}\b(otp|one.?time|code|pin|cvv|cvc|password|passcode|six (numbers|digits)|6.?digit|number (on|in|from) (the|your) (bank )?(sms|text|message)|banking code|card (number|details))/i,
      /(أرسل|ارسل|شارك|زودنا|زوّدنا|أعطني|اعطني|أعط|اعط|ابعث|أخبرنا|قول لي|قل لي|اقرأ|اقرا|يحتاج|نحتاج).{0,30}(الرمز|رمز|الكود|كود|الرقم السري|كلمة (السر|المرور)|cvv|otp|الأرقام اللي|رقم البطاقة|بيانات البطاقة)/i],
    negate: [/(never|do not|don.?t|won.?t|will not|not) (ever )?(send|share|give|tell|disclose|forward|ask)/i, /(لا|لن|ما) ?(ترسل|تشارك|تعطي|تعط|تخبر|نطلب|يطلب)/] },
  { id: 'approval_coercion', weight: 40, en: 'Pushes you to approve a UAE PASS / banking notification or pick a number for someone else.', ar: 'يضغط عليك للموافقة على إشعار الهوية الرقمية أو البنك أو اختيار رقم لشخص آخر.',
    re: [/(approve|accept|confirm|tap yes|press yes|choose|select|pick).{0,40}(notification|request|push|prompt|number i (say|tell)|the number)/i, /push (is )?(coming|jay|جاي)/i,
      /(وافق|وافقي|اقبل|اختار|اختر|اضغط موافق).{0,30}(الإشعار|الاشعار|الطلب|طلب التحويل|الرقم)/] },
  { id: 'payment_diversion', weight: 30, en: 'Wants money sent to a person, courier, “holding account” or private wallet instead of the official channel.', ar: 'يريد تحويل المال إلى شخص أو مندوب أو “حساب أمانات” أو محفظة خاصة بدلاً من القناة الرسمية.',
    re: [/(pay|send|transfer|move|settle|deposit|wire|7awel|7awl).{0,60}(personal|private|my (own )?account|the courier|technician|recruiter|coordinator|agent|holding (account|iban)|safe account|secure (holding )?account|wallet|this person|on my behalf|landlord|usdt|crypto)/i,
      /(حول|حوّل|حولي|سدد|ادفع|أرسل|ارسل|ودّي|ودي).{0,40}(لهالشخص|لهذا الشخص|رقم حسابي|حسابي|حساب المنسق|الفني|المندوب|المحفظة|محفظة|بدل عني|عنوان المحفظة|حساب آمن|حساب الأمانات)|(حساب|محفظة) (شخصي|شخصية|خاص|المدير|المنسق)/] },
  { id: 'secrecy', weight: 20, en: 'Tells you to keep it secret or lie to your bank — a hallmark of fraud.', ar: 'يطلب منك الكتمان أو الكذب على البنك — علامة احتيال واضحة.',
    re: [/(don.?t|do not|dont) (tell|inform|call|contact) (anyone|anybody|the bank|your bank|family|the police|old number)|keep (this|it) (between us|secret|confidential)|tell the (teller|bank) (it is|it's) for/i,
      /(لا|ولا) (تخبر|تقول|تعلم|تكلم|تتصل)( ب| على| ل)?.{0,10}(حد|أحد|احد|البنك|أهلك)|خلها بيننا|سرية تامة|ma (t9ar7|tkhabber)|ma klmt/i] },
  { id: 'document_harvest', weight: 30, en: 'Asks for photos of your Emirates ID, passport or a selfie over chat.', ar: 'يطلب صور الهوية أو الجواز أو سيلفي عبر المحادثة.',
    re: [/(send|text|share|upload|whatsapp|dm).{0,40}(both sides|passport|selfie|front and back|emirates id (copy|photo)|id copy|car registration|mulkiya)/i,
      /(صورة|صور) (الهوية|جوازك|الجواز|الملكية)|من الجهتين|سيلفي|أرسلها على الخاص/] },
  { id: 'upfront_fee', weight: 28, en: 'Demands a fee or deposit to release a job, prize, parcel or your own money.', ar: 'يطلب رسوماً أو إيداعاً لإطلاق وظيفة أو جائزة أو شحنة أو أموالك.',
    re: [/(uniform|training|visa|processing|release|clearance|unlock|withdraw(al)?|activation|registration) (deposit|fee|bond|tax|charge)|pay (a |the )?(deposit|fee|tax) (to|before|for) (release|unlock|withdraw|get|receive|the recruiter)|top.?up (to|before) (withdraw|unlock)/i,
      /(رسوم|ضريبة|إيداع|ايداع|عربون) (الفحص|التحرير|السحب|الإفراج|التفعيل|التسجيل|العقد)|قبل أن يرفع عقدك|لازم تدفع.{0,20}(قبل|عشان) (السحب|تستلم)/] },
  { id: 'authority_call', weight: 12, en: 'Someone claims official authority in a chat or call.', ar: 'شخص يدّعي صفة رسمية في محادثة أو مكالمة.',
    re: [/(i.?m|i am|this is|we are|calling from|here from).{0,25}(police|shurta|bank|inspector|cyber|crossing office|registry|support|ministry|immigration|court|customs|loyalty team)/i,
      /(معك|معاك|نحن|أنا من|انا من|يكلمك).{0,15}(شرطة|الشرطة|البنك|الدعم الفني|المحكمة|الجمارك|النيابة|الإقامة)|shurta/i] },
];
const ACTION = [/\b(pay|send|transfer|deposit|settle|wire|redeem|reply|call|contact|whatsapp|dm|click|tap|open|verify|update|confirm|7awel)\b/i, /(ادفع|حول|حوّل|سدد|أرسل|ارسل|اضغط|افتح|حدّث|حدث|تواصل|اتصل|رد|أكد|استبدل)/];

const PRESSURE = [
  /within (\d+|twenty.?four|24|48) ?(hours?|hrs|minutes?|mins)|immediately|urgent(ly)?|final (notice|warning|reminder)|last (chance|day|warning)|today only|expires? (today|soon|tonight)|act now|avoid (penalt|legal|suspension|cancellation)/i,
  /خلال (\d+|٢٤|٤٨|24|48) ?(ساعة|ساعات|دقيقة|دقائق)|فوراً|فورا|عاجل|إنذار نهائي|اخر (فرصة|تنبيه|إنذار)|آخر (فرصة|تنبيه|إنذار)|اليوم فقط|لتجنب (الغرامة|الإيقاف|الإجراءات)|قبل (فوات الأوان|إلغاء)/,
];
const SMALL_FEE = [/(aed|dhs?|dirhams?|usd|\$)\s?([0-9]{1,2}(\.[0-9]{1,2})?)\b(?!\s?(million|k|,|\d))/i, /([0-9]{1,2}([.,][0-9]{1,2})?)\s?(درهم|د\.إ|دراهم)/];
const ASKS_TO_CLICK = [/(click|tap|visit|open|press|follow) (the |this |on |below )?(link|here|url)|(pay|confirm|update|verify).{0,20}(here|via|at|link|below)/i, /(اضغط|اضغطي|انقر|ادخل|افتح|زر|قم بزيارة).{0,15}(الرابط|هنا|على)|عبر الرابط|من خلال الرابط/];
const MOVE_CHANNEL = [/(contact|message|add|chat with) (me|us|our (agent|manager|hr)).{0,20}(on )?(whatsapp|telegram|signal)|t\.me\/|wa\.me\//i, /(تواصل|راسل|أضف|اضف).{0,20}(واتساب|تيليجرام|تلغرام)/];
const OFFICIAL_SENDERS = /^(AD ?POLICE|ADPOLICE|DUBAIPOLICE|DXBPOLICE|MOI|RTA|SALIK|DARB|ITC|ETISALAT|E&|DU|EMIRATESNBD|ENBD|FAB|ADCB|ADIB|DIB|MASHREQ|DEWA|ADDC|TAQA|SEWA|EMIRATESPOST|EMPOST|ARAMEX|ICP|UAEPASS|TAMM)$/i;

const URL_RE = /((?:https?|hxxps?):\/\/[^\s<>"'،]+|(?:www\.)[^\s<>"'،]+|\b[a-z0-9][a-z0-9-]{0,62}(?:\[?\.\]?[a-z0-9-]{1,63})*\[?\.\]?(?:com|net|org|info|top|xyz|icu|buzz|sbs|cfd|click|link|live|shop|online|site|vip|bond|rest|cyou|lol|today|support|help|win|cc|ae|me|io|co|ly|gl|to|app|dev|ws|pw|store|fun|space|club|asia|cam|mom|quest|gd|at|ru|cn|tk|ml|ga|cf|gq|sa|qa|in|pk|uk|us|biz|world|life|pro|pics|zip|mov)\b(?:\/[^\s<>"'،]*)?)/gi;
const PHONE_RE = /(?:\+|00)\d{1,3}[\s-]?\d{2,4}[\s-]?\d{3,4}[\s-]?\d{3,4}|\b05\d[\s-]?\d{3}[\s-]?\d{4}\b|\b800\s?\d{3,6}\b/g;

export function extractUrls(text) {
  const seen = new Set();
  const out = [];
  for (const m of String(text).matchAll(URL_RE)) {
    let u = m[0].replace(/[).,;!؟،]+$/, '');
    if (/^\d+(\.\d+)*$/.test(u) || /@/.test(u.split('/')[0] || '') && !/^https?:/i.test(u)) continue;
    const key = u.toLowerCase();
    if (!seen.has(key)) { seen.add(key); out.push(u); }
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* Arabizi (Gulf chat Arabic in Latin letters + digits) → Arabic hints  */
/* “7awel el floos 3al 7sab” becomes “حول فلوس حساب” so the Arabic      */
/* rules can read it. Lexicon-based: robust to spelling variants.      */
/* ------------------------------------------------------------------ */
const ARABIZI = [
  [/^(7a?ww?e?l|7aw[ei]l|7wl|7awlo|7awli|ta7wee?l|t7wee?l)/, 'حول'], [/^(e?d?fa3|idfa3|edf3|dfa3|ndfa3|tdfa3|sadded|sadid|sdd)/, 'ادفع'],
  [/^(fl[ou]{1,2}s|floo?s|flus|mablagh|mbl[ae]gh)/, 'فلوس مبلغ'], [/^(7s[ae]?b|7esab|7isab|7sabk|7sabak)/, 'حساب'],
  [/^(shu?rt[ae]|sh[ou]rta|shurtah|police)/, 'شرطة'], [/^(mo?5al?af[ae]|mkhalf[ae]|mukhalaf[ae]|mo5alfa)/, 'مخالفة'], [/^(gh?ra?ma|gharama|8rama)/, 'غرامة'],
  [/^(sh?u?7n[ae]|sha7na|shu7na|shiipment)/, 'شحنة'], [/^(tard|6ard)$/, 'طرد'], [/^(ramz|rmz|kood|kod|code)$/, 'الرمز'], [/^(otp)$/, 'رمز التحقق'],
  [/^(3a?j[ie]l|3ajlan|3jl|bsor3a|bsr3a)/, 'عاجل'], [/^(t5a?b(b)?er|tkhabbe?r|t9a?ra7|tgool|tqool)/, 'تخبر'], [/^(ma|la|wla|w?la)$/, 'لا'],
  [/^(ba7o?t|bansh(e|i)r|anshur|ansher|bafda7|af?da7|fadee?7a|fdee7a)/, 'بنشر بفضحك'], [/^(soo?r|sowar|9oor|9owar|video|vid|clip|clips|ma?qta3)/, 'الصور الفيديو'],
  [/^(wa?[dzth]i[fv]a|wadhifa|wazifa|shu?3?ghl)/, 'وظيفة'], [/^(ar?ba7|rib7|rb7|arba7)/, 'أرباح'], [/^(ja?[2a]?[ie]za|jayza|jaiza)/, 'جائزة'], [/^(mabroo?k|mbrook|mbrk)/, 'مبروك'],
  [/^(hawi(y|ee)a|hwya|howiya|hawya)/, 'الهوية'], [/^([ei]qa?ma|iqama)/, 'الإقامة'], [/^(rasoo?m|rsoom|rusoom)/, 'رسوم'], [/^(dareeb[ae]|9areeba)/, 'ضريبة'],
  [/^(ra?qmi|rgmi|ra8mi)$/, 'رقمي'], [/^(jdeed|jedeed|jadid|jdid)$/, 'الجديد'], [/^(telefoo?ni|tilfoni|mobaili|jawali)/, 'تلفوني'], [/^(5arab|5irab|5rb|enkasar|inkisar|ta?fa)$/, 'خرب'],
  [/^(wafe?[gq]|waf[ie]j|w[ae]fq)/, 'وافق'], [/^(ish3ar|esh3ar|notification)$/, 'الإشعار'], [/^(m7fa?[dzth]a|ma7fatha|ma7fa?[dz]a|wallet)$/, 'محفظة'],
  [/^(sa?7b|sa7ab)$/, 'السحب'], [/^(qa?[dt]iyy?a|8a?[dt]iya|gadhiya|qadiya)$/, 'قضية'], [/^(balagh|bla8|blagh)$/, 'بلاغ'], [/^(mo?7akm?a|ma7kama)$/, 'المحكمة'],
];
export function arabiziHints(text) {
  const tokens = String(text).toLowerCase().match(/[a-z0-9]*[2356789][a-z0-9]*|[a-z]{3,}/g) || [];
  if (!tokens.some((t) => /[a-z][2356789]|[2356789][a-z]/.test(t))) return ''; // only for real Arabizi
  const out = [];
  for (const t of tokens) for (const [re, ar] of ARABIZI) if (re.test(t)) { out.push(ar); break; }
  return out.join(' ');
}

export function analyzeMessage(text, opts = {}) {
  const body = String(text || '').normalize('NFKC');
  const signals = [];
  const playbooks = [];
  const tactics = [];
  const urlsRaw = extractUrls(body);
  const plain = urlsRaw.reduce((s, u) => s.split(u).join(' '), body); // text without the links
  const hints = arabiziHints(plain);
  const prose = hints ? `${plain}\n${hints}` : plain;
  if (hints) signals.push(sig('arabizi', 0, 'Arabizi (Arabic in Latin letters) understood.', 'تم فهم العربيزي (العربية بحروف لاتينية).', 'low'));

  /* tactics: behavioural evidence */
  for (const t of TACTICS) {
    const m = t.re.map((r) => prose.match(r)).find(Boolean);
    if (!m) continue;
    if (t.negate) {
      const around = prose.slice(Math.max(0, m.index - 30), m.index + m[0].length);
      if (t.negate.some((n) => n.test(around))) continue;
    }
    tactics.push(t.id);
    signals.push(sig('tactic_' + t.id, t.weight, t.en, t.ar));
  }
  const hasAction = ACTION.some((r) => r.test(prose)) || urlsRaw.length > 0;

  /* playbooks: the story being told. A story alone ("I paid my Salik today") is not a scam —
   * it only weighs fully when it comes with a link, an action request or a manipulation tactic. */
  for (const p of SCAM_PLAYBOOKS) {
    if (p.re.some((r) => r.test(prose))) {
      const backed = tactics.length > 0 || (hasAction && !p.needsAction) || (p.needsAction && (tactics.length > 0 || urlsRaw.length > 0 || /\b(pay|transfer|send|settle|money|7awel|aed|dhs)\b|(فلوس|مبلغ|حول|سدد|درهم)/i.test(prose)));
      playbooks.push(p.id);
      const w = backed ? p.weight : Math.round(p.weight * 0.35);
      signals.push(sig('playbook_' + p.id, w, `Matches the “${p.en}” scam pattern.`, `يطابق نمط احتيال “${p.ar}”.`, backed ? undefined : 'low'));
    }
  }
  if (PRESSURE.some((r) => r.test(body))) signals.push(sig('pressure', playbooks.length || tactics.length ? 15 : 6, 'Creates time pressure so you act before thinking.', 'يضغط عليك بالوقت لتتصرف دون تفكير.'));
  const fee = SMALL_FEE.map((r) => body.match(r)).find(Boolean);
  if (fee && playbooks.length) signals.push(sig('small_fee', 15, 'Asks for a small fee — the real goal is your full card details.', 'يطلب رسوماً صغيرة — الهدف الحقيقي بيانات بطاقتك كاملة.'));
  if (ASKS_TO_CLICK.some((r) => r.test(body))) signals.push(sig('asks_click', 8, 'Pushes you to tap a link.', 'يدفعك للضغط على رابط.'));
  if (MOVE_CHANNEL.some((r) => r.test(body))) signals.push(sig('move_channel', 15, 'Moves you to WhatsApp/Telegram, away from official channels.', 'ينقلك إلى واتساب أو تيليجرام بعيداً عن القنوات الرسمية.'));
  if (/[A-Za-z]/.test(body) && /(dear (customer|user|client)|kindly|valued customer)/i.test(body)) signals.push(sig('generic_greeting', 5, 'Generic greeting — a real organisation usually knows your name.', 'تحية عامة — الجهة الحقيقية تعرف اسمك عادة.'));

  /* phone numbers: foreign mobiles pretending to be local services */
  const phones = [...new Set((body.match(PHONE_RE) || []).map((p) => p.replace(/[\s-]/g, '')))];
  const foreign = phones.filter((p) => /^(\+|00)/.test(p) && !/^(\+|00)971/.test(p));
  if (foreign.length && playbooks.length) signals.push(sig('foreign_number', 15, `Asks you to contact a foreign number (${foreign[0]}).`, `يطلب التواصل مع رقم أجنبي (${foreign[0]}).`));

  /* sender id */
  const sender = String(opts.sender || '').trim();
  if (sender) {
    const looksOfficial = OFFICIAL_SENDERS.test(sender.replace(/[^A-Za-z&]/g, ''));
    if (/^(\+|00)?\d{7,15}$/.test(sender.replace(/[\s-]/g, '')) && playbooks.some((p) => ['fake_fine', 'bank_block', 'parcel', 'id_expiry', 'police_impersonation', 'utility'].includes(p)))
      signals.push(sig('personal_sender', 25, 'Claims to be an organisation but was sent from a personal phone number.', 'يدّعي أنه من جهة رسمية لكنه مُرسل من رقم هاتف شخصي.'));
    if (/^(\+|00)(?!971)/.test(sender.replace(/[\s-]/g, ''))) signals.push(sig('foreign_sender', 12, 'Sent from a foreign phone number.', 'مُرسل من رقم أجنبي.'));
    if (looksOfficial) signals.push(sig('official_sender', -10, 'Sender ID looks official — but scammers can still spoof it, judge the link.', 'اسم المرسل يبدو رسمياً — لكن يمكن تزويره، احكم على الرابط.', 'good'));
  }

  /* links */
  const urls = extractUrls(body).slice(0, 8);
  const links = urls.map((u) => analyzeUrl(u));
  const worstLink = links.reduce((a, b) => (!a || b.score > a.score ? b : a), null);

  /* a message that names a brand but links elsewhere is the strongest tell */
  const named = BRANDS.filter((b) => {
    if (b.ambiguous) return new RegExp(`^\\s*\\[?${esc(b.en)}\\]?\\s*:|\\b${esc(b.domains[0])}\\b`, 'i').test(body) || sender.toLowerCase() === b.en;
    return b.arWords.some((w) => prose.includes(w)) || new RegExp(`\\b(${[b.en.split(' (')[0], ...b.words.filter((w) => w.length >= 4).map((w) => w.replace(/-$/, ''))].map(esc).join('|')})\\b`, 'i').test(prose);
  });
  for (const b of named.slice(0, 2)) {
    const offDomain = links.filter((l) => l.host && !b.domains.some((d) => hostMatches(l.host, d)) && l.brand !== b.id && !l.signals.some((s) => s.id === 'trusted_domain') && !l.input.match(/^(tel|mailto):/));
    if (offDomain.length) {
      signals.push(sig('brand_link_mismatch', 35, `Says it is from ${b.en}, but the link goes to ${offDomain[0].registrable}, not ${b.domains[0]}.`, `يدّعي أنه من ${b.ar} لكن الرابط يذهب إلى ${offDomain[0].registrable} وليس ${b.domains[0]}.`));
      break;
    }
  }

  /* Links that all point to verified official domains are strong evidence of a genuine message,
   * unless the text itself asks for codes, approvals or off-channel payment. */
  const allOfficial = links.length > 0 && links.every((l) => l.signals.some((s) => s.id === 'official_domain' || s.id === 'trusted_domain'));
  const hardTactic = tactics.some((t) => ['credential_request', 'approval_coercion', 'payment_diversion', 'document_harvest'].includes(t));
  let textScore = signals.reduce((s, x) => s + x.weight, 0);
  if (allOfficial && !hardTactic) {
    textScore = Math.round(textScore * 0.25);
    signals.push(sig('official_links_only', 0, 'Every link points to a verified official domain.', 'جميع الروابط تشير إلى نطاقات رسمية موثقة.', 'good'));
  }
  const result = {
    kind: 'message',
    input: body,
    playbooks,
    tactics,
    links,
    phones,
    impersonates: worstLink?.impersonates || (named[0] && (playbooks.length || tactics.length) ? named[0].id : null),
    signals,
  };
  const out = finalise(result, worstLink ? worstLink.score : 0, textScore);
  return out;
}

function esc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

/* ------------------------------------------------------------------ */
/* 5. Scoring, verdict, advice                                          */
/* ------------------------------------------------------------------ */
function squash(raw) {
  // Smooth saturating curve: 0 -> 0, 30 -> ~45, 60 -> ~70, 100 -> ~87
  if (raw <= 0) return Math.max(0, Math.round(raw / 10 + 3));
  return Math.round(100 * (1 - Math.exp(-raw / 50)));
}

function finalise(result, linkScore = null, textScore = null) {
  let score;
  if (result.kind === 'message') {
    const text = squash(textScore);
    // Combine like independent evidence: 1 - (1-a)(1-b)
    score = Math.round(100 * (1 - (1 - text / 100) * (1 - (linkScore || 0) / 100)));
  } else {
    score = squash(result.signals.reduce((s, x) => s + x.weight, 0));
  }
  score = clamp(score, 0, 100);
  const verdict = score >= 65 ? 'dangerous' : score >= 35 ? 'suspicious' : 'safe';
  const brand = BRANDS.find((b) => b.id === result.impersonates);
  result.signals.sort((a, b) => b.weight - a.weight);
  return {
    ...result,
    engine: ENGINE_VERSION,
    score,
    verdict,
    impersonatedBrand: brand ? { id: brand.id, en: brand.en, ar: brand.ar, official: brand.domains[0], sector: brand.sector } : null,
    advice: advice(verdict, brand, result),
  };
}

export function adviceFor(verdict, brandId, playbooks = [], tactics = []) {
  return advice(verdict, BRANDS.find((b) => b.id === brandId), { playbooks, tactics });
}

function advice(verdict, brand, r) {
  if (verdict === 'safe') {
    return {
      en: ['No strong scam signs found. Still never share OTPs, PINs or card CVV with anyone.'],
      ar: ['لم نجد مؤشرات احتيال قوية. ومع ذلك لا تشارك رمز التحقق أو الرقم السري أو CVV مع أي أحد.'],
    };
  }
  const en = [], ar = [];
  en.push('Do not tap the link or enter any card, OTP or UAE PASS details.');
  ar.push('لا تضغط على الرابط ولا تُدخل بيانات البطاقة أو رمز التحقق أو الهوية الرقمية.');
  if (brand) {
    en.push(`If you are worried, open the official ${brand.en} app or type ${brand.domains[0]} yourself.`);
    ar.push(`إذا كنت قلقاً، افتح تطبيق ${brand.ar} الرسمي أو اكتب ${brand.domains[0]} بنفسك.`);
  }
  if (r.tactics?.includes('credential_request') || r.tactics?.includes('approval_coercion')) { en.push('No bank, police or ministry will ever ask for your OTP.'); ar.push('لا يطلب أي بنك أو شرطة أو وزارة رمز التحقق منك أبداً.'); }
  if (verdict === 'dangerous') {
    en.push('Already paid or typed details? Call your bank now to block the card, then report to Abu Dhabi Police (Aman 8002626 / 999) or ecrime.ae.');
    ar.push('إذا دفعت أو أدخلت بياناتك: اتصل ببنكك فوراً لإيقاف البطاقة، ثم أبلغ شرطة أبوظبي (أمان 8002626 / 999) أو ecrime.ae.');
  }
  return { en, ar };
}

/* ------------------------------------------------------------------ */
/* 6. Privacy-safe campaign fingerprint                                 */
/* Only structural features are kept — never the message text, phone   */
/* numbers or the full URL path (which can contain victim tokens).      */
/* ------------------------------------------------------------------ */
export function fingerprint(r) {
  const link = r.kind === 'url' ? r : (r.links || []).reduce((a, b) => (!a || b.score > a.score ? b : a), null);
  const domainShape = link?.registrable
    ? link.registrable.replace(/\d+/g, '#').replace(/^[^.]+/, (l) => l.split('-').map((p) => (p.length > 10 ? '*' : p)).join('-'))
    : 'none';
  return {
    brand: r.impersonates || 'unknown',
    playbook: (r.playbooks && r.playbooks[0]) || (r.tactics && r.tactics[0]) || (link?.impersonates ? 'phishing_link' : 'unknown'),
    tld: link?.tld || null,
    domain: link?.registrable || null,
    domainShape,
    freeHost: link?.freeHost || null,
    verdict: r.verdict,
    score: r.score,
    signalIds: r.signals.filter((s) => s.weight > 0).map((s) => s.id).slice(0, 8),
  };
}

/* ------------------------------------------------------------------ */
/* 7. Look-alike domain generator — feeds the proactive hunting module  */
/* ------------------------------------------------------------------ */
export function lookalikeCandidates(brandId) {
  const b = BRANDS.find((x) => x.id === brandId);
  if (!b) return [];
  const label = b.domains[0].split('.')[0];
  const out = new Set();
  const swaps = { o: '0', l: '1', i: '1', e: '3', a: '4', s: '5', m: 'rn', w: 'vv' };
  for (let i = 0; i < label.length; i++) {
    out.add(label.slice(0, i) + label.slice(i + 1));                         // omission
    out.add(label.slice(0, i) + label[i] + label.slice(i));                  // repetition
    if (swaps[label[i]]) out.add(label.slice(0, i) + swaps[label[i]] + label.slice(i + 1));
    if (i < label.length - 1) out.add(label.slice(0, i) + label[i + 1] + label[i] + label.slice(i + 2)); // transposition
  }
  for (const affix of ['-uae', '-ae', 'uae', '-gov', '-pay', '-online', '-portal', '-services', '-fines', '-track', 'ae-', 'gov-', 'my-', 'e-'])
    out.add(affix.startsWith('-') || affix.endsWith('uae') || affix.endsWith('ae') ? label + affix : affix + label);
  out.delete(label);
  return [...out].filter((l) => l.length >= 3);
}
