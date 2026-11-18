import { fingerprint } from './engine/scamshield.js';
import { checkLink } from './check.js';

const language = /^ar\b/i.test(navigator.language) ? 'ar' : 'en';
const copy = {
  en: {
    name: 'ScamShield AI Guard', safe: 'Low risk', suspicious: 'Suspicious link',
    dangerous: 'Dangerous link', blocked: 'ScamShield blocked a dangerous link',
    unavailable: 'No verdict available', signals: 'Why this verdict', official: 'Official domain',
    none: 'No strong scam signals found.', report: 'Report to Abu Dhabi Police',
    leave: 'Go back to safety', continue: 'I understand the risk, continue',
    visit: 'Visit ScamShield AI', sent: 'Report sent.', sending: 'Sending report…',
    failed: 'The report could not be sent. Try again.', navFailed: 'Could not open the page. Try again.',
    score: 'Risk score',
  },
  ar: {
    name: 'درع الاحتيال', safe: 'مخاطر منخفضة', suspicious: 'رابط مشبوه',
    dangerous: 'رابط خطير', blocked: 'حظر درع الاحتيال رابطاً خطيراً',
    unavailable: 'التقييم غير متاح', signals: 'أسباب التقييم', official: 'النطاق الرسمي',
    none: 'لم نجد مؤشرات احتيال قوية.', report: 'أبلغ شرطة أبوظبي',
    leave: 'العودة إلى الأمان', continue: 'أفهم المخاطر وأريد المتابعة',
    visit: 'زيارة موقع درع الاحتيال', sent: 'تم إرسال البلاغ.', sending: 'جارٍ إرسال البلاغ…',
    failed: 'تعذّر إرسال البلاغ. حاول مرة أخرى.', navFailed: 'تعذّر فتح الصفحة. حاول مرة أخرى.',
    score: 'درجة الخطورة',
  },
}[language];
const $ = (id) => document.getElementById(id);
const warning = document.body.classList.contains('warning');
const params = new URL(location.href).searchParams;

document.documentElement.lang = language;
document.documentElement.dir = language === 'ar' ? 'rtl' : 'ltr';
document.title = copy.name;
for (const node of document.querySelectorAll('[data-text]')) {
  node.textContent = copy[node.dataset.text];
}

function status(key) {
  $('status').hidden = false;
  $('status').textContent = copy[key];
}

async function report(result) {
  $('report').disabled = true;
  status('sending');
  try {
    const response = await fetch('https://scamshield-ai-eaj.pages.dev/api/report', {
      method: 'POST',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fingerprint: fingerprint(result), channel: 'extension' }),
    });
    if (!response.ok) throw new Error('Report rejected');
    status('sent');
  } catch {
    $('report').disabled = false;
    status('failed');
  }
}

async function activeUrl() {
  if (warning) return params.get('u');
  if (params.has('check')) return params.get('check');
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const warningUrl = chrome.runtime.getURL('warning.html') + '?';
  return tab?.url?.startsWith(warningUrl) ? new URL(tab.url).searchParams.get('u') : tab?.url;
}

function render(result) {
  $('verdict').textContent = copy[result?.verdict ?? 'unavailable'];
  if (!result) return;
  document.body.dataset.verdict = result.verdict;
  $('host').textContent = result.host ?? '';
  if ($('score')) {
    $('score').textContent = result.score;
    const ring = $('score').parentElement;
    ring.style.setProperty('--progress', result.score + '%');
    ring.removeAttribute('aria-hidden');
    ring.setAttribute('role', 'img');
    ring.setAttribute('aria-label', copy.score + ' ' + result.score + '/100');
  }
  $('details').hidden = false;
  const signals = result.signals.slice(0, 3);
  for (const signal of signals) {
    const item = document.createElement('li');
    for (const lang of warning ? [language, language === 'en' ? 'ar' : 'en'] : [language]) {
      const line = document.createElement('span');
      line.lang = lang;
      line.dir = lang === 'ar' ? 'rtl' : 'ltr';
      line.textContent = signal[lang];
      item.append(line);
    }
    $('signals').append(item);
  }
  if (!signals.length) {
    const item = document.createElement('li');
    item.textContent = copy.none;
    $('signals').append(item);
  }
  if (result.impersonatedBrand) {
    $('official').hidden = false;
    $('official').querySelector('bdi').textContent = result.impersonatedBrand.official;
  }
  $('report').hidden = false;
  $('report').addEventListener('click', () => report(result));
  if (warning && result.verdict === 'dangerous') {
    $('verdict').textContent = copy.blocked;
    $('continue').hidden = false;
  }
}

async function navigate(action) {
  try {
    const response = await chrome.runtime.sendMessage({ action });
    if (!response?.ok) status('navFailed');
  } catch {
    status('navFailed');
  }
}

if (warning) {
  $('leave').addEventListener('click', () => navigate('leave'));
  $('continue').addEventListener('click', (event) => {
    event.preventDefault();
    navigate('continue');
  });
}

try {
  render(checkLink(await activeUrl()));
} catch {
  render(null);
}
