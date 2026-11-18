import { BRANDS, analyzeUrl, lookalikeCandidates } from '../../public/engine/scamshield.js';
import { doh, withTimeout } from '../_lib/enrich.js';
import { json, preflight, readJson } from '../_lib/http.js';

export const onRequestOptions = preflight;

/**
 * Proactive hunting — find phishing domains BEFORE the SMS wave goes out.
 * GET /api/hunt?brand=rta
 *  1. Certificate Transparency: every HTTPS phishing site needs a certificate, and CAs publish them publicly (crt.sh).
 *  2. Permutation DNS sweep: generate look-alikes (rta-fines, rtta, rta-uae…) x scam TLDs and see which ones are live.
 */
const SWEEP_TLDS = ['com', 'net', 'top', 'xyz', 'online', 'site', 'info', 'live', 'cfd', 'sbs', 'icu', 'click', 'vip', 'shop'];

export async function onRequestGet({ request, env }) {
  const u = new URL(request.url);
  const brand = BRANDS.find((b) => b.id === u.searchParams.get('brand'));
  if (!brand) return json({ brands: BRANDS.map((b) => ({ id: b.id, en: b.en, ar: b.ar, official: b.domains[0] })) });

  const label = brand.domains[0].split('.')[0];
  const found = [];

  // 1) Certificate Transparency
  const ct = await withTimeout(
    fetch(`https://crt.sh/?q=${encodeURIComponent('%' + label + '%')}&output=json&exclude=expired`, { headers: { accept: 'application/json', 'user-agent': 'ScamShieldAI/1.0 (hackathon prototype)' } })
      .then((r) => (r.ok ? r.json() : [])),
    12000,
  ).catch(() => null);
  if (Array.isArray(ct)) {
    const seen = new Set();
    for (const c of ct.sort((a, b) => (b.entry_timestamp || '').localeCompare(a.entry_timestamp || '')).slice(0, 400)) {
      for (const name of String(c.name_value || '').split('\n')) {
        const host = name.replace(/^\*\./, '').toLowerCase().trim();
        if (!host || seen.has(host)) continue;
        seen.add(host);
        const r = analyzeUrl('https://' + host);
        if (r.verdict === 'safe') continue;
        found.push({ domain: r.registrable, host, source: 'ct', detail: `cert ${String(c.not_before || '').slice(0, 10)} by ${String(c.issuer_name || '').match(/O=([^,]+)/)?.[1] || 'CA'}`, score: r.score });
      }
      if (found.length >= 40) break;
    }
  }

  // 2) Permutation sweep via DNS over HTTPS
  const candidates = lookalikeCandidates(brand.id).slice(0, 18).flatMap((l) => SWEEP_TLDS.slice(0, 6).map((t) => `${l}.${t}`));
  const extra = ['top', 'xyz', 'online', 'cfd'].map((t) => `${label}-uae.${t}`).concat(['com', 'top', 'xyz'].map((t) => `${label}-ae.${t}`));
  const names = [...new Set([...extra, ...candidates])].slice(0, 90);
  const res = await Promise.all(names.map(async (n) => ({ n, d: await doh(n) })));
  for (const { n, d } of res) {
    if (d && d.status === 0 && d.answers.length) {
      const r = analyzeUrl('https://' + n);
      found.push({ domain: r.registrable, host: n, source: 'dns', detail: `resolves to ${d.answers.slice(0, 2).join(', ')}`, score: Math.max(r.score, 50) });
    }
  }

  // de-duplicate by registrable domain, keep best
  const byDomain = new Map();
  for (const f of found) if (!byDomain.has(f.domain) || byDomain.get(f.domain).score < f.score) byDomain.set(f.domain, f);
  const list = [...byDomain.values()].filter((f) => !brand.domains.includes(f.domain)).sort((a, b) => b.score - a.score).slice(0, 40);

  if (env.DB && list.length) {
    await env.DB.batch(list.map((f) => env.DB.prepare(
      'INSERT INTO ss_hunts (domain, brand, source, detail, score) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(domain) DO UPDATE SET detail = ?4, score = MAX(score, ?5)',
    ).bind(f.domain, brand.id, f.source, f.detail.slice(0, 200), f.score))).catch(() => {});
  }
  return json({ brand: { id: brand.id, en: brand.en, official: brand.domains[0] }, ctAvailable: Array.isArray(ct), checked: names.length, found: list });
}

/** POST /api/hunt { domain, status } — analyst workflow; requires the police key. */
export async function onRequestPost({ request, env }) {
  const auth = request.headers.get('authorization') || '';
  if (!env.POLICE_KEY || auth !== `Bearer ${env.POLICE_KEY}`) return json({ error: 'Analyst key required' }, 401);
  const body = await readJson(request).catch(() => ({}));
  const status = ['new', 'watching', 'takedown_requested', 'down', 'false_positive'].includes(body.status) ? body.status : null;
  const domain = String(body.domain || '').toLowerCase().replace(/[^a-z0-9.\-]/g, '');
  if (!status || !domain) return json({ error: 'domain and status required' }, 400);
  await env.DB.prepare('UPDATE ss_hunts SET status = ?1 WHERE domain = ?2').bind(status, domain).run();
  await env.DB.prepare("UPDATE ss_campaigns SET status = ?1 WHERE domains LIKE ?2").bind(status === 'false_positive' ? 'active' : status, `%"${domain}"%`).run();
  return json({ ok: true });
}
