import { json, preflight, readJson, rateLimit } from '../_lib/http.js';

export const onRequestOptions = preflight;

const CHANNELS = new Set(['sms', 'whatsapp', 'email', 'web', 'extension', 'api', 'qr', 'call', 'social']);
const EMIRATES = new Set(['AD', 'DXB', 'SHJ', 'AJM', 'UAQ', 'RAK', 'FUJ']);
const clean = (v, max = 80) => (v == null ? null : String(v).toLowerCase().replace(/[^a-z0-9._#*\-]/g, '').slice(0, max) || null);

/**
 * POST /api/report — anonymous, opt-in. Accepts ONLY the privacy-safe fingerprint produced by the engine.
 * { fingerprint: {...}, channel, emirate?, lostMoney? }
 */
export async function onRequestPost({ request, env }) {
  if (!env.DB) return json({ error: 'Reporting unavailable' }, 503);
  if (!(await rateLimit(env, request, 'report', 10))) return json({ error: 'Too many reports, wait a minute.' }, 429);
  let body;
  try { body = await readJson(request, 4000); } catch { return json({ error: 'Bad request' }, 400); }
  const f = body.fingerprint || {};
  const channel = CHANNELS.has(body.channel) ? body.channel : 'web';
  const emirate = EMIRATES.has(body.emirate) ? body.emirate : null;
  const row = {
    brand: clean(f.brand, 30) || 'unknown',
    playbook: clean(f.playbook, 40) || 'unknown',
    domain: clean(f.domain, 120),
    shape: clean(f.domainShape, 120),
    tld: clean(f.tld, 20),
    freeHost: clean(f.freeHost, 60),
    verdict: ['safe', 'suspicious', 'dangerous'].includes(f.verdict) ? f.verdict : 'suspicious',
    score: Math.max(0, Math.min(100, Number(f.score) || 0)),
    signals: (Array.isArray(f.signalIds) ? f.signalIds : []).map((s) => clean(s, 40)).filter(Boolean).slice(0, 10).join(','),
    lost: body.lostMoney ? 1 : 0,
  };
  const key = `${row.brand}|${row.playbook}|${row.tld || 'none'}`;
  const now = new Date().toISOString().replace('T', ' ').slice(0, 19);

  await env.DB.prepare(`INSERT INTO ss_campaigns (key, brand, playbook, tld, first_seen, last_seen, reports, victims, domains)
      VALUES (?1, ?2, ?3, ?4, ?5, ?5, 0, 0, '[]') ON CONFLICT(key) DO NOTHING`).bind(key, row.brand, row.playbook, row.tld, now).run();
  const camp = await env.DB.prepare('SELECT id, domains FROM ss_campaigns WHERE key = ?1').bind(key).first();
  let domains = [];
  try { domains = JSON.parse(camp.domains || '[]'); } catch {}
  if (row.domain && !domains.includes(row.domain)) domains = [row.domain, ...domains].slice(0, 50);

  await env.DB.batch([
    env.DB.prepare(`INSERT INTO ss_reports (channel, brand, playbook, domain, domain_shape, tld, free_host, verdict, score, signals, emirate, lost_money, campaign_id)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)`)
      .bind(channel, row.brand, row.playbook, row.domain, row.shape, row.tld, row.freeHost, row.verdict, row.score, row.signals, emirate, row.lost, camp.id),
    env.DB.prepare('UPDATE ss_campaigns SET last_seen = ?1, reports = reports + 1, victims = victims + ?2, domains = ?3, demo = 0 WHERE id = ?4')
      .bind(now, row.lost, JSON.stringify(domains), camp.id),
  ]);
  const count = await env.DB.prepare('SELECT reports FROM ss_campaigns WHERE id = ?1').bind(camp.id).first();
  return json({ ok: true, campaignId: camp.id, campaignReports: count?.reports || 1 });
}
