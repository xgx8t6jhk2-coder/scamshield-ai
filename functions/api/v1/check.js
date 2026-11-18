import { analyzeMessage } from '../../../public/engine/scamshield.js';
import { deepScanUrl } from '../../_lib/enrich.js';
import { json, preflight, squash, verdictOf, rateLimit } from '../../_lib/http.js';

export const onRequestOptions = preflight;

/**
 * Partner API for banks, telcos (SMS firewalls), e-commerce and messaging apps.
 * GET /api/v1/check?url=...           -> verdict for one link (with live checks)
 * GET /api/v1/check?text=...&fast=1   -> verdict for a message, rules only (< 5 ms, no network)
 */
export async function onRequestGet({ request, env }) {
  if (!(await rateLimit(env, request, 'v1', 120))) return json({ error: 'rate limited' }, 429);
  const p = new URL(request.url).searchParams;
  const t0 = Date.now();
  if (p.get('url')) {
    const d = await deepScanUrl(p.get('url').slice(0, 2000));
    const signals = [...d.final.signals, ...d.extra].sort((a, b) => b.weight - a.weight);
    const official = signals.some((s) => s.id === 'official_domain');
    const score = official ? Math.min(d.final.score, 10) : squash(signals.reduce((s, x) => s + x.weight, 0));
    return json({ verdict: verdictOf(score), score, domain: d.final.registrable, finalUrl: d.final.url, impersonates: d.final.impersonatedBrand?.id || null,
      reasons: signals.filter((s) => s.weight > 0).slice(0, 5).map((s) => ({ id: s.id, en: s.en, ar: s.ar })), ageDays: d.rdap?.ageDays ?? null, ms: Date.now() - t0 });
  }
  if (p.get('text')) {
    const r = analyzeMessage(p.get('text').slice(0, 2000), { sender: p.get('sender') || '' });
    return json({ verdict: r.verdict, score: r.score, playbooks: r.playbooks, impersonates: r.impersonates,
      reasons: r.signals.filter((s) => s.weight > 0).slice(0, 5).map((s) => ({ id: s.id, en: s.en, ar: s.ar })), links: r.links.map((l) => ({ domain: l.registrable, verdict: l.verdict, score: l.score })), ms: Date.now() - t0 });
  }
  return json({ error: 'pass ?url= or ?text=' }, 400);
}
