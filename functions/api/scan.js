import { analyzeMessage, adviceFor, fingerprint } from '../../public/engine/scamshield.js';
import { deepScanUrl } from '../_lib/enrich.js';
import { aiJudge } from '../_lib/ai.js';
import { json, preflight, readJson, today, squash, verdictOf, rateLimit } from '../_lib/http.js';

export const onRequestOptions = preflight;

/**
 * POST /api/scan
 * { type: 'url' | 'message', input: string, sender?: string, source?: 'paste'|'screenshot'|'qr', ai?: boolean }
 * Content is analysed in memory and discarded. Only an anonymous daily counter is written.
 */
export async function onRequestPost({ request, env }) {
  if (!(await rateLimit(env, request, 'scan', 30))) return json({ error: 'Too many scans, wait a minute.' }, 429);
  let body;
  try { body = await readJson(request); } catch { return json({ error: 'Bad request' }, 400); }
  const input = String(body.input || '').slice(0, 4000).trim();
  if (!input) return json({ error: 'Nothing to scan' }, 400);
  const type = body.type === 'url' ? 'url' : 'message';
  const t0 = Date.now();

  let result;
  if (type === 'url') {
    const deep = await deepScanUrl(input);
    result = merge(deep.final, deep.extra);
    result.input = input;
    result.live = { chain: deep.chain, rdap: deep.rdap, page: deep.page, dns: deep.dns };
  } else {
    const local = analyzeMessage(input, { sender: body.sender });
    const worst = local.links.reduce((a, b) => (!a || b.score > a.score ? b : a), null);
    const [deep, ai] = await Promise.all([
      worst ? deepScanUrl(worst.input) : Promise.resolve(null),
      body.ai === false ? Promise.resolve(null) : aiJudge(env, input, `${local.verdict} (${local.score}/100), signals: ${local.signals.map((s) => s.id).join(', ') || 'none'}`),
    ]);
    result = local;
    if (deep) {
      const deepLink = merge(deep.final, deep.extra);
      result.links = local.links.map((l) => (l === worst ? deepLink : l));
      result.live = { chain: deep.chain, rdap: deep.rdap, page: deep.page, dns: deep.dns, link: deepLink.registrable };
      const textRaw = local.signals.reduce((s, x) => s + x.weight, 0);
      result.score = Math.round(100 * (1 - (1 - squash(textRaw) / 100) * (1 - deepLink.score / 100)));
    }
    if (ai) {
      result.ai = ai;
      // AI can raise a verdict the rules missed, and soften a borderline one — never override strong rule evidence.
      if (ai.probability >= 0.8 && result.score < 65) {
        result.signals.unshift({ id: 'ai_judgement', weight: 30, severity: 'high', source: 'ai', en: `AI analyst: ${ai.en}`, ar: `المحلل الذكي: ${ai.ar}` });
        result.score = Math.max(result.score, 66);
      } else if (ai.probability <= 0.15 && result.score < 50 && !result.signals.some((s) => s.weight >= 35)) {
        result.score = Math.max(0, result.score - 10);
      }
    }
    result.verdict = verdictOf(result.score);
  }

  result.fingerprint = fingerprint(result);
  result.ms = Date.now() - t0;
  delete result.input; // never echo stored content beyond this response

  const kind = body.source === 'screenshot' ? 'screenshot' : body.source === 'qr' ? 'qr' : type;
  if (env.DB) {
    env.DB.prepare('INSERT INTO ss_daily (day, kind, verdict, n) VALUES (?1, ?2, ?3, 1) ON CONFLICT(day, kind, verdict) DO UPDATE SET n = n + 1')
      .bind(today(), kind, result.verdict).run().catch(() => {});
    if (result.fingerprint.domain) {
      const row = await env.DB.prepare("SELECT COUNT(*) AS n, MIN(created_at) AS first FROM ss_reports WHERE domain = ?1").bind(result.fingerprint.domain).first().catch(() => null);
      const hunt = await env.DB.prepare('SELECT source, first_seen FROM ss_hunts WHERE domain = ?1').bind(result.fingerprint.domain).first().catch(() => null);
      result.community = { reports: row?.n || 0, firstReported: row?.first || null, huntedSince: hunt?.first_seen || null };
      if ((row?.n || 0) >= 3 && result.score < 90) {
        result.signals.unshift({ id: 'community_reports', weight: 30, severity: 'high', source: 'community', en: `Reported by ${row.n} people in the UAE.`, ar: `أبلغ عنه ${row.n} أشخاص في الإمارات.` });
        result.score = Math.max(result.score, 70);
        result.verdict = verdictOf(result.score);
      }
    }
  }
  result.advice = adviceFor(result.verdict, result.impersonates, result.playbooks || [], result.tactics || []);
  result.fingerprint = fingerprint(result);
  return json(result);
}

function merge(base, extra) {
  const signals = [...base.signals, ...extra].sort((a, b) => b.weight - a.weight);
  const official = signals.some((s) => s.id === 'official_domain');
  const raw = signals.reduce((s, x) => s + x.weight, 0);
  const score = official ? Math.min(base.score, 10) : Math.max(0, Math.min(100, squash(raw)));
  return { ...base, signals, score, verdict: verdictOf(score) };
}
