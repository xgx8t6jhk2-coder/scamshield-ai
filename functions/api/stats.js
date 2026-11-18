import { json, preflight } from '../_lib/http.js';

export const onRequestOptions = preflight;

/** GET /api/stats?days=14&demo=1 — aggregated, anonymous intelligence for the police dashboard. */
export async function onRequestGet({ request, env }) {
  if (!env.DB) return json({ error: 'No database' }, 503);
  const u = new URL(request.url);
  const days = Math.max(1, Math.min(90, Number(u.searchParams.get('days')) || 14));
  const demo = u.searchParams.get('demo') !== '0';
  const since = new Date(Date.now() - days * 86400000).toISOString().replace('T', ' ').slice(0, 19);
  const dw = demo ? '' : ' AND demo = 0';
  const q = (sql, ...b) => env.DB.prepare(sql).bind(...b).all().then((r) => r.results);

  const [totals, timeline, byBrand, byPlaybook, byChannel, byEmirate, topDomains, campaigns, hunts, scans] = await Promise.all([
    env.DB.prepare(`SELECT COUNT(*) AS reports, SUM(lost_money) AS victims, COUNT(DISTINCT domain) AS domains, COUNT(DISTINCT campaign_id) AS campaigns
                    FROM ss_reports WHERE created_at >= ?1${dw}`).bind(since).first(),
    q(`SELECT substr(created_at,1,10) AS day, COUNT(*) AS n, SUM(lost_money) AS victims FROM ss_reports WHERE created_at >= ?1${dw} GROUP BY day ORDER BY day`, since),
    q(`SELECT brand, COUNT(*) AS n FROM ss_reports WHERE created_at >= ?1${dw} GROUP BY brand ORDER BY n DESC LIMIT 12`, since),
    q(`SELECT playbook, COUNT(*) AS n FROM ss_reports WHERE created_at >= ?1${dw} GROUP BY playbook ORDER BY n DESC LIMIT 12`, since),
    q(`SELECT channel, COUNT(*) AS n FROM ss_reports WHERE created_at >= ?1${dw} GROUP BY channel ORDER BY n DESC`, since),
    q(`SELECT emirate, COUNT(*) AS n FROM ss_reports WHERE created_at >= ?1 AND emirate IS NOT NULL${dw} GROUP BY emirate ORDER BY n DESC`, since),
    q(`SELECT domain, brand, playbook, COUNT(*) AS n, MIN(created_at) AS first_seen, MAX(created_at) AS last_seen, SUM(lost_money) AS victims, MAX(score) AS score
       FROM ss_reports WHERE created_at >= ?1 AND domain IS NOT NULL${dw} GROUP BY domain ORDER BY n DESC LIMIT 25`, since),
    q(`SELECT id, brand, playbook, tld, first_seen, last_seen, reports, victims, domains, status, demo FROM ss_campaigns
       WHERE last_seen >= ?1${demo ? '' : ' AND demo = 0'} ORDER BY (reports + victims * 5) DESC LIMIT 20`, since),
    q(`SELECT domain, brand, source, first_seen, detail, score, status FROM ss_hunts ORDER BY first_seen DESC LIMIT 40`),
    q(`SELECT kind, verdict, SUM(n) AS n FROM ss_daily WHERE day >= ?1 GROUP BY kind, verdict`, since.slice(0, 10)),
  ]);

  // Surge detection: compare the last 24h to the average of the window per brand.
  const last24 = new Date(Date.now() - 86400000).toISOString().replace('T', ' ').slice(0, 19);
  const surges = await q(`SELECT brand, playbook, SUM(CASE WHEN created_at >= ?2 THEN 1 ELSE 0 END) AS today, COUNT(*) AS total
      FROM ss_reports WHERE created_at >= ?1${dw} GROUP BY brand, playbook HAVING today >= 3 ORDER BY today DESC LIMIT 8`, since, last24);
  const alerts = surges
    .map((s) => ({ ...s, avg: (s.total - s.today) / Math.max(1, days - 1), factor: +(s.today / Math.max(0.5, (s.total - s.today) / Math.max(1, days - 1))).toFixed(1) }))
    .filter((s) => s.factor >= 1.8);

  return json({
    days, demoIncluded: demo, generated: new Date().toISOString(),
    totals: { ...totals, warned: scans.filter((s) => s.verdict !== 'safe').reduce((a, b) => a + b.n, 0), scans: scans.reduce((a, b) => a + b.n, 0) },
    timeline, byBrand, byPlaybook, byChannel, byEmirate, topDomains,
    campaigns: campaigns.map((c) => ({ ...c, domains: safeParse(c.domains) })),
    hunts, scans, alerts,
  });
}

function safeParse(s) { try { return JSON.parse(s); } catch { return []; } }
