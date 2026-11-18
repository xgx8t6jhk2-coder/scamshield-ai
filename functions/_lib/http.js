export const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET,POST,OPTIONS',
  'access-control-allow-headers': 'content-type,authorization',
};

export const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...CORS, ...extra } });

export const preflight = () => new Response(null, { status: 204, headers: CORS });

export async function readJson(request, max = 20_000) {
  const text = await request.text();
  if (text.length > max) throw new Error('payload too large');
  return JSON.parse(text || '{}');
}

export const today = () => new Date().toISOString().slice(0, 10);

export function squash(raw) {
  if (raw <= 0) return Math.max(0, Math.round(raw / 10 + 3));
  return Math.round(100 * (1 - Math.exp(-raw / 50)));
}

export const verdictOf = (score) => (score >= 65 ? 'dangerous' : score >= 35 ? 'suspicious' : 'safe');

/** Simple fixed-window rate limit on a hashed client key, stored in D1 (no raw IP kept). */
export async function rateLimit(env, request, bucket, limit) {
  if (!env.DB) return true;
  if (env.POLICE_KEY && request.headers.get('authorization') === `Bearer ${env.POLICE_KEY}`) return true; // analysts / evaluation runs
  const ip = request.headers.get('cf-connecting-ip') || 'anon';
  const minute = Math.floor(Date.now() / 60000);
  const data = new TextEncoder().encode(`${ip}|${bucket}|${minute}|${env.RL_SALT || 'scamshield'}`);
  const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', data))].slice(0, 12).map((b) => b.toString(16).padStart(2, '0')).join('');
  try {
    await env.DB.prepare('INSERT INTO ss_rate (k, n, minute) VALUES (?1, 1, ?2) ON CONFLICT(k) DO UPDATE SET n = n + 1').bind(hash, minute).run();
    const row = await env.DB.prepare('SELECT n FROM ss_rate WHERE k = ?1').bind(hash).first();
    if (Math.random() < 0.02) await env.DB.prepare('DELETE FROM ss_rate WHERE minute < ?1').bind(minute - 5).run();
    return (row?.n || 0) <= limit;
  } catch { return true; }
}
