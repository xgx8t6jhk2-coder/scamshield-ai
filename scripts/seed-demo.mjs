// Generates schema/demo-seed.sql — synthetic, clearly-flagged (demo = 1) reports so the police
// dashboard can be demonstrated before real reports arrive. Every demo domain contains "demo".
// Usage: node scripts/seed-demo.mjs && wrangler d1 execute scamshield-db --remote --file schema/demo-seed.sql
import { writeFileSync } from 'node:fs';

let seed = 42;
const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31);
const pick = (arr) => arr[Math.floor(rnd() * arr.length)];
const weighted = (pairs) => { const t = pairs.reduce((a, b) => a + b[1], 0); let r = rnd() * t; for (const [v, w] of pairs) { if ((r -= w) <= 0) return v; } return pairs[0][0]; };

const CAMPAIGNS = [
  { brand: 'salik', playbook: 'fake_fine', tld: 'top', domains: ['salik-pay-demo1.top', 'salik-uae-demo2.top', 'salik-toll-demo3.top'], w: 9, surge: true, signals: 'brand_in_domain,risky_tld,intent_words,pressure,small_fee' },
  { brand: 'rta', playbook: 'fake_fine', tld: 'cfd', domains: ['rta-fines-demo1.cfd', 'rta-parking-demo2.cfd'], w: 7, signals: 'brand_in_domain,risky_tld,fake_ae,small_fee' },
  { brand: 'emiratespost', playbook: 'parcel', tld: 'icu', domains: ['emirtespost-demo.icu', 'epost-track-demo.icu', 'empost-ae-demo.icu'], w: 8, signals: 'lookalike,risky_tld,intent_words,small_fee' },
  { brand: 'aramex', playbook: 'parcel', tld: 'xyz', domains: ['aramex-redeliver-demo.xyz'], w: 4, signals: 'brand_in_domain,risky_tld,intent_words' },
  { brand: 'uaepass', playbook: 'id_expiry', tld: 'pages.dev', domains: ['uaepass-verify-demo.pages.dev'], w: 4, signals: 'brand_in_domain,brand_on_free_host,free_host' },
  { brand: 'enbd', playbook: 'bank_block', tld: 'online', domains: ['enbd-secure-demo.online', 'emiratesnbd-kyc-demo.online'], w: 5, signals: 'brand_in_domain,risky_tld,intent_words,tactic_credential_request' },
  { brand: 'adpolice', playbook: 'police_impersonation', tld: null, domains: [], w: 3, signals: 'tactic_authority_call,tactic_payment_diversion,move_channel,foreign_number' },
  { brand: 'etisalat', playbook: 'prize', tld: 'live', domains: ['etisalat-points-demo.live'], w: 4, signals: 'brand_in_domain,risky_tld,pressure' },
  { brand: 'unknown', playbook: 'job', tld: null, domains: [], w: 5, signals: 'tactic_upfront_fee,move_channel' },
  { brand: 'unknown', playbook: 'investment', tld: 'vip', domains: ['usdt-profit-demo.vip'], w: 3, signals: 'tactic_payment_diversion,risky_tld' },
  { brand: 'dewa', playbook: 'utility', tld: 'shop', domains: ['dewa-refund-demo.shop'], w: 2, signals: 'brand_in_domain,risky_tld,intent_words' },
  { brand: 'unknown', playbook: 'family_emergency', tld: null, domains: [], w: 2, signals: 'tactic_payment_diversion,tactic_secrecy' },
];
const CHANNELS = { fake_fine: [['sms', 8], ['whatsapp', 2], ['qr', 1]], parcel: [['sms', 7], ['whatsapp', 2], ['email', 1]], id_expiry: [['sms', 5], ['email', 2]], bank_block: [['sms', 5], ['call', 3], ['whatsapp', 1]], police_impersonation: [['call', 5], ['whatsapp', 4]], prize: [['sms', 6], ['whatsapp', 2]], job: [['whatsapp', 6], ['social', 4]], investment: [['social', 6], ['whatsapp', 3]], utility: [['sms', 5], ['email', 2]], family_emergency: [['whatsapp', 9]] };
const EMIRATES = [['AD', 32], ['DXB', 38], ['SHJ', 14], ['AJM', 6], ['RAK', 5], ['FUJ', 3], ['UAQ', 2]];

const q = (v) => (v == null ? 'NULL' : typeof v === 'number' ? String(v) : `'${String(v).replace(/'/g, "''")}'`);
const now = Date.now();
const lines = ['DELETE FROM ss_reports WHERE demo = 1;', 'DELETE FROM ss_campaigns WHERE demo = 1;', "DELETE FROM ss_hunts WHERE domain LIKE '%demo%';", "DELETE FROM ss_daily WHERE day >= '2000-01-01' AND kind LIKE 'demo%';"];
const stats = CAMPAIGNS.map(() => ({ reports: 0, victims: 0, first: null, last: null }));
const reportRows = [];

for (let d = 13; d >= 0; d--) {
  for (let ci = 0; ci < CAMPAIGNS.length; ci++) {
    const c = CAMPAIGNS[ci];
    let n = Math.round(c.w * (0.6 + rnd() * 0.9) * (d < 3 ? 1.25 : 1));
    if (c.surge && d === 0) n = c.w * 4;            // today's Salik surge
    if (c.playbook === 'id_expiry' && d > 8) n = 0;  // a newer campaign
    for (let i = 0; i < n; i++) {
      const ts = new Date(now - d * 86400000 - Math.floor(rnd() * (d === 0 ? 10 : 23)) * 3600000 - Math.floor(rnd() * 3600000)).toISOString().replace('T', ' ').slice(0, 19);
      const domain = c.domains.length ? pick(c.domains) : null;
      const lost = rnd() < (c.playbook === 'police_impersonation' || c.playbook === 'investment' ? 0.18 : 0.05) ? 1 : 0;
      const st = stats[ci];
      st.reports++; st.victims += lost;
      st.first = !st.first || ts < st.first ? ts : st.first; st.last = !st.last || ts > st.last ? ts : st.last;
      reportRows.push(`(${q(ts)}, ${q(weighted(CHANNELS[c.playbook]))}, ${q(c.brand)}, ${q(c.playbook)}, ${q(domain)}, ${q(domain ? domain.replace(/\d+/g, '#') : null)}, ${q(c.tld)}, ${q(c.tld === 'pages.dev' ? 'pages.dev' : null)}, 'dangerous', ${70 + Math.floor(rnd() * 28)}, ${q(c.signals)}, ${rnd() < 0.7 ? q(weighted(EMIRATES)) : 'NULL'}, ${lost}, ${ci + 9001}, 1)`);
    }
  }
}
CAMPAIGNS.forEach((c, ci) => {
  const st = stats[ci];
  lines.push(`INSERT INTO ss_campaigns (id, key, brand, playbook, tld, first_seen, last_seen, reports, victims, domains, status, demo) VALUES (${ci + 9001}, ${q(`demo|${c.brand}|${c.playbook}|${c.tld || 'none'}`)}, ${q(c.brand)}, ${q(c.playbook)}, ${q(c.tld)}, ${q(st.first)}, ${q(st.last)}, ${st.reports}, ${st.victims}, ${q(JSON.stringify(c.domains))}, ${q(ci === 3 ? 'takedown_requested' : ci === 10 ? 'down' : 'active')}, 1);`);
});
for (let i = 0; i < reportRows.length; i += 50) {
  lines.push(`INSERT INTO ss_reports (created_at, channel, brand, playbook, domain, domain_shape, tld, free_host, verdict, score, signals, emirate, lost_money, campaign_id, demo) VALUES\n${reportRows.slice(i, i + 50).join(',\n')};`);
}
const hunts = [
  ['salik-pay-demo4.top', 'salik', 'ct', 'cert issued 2 h ago by R11 — not yet seen in any SMS', 88, 'new'],
  ['rta-ae-demo.online', 'rta', 'dns', 'resolves to 203.0.113.24 (demo)', 72, 'watching'],
  ['uaepass-login-demo.site', 'uaepass', 'ct', 'cert issued yesterday by E6', 91, 'new'],
  ['emiratespost-uae-demo.top', 'emiratespost', 'dns', 'resolves to 198.51.100.7 (demo)', 80, 'takedown_requested'],
];
hunts.forEach(([d, b, s, det, sc, st], i) => lines.push(`INSERT INTO ss_hunts (domain, brand, source, first_seen, detail, score, status) VALUES (${q(d)}, ${q(b)}, ${q(s)}, ${q(new Date(now - i * 7200000).toISOString().replace('T', ' ').slice(0, 19))}, ${q(det)}, ${sc}, ${q(st)}) ON CONFLICT(domain) DO NOTHING;`));

writeFileSync(new URL('../schema/demo-seed.sql', import.meta.url), lines.join('\n') + '\n');
console.log(`demo-seed.sql: ${reportRows.length} reports, ${CAMPAIGNS.length} campaigns, ${hunts.length} hunts`);
