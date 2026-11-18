// Evaluates the FULL deployed pipeline (rules + live link checks + AI analyst) through /api/scan.
// Usage: SS_KEY=<analyst key> node eval/run-hybrid.mjs eval/holdout.json eval/HYBRID_HOLDOUT_RESULTS.md [baseUrl]
import { readFileSync, writeFileSync } from 'node:fs';

const [file = 'eval/holdout.json', out = 'eval/HYBRID_RESULTS.md', base = 'https://scamshield-ai-eaj.pages.dev'] = process.argv.slice(2);
const raw = JSON.parse(readFileSync(file, 'utf8'));
const items = Array.isArray(raw) ? raw : raw.items || raw.samples;
const key = process.env.SS_KEY;

async function scan(it) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await fetch(`${base}/api/scan`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...(key ? { authorization: `Bearer ${key}` } : {}) },
        body: JSON.stringify({ type: it.type === 'url' ? 'url' : 'message', input: it.text, sender: it.sender || '' }),
      });
      if (res.ok) return await res.json();
    } catch {}
    await new Promise((r) => setTimeout(r, 1500));
  }
  return null;
}

const results = [];
let next = 0;
await Promise.all(Array.from({ length: 4 }, async () => {
  while (next < items.length) {
    const it = items[next++];
    const t0 = Date.now();
    const r = await scan(it);
    results.push({ it, r, ms: Date.now() - t0 });
    process.stdout.write(r ? '.' : 'x');
  }
}));
console.log();

const m = (rows) => {
  let tp = 0, fp = 0, fn = 0, tn = 0;
  for (const { it, r } of rows) { if (!r) continue; const p = r.verdict !== 'safe'; const a = it.label === 'scam'; if (p && a) tp++; else if (p) fp++; else if (a) fn++; else tn++; }
  const prec = tp / (tp + fp || 1), rec = tp / (tp + fn || 1);
  return { n: tp + fp + fn + tn, tp, fp, fn, tn, acc: (tp + tn) / (tp + fp + fn + tn || 1), prec, rec, f1: (2 * prec * rec) / (prec + rec || 1) };
};
const pct = (x) => (x * 100).toFixed(2) + '%';
const all = m(results);
const byLang = ['ar', 'en', 'mixed'].map((l) => [l, m(results.filter((x) => x.it.lang === l))]);
const aiUsed = results.filter((x) => x.r?.ai).length;
const aiRaised = results.filter((x) => x.r?.signals?.some((s) => s.id === 'ai_judgement')).length;
const ms = results.map((x) => x.ms).sort((a, b) => a - b);
const errors = results.filter((x) => !x.r).length;

const md = `# ScamShield — full pipeline evaluation (rules + live checks + AI analyst)

File: \`${file}\` · ${items.length} samples · endpoint ${base}/api/scan · ${new Date().toISOString()}
Positive class = scam; suspicious and dangerous both count as positive. ${errors} request errors excluded.

| Accuracy | Precision | Recall | F1 |
| ---: | ---: | ---: | ---: |
| ${pct(all.acc)} | ${pct(all.prec)} | ${pct(all.rec)} | ${pct(all.f1)} |

| Actual | Predicted scam | Predicted benign |
| --- | ---: | ---: |
| Scam | ${all.tp} | ${all.fn} |
| Benign | ${all.fp} | ${all.tn} |

## Per language

| Language | n | Accuracy | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
${byLang.map(([l, x]) => `| ${l} | ${x.n} | ${pct(x.acc)} | ${pct(x.prec)} | ${pct(x.rec)} | ${pct(x.f1)} |`).join('\n')}

## AI analyst

AI opinion returned for ${aiUsed} of ${results.filter((x) => x.it.type !== 'url').length} messages; it raised the verdict on ${aiRaised}.

## Latency (end-to-end, incl. network)

Median ${ms[Math.floor(ms.length / 2)]} ms · p95 ${ms[Math.floor(ms.length * 0.95)]} ms
`;
writeFileSync(out, md);
console.log(md.split('\n').slice(0, 16).join('\n'));
