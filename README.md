# ScamShield AI · درع الاحتيال الذكي

**From a resident's phone to the police operations room, in one system.**
Prototype for the Abu Dhabi Police × 42 Abu Dhabi *AI Hackathon for Combating Cyber Crime* (24–30 Nov 2026).

Live demo: **https://scamshield-ai-eaj.pages.dev** · Police dashboard: **/dashboard** · Partner API: **/developers** · Privacy design: **/privacy**

> Independent prototype. Not an official Abu Dhabi Police product.

---

## 1. The problem

UAE residents receive a steady stream of fraudulent SMS, WhatsApp messages, calls and QR codes. They impersonate Salik, RTA, Emirates Post, UAE PASS, banks and the police itself. Three gaps let these scams work:

1. **Residents can't tell real from fake in the moment.** A look-alike domain such as `salik-uae-pay.top` or `emirtespost.icu`, a "AED 12.50" fee and a 24-hour deadline are designed to beat a busy person in five seconds. Many victims are elderly or read Arabic first. Many scams are written in Gulf Arabizi (`7awel el floos`).
2. **Police see scams late and one by one.** Individual complaints arrive after money is lost. The *campaign* behind them (one domain family, one script, hundreds of victims) is invisible until someone joins the dots by hand.
3. **Takedown is slow.** Pulling registrar, DNS and evidence together for each domain takes analyst hours, while the domain lives only days.

## 2. The solution

ScamShield has three layers that feed each other:

| Layer | Who | What it does |
|---|---|---|
| **Citizen shield** (PWA + browser extension) | Residents | Paste a message or link, upload a screenshot, or scan a QR code. You get a verdict in under a second, in Arabic or English, with the reason. It shows "They used `salik-uae-pay.top` / The real one `salik.ae`" with the differing letters highlighted. Then: report anonymously, warn your family with a defanged message, or follow an "I already paid" emergency checklist. |
| **Analysis core** | Edge API | An on-device rule engine (Arabic, English, Arabizi; 43 UAE entities, 12 scam playbooks, 7 manipulation tactics). Optional deep check adds safe link detonation (redirect unrolling, RDAP domain age, landing-page inspection for card/OTP/Emirates ID forms and Telegram exfiltration) and an **AI analyst** (Llama 3.3 70B on Cloudflare Workers AI) as a second opinion. |
| **Police command** | Analysts | Anonymous reports cluster into **campaigns**. Surge alerts fire ("Salik fake-fine ×4 vs average"). **Proactive hunting** searches Certificate Transparency logs and sweeps look-alike domains over live DNS, finding the phishing site *before the SMS wave*. A one-click **takedown pack** gathers registrar, abuse contact, DNS and evidence, and drafts the abuse notice. |

### What makes it different
- **Privacy by construction.** The engine runs on the phone. Screenshot OCR and QR decoding run in the browser. Reports are structural fingerprints: brand, scam type and domain. There is never message text, phone number or IP. See [/privacy](public/privacy.html).
- **Catches scams with no link at all.** The *tactics* layer detects how the scammer operates: asking for OTPs, coercing UAE PASS approvals, diverting payment to a "holding account", secrecy, document harvesting, upfront fees. It does not depend on the story they tell.
- **Explainable.** Every verdict lists its reasons in both languages. The AI can raise a borderline verdict but never silently overrides strong rule evidence.
- **Proactive, not only reactive.** It does CT-log and DNS hunting and produces takedown packs. The police act on infrastructure, not just on complaints.
- **Arabizi-aware.** A lexicon maps Gulf chat Arabizi to Arabic, so `ma t5aber el bank, 7awel` is understood.

## 3. Results (measured, not claimed)

| Evaluation | Accuracy | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| Rules only, dev corpus (200, used for tuning) | 92.5% | 99.1% | 88.3% | 93.4% |
| Rules only, **blind holdout** (150, written separately, never tuned on) | 62.0% | 84.6% | 47.3% | 60.7% |
| **Full pipeline (rules + live checks + AI), blind holdout** | **85.3%** | **85.9%** | **91.4%** | **88.5%** |

The gap between dev and holdout for rules alone is the honest reason the AI layer exists. Rules are fast, private and precise, but they overfit. The AI analyst carries generalisation: on the holdout it raised recall from 47% to 91%, and Arabizi recall from 12% to 91%. The full reports are [eval/RESULTS.md](eval/RESULTS.md), [eval/HOLDOUT_RESULTS.md](eval/HOLDOUT_RESULTS.md) and [eval/HYBRID_HOLDOUT_RESULTS.md](eval/HYBRID_HOLDOUT_RESULTS.md).

On-device latency is about 0.3 ms per message (mean), and about 4 s end-to-end for a deep check with live link detonation and AI.

## 4. Architecture

```
 Phone / browser                         Cloudflare edge (Pages Functions)                Police
┌──────────────────────┐   opt-in    ┌────────────────────────────────────┐      ┌──────────────────────┐
│ PWA  ·  Extension    │──────────▶ │ /api/scan   unroll · RDAP · page   │      │ /dashboard           │
│ engine/scamshield.js │  deep check │             inspect · Workers AI   │      │ campaigns · surges   │
│ OCR (Tesseract.js)   │            │ /api/report  fingerprint → D1      │────▶ │ hunting · takedown   │
│ QR (jsQR)            │──report──▶ │ /api/hunt    crt.sh + DNS sweep     │      │ /api/stats           │
│ verdict < 1 ms       │            │ /api/takedown RDAP + evidence pack │      └──────────────────────┘
└──────────────────────┘            │ /api/v1/check partner API          │
                                    └────────────────────────────────────┘
```

| Path | Purpose |
|---|---|
| `public/engine/scamshield.js` | The engine. Zero dependencies, runs in browser, extension and edge. |
| `public/index.html`, `assets/app.js`, `assets/fx.*` | Citizen PWA (bilingual, RTL, share-target, offline). |
| `public/dashboard.html`, `assets/dashboard.*` | Police command dashboard. |
| `functions/api/*` | Edge API: scan, report, stats, hunt, takedown, v1/check. |
| `functions/_lib/*` | Enrichment (unroll, RDAP, DoH, HTML inspection), AI, HTTP helpers. |
| `extension/` | Chrome/Edge MV3 extension (local checks, interstitial, hover warnings in Gmail/Outlook/WhatsApp Web). |
| `eval/` | Corpus, blind holdout, evaluators, results. |
| `schema/` | D1 schema and demo-seed generator output. |
| `docs/TECHNICAL.md` | Technical document (model choices, privacy, threat model). |
| `docs/ScamShield-AI.pptx` | Presentation. |

## 5. Technical trade-offs

| Decision | Why | Cost we accepted |
|---|---|---|
| Rule engine on device, AI as second opinion | Privacy, works offline, under 1 ms, explainable, no per-message cost | Rules overfit: 47% recall alone on the blind set. AI is required for generalisation. |
| AI cannot override strong rule evidence | Keeps verdicts explainable and stops the model from "talking down" a clear phish | Some AI-only false positives remain (precision 86% on the holdout) |
| Open-weight Llama on Workers AI, not a third-party chatbot API | Data stays on one provider, no training on prompts, cheap | Smaller than frontier models. Arabic explanations are adequate, not perfect |
| Static HTML inspection, no headless browser | Safe (no JS execution), fast, runs at the edge | Misses phishing kits that render only through JavaScript |
| Fingerprint-only reports | Anonymous by construction, PDPL-friendly | Police can't contact a reporter. A production version would add an opt-in "contact me" channel through the official app |
| Campaign key = brand × scam type × TLD | Simple and transparent | Coarse. Production would cluster on domain-shape, hosting ASN and registration time |
| crt.sh for CT search | Free, public | Rate-limited and slow, so it falls back to DNS sweep only. Production would use a CT stream (certstream) |
| D1 (SQLite) | Zero ops for a prototype | Production needs in-country hosting and retention policies |

## 6. Build & run

Requirements: Node 20+, a Cloudflare account, and `wrangler` (`npm i -g wrangler`).

```bash
npm test                                  # rules-only eval on eval/corpus.json → eval/RESULTS.md
npm run test:holdout                      # rules-only eval on blind holdout
SS_KEY=<analyst key> node eval/run-hybrid.mjs eval/holdout.json   # full pipeline eval against a deployment
```

Local development:
```bash
wrangler d1 create scamshield-db          # put the id in wrangler.jsonc
wrangler d1 execute scamshield-db --local --file schema/schema.sql
node scripts/seed-demo.mjs && wrangler d1 execute scamshield-db --local --file schema/demo-seed.sql   # optional demo data (demo=1)
echo 'POLICE_KEY="choose-a-key"' > .dev.vars
npx wrangler pages dev                     # http://localhost:8788
```

Deploy:
```bash
wrangler d1 execute scamshield-db --remote --file schema/schema.sql
wrangler pages secret put POLICE_KEY --project-name scamshield-ai
npm run deploy
```

Browser extension: run `node scripts/build-extension.mjs`, then open `chrome://extensions`, turn on Developer mode, click "Load unpacked" and select `extension/`.

Use the engine anywhere:
```js
import { analyzeMessage, analyzeUrl } from './public/engine/scamshield.js';
analyzeMessage('Salik: unpaid AED 12.50 … https://salik-uae.cfd/pay', { sender: '+639171234567' });
// → { verdict: 'dangerous', score: 98, signals: [{ en, ar, weight }...], advice: { en, ar }, impersonatedBrand: {...} }
```

## 7. Third-party components and IP

All application code in this repository was written for this hackathon. Runtime libraries are loaded from public CDNs under their own open-source licences: Tesseract.js (Apache-2.0), jsQR (Apache-2.0), and Google Fonts IBM Plex Sans Arabic and Space Grotesk (OFL). The AI model is Meta Llama 3.3 (Llama 3.3 Community Licence), served by Cloudflare Workers AI. Organisation names appear only to detect their impersonation. No logos or trademarks are reproduced. The evaluation messages are synthetic and were written from publicly described scam *types*.

## 8. Team

_Add team members (3–5) here before submission._
