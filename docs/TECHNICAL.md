# ScamShield AI — Technical Document

Version 1.0 · 18 Nov 2026 · Abu Dhabi Police × 42 Abu Dhabi AI Hackathon for Combating Cyber Crime

## 1. Scope

ScamShield AI detects and explains SMS, WhatsApp, email, link and QR fraud aimed at UAE residents. It turns anonymous resident reports into campaign intelligence for police. It also finds phishing infrastructure before it is used, and speeds up takedown. This document covers the architecture, detection models, AI model choices, privacy design, security, evaluation, and limitations.

## 2. Architecture

```
Client tier (no server needed)        Edge tier (Cloudflare Pages Functions)          Data tier
──────────────────────────────        ───────────────────────────────────────         ─────────
PWA (index.html, app.js)       ─────▶ POST /api/scan      → enrich.js + ai.js          D1 (SQLite)
Extension (MV3, background.js)        POST /api/report    → fingerprint → campaigns    ss_reports
engine/scamshield.js  ◀── same file ─ GET  /api/stats     → aggregates, surges         ss_campaigns
Tesseract.js OCR (in browser)         GET  /api/hunt      → crt.sh + DoH sweep         ss_hunts
jsQR (in browser)                     GET  /api/takedown  → RDAP + DoH + evidence      ss_daily
Service worker (offline engine)       GET  /api/v1/check  → partner API                ss_rate
                                      Workers AI binding  → Llama 3.3 70B (fallback 3.1 8B)
```

One JavaScript module, `public/engine/scamshield.js`, is the single source of truth for detection. The browser, the extension (copied by `scripts/build-extension.mjs`) and the edge all import it, so a verdict never depends on where it was computed.

## 3. Detection engine (on-device)

### 3.1 Link analysis — `analyzeUrl(url)`
1. **Normalisation.** Strips zero-width and bidi control characters. Re-fangs `hxxp` and `[.]`. Adds a missing scheme.
2. **Registrable domain.** A public-suffix subset that includes `gov.ae`, `co.ae` and GCC suffixes. Free-hosting platforms (`pages.dev`, `web.app`, `netlify.app` …) are treated as suffixes, so each tenant counts as its own domain.
3. **Trust short-circuit.** Official domains of 43 UAE entities, plus any `*.gov.ae`, return "safe" immediately (score ≤ 10).
4. **Structural signals.** IP host, `user@host` disguise, punycode or mixed scripts (the label is decoded with an embedded RFC 3492 decoder), non-standard port, http, stacked sub-domains, hyphen-chains, digit runs, risky TLDs, shorteners, free hosts, fake `gov`, fake `ae`, nested redirect parameters (scored by the inner URL's risk), direct app or file downloads, and intent words (`pay`, `fine`, `otp`, `دفع` …).
5. **Brand impersonation.** The host is folded through a confusables map (Cyrillic and Greek homoglyphs, `0→o`, `rn→m`, `vv→w`) and then tested three ways: (a) a brand keyword appears in a non-official domain, (b) Levenshtein ≤ 1–2 from an official label (typosquat), (c) the brand appears only in the path. A brand on a free host adds extra weight.

### 3.2 Message analysis — `analyzeMessage(text, {sender})`
Four evidence families:

| Family | Count | Examples |
|---|---:|---|
| **Playbooks** (the story) | 12 | fake fine/toll, parcel fee, bank block, prize, task job, investment, police threat, ID/UAE PASS expiry, utility, "new number" family, sextortion, charity |
| **Tactics** (the manipulation) | 7 | credential request (with negation guard, so "never share this code" is not flagged), approval coercion, payment diversion, secrecy, document harvest, upfront fee, authority claim |
| **Context** | — | time pressure, small fee, asks to click, move to WhatsApp/Telegram, foreign numbers, personal-number sender claiming to be an organisation |
| **Links** | ≤ 8 | each link analysed as above. Brand named in the text but the link goes elsewhere = strong signal |

**Backing rule.** A playbook (story) on its own weighs 35 %. It counts in full only with a link, an action request or a tactic. This is what keeps "I paid my Salik today" safe.

**Official-links dampener.** If every link is a verified official domain and no hard tactic is present, the text evidence is multiplied by 0.25.

**Arabizi.** A lexicon of about 45 regex stems maps Gulf Latin-script Arabic (`7awel`, `flous`, `shurta`, `t5aber`, `ba7ot` …) to Arabic tokens that the Arabic rules then read. It only runs when real Arabizi is detected (a digit-letter mix).

### 3.3 Scoring
Each signal carries a signed weight. Score = `100·(1 − e^(−Σw/50))`, a saturating curve. For messages, text and link evidence combine like independent probabilities: `1 − (1 − text)(1 − link)`. Verdicts: ≥ 65 dangerous, ≥ 35 suspicious, else safe. Every signal carries an English and an Arabic explanation and a source tag (engine / live / page / AI / community).

### 3.4 Privacy-safe fingerprint
`fingerprint(result)` = `{brand, playbook, tld, domain (registrable only), domainShape (digits masked), freeHost, verdict, score, signalIds}`. It contains no text, no path, no phone numbers and no identifiers. This is the only thing a report ever sends.

## 4. Live enrichment (edge, deep-check mode)

| Check | Method | Safety |
|---|---|---|
| Redirect unrolling | `fetch(redirect:'manual')` up to 6 hops, plus meta-refresh and `location=` detection in the first 120 KB | Blocks private, loopback and link-local hosts (SSRF guard). 5 s timeout per hop. No JavaScript is executed |
| Domain age and registrar | RDAP via rdap.org | < 30 days: +35, < 6 months: +15, > 5 years: −12 |
| DNS | Cloudflare DNS-over-HTTPS | NXDOMAIN noted as "possibly taken down" |
| Landing page | Static HTML inspection | Card/CVV fields +35, OTP +25, Emirates ID +15, `api.telegram.org/bot` +60, off-site form +25, obfuscation +15, brand title plus credential form on a non-official host +40 |
| Community | D1 lookup by domain | ≥ 3 independent reports: floor at 70 |

## 5. AI model choices

| Option considered | Decision | Reason |
|---|---|---|
| Frontier API (GPT/Claude/Gemini) | Not used in the prototype | Message text would leave for a third-party vendor. Cost per message. Data-residency questions |
| Fine-tuned small classifier (e.g. AraBERT) | Future work | Needs a large labelled UAE corpus that does not exist publicly. Our 350 synthetic samples are too few to train on honestly |
| **Llama 3.3 70B Instruct (fp8) on Cloudflare Workers AI** | **Chosen** | Strong multilingual reading including Arabic and Arabizi. Runs on the same provider as the API (no extra processor). Open weights, so it can be self-hosted in-country later. JSON mode. No training on prompts |
| Llama 3.1 8B Instruct | Automatic fallback | Cheap and fast if the 70B model is unavailable |

**Prompt.** A system prompt describes the UAE scam taxonomy and the legitimate look-alikes (real OTPs, real delivery links). The model returns JSON: `scam_probability`, `category`, `red_flags`, `explanation_en`, `explanation_ar`. Temperature 0.1. The rule engine's pre-verdict is passed as a hint.

**Merge policy (explainability first).**
- AI ≥ 0.80 and rules < 65: add an `ai_judgement` signal and raise the score to at least 66.
- AI ≤ 0.15, rules < 50 and no high-weight rule signal: −10.
- In every other case the rules decide. The AI explanation is always shown to the user, labelled as AI.

**Why rules plus AI and not AI alone.** Rules are deterministic, explainable, offline and free. They give precision and run on every keystroke. The AI gives recall on wording the rules have never seen. The evaluation (§8) shows that neither is enough alone.

## 6. Proactive hunting and takedown

**Certificate Transparency.** `crt.sh` is queried for `%<brand-label>%`. Each certificate name is scored with the engine, and non-safe hosts are kept. Every HTTPS phishing site must obtain a public certificate, often hours before the SMS campaign starts.

**Permutation DNS sweep.** `lookalikeCandidates(brand)` generates omission, repetition, transposition, homoglyph and affix variants (`-uae`, `-pay`, `-fines`, `gov-` …). These are crossed with high-abuse TLDs and resolved over DoH, up to 90 names per hunt. Live names go on the watch-list (`ss_hunts`).

**Takedown pack.** `/api/takedown?domain=` assembles the RDAP registrar, abuse e-mail and phone, A/NS/MX records, engine findings, community report counts and hunt provenance. It returns a drafted abuse notice with a reference number, plus a JSON evidence file. Analysts mark status (`watching → takedown_requested → down`) with a bearer analyst key.

**Campaigns and surges.** Reports cluster by `brand × playbook × TLD`. A surge alert fires when the last 24 h for a brand and playbook exceeds 1.8× the window's daily average, with at least 3 reports.

## 7. Privacy design

| Principle | Implementation |
|---|---|
| Data minimisation | Reports are fingerprints only (§3.4). Scans store only `day, kind, verdict` counters |
| Local first | Engine, OCR and QR all run on the device. "On-device only" mode makes zero network calls |
| Purpose limitation | Scan content is analysed in memory and discarded. It is not logged or echoed back beyond the response |
| No identifiers | No accounts, cookies or analytics. Rate limiting uses `SHA-256(ip | bucket | minute | salt)` truncated, and rows are deleted after 5 minutes |
| Transparency | Every verdict explains itself. A public `/privacy` page. Demo data is flagged `demo = 1` and can be switched off |
| Least privilege | The police dashboard sees only infrastructure and aggregates. Write actions need an analyst key |
| Legal alignment | Designed around UAE PDPL (Federal Decree-Law 45/2021) principles. Production: in-country hosting, DPIA, retention schedule |

The extension checks every navigation locally. It sends nothing unless the user presses Report.

## 8. Evaluation

**Datasets.** Both are synthetic. The scenarios were written from publicly described UAE fraud types; no real victim messages were used.
- `eval/corpus.json`: 200 items (90 scam messages, 50 benign messages, 60 URLs). Written by the Codex agent before tuning. **Used for development.**
- `eval/holdout.json`: 150 items. Written in a separate session under instructions not to read the engine and not to change items after seeing results. A checksum was verified before and after the run. **Never tuned on.** Only per-category aggregates were inspected.

| Setting | Accuracy | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| Rules, dev | 92.5 % | 99.1 % | 88.3 % | 93.4 % |
| Rules, holdout | 62.0 % | 84.6 % | 47.3 % | 60.7 % |
| Rules + live + AI, holdout | 85.3 % | 85.9 % | 91.4 % | 88.5 % |

Holdout recall for the full pipeline by language: Arabic 100 %, English 88 %, Arabizi/mixed 91 %. Rules-only Arabizi recall was 12 %.

**Reading the numbers.** The 30-point dev-to-holdout drop for rules shows overfitting to the style of the dev set, which is expected for hand-written rules. The full pipeline holds up on unseen wording. Its weakness is precision: 14 benign holdout messages were flagged, mostly by the AI raising them. The next step is to calibrate the AI threshold on a third, separate validation set, not on the holdout.

**Latency.** Engine: 0.3 ms mean per item (Node, M-series). Deep check: about 3.8 s median and 8.7 s p95 end-to-end, dominated by remote link fetches and the 70B model.

## 9. Security considerations

- **SSRF.** Unrolling refuses private, loopback, link-local and `.local`/`.internal` hosts. *Known gap:* DNS-rebinding to private IPs is not resolved before fetch. Production should resolve first and pin the IP.
- **Malicious pages.** Pages are only read as text, never rendered or executed. The body is capped at 120 KB.
- **Abuse of the API.** Hashed per-minute rate limits apply (scan 30/min, report 10/min, v1 120/min). Report fields are whitelisted and character-filtered.
- **Report poisoning.** One person could fake reports against a legitimate domain. Mitigations: official domains can never be flagged, community weight caps at a floor of 70, and status changes need an analyst. Production would add device attestation via the official app.
- **XSS.** All dynamic content is escaped. Security headers: `nosniff`, `no-referrer`, `X-Frame-Options: DENY`, and a restricted Permissions-Policy.

## 10. Limitations and roadmap

| Now | Next |
|---|---|
| Synthetic evaluation data | Partner with AD Police / TDRA for real, anonymised, labelled reports |
| Rules + general LLM | Fine-tune an Arabic classifier (AraBERT or a small Llama) on that data. Calibrate thresholds on a separate validation split |
| Static page inspection | Sandboxed headless rendering for JavaScript-only phishing kits, plus screenshot similarity to official login pages |
| crt.sh polling | Stream CT logs (certstream) for real-time alerts |
| Coarse campaign key | Cluster on domain shape, ASN, registrar and registration time |
| Web PWA and extension | Native SMS filter integration (iOS Message Filter extension, Android) and a WhatsApp bot through the official Abu Dhabi Police channel |
| Cloudflare global edge | In-country hosting and self-hosted open-weight model for full data residency |
