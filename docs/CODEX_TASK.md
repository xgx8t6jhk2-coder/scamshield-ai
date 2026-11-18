# Codex task — ScamShield AI (Abu Dhabi Police ScamShield AI hackathon, Nov 2026)

Project root: this folder. Claude is building `public/` (web app + police dashboard), `functions/` (Cloudflare Pages API) and docs.
**Do not edit anything in `public/` or `functions/`.** Only create/modify files in `extension/`, `eval/` and `scripts/`.

The detection engine is `public/engine/scamshield.js` (ES module, zero deps). Read it first. Exports:
`analyzeUrl(url)`, `analyzeMessage(text, {sender})`, `fingerprint(result)`, `BRANDS`, `lookalikeCandidates(brandId)`, `ENGINE_VERSION`.
Each result has `{score 0-100, verdict: 'safe'|'suspicious'|'dangerous', signals:[{id, weight, en, ar, severity}], impersonatedBrand, advice:{en:[],ar:[]}}`.

## Part 1 — Browser extension `extension/` (Manifest V3, Chrome + Edge)
Name: "ScamShield AI Guard" / "درع الاحتيال". Bilingual EN/AR (RTL for Arabic), language follows `navigator.language`.
- `scripts/build-extension.mjs`: copies `public/engine/scamshield.js` into `extension/engine/scamshield.js` (so the engine stays single-sourced). Run it.
- Background service worker (module) listens to `webNavigation.onBeforeNavigate`/`onCommitted` for top frames, runs `analyzeUrl` **locally**. Nothing about browsing is sent anywhere.
- `dangerous` → redirect the tab to `warning.html?u=<encoded>` : full-page red interstitial, shows the top 3 signals (EN+AR), the impersonated brand's official domain, buttons "Go back to safety" and a small "I understand the risk, continue" link (adds host to a session allow-list), plus "Report to Abu Dhabi Police" which POSTs `{fingerprint: fingerprint(result), channel: 'extension'}` to `https://scamshield-ai-eaj.pages.dev/api/report` only when the user clicks.
- `suspicious` → orange badge "!" on the action icon.
- Context menu on links: "Check this link with ScamShield" → shows a notification/popup with the verdict, without opening the link.
- Popup (`popup.html`): verdict for the current tab, score ring, top signals, report button, link to https://scamshield-ai-eaj.pages.dev.
- Content script: hover any link in Gmail/Outlook web/WhatsApp Web (`web.whatsapp.com`) and dangerous links get a red dashed outline + tooltip. Keep it light (scan anchors on mutation, debounce).
- Icons: generate simple PNG shield icons (16/32/48/128) with a Node script (no external deps — write a tiny PNG encoder with zlib) — navy #0B1F3A shield, gold #C9A227 check.
- Design: navy #0B1F3A, gold #C9A227, danger #E5484D, warn #F5A524, ok #30A46C. Font: system-ui. Must look polished.
- `extension/README.md`: how to load unpacked, permissions and why each is needed, privacy statement.

## Part 2 — Evaluation `eval/`
- `eval/corpus.json`: **at least 200** labelled samples you write yourself (synthetic, realistic, modelled on publicly reported UAE scam *types* — do not copy real messages verbatim). Mix: ~45% scam messages (Arabic, English, Arabizi, mixed), ~25% benign messages (real-looking OTPs from official sender, delivery notifications from real domains, family chats, government reminders that link to real .gov.ae domains), ~30% URLs (phishing look-alikes vs real official URLs).
  Item: `{ "id", "type": "message"|"url", "lang": "ar"|"en"|"mixed", "text", "sender"?, "label": "scam"|"benign", "category" }`.
  Include hard cases: legit messages that mention fines with official links, legit bit.ly from a known org, scams with no link (phone-call or WhatsApp move), Unicode/punycode tricks, hxxp-defanged, "Hi mum" scams, job/task scams, crypto, sextortion, fake charity, UAE PASS, Emirates ID, Salik, Darb, DEWA, Etisalat points, Emirates Post, Aramex.
- `eval/run-eval.mjs`: runs the engine on the corpus (`scam` if verdict != 'safe'), prints and writes `eval/RESULTS.md` with: accuracy, precision, recall, F1, confusion matrix, per-category recall, per-language metrics, latency (mean/p95 ms per item), and a list of every false positive and false negative with its score and signals.
- Do **not** tune the corpus to the engine. If you find engine weaknesses, list them in `eval/ENGINE_FINDINGS.md` with concrete proposed regex/weight fixes (Claude will apply them to the engine).

When finished, print a short summary of what you built and the eval numbers.
