/* Second-opinion language model (Cloudflare Workers AI, runs on Cloudflare's network, no third-party AI vendor).
 * Used only for message text, never stored. The rule engine stays the primary, explainable decision;
 * the model catches novel wording the rules have not seen and writes a plain-language explanation. */

const MODELS = ['@cf/meta/llama-3.3-70b-instruct-fp8-fast', '@cf/meta/llama-3.1-8b-instruct'];

const SYSTEM = `You are ScamShield, a fraud analyst for Abu Dhabi Police. You judge SMS, WhatsApp and email messages received by UAE residents.
Known UAE scam types: fake traffic fine / Salik / Darb toll, fake parcel (Emirates Post, Aramex) customs fee, bank or card "blocked", OTP or PIN request,
prize / points expiry, part-time "task" job, guaranteed-profit investment / crypto, fake police or court threat, Emirates ID / UAE PASS / visa expiry,
utility disconnection or refund, "Hi Mum new number" emergency, sextortion, fake charity.
Legitimate messages exist too: real OTPs that say "do not share", delivery updates linking to the real company domain, government reminders on .gov.ae.
Reply with JSON only: {"scam_probability": number 0..1, "category": string, "red_flags": [up to 4 short strings], "explanation_en": one sentence, "explanation_ar": one sentence in Modern Standard Arabic}`;

export async function aiJudge(env, text, engineHint) {
  if (!env.AI || !text || text.length < 8) return null;
  const user = `Message:\n"""${text.slice(0, 1500)}"""\nRule engine pre-check: ${engineHint}`;
  for (const model of MODELS) {
    try {
      const res = await env.AI.run(model, {
        messages: [{ role: 'system', content: SYSTEM }, { role: 'user', content: user }],
        max_tokens: 350,
        temperature: 0.1,
        response_format: { type: 'json_object' },
      });
      const raw = typeof res?.response === 'string' ? res.response : JSON.stringify(res?.response ?? '');
      const j = typeof res?.response === 'object' && res.response ? res.response : JSON.parse(raw.slice(raw.indexOf('{'), raw.lastIndexOf('}') + 1));
      const p = Number(j.scam_probability);
      if (Number.isNaN(p)) continue;
      return {
        model: model.split('/').pop(),
        probability: Math.max(0, Math.min(1, p)),
        category: String(j.category || '').slice(0, 60),
        redFlags: (Array.isArray(j.red_flags) ? j.red_flags : []).slice(0, 4).map((x) => String(x).slice(0, 120)),
        en: String(j.explanation_en || '').slice(0, 300),
        ar: String(j.explanation_ar || '').slice(0, 300),
      };
    } catch (e) { /* try the next model */ }
  }
  return null;
}
