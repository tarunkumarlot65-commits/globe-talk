// Text translation used by the live voice translator and by text chat.
// Pick a provider in .env:
//   GOOGLE_TRANSLATE_KEY=...            -> Google Cloud Translation (best quality, free monthly quota)
//   LIBRETRANSLATE_URL=https://...      -> LibreTranslate (self-hosted or public, free, weaker quality)
//   (nothing set)                       -> "mock" mode for testing: text comes back as "[hi] your text"
// Needs Node 18 or newer (built-in fetch).

const PROVIDER =
  process.env.TRANSLATE_PROVIDER ||
  (process.env.GOOGLE_TRANSLATE_KEY ? 'google' : process.env.LIBRETRANSLATE_URL ? 'libre' : 'mock');

const TIMEOUT_MS = 6000;
const CACHE_MAX = 800;
const cache = new Map();

if (PROVIDER === 'mock') console.warn('[translate] No translation key set. Using MOCK mode (fake translations, for testing only).');
else console.log('[translate] provider:', PROVIDER);

async function fetchJson(url, body) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    if (!r.ok) throw new Error('translate http ' + r.status);
    return await r.json();
  } finally {
    clearTimeout(timer);
  }
}

// LibreTranslate uses slightly different codes for Chinese
const libreCode = (c) => (c === 'zh-CN' ? 'zh' : c === 'zh-TW' ? 'zt' : c);

async function google(text, from, to) {
  const body = { q: text, target: to, format: 'text' };
  if (from) body.source = from;
  const d = await fetchJson('https://translation.googleapis.com/language/translate/v2?key=' + encodeURIComponent(process.env.GOOGLE_TRANSLATE_KEY), body);
  return d.data.translations[0].translatedText;
}

async function libre(text, from, to) {
  const body = { q: text, source: from ? libreCode(from) : 'auto', target: libreCode(to), format: 'text' };
  if (process.env.LIBRETRANSLATE_KEY) body.api_key = process.env.LIBRETRANSLATE_KEY;
  const d = await fetchJson(process.env.LIBRETRANSLATE_URL.replace(/\/$/, '') + '/translate', body);
  return d.translatedText;
}

async function mock(text, from, to) {
  await new Promise((r) => setTimeout(r, 30));
  return `[${to}] ${text}`;
}

const providers = { google, libre, mock };

async function translate(text, { from = null, to }) {
  const key = (from || '') + '|' + to + '|' + text;
  if (cache.has(key)) return cache.get(key);
  const fn = providers[PROVIDER] || mock;
  const out = await fn(text, from, to);
  if (cache.size >= CACHE_MAX) cache.delete(cache.keys().next().value);
  cache.set(key, out);
  return out;
}

module.exports = { translate, PROVIDER };
