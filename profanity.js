// Blocks vulgar/sexual language in text chat and speech (separate from the video nudity AI).
// Kept intentionally moderate: this catches clearly vulgar/sexual words, not every rude word,
// to avoid over-blocking normal conversation. Add more words to the lists below any time.

const ENGLISH = [
  'fuck','fucking','fucker','motherfucker','shit','bullshit','bitch','asshole','dick','dickhead',
  'pussy','cunt','cock','whore','slut','porn','pornhub','nude','nudes','sex chat','sexchat',
  'blowjob','handjob','jerkoff','jerk off','cum','horny','nsfw','xxx','rape','molest',
];

// Common Hinglish / Hindi (Roman script) vulgar/sexual words and their frequent misspellings
const HINGLISH = [
  'chutiya','chutia','madarchod','behenchod','bhenchod','bhosdike','bhosdi','randi','randiwa',
  'gandu','gaand','lund','lauda','loda','laude','chut','chudai','chod','chodu','harami','saala kutta',
  'kutta','kutti','sex karo','nangi','nanga','boobs dikha','nangi photo','nude photo','video call sex',
];

// Turn a word list into regexes that also catch spaced-out or symbol-separated spellings,
// e.g. "f u c k", "f.u.c.k", "f*ck" -> still matches "fuck".
function toPattern(word) {
  const loose = word
    .split('')
    .map((ch) => (/[a-z0-9]/i.test(ch) ? ch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '[\\s\\W_]*' : ch))
    .join('');
  return new RegExp('(?:^|\\W)' + loose.replace(/\s\[\\s\\W_\]\*/g, '[\\s\\W_]*') + '(?:$|\\W)', 'i');
}

const PATTERNS = [...ENGLISH, ...HINGLISH].map(toPattern);

function containsVulgarLanguage(text) {
  const t = String(text || '').toLowerCase();
  return PATTERNS.some((re) => re.test(t));
}

module.exports = { containsVulgarLanguage };
