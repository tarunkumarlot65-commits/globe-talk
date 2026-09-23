// Detects whether an IP is a known VPN/proxy/datacenter, using proxycheck.io's free API.
// Honest limits: this is a best-effort signal, not proof. New/unlisted VPNs, or paid
// residential-proxy services, can slip through. We use it to add friction for ban-evasion,
// not to block every VPN user outright (many real users, especially in countries with
// internet restrictions, rely on VPNs for everyday access).
const TIMEOUT_MS = 2500;
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const cache = new Map();

async function checkProxy(ip) {
  if (!ip || ip === 'unknown' || ip.startsWith('127.') || ip.startsWith('192.168.') || ip === '::1') {
    return { checked: false, isProxy: false };
  }
  const hit = cache.get(ip);
  if (hit && Date.now() - hit.time < CACHE_TTL_MS) return hit.result;

  const key = process.env.PROXYCHECK_API_KEY ? `&key=${process.env.PROXYCHECK_API_KEY}` : '';
  const url = `https://proxycheck.io/v2/${encodeURIComponent(ip)}?vpn=1&asn=0${key}`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  let result = { checked: false, isProxy: false };
  try {
    const r = await fetch(url, { signal: ctrl.signal });
    const d = await r.json();
    const info = d && d[ip];
    if (info) {
      result = { checked: true, isProxy: info.proxy === 'yes', type: info.type || null };
    }
  } catch (e) {
    result = { checked: false, isProxy: false }; // fail open: never block someone just because the check failed
  } finally {
    clearTimeout(timer);
  }
  cache.set(ip, { time: Date.now(), result });
  return result;
}

module.exports = { checkProxy };
