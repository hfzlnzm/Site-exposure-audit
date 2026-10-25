// Backend kecil untuk Site Exposure Audit (Vercel serverless, tiada dependency).
// Fungsi: sahkan URL penemuan masih hidup, semak security headers, baca robots/sitemap/security.txt.
// Hanya URL dalam domain yang diaudit diterima. Kandungan fail TIDAK dipulangkan, hanya jenis signature.
const dns = require('dns').promises;
const net = require('net');
const UA = 'Mozilla/5.0 (compatible; SiteExposureAudit/1.0)';
const priv = ip => net.isIPv4(ip)
  ? /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip)
  : /^(::1|fc|fd|fe80|::ffff:)/i.test(ip);
const inScope = (h, d) => h === d || h.endsWith('.' + d);
const SIGS = [
  ['env', /^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+/m], ['git', /\[core\]|ref: refs\//],
  ['dir-listing', /<title>Index of/i], ['sql-dump', /CREATE TABLE|INSERT INTO/i],
  ['private-key', /BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY/], ['phpinfo', /phpinfo\(\)|PHP Version/i],
];
const HDRS = ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy'];

async function guard(host) {
  const a = await dns.lookup(host, { all: true });
  if (a.some(x => priv(x.address))) throw new Error('blocked');
}
async function hop(url, d, opts = {}) {
  for (let i = 0; i < 3; i++) {
    const u = new URL(url);
    if (!/^https?:$/.test(u.protocol) || !inScope(u.hostname, d)) throw new Error('out of scope');
    await guard(u.hostname);
    const r = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(8000), ...opts, headers: { 'user-agent': UA, ...(opts.headers || {}) } });
    const loc = r.headers.get('location');
    if (r.status >= 300 && r.status < 400 && loc) { url = new URL(loc, url).href; continue; }
    return r;
  }
  throw new Error('too many redirects');
}
async function probe(url, d) {
  const out = { status: 0, type: '', sig: null };
  try {
    const r = await hop(url, d, { headers: { range: 'bytes=0-2047' } });
    out.status = r.status; out.type = (r.headers.get('content-type') || '').split(';')[0];
    if (r.status >= 200 && r.status < 300) {
      const t = (await r.text()).slice(0, 2048);
      const s = SIGS.find(([, re]) => re.test(t)); if (s) out.sig = s[0];
    }
  } catch (e) { out.error = e.name === 'TimeoutError' ? 'timeout' : e.message; }
  return out;
}
async function site(d) {
  const o = { status: 0, headers: {}, files: {}, disallow: [] };
  try {
    const r = await hop('https://' + d + '/', d);
    o.status = r.status;
    HDRS.forEach(h => o.headers[h] = r.headers.get(h) ? 'present' : 'missing');
  } catch (e) { o.error = e.message; }
  for (const p of ['/robots.txt', '/sitemap.xml', '/.well-known/security.txt']) {
    try {
      const r = await hop('https://' + d + p, d);
      o.files[p] = r.status;
      if (p === '/robots.txt' && r.status === 200) {
        o.disallow = (await r.text()).slice(0, 20000).split('\n')
          .map(l => (l.match(/^\s*Disallow:\s*(\S+)/i) || [])[1]).filter(Boolean).slice(0, 15);
      }
    } catch { o.files[p] = 'error'; }
  }
  return o;
}
module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'content-type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });
  const { domain, urls = [] } = req.body || {};
  const d = String(domain || '').toLowerCase();
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)) return res.status(400).json({ error: 'invalid domain' });
  const allow = (process.env.ALLOWED_DOMAINS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  if (allow.length && !allow.some(a => inScope(d, a))) return res.status(403).json({ error: 'domain not allowed on this server' });
  const list = [...new Set(urls.map(String))].slice(0, 30);
  const [s, ...results] = await Promise.all([site(d), ...list.map(u => probe(u, d))]);
  const map = {}; list.forEach((u, i) => map[u] = results[i]);
  res.status(200).json({ site: s, urls: map });
};
