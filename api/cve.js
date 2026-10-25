// Backend CVE/CVSS untuk Site Exposure Audit (Vercel serverless, tiada dependency).
// Fungsi: cari CVE dalam NVD API 2.0 untuk satu produk (+ versi), pulangkan skor CVSS asas, vector, dan penanda CISA KEV.
// Pilihan: tetapkan env NVD_API_KEY (percuma di nvd.nist.gov) supaya had request jauh lebih longgar.
const KEY = process.env.NVD_API_KEY || '';
const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0?';
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function nvd(params) {
  const r = await fetch(NVD + new URLSearchParams(params), { headers: KEY ? { apiKey: KEY } : {}, signal: AbortSignal.timeout(25000) });
  if (r.status === 403 || r.status === 429) throw new Error('NVD rate limit reached. Set NVD_API_KEY on the server or try again in a minute');
  if (!r.ok) throw new Error('NVD HTTP ' + r.status);
  return r.json();
}
// Pilih metrik CVSS: v4.0 > v3.1 > v3.0 > v2.0 (utamakan sumber "Primary" = NVD)
function pickCvss(cve) {
  const m = cve.metrics || {};
  for (const [k, ver] of [['cvssMetricV40', '4.0'], ['cvssMetricV31', '3.1'], ['cvssMetricV30', '3.0'], ['cvssMetricV2', '2.0']]) {
    const arr = m[k] || [], e = arr.find(x => x.type === 'Primary') || arr[0];
    if (e && e.cvssData) return { score: e.cvssData.baseScore, ver, vector: e.cvssData.vectorString };
  }
  return null;
}
// Tahap mengikut FIRST: 0.1-3.9 Low, 4.0-6.9 Medium, 7.0-8.9 High, 9.0-10.0 Critical
const sevOf = s => s >= 9 ? 'Critical' : s >= 7 ? 'High' : s >= 4 ? 'Medium' : s > 0 ? 'Low' : 'None';
function shape(v) {
  const c = v.cve, s = pickCvss(c), d = ((c.descriptions || []).find(x => x.lang === 'en') || {}).value || '';
  return { id: c.id, score: s ? s.score : null, sev: s ? sevOf(s.score) : 'N/A', ver: s ? s.ver : '', vector: s ? s.vector : '', kev: !!c.cisaExploitAdd, published: c.published || '', desc: d.slice(0, 220) };
}
// Susun: CISA KEV dahulu, kemudian skor tertinggi, kemudian paling baru
const rank = (a, b) => (b.kev - a.kev) || ((b.score || 0) - (a.score || 0)) || String(b.published).localeCompare(String(a.published));

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'content-type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });
  const { name = '', cpe = '', version = null } = req.body || {};
  if (!/^[a-z0-9_.-]+:[a-z0-9_.-]+$/.test(cpe)) return res.status(400).json({ error: 'invalid cpe' });
  if (version != null && !/^\d+(\.\d+){0,3}$/.test(String(version))) return res.status(400).json({ error: 'invalid version' });
  const base = 'cpe:2.3:a:' + cpe + ':' + (version || '*') + ':*:*:*:*:*:*:*:*';
  const gap = KEY ? 700 : 6500; let n = 0;
  const q = async p => { if (n++) await sleep(gap); return nvd({ virtualMatchString: base, resultsPerPage: '100', ...p }); };
  try {
    const counts = { critical: 0, high: 0 }; let items = [], partial = false;
    const crit = await q({ cvssV3Severity: 'CRITICAL' });
    counts.critical = crit.totalResults; partial = crit.totalResults > 100;
    items.push(...(crit.vulnerabilities || []).map(shape));
    if (version) { // produk berversi: kira juga CVE High
      const high = await q({ cvssV3Severity: 'HIGH' });
      counts.high = high.totalResults; partial = partial || high.totalResults > 100;
      items.push(...(high.vulnerabilities || []).map(shape));
    }
    items = items.sort(rank).slice(0, 5);
    res.status(200).json({ name, version: version || null, confirmed: !!version, counts, items, partial });
  } catch (e) { res.status(502).json({ error: e.message }); }
};
