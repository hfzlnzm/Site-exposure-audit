# Site Exposure Audit

**Exposure assessment and security posture check for a domain you own**

Live tool: https://site-exposure-audit.vercel.app

Site Exposure Audit is a browser-based tool that runs Google dorking against a domain, validates what it finds against the live site, checks DNS/mail/header posture, and matches detected software versions against known CVEs in the NVD. Results are shown as a single dashboard: a risk score, exposure findings grouped by category, and detail cards for headers, DNS, subdomains and CVEs.


---

## What this tool is — and isn't


This is an **exposure assessment / OSINT recon tool**, not a vulnerability scanner.

**What it does:**
- Finds what's publicly indexed by Google (exposed files, open directories, backups, `.git`, admin panels, dev/staging environments) via the Serper API.
- Confirms whether each indexed URL is still live, and checks its response signature (e.g. `.env` content, directory listing, SQL dump) via a backend request.
- Reads DNS and mail posture (SPF, DMARC, CAA, name servers) and security headers.
- Enumerates subdomains from certificate transparency logs (crt.sh).
- Fingerprints software (WordPress, PHP, Apache, phpMyAdmin, etc.) from response headers and page source, then looks up matching CVEs and CVSS scores in the NVD.
- Produces a weighted 0–100 risk score and, optionally, an AI-written narrative report.

**What it does NOT do:**
- No port scanning, no service enumeration, no active vulnerability exploitation (no Nmap, no Nuclei, no Burp/ZAP).
- No TLS/cipher inspection, no WHOIS/RDAP lookup (not yet).
- An asset that Google has never indexed will not be found, no matter how exposed it is.
- The CVE match is only as good as the version string the tool can read; many sites don't expose one.

If you need real vulnerability scanning (port scans, exploit-based checks), run Nmap/Nuclei/ZAP against the authorized target separately — that can't run on Vercel's serverless functions (no raw sockets, 60s execution limit).

---

## How it works

```
Domain
  → 22 fixed dork queries, scoped with site:yourdomain.com, via the Serper API
  → results filtered to the target domain and its subdomains
  → each URL re-checked live by the backend (status code, content-type, signature)
  → DNS/mail/header checks + certificate-log subdomain enumeration
  → detected software versions matched against NVD for CVE / CVSS
  → one dashboard: risk score, exposure findings, header/DNS/subdomain/CVE cards
  → optional: an Anthropic key lets Claude turn the raw findings into a written report,
    and answer follow-up questions about the same domain
```

1. **Input** — you enter a domain and a Serper API key (required) and an Anthropic key (optional, for the AI report).
2. **Collection** — 22 dork queries run against Serper, all scoped to `site:yourdomain.com`.
3. **Filtering** — only results on the target domain or its subdomains are kept.
4. **Validation** — `/api/validate` re-fetches each indexed URL directly (range request, 8s timeout, redirects followed only within scope, private/internal IPs blocked) to confirm it's still live and check its response signature. It also reads the homepage once for security headers, `robots.txt` / `sitemap.xml` / `security.txt`, and software version fingerprints (`Server`/`X-Powered-By` headers, WordPress core assets, Divi theme assets).
5. **CVE/CVSS** — `/api/cve` queries the NVD API 2.0 for each detected product. A confirmed version is matched exactly (CVSS v3 Critical + High); an unconfirmed product shows known critical CVEs labelled "may not apply" and is excluded from the score.
6. **Reporting** — with only a Serper key, results are shown as a dashboard with risk score, category breakdown, and detail cards. With an Anthropic key as well, Claude also writes a narrative summary and can answer follow-up questions, scoped strictly to the same domain.

### Note on "passive"

Dork collection (step 2–3) is passive: it only queries Serper's search index, never the target site. **Validation (step 4) is not passive** — `/api/validate` sends a small number of real GET/range requests to the target domain to confirm findings are actually live, rather than trusting Google's cache. This keeps the risk score honest: a hit that's no longer reachable scores 0, not full weight.

---

## Risk score

The 0–100 score is a weighted indicator, not a CVSS score and not proof of a vulnerability:

| Category | Weight (confirmed live) |
|---|---|
| Exposed files (`.env`, `.sql`, keys, etc.) | 25 |
| Version control (`.git`, `.svn`) | 25 |
| Sensitive documents | 15 |
| Backup archives | 15 |
| Open directories | 10 |
| Misconfig files (phpinfo, server-status) | 10 |
| Admin / login panels | 8 |
| Error messages & debug | 8 |
| API & dev environments | 8 |
| Subdomains (informational) | 2 |

Plus DNS/mail gaps (missing SPF/DMARC/CAA), missing security headers, a large or non-production-heavy subdomain footprint, and confirmed Critical/High CVEs on a version-confirmed product. A finding that's indexed but no longer reachable scores 0; one that's access-controlled (401/403) scores half weight. The full breakdown is shown under "How the score is built" on every report.

---

## Setup

### 1. Frontend
`index.html` is a single static file — open it directly, or host it (GitHub Pages, Vercel, any static host).

### 2. Backend (required for validation + CVE matching)
Deploy `api/validate.js` and `api/cve.js` as Vercel serverless functions (or adapt to any Node host that supports `fetch`).

- `vercel.json` must set a longer function timeout, since CVE lookups can take a while:
  ```json
  { "functions": { "api/*.js": { "maxDuration": 60 } } }
  ```
- Environment variables (Vercel → Settings → Environment Variables):
  - `NVD_API_KEY` — optional but recommended. Without it, NVD rate-limits requests to 5 per 30s, which makes CVE lookups slow and prone to failure. Get a free key at https://nvd.nist.gov/developers/request-an-api-key.
  - `ALLOWED_DOMAINS` — optional comma-separated allowlist (e.g. `unikl.edu.my,example.com`) restricting which domains `/api/validate` will send requests to. Recommended for a public deployment.

If `index.html` is hosted separately from the backend (e.g. GitHub Pages), set `API_BASE` near the top of the `<script>` block in `index.html` to your backend's URL.

### 3. Keys (user-supplied, stored in browser only)
- **Serper API key** (required) — serper.dev, for the dork queries.
- **Anthropic API key** (optional) — for the AI-written report and follow-up chat.

Both are stored in `localStorage` in the user's own browser and sent only to Serper/Anthropic directly from the browser; they never pass through this tool's backend.

---

## Project structure

```
index.html        UI + dork logic + report rendering (single file)
api/validate.js    Live validation, security headers, robots/sitemap, tech fingerprint
api/cve.js         NVD CVE/CVSS lookup per detected product
vercel.json        Function timeout config
```

---

## Prioritisation, remediation and reports

- CVEs are ordered **CISA KEV first, then EPSS (FIRST.org), then CVSS**, so the vulnerabilities most likely to be exploited surface first. EPSS is optional: if the FIRST.org API is unreachable the lookup still works.
- Every finding category shows a **How to fix** note with a CWE reference, next to the existing OWASP Top 10 candidates.
- **Download JSON** exports findings, remediation, headers, DNS and CVEs. **Save as PDF** uses the browser's print dialog (all sections are expanded automatically).


## Disclaimer

This tool only surfaces what's already publicly indexed or directly observable from a handful of HTTP requests to the domain itself. It does not confirm exploitability, does not replace a professional penetration test, and should only ever be pointed at a domain you own or are explicitly authorized in writing to test.
