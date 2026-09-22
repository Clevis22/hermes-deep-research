# Candidate sources (probed 2026-09-22 from this Pi)

Method: one keyless request per endpoint, default Python UA, documented API path.
**Usable = HTTP 200 with a real payload.** Rate-limited endpoints were retried with
spacing before being called dead.

> **Wired in already (registry 91 sources / 10 lanes; 89 keyless):** Google Patents (patents lane),
> SearXNG `packages`, the seven security-news feeds, and the security tier
> (Red Hat CVE, Ubuntu CVE, SigmaHQ rules, MITRE CWE, MITRE CAPEC + a working
> ExploitDB parser). **Everything else in this file is verified but NOT registered
> yet** — add it with one `register(name, lane, build, kind, parse, ...)` call in the
> matching lane section. Do not re-add a row that is already wired (the registry is
> the source of truth: `deep_research.py --sources`).
> Re-run `scripts/verify_deep_research.sh` (23 checks) after any change.

The registry is 91 sources. These are verified, not guessed.

## Validated next additions (2026-09-22)

These are the best next integrations because they add structured evidence rather
than another copy of ordinary web results. The first four were live-probed from
this host on 2026-09-22.

| Priority | Source | Auth / cost | Query shape and value | Suggested lane |
|---|---|---|---|---|
| **P0** | **GitHub Advisory Database REST API** | Keyless for public resources | CVE/GHSA, ecosystem, package/version, severity and CWE filters. A keyless `CVE-2021-44228` probe returned the critical GHSA record and four CWE links. | `security` |
| **P0** | **deps.dev API v3** | Keyless | Exact package and version lookups across npm, PyPI, Maven, Cargo, Go, NuGet and RubyGems; adds dependencies, licenses, advisories and provenance. A keyless npm `express` probe returned 289 versions. | `code` / `security` |
| **P0** | **OpenSSF Scorecard API** | Keyless | Repository-shaped queries return a current supply-chain score plus individual checks. Treat the score as a heuristic signal, never a vulnerability verdict. | `security` / `code` |
| **P1** | **OpenReview API v2** | Keyless public search | Term/title/abstract/author search over ML papers, submissions and reviews. A keyless `transformer` probe returned a real Note record. | `academic` |
| **P1** | **Semantic Scholar Academic Graph API** | Keyless for most endpoints; optional free key for a private 1-RPS quota | Direct paper, author, citation and recommendation search. Better provenance and field control than reaching it only through SearXNG. | `academic` |
| **P1** | **GreyNoise Community API v3** | 10 unauthenticated IP lookups/day; free account up to 50/week (business email for key access) | Exact IPv4 enrichment: observed scanner status, benign service classification and last seen. Use only for IP-shaped queries. | `security` / `infra` |
| **P1** | **FRED API** | Free registered key; up to 120 requests/minute | Primary economic time series, releases and historical vintages. Strong for economy, policy and market-context questions. | `public-data` |
| **P1** | **abuse.ch Community APIs** (ThreatFox, URLhaus, MalwareBazaar) | Free Auth-Key under fair-use terms; commercial use may require a paid plan | IOC, malicious URL and malware-hash enrichment. Route only exact indicators to avoid noise and unnecessary calls. | `security` |
| **P2** | **Tavily Search API** | Free key, 1,000 credits/month; pay-as-you-go $0.008/credit | General current-web fallback when the structured lanes are silent. Keep optional so the core remains keyless. | `web` |
| **P2** | **Brave Search API** | Key required; $5 monthly credit (about 1,000 Search calls), then $5/1,000 calls; payment card required | Independent web/news/image index. Attractive as an optional broad-search fallback, but less frictionless than Tavily. | `web` / `news` |
| **P3** | **VirusTotal Public API** | Free community key; 4 requests/minute and 500/day | Useful exact hash, URL, domain and IP enrichment, but public-tier terms prohibit commercial products/workflows. Do not enable by default. | `security` |

Recommended implementation order: GitHub Advisories, deps.dev, Scorecard, then
direct Semantic Scholar/OpenReview. Those five improve evidence quality without
making the default run depend on a credential. Add optional providers behind
environment variables and show them as `skipped_not_applicable` when the query is
the wrong shape, not as coverage gaps.

## OSINT expansion shortlist (2026-09-22)

The registry already includes useful OSINT pivots through CertSpotter CT, Shodan
InternetDB, RIPEstat, AlienVault OTX, urlscan.io, Wayback CDX, SEC EDGAR,
CourtListener, openFEC and Nominatim. These additions cover the largest remaining
gaps. RDAP, PeeringDB, GLEIF and RIPE Atlas were live-probed keylessly from this
host on 2026-09-22.

| Priority | Source | Auth / cost | OSINT value and routing rule |
|---|---|---|---|
| **P0** | **RDAP.org** | Keyless; bootstrap service limits clients to 10 requests per 10 seconds | Domain, IP and ASN registration, status, dates and public entities. Replace ad-hoc WHOIS parsing; call only for exact domain/IP/ASN shapes. |
| **P0** | **PeeringDB** | Keyless guest `GET` requests | ASN-to-network identity, peering policy, facilities, exchanges and interconnection points. Especially useful with RIPEstat and Shodan InternetDB. |
| **P0** | **GLEIF API** | Keyless | Legal entities, LEIs, registered names/addresses, BIC/ISIN mappings and parent-child relationships. Use exact/fuzzy organization-name routing and label matches as registry evidence, not proof of current ownership. |
| **P0** | **OFAC Sanctions List Service** | Keyless API and XML/CSV downloads | Primary US sanctions records, aliases, programs and identifiers. Prefer a cached daily file; require exact entity-shaped queries and prominently warn that name matches need human verification. |
| **P1** | **RIPE Atlas** | Most public reads are keyless; free key/credits only for creating measurements | Public probes and historical ping, traceroute, DNS, TLS and HTTP measurement results. Geographic coordinates are deliberately obfuscated by 80-400 metres. Route only IP/domain/ASN investigations. |
| **P1** | **UK Companies House** | Free registered key; 600 requests per 5 minutes | Live UK company profiles, officers, filing history and insolvency/charge data. Keep optional via `COMPANIES_HOUSE_API_KEY` and use for company names/numbers only. |
| **P1** | **OpenSky Network** | Anonymous access: 400 credits/day per endpoint; free account: 4,000/day; non-commercial use | Live state vectors, tracks and flight records. Route exact ICAO24, callsign or bounded geographic queries; do not issue global requests for ordinary research terms. |
| **P1** | **FAA Aircraft Registry** | Keyless daily bulk CSV (about 60 MB) | US N-number, make/model, registration and deregistration pivots. Cache locally once per day instead of downloading during each research run. |
| **P2** | **OpenSanctions** | Keyless bulk data for non-commercial use under CC BY-NC 4.0; free hosted keys for qualifying public-interest work; commercial search/match is metered | Cross-jurisdiction sanctions, PEPs and corporate relationship data. Valuable but license-sensitive; keep disabled unless the deployment declares an eligible use or supplies a licensed key. |
| **P2** | **WhatsMyName dataset** | Keyless CC BY-SA dataset; downstream checks hit 700+ third-party sites | Username-to-profile discovery. Make it an explicit, opt-in username mode with a small site allowlist, bounded concurrency and per-site rate/terms enforcement—never part of the default 91-source fan-out. |

Implementation order for an OSINT lane: **RDAP + PeeringDB + GLEIF + OFAC** first,
then RIPE Atlas. Together they provide complementary pivots without spraying the
same free-text query across hundreds of services. Every adapter should declare its
accepted query shape and return `skipped_not_applicable` for everything else.

## Tier 1 - closes a gap the skill itself declares

| Source | Endpoint | Evidence | Suggested lane |
|---|---|---|---|
| **Google Patents xhr** | `patents.google.com/xhr/query?url=q%3D<terms>` | 200, 3/3 identical runs; `total_num_results` + publication numbers/titles ("US12381958B2 ...regionally contiguous proxy..."). Closes the skill's "no working keyless patent search" gap. | new `patents` |
| **SearXNG `packages`** | `/search?...categories=packages` | 74 rows in ONE call: crates.io, npm, Packagist, Hex, pkg.go.dev, pub.dev, lib.rs, Docker Hub. Cheaper than 8 separate registry calls. | `code` |
| **SearXNG `it`** | `categories=it` | 71 rows: GitHub, Docker Hub, MDN, StackOverflow, Superuser, AskUbuntu. | `code` |
| **SearXNG `news`** | `categories=news` | 57 rows: Reuters, Wikinews, Google News, DDG news. Adds Reuters, which the registry lacks. | `news` |
| **Red Hat CVE API** | `access.redhat.com/hydra/rest/securitydata/cve.json?per_page=N` | 200 JSON, newest CVEs. | `security` |
| **Ubuntu CVE tracker** | `ubuntu.com/security/cves.json?limit=N` | 200 JSON, CVE id + timestamps. | `security` |
| **Debian security tracker** | `security-tracker.debian.org/tracker/data/json` | 200, full package->CVE->fix-version map (large: >60KB). | `security` |
| **Alpine secdb** | `secdb.alpinelinux.org/v3.20/main.json` | 200 JSON per-release. | `security` |
| **MSRC CVRF updates** | `api.msrc.microsoft.com/cvrf/v3.0/updates` | 200 JSON, monthly update ids. | `security` |
| **Cisco advisories RSS** | `sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml` | 200 XML. | `news`/`security` |
| **CISA KEV JSON (feed)** | `cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | 200, full catalog with `catalogVersion`. Direct feed vs keyword-searching KEV. | `security` |
| **CWE API** | `cwe-api.mitre.org/api/v1/cwe/weakness/<id>` | 200 JSON. | `security` |
| **CAPEC** | `capec.mitre.org/data/definitions/<id>.html` | 200 HTML (no JSON API). | `security` |
| **D3FEND ontology** | `d3fend.mitre.org/api/technique/d3f:<Name>.json` | 200 JSON. | `security` |
| **MITRE ATT&CK STIX** | `raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json` | 200, full enterprise bundle (one fetch, then local lookup). TAXII 2.1 endpoint returns 400 - use the STIX file. | `security` |
| **Sigma rules / Atomic Red Team / LOLBAS / GTFOBins** | raw.githubusercontent.com + gtfobins.github.io | 200. Detection + living-off-the-land content the security lane has none of. | `security` |
| **ExploitDB CSV (gitlab raw)** | `gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv` | 200 CSV, ~60KB, full DB. | `security` |

## Tier 1b - security news (registry news lane is only 3 sources)

All 200 at time of probe: **BleepingComputer** `/feed/` - **Krebs** `/feed/` -
**The Record** `/feed` - **The Hacker News** `feeds.feedburner.com/TheHackersNews` -
**SecurityWeek** `/feed/` - **Dark Reading** `/rss.xml` - **Packet Storm** `/files/rss`.

Pitfall: Krebs and Dark Reading serve RSS under `Content-Type: text/html` - the parser
must sniff the body, not trust the header.

## Tier 2 - real breadth, cheap

**Academic**: OpenReview `api2.openreview.net/notes/search?term=` (ML papers + reviews);
zbMATH `api.zbmath.org/v1/document/_search`; ERIC `api.ies.ed.gov/eric/`; J-STAGE
`api.jstage.jst.go.jp/searchapi/do`; Dryad, Harvard Dataverse, HF datasets, OpenAIRE.
`api.core.ac.uk/v3` answered once then 429'd - intermittent, not usable as standalone.

**Public data**: BLS timeseries (POST), regulations.gov v4 with `DEMO_KEY`, data.gov
CKAN v2, data.gov.uk CKAN, EU data hub, Eurostat dissemination, UK ONS, GLEIF LEI,
Treasury Fiscal Data, USAspending (POST), NSF awards, NIH RePORTER (POST),
ProPublica nonprofits, Socrata catalog discovery, openFDA, Census (needs a key).

**Infra attribution** (directly supports the residential-proxy capstone): RDAP
(`rdap.org/domain/...`), Tranco ranks, CAIDA asrank, PeeringDB (+`netixlan`), Team Cymru
whois, ipinfo.io, AWS/GCP/Cloudflare IP-range JSON, Tor bulk exit list, Tor Onionoo,
RIR delegated stats. Plus live proxy-list feeds: Geonode API, ProxyScrape v2, monosans,
OpenIntel, Spamhaus ASN-DROP. These give hosting-vs-eyeball ASN classification.

**Misc**: Stack Exchange API (all sites, not just 3), RFC index XML, IETF datatracker,
Wikipedia REST summary, Wikidata entity JSON, CORDIS, OEIS, OpenLibrary search,
Internet Archive advancedsearch, World Bank, Our World in Data CSV, USGS, open-meteo,
NOAA tides/buoys, Frankfurter FX, Nager holidays, sunrise-sunset, CoinGecko,
Polymarket/Manifold/Kalshi, iTunes search, Wikipedia pageviews, MusicBrainz.

## SearXNG categories the skill never queries

Measured on `q="residential proxy"`:

| Category | Rows | Engines reached |
|---|---|---|
| `images` | 154 | bing, flickr, openverse, pexels, unsplash, pinterest, artic |
| `videos` | 99 | bing, dailymotion, google, ddg, youtube, sepiasearch |
| `packages` | 74 | crates.io, npm, packagist, hex, pkg.go.dev, pub.dev, docker hub, lib.rs |
| `it` | 71 | github, docker hub, mdn, stackoverflow, superuser, askubuntu |
| `web` | 59 | **bing + google directly**, plus the general/web set |
| `news` | 57 | reuters, wikinews, google news, ddg news |
| `science` | 53 | arxiv, pubmed, semantic scholar, openaire |
| `q&a` | 26 | stackoverflow, superuser, askubuntu, discuss.python, caddy, pi-hole |
| `wikimedia` | 25 | wikibooks, wikinews, wikiquote, wikisource, wikiversity, wikivoyage |
| `social media` | 21 | lemmy posts/comments, mastodon hashtags |

The skill currently queries general/web, science, scientific publications, repos/it,
social, q&a, news, files. **`packages`, `it`, and `news` are the ones worth adding** -
they each replace several single-purpose registry entries.

`general` is the *weakest* category (20 rows, `brave` only, DDG CAPTCHA'd); `web` is
strictly better - prefer `web`.

**Read the whole JSON body.** A 40KB read cap makes large SearXNG responses look
"unparsable" (`Unterminated string starting at...`) - that is a probe bug, not an
engine failure. `images`/`news`/`packages` all parsed fine at full size.

## Confirmed-dead (do not re-add)

`dblp.org/api` (now an Anubis "not a bot" wall) - Bluesky public AppView (403) -
GDELT (429 at any spacing) - CommonCrawl index (504, and collinfo only lists indexes) -
**Overpass (406 both JSON-body and form-encoded)** - Fatcat (timeout) - bgpview (DNS) -
iptoasn API (403) - ipapi.co (403) - SciELO (403 both hosts) - Wikidata SPARQL (self-
throttles to 1 req/min) - Phishstats (522) - libraries.io (401) - eCosyste.ms (402) -
AbuseIPDB/openCVE/Vulners (401-403, keyed) - GreyNoise v2 (deprecated; use the v3
Community API above) - MalwareBazaar/ThreatFox keyless requests (their free
community APIs now require an Auth-Key; see the free-key shortlist above) -
PatentsView (NXDOMAIN on `search.patentsview.org`; `api.patentsview.org` now serves an
Angular page, not JSON) - HathiTrust (403) - searchcode (404) - Azure ServiceTags (404
URL) - NIST CSRC (no JSON path) - Ars Security RSS (404) - Memento (DNS gone) -
OECD SDMX (406) - CFPB (403) - GovInfo wssearch (500) - GAO RSSHub (403) -
Google Trends (429) - Census API (works but demands a key) - EPO OPS (403).

Broken *inside* SearXNG (so those engines never contribute): `brave.images`
(unexpected crash), `qwant*`, `duckduckgo`, `startpage*` (CAPTCHA), `yahoo` (parsing
error), `mojeek images` (access denied), `google cse*` (frequent rate-limit), `vimeo`,
`wiktionary`, `radio browser`, `photon` (timeouts).
