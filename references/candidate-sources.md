# Candidate sources (probed 2026-09-22 from this Pi)

Method: one keyless request per endpoint, default Python UA, documented API path.
**Usable = HTTP 200 with a real payload.** Rate-limited endpoints were retried with
spacing before being called dead. Probe scripts: `~/workspace/research_source_probe{,2,3,4,5}.py`.

> **Wired in already (registry 90 sources / 10 lanes):** Google Patents (patents lane),
> SearXNG `packages`, the seven security-news feeds, and the security tier
> (Red Hat CVE, Ubuntu CVE, SigmaHQ rules, MITRE CWE, MITRE CAPEC + a working
> ExploitDB parser). **Everything else in this file is verified but NOT registered
> yet** — add it with one `register(name, lane, build, kind, parse, ...)` call in the
> matching lane section. Do not re-add a row that is already wired (the registry is
> the source of truth: `deep_research.py --sources`).
> Re-run `scripts/verify_deep_research.sh` (21 assertions) after any change.

The registry is 90 sources. These are verified, not guessed.

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
MalwareBazaar/ThreatFox/AbuseIPDB/GreyNoise-v2/openCVE/Vulners (401-403, all keyed) -
PatentsView (NXDOMAIN on `search.patentsview.org`; `api.patentsview.org` now serves an
Angular page, not JSON) - HathiTrust (403) - searchcode (404) - Azure ServiceTags (404
URL) - NIST CSRC (no JSON path) - Ars Security RSS (404) - Memento (DNS gone) -
OECD SDMX (406) - CFPB (403) - GovInfo wssearch (500) - GAO RSSHub (403) -
Google Trends (429) - Census API (works but demands a key) - EPO OPS (403).

Broken *inside* SearXNG (so those engines never contribute): `brave.images`
(unexpected crash), `qwant*`, `duckduckgo`, `startpage*` (CAPTCHA), `yahoo` (parsing
error), `mojeek images` (access denied), `google cse*` (frequent rate-limit), `vimeo`,
`wiktionary`, `radio browser`, `photon` (timeouts).
