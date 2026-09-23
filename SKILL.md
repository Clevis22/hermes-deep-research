---
name: deep-research
description: "Use when the user asks for deep research or a multi-source sweep. Routes one query across 101 configured sources; 99 are keyless."
version: 1.7.0
author: Hermes Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [research, keyless, deep-research, searxng, academic, security, citations]
    related_skills: [grounded-citations, osint-recon, arxiv, local-web-search-backend, deep-research-lanes]
---

# Deep Research

Trigger: **"deep research X"**, "research X thoroughly", "sweep the literature on
X", "what's the evidence for X". One command routes the query across **101
configured sources in 11 lanes**, in parallel, merged and grouped, with
per-source coverage accounting. **99 are keyless**; GitHub code search and
Bluesky are optional credentialed sources. `--auto` can use Jev to select
relevant lanes while deterministic rules protect exact identifiers.

## When to use

- "Deep research", "thorough research", "find everything on", "sweep", or any
  request for primary sources rather than an answer.
- Capstone / paper / project sourcing — especially `CYBER 400` (residential
  proxy networks).
- Cyber topics where the CVE, advisory and filing lanes matter: the security
  lane alone reaches CISA KEV, NVD, EPSS, CIRCL, OSV and CT logs.
- A domain or IP target (use `--lanes security,osint,archive,reference`).
- Before writing anything citable — pair with `grounded-citations`.

**Not for**: single-fact lookups, casual questions, or "what's the weather".
Use plain `web_search` — it is one call instead of roughly 100 configured sources.

## How to run

```bash
S=~/.hermes/skills/research/deep-research/scripts/deep_research.py

python3 "$S" "residential proxy networks" --deep                 # all 101 configured sources
python3 "$S" "residential proxy networks" --auto                 # relevant lanes only
python3 "$S" "residential proxy networks" --auto --plan          # explain; no source calls
python3 "$S" "residential proxy networks" --deep --read 3 --md ~/dr.md
python3 "$S" "topic" --quick                                     # 52 keyless + optional Bluesky
python3 "$S" "log4j" --lanes academic,community,security
python3 "$S" "CVE-2021-44228" --deep                             # CVE shape
python3 "$S" "CWE-89" --lanes security                           # CWE/CAPEC shape
python3 "$S" "residential proxy" --lanes patents                 # Google Patents
python3 "$S" "stegzero.com" --lanes archive,security,reference   # domain shape
python3 "$S" "topic" --deep --json > evidence.json
python3 "$S" "topic" --auto --ledger ledger.json
python3 "$S" --sources                                           # list the registry
```

| Flag | Purpose |
|---|---|
| `--deep` | all 11 lanes (default) |
| `--quick` | web+academic+community+news+reference only |
| `--auto` | exact-shape rules + optional Jev semantic lane routing |
| `--lanes a,b` | pick lanes: `web academic code community news regulatory security osint reference archive patents` |
| `--plan` | print the route without querying research sources |
| `--auto-threshold P` | Jev lane probability threshold (default `0.70`); `--threshold` is an exact alias |
| `--cost-aware` | with `--auto`, drop a lane Jev chose on topic alone when its sources cannot answer the query shape (reported as `dropped <lane>` in `--plan`) |
| `--limit N` | rows per source (default 5) |
| `--read N` | also pull full text of the top N URLs via local PiExtract |
| `--md PATH` | write a markdown report incl. a Sources block |
| `--ledger PATH` | write the full evidence/provenance ledger as JSON |
| `--json [full\|compact]` | machine output. `compact` is the analysis form — see below |
| `--render PATH` | render a JSON run as text (no searching; rebuilds the lane view) |
| `--no-unrelated` | omit the unrelated-matches section |
| `--no-sources` | suppress the stdout/`--md` Sources block |
| `--max-sources N` | cap the stdout Sources list (default 30; `0` = all) |
| `--live` | stream per-source progress to stderr |
| `--workers N` | concurrency (default 8; raise to 12 if the box is idle) |

## The 11 lanes (101 configured sources; 99 keyless)

| Lane | Sources |
|---|---|
| **web** (2) | SearXNG general, SearXNG web |
| **academic** (18) | SearXNG **scientific publications**, Crossref, OpenAlex, **Semantic Scholar, OpenReview**, arXiv, PubMed, Europe PMC, Zenodo, DataCite, DOAJ, OpenAIRE, HAL, OSF, Figshare, Unpaywall, OpenCitations, HF Papers |
| **code** (15) | SearXNG repos, SearXNG IT, SearXNG packages, GitHub repos, GitHub code, GitLab, Codeberg, **deps.dev**, npm, crates.io, Packagist, Maven, Docker Hub, HuggingFace models, Software Heritage |
| **community** (12) | SearXNG social, SearXNG Q&A, Hacker News, Reddit (pullpush), Security.SE, StackOverflow, ServerFault, SuperUser, Lemmy, Dev.to, Mastodon, **Bluesky** (optional app password) |
| **news** (11) | SearXNG news, Bing News RSS, Google News RSS, BleepingComputer, Krebs on Security, The Record, The Hacker News, SecurityWeek, Dark Reading, Cisco Security Advisories |
| **regulatory** (7) | SEC EDGAR full-text, Federal Register, Congress.gov, GovTrack, CourtListener, openFEC, ClinicalTrials.gov |
| **security** (18) | CISA KEV, NVD, EPSS, CIRCL CVE, OSV, **GitHub Advisories, OpenSSF Scorecard**, CertSpotter CT, Shodan InternetDB, RIPEstat, AlienVault OTX, OpenPhish, ExploitDB, Red Hat CVE, Ubuntu CVE, SigmaHQ rules, MITRE CWE, MITRE CAPEC |
| **osint** (5) | **RDAP, PeeringDB, GLEIF, OFAC SDN, OFAC Consolidated** |
| **reference** (10) | SearXNG files, Wikipedia, Wikipedia search, Wikidata, Commons, OpenLibrary, Internet Archive, DBpedia, Datamuse, Nominatim |
| **archive** (2) | Wayback CDX, urlscan.io |
| **patents** (1) | Google Patents (`xhr/query`) — best-effort, see below |

**Query shapes matter.** Sources are only queried when the shape fits: CVE-id
APIs (EPSS, CIRCL, Red Hat per-CVE) need a `CVE-…` in the query; **CWE/CAPEC need
an explicit `CWE-<n>`**. CAPEC results come from MITRE's
`RelatedAttackPatterns` mapping—the CWE number is never reused as a CAPEC ID;
domain APIs need a domain; package and repository enrichers require explicit
shapes. OFAC runs only for explicit sanctions queries, caches its official bulk
XML for 24 hours, and labels every name hit as requiring manual verification.
Misfits are listed under "not applicable" rather than failing.

**The vendor-advisory tier is the point of the security lane.** NVD and CISA KEV
describe a vulnerability; Red Hat, Ubuntu and Cisco say whether a fix actually
shipped. On `CVE-2021-44228`, Red Hat returns `threat_severity=Critical` with a
CVSS3 score and affected-release data. Red Hat's API answers only per-CVE
(`.../cve/<ID>.json`) and `package=<name>` — `keyword=` and the `?cve=` list form
both return HTTP 400.

**Google Patents is best-effort.** It answers a burst of requests and then serves
HTTP 503 for a while (measured: 3 clean runs, then 5/5 503 — not a UA problem).
It is worth a retry, and a 503 is reported as a coverage gap. Never read a
patents gap as "no patents exist".

**Two sources accept optional credentials.** GitHub code search requires a
`GITHUB_TOKEN`; without one it is skipped as not applicable. Use a fine-grained,
read-only token and place it in `~/.hermes/.env` alongside the Bluesky values.
Bluesky's public AppView 403s
`searchPosts` from this network, but an authenticated session works. The
credential lives in `~/.hermes/.env` as `BSKY_HANDLE` + `BSKY_APP_PASSWORD`
(an app password, **not** the account password) and is read directly from that
file, because the shell that runs this script does not inherit Hermes' env.

Semantic Scholar works without authentication but its public quota is shared
and frequently returns 429. A free `SEMANTIC_SCHOLAR_API_KEY` in the same env
file gives the direct adapter a private 1-request-per-second quota; SearXNG
science remains the fallback.

**Jev routing is optional.** Put `OPENROUTER_API_KEY` in `~/.hermes/.env` to
enable semantic lane scoring for `--auto`. The pinned default is
`typesafe/jev-1.13`; override it with `JEV_MODEL` only after re-running the
routing tests. Exact CVE/GHSA/CWE, domain, URL, IP, ASN, LEI, hash, DOI, arXiv,
NCT, patent, repository and explicit package shapes are routed locally and
cannot be vetoed by Jev; a bare exact identifier does not call Jev at all. If
the key is absent, the Decisions endpoint fails, or the probabilities are uniformly uncertain,
the command widens to a conservative local fallback. Use `--auto --plan` to
audit the selected lanes before a live sweep.

Two traps, both of which silently cost a whole session:

- **The identifier is the handle, not the email.** `khermes.bsky.social`
  authenticates; `khermes@bsky.social` returns `Invalid identifier or password`
  (a handle is not an email address — the `@` is wrong).
- **Use the app password as-is, dashes included.** An app password is 4-char
  groups joined by dashes; if `createSession` fails with both the dashed and
  undashed forms, the credential is expired, not misformatted.

With no `BSKY_` credential the source reports itself as *not applicable* and
every other lane still runs keyless — a missing credential must never surface as
a failure. Verify with `scripts/bsky_probe.py`.

## Historical measured results (2026-09-22, this Pi)

These measurements predate the corrected corroborating-source accounting and
the 101-source registry. Retain them as latency guidance, not current acceptance
numbers; refresh the table after the next full live verification.

| Query | Result | Time |
|---|---|---|
| `residential proxy networks --deep` | 67 on-topic findings, 14 of 90 sources hit | 12.5s |
| `CVE-2021-44228 --deep` | 282 on-topic findings, 47 of 90 sources hit | 11.8s |
| `CWE-89 SQL injection --lanes security` | 20 findings, 6 of 16 sources hit | 11.9s |
| `--quick` | 65 findings, 13 of 50 sources hit | 9.2s |

Cold runs are slower (DNS/TLS); a warm full deep run settles around 8–25s.
First-ever run to a fresh host can add 10s+.

## Don't read raw JSON into context

The report is not the expensive part — **reading a `--json` dump into context is**.
A measured 13-query run produced **878 KB** of JSON, of which the single largest dump
was **88 KB** (~22k tokens in one turn). Most of it was noise that never got cited:
in that run **106 of 147 rows (28 KB) were off-topic**, and `by_lane` was a second
copy of the on-topic rows (**13 KB** of pure duplication — verified: it is exactly
`regroup(on-topic findings)`).

So: run with `--json compact` and read the **rendered text**, not the dump.

```bash
python3 "$S" "topic" --deep --json compact > run.json   # 50-76% smaller than full
python3 "$S" --render run.json                          # text; this is what you read
```

`--json compact` keeps only what is citable or needed to analyse:

- `counts` — one place for every total (on-topic, off-topic, raw, collapsed).
- `on_topic` — citable fields only (`lane`/`title`/`url`/`meta`/`sources`).
- `unrelated_urls` — off-topic rows as **URLs, not bodies**. That is where the
  bytes were. Verify one before citing it.
- `sources` — the same numbered list the text report prints.
- `gaps`, `empty_sources`, `skipped_not_applicable` — unchanged.

**Dropped on purpose:** `by_lane` (rebuild with `to_lanes()`, or `--render`
reconstructs it), and the duplicate `full_text` key. `--read` output **is** kept,
because it cannot be re-derived from the search output. `--json` with no value
still means `full`, so existing pipelines are unaffected.

`--render` accepts either form: hand it a full dump from an older run and it
projects the on-topic view and renders that, without re-running any query.

Rule of thumb: **never `cat`/`read_file` a raw dump.** `--render` it, or project
with `execute_code` and print only the shortlist. Analysis that needs real page
text should `--read` the specific URLs it needs, not drag every body in.

## Sources come out in the response

Every stdout run ends with a numbered `## Sources (N unique — cite as [n])` block:

```
## Sources (67 unique — cite as [n])

[1] Evading Residential Proxy Networks: Protecting Your Devices…
     https://www.fbi.gov/investigate/cyber/alerts/2026/…
     via SearXNG general
```

**Report these sources back to the user** — the response is not done at the findings.
Paste the block (or your cited subset) into the reply, so the user gets the sources
in the response rather than having to re-run anything or open a file. Pair with
`grounded-citations` and cite as `[n]` against these numbers; the numbering is stable
within one run, so copy the URLs out of the block rather than retyping them.

The block lists **on-topic rows only**. Off-topic matches are deliberately excluded,
because those are exactly the rows that must not reach a reference list. `--md`
writes one link-form `## Sources` block with no cap.

- Default cap is 30 rows; the block says `... N more not shown` when it truncates.
  Raise `--max-sources` (or `0` for all) when writing a full reference list.
- `--no-sources` suppresses the block in both stdout and `--md`.
- `--json` is unchanged: it already carries the full `sources` list per finding.

## Reading the output honestly

The report separates four things — do not collapse them:

1. **On-topic findings**, grouped by lane. Each line names the source that
   produced it, so every claim is attributable.
2. **Unrelated matches** — rows that matched only a generic shared word (e.g.
   "Residential Painting Cost" for a residential-proxy query). They are **kept,
   not discarded**, because deep research means maximum coverage; they are
   parked in their own section. Verify before citing.
3. **Coverage gaps** — sources that errored, with the error. A gap is *not*
   evidence of absence. SearXNG also reports per-query `unresponsive_engines`.
4. **Sources not applicable** — skipped on purpose because of query shape.

Reporting rule: say which lanes were quiet. An empty `security` lane on a
free-text query is expected; an empty `academic` lane is a finding.

## Merging and evidence independence

Rows that describe the same item — same normalized title, or same normalized URL
— are **merged into one finding that lists every adapter which carried it**.
Adapter count is not evidence independence: two search adapters pointing to one
publisher are labeled `rediscovered-single-origin`. Only distinct conservative
publisher/service origins are labeled `independently-corroborated`; a structured
registry/API record can instead be `structured-record`.

The merge is a *display* choice, not evidence-gathering: nothing is discarded,
and full JSON carries each support record. `--ledger PATH` writes the portable
`hermes-evidence-ledger/v1` artifact. Read
[references/evidence-ledger.md](references/evidence-ledger.md) when consuming or
changing that schema.

Aggregator rows from one source are collapsed inside that source before merging,
which is what removed the repeated Crossref/Google-Scholar pairs.

## Pitfalls

- **Not pasting the Sources block into the chat reply.** The `## Sources (N unique — cite
  as [n])` block is part of the deliverable, not just a file artifact. Kieran has called
  this out: after the answer, paste the numbered `[n]` list (or the cited subset) as normal
  assistant text in the reply. Writing it to a `--md` file only, or leaving it in the
  ledger, counts as *not* delivering it. Do this every time the research skill runs, even
  when the answer already has inline `[n]` citations.
- **A Jev lane score is semantic relevance, NOT expected yield.** Measured on
  `cybersecurity incidents involving residential proxy networks botnets`, Jev
  scored `security=0.98` — and the security lane returned **zero on-topic
  findings**. All 18 sources there key on an exact identifier (CVE, GHSA, CWE,
  domain, repo, package): 12 are skipped as *not applicable* on prose, while
  NVD, CISA KEV and ExploitDB keyword-match the prose and emit CVE and
  unrelated-exploit noise. Before treating a lane as valuable, check whether its
  sources can *answer the query shape*; a high probability cannot tell you that.
  `--cost-aware` drops the lane in that case and reports
  `dropped security: <reason>` in `--plan` and in the route JSON.
- **`--cost-aware` is opt-in on purpose — do not make it the default.** The same
  heuristic cannot separate a topic-word query from a legitimate
  detection-engineering one: `residential proxy detection research` really does
  belong in the security lane (SigmaHQ, vendor advisories). Turning the drop on
  by default broke the upstream calibration test for exactly that query. Hard
  identifier rules always outrank the cost model, so a forced lane (bare `CVE-`,
  domain, repo, package) is never dropped.
- **Jev's marginal lane value decays sharply — measure it, don't trust the
  score.** On the same query, adding lanes to `web`: `news` added 7 on-topic
  findings for +0s (3.9s vs 4.0s); `security` then added **1 finding for +22s**
  (26.1s vs 3.9s) — and that one was noise. Jev scored both highly
  (`news=0.73`, `security=0.98`). The cost is not the inapplicable sources (they
  skip in ~0s); it is the three that keyword-match prose — ExploitDB ~7s,
  NVD ~4s, CISA KEV ~2s.
- **ExploitDB matched on a single shared word and returned pure noise.** Its
  adapter accepted a row when *any one* query word appeared in the title, so
  "proxy" pulled in Proxy Anket, Squid Web Proxy and IPFire proxy.cgi:
  measured 270 rows from 47k, every one off-topic. `_exploit_row_matches` now
  requires 2 words for a multi-word query (mirroring `relevant()`), which
  returned 0 spurious rows. A single-word query is still allowed through.
- **DBpedia emitted a finding for every query it was given.** A miss returns
  `{}` and the old adapter still produced a "0 linked-data resources" line whose
  title echoed the query string back, so it scored as relevant to everything it
  appeared on. `_dbpedia_parse` now returns real entity pages only (predicates
  beyond `primaryTopic`/`wikiPageWikiLink`) under the resource's own name.
- **The 101-source registry is mostly redundancy on real queries.** Measured on
  the residential-proxy incident `--deep` run: only **11 of 101 sources**
  produced any on-topic row, and **80% of all attributions came from 4 SearXNG
  categories** (`news` 21, `web` 19, `science` 18, `general` 14 of 90). The long
  tail of direct registry APIs (Crossref 5, Zenodo 3, OpenReview 2, OpenAlex 1)
  largely re-found what SearXNG already had. SearXNG is load-bearing: if lanes
  go quiet, check those backends first, and read a `--deep` run's
  source-attribution tail before claiming broad coverage.
- **`--threshold` is an exact alias, and abbreviations are now disabled.**
  Previously argparse prefix matching silently accepted `--threshold 0.60` (and
  a typo like `--thresold`) as an abbreviation of `--auto-threshold`, so a
  mistyped flag looked honoured while the route never changed. The parser now
  sets `allow_abbrev=False`, so an unknown flag is an error. Always read the
  `route:` line back rather than assuming a flag applied.
- **`--deep` on every question is waste.** A simple lookup should use `--auto`,
  `--quick`, or plain web search. Reserve `--deep` for a genuinely exhaustive
  sweep.
- **SearXNG `scientific publications` remains load-bearing.** It reaches Google
  Scholar and provides redundancy when the direct Semantic Scholar public pool
  returns 429.
  Omitting it once cost the NDSS residential-proxy-detection paper entirely. Its
  results arrive ordered by position, and relevant papers can sit ~11 deep, so
  SearXNG sources are read with `limit_multiplier=5` (5 × `--limit` rows).
- **Adapter duplication is not independent corroboration.** Rows with the same
  normalized title or URL merge, every adapter remains visible, and the ledger
  separately counts conservative publisher/service origins.
- **NVD `keywordSearch` matches CVE text, not nicknames** — `log4shell` → 0,
  `log4j` → 34. Pass the CVE id and the script does an exact `cveId=` lookup.
- **CISA KEV matches vendor/product text**, substring-wise. CVE ids are stripped
  from the keyword set first, or a bare `CVE-2021-44228` matches every entry
  containing "2021".
- **OpenAlex needs `&mailto=`** — anonymous search 429s. It is a courtesy
  header, not a credential, and it still throttles under rapid repeats (one
  retry with backoff is built in).
- **GitHub code search needs auth.** Configure `GITHUB_TOKEN` for this optional
  source; without it the source is skipped instead of producing a guaranteed
  401 gap. GitHub *repo* search remains keyless but is capped at ~10 req/min.
- **Wayback CDX 503s intermittently**; one retry is built in.
- **Reddit's own JSON 403s** from this network — pullpush is the working mirror
  and it 429s sometimes too.
- **SEC EDGAR full-text covers 2001+ only**, and a 0-hit exact phrase is not
  proof the term was never used — filings use corporate phrasing. Query the
  words a company would write.
- **RSS wrappers hide duplicates**: Bing/Yahoo `apiclick` URLs are unwrapped
  before dedup, or the same story appears twice (search + RSS).
- **Sources that cannot answer were removed on purpose**: bioRxiv/medRxiv
  (date-range listings, no keyword search) and BLS/World Bank/Eurostat (fixed
  series). They always emitted a row that *looked* like a finding. Do not
  re-add them without a real search endpoint.
- **Single-word queries skip the relevance tagging** — they are exact lookups by
  nature, so filtering them would drop the answer.
- **`--read` goes through local PiExtract** (`127.0.0.1:3002`), which is
  SSRF-guarded and strips boilerplate. If PiExtract is down, `--read` fails and
  the rest of the report still prints.

### Pitfalls specific to the vendor-advisory and patents sources

- **Red Hat's API answers only two shapes**: the per-CVE path
  (`.../securitydata/cve/<CVE-ID>.json`) and `?package=<name>`. `keyword=` and
  the `?cve=` list form return **HTTP 400** — building either of those is a bug,
  not a gap. The per-CVE record is a dict (severity, CVSS3, affected releases);
  the `package=` listing is a list. The parser must handle both.
- **A CVE id is never a CWE number.** `CWE-44228` does not exist and 404s.
  `Q.cwes` is captured separately from `Q.cves` for exactly this reason — never
  reuse a `CVE-YYYY-NNNN` suffix as a CWE id.
- **Packet Storm's RSS is malformed XML** (`mismatched tag`). `xload()` retries
  after escaping bare ampersands and stripping control characters; without that
  fallback the feed silently yields no rows at all.
- **Some feeds serve RSS under `Content-Type: text/html`** (Krebs, Dark
  Reading). Never gate the RSS parser on the content-type header.
- **Google Patents rate-limits by burst, not by UA.** Adding a browser UA does
  not make it reliable; keep the retry and treat 503 as a coverage gap.
- **Per-source headers exist now** (`register(..., headers={...})`). They are
  for endpoints that genuinely require them — don't set a browser UA globally,
  every other source should keep identifying itself honestly.

## Verified additions (2026-09-22)

A five-round keyless probe of ~230 endpoints from this Pi first took the registry
from 76 to 90 sources. Bluesky and the structured-evidence expansion later
brought the configured registry to 101. What was added:

- **patents lane (new)** — Google Patents `xhr/query`, best-effort.
- **code** — SearXNG `packages` (crates.io, npm, Packagist, Hex, pkg.go.dev,
  pub.dev, lib.rs, Docker Hub in one call).
- **news** — BleepingComputer, Krebs on Security, The Record, The Hacker News,
  SecurityWeek, Dark Reading, Cisco Security Advisories.
- **security** — Red Hat CVE, Ubuntu CVE, SigmaHQ rules, MITRE CWE, MITRE CAPEC,
  GitHub Advisories and OpenSSF Scorecard; plus a working ExploitDB parser.
- **academic** — direct Semantic Scholar and OpenReview adapters.
- **code (structured)** — deps.dev package/version, provenance and repository
  enrichment.
- **osint lane (new)** — RDAP, PeeringDB, GLEIF, OFAC SDN and OFAC Consolidated.
  OFAC bulk files are cached for 24 hours and require explicit sanctions intent.
- **infra** — `http()` gained per-source `headers`; `xload()` gained malformed-XML
  tolerance; `_csv_rows()` was added.

Full per-endpoint evidence, remaining candidates (public-data,
infra-attribution and community), and the confirmed-dead list live in
`references/candidate-sources.md`.

Re-verify with `bash scripts/verify_deep_research.sh`. It runs deterministic
unit tests before the live controls for CWE/CAPEC resolution, Sources-block
flags, JSON round-tripping, and lane validation. A transient upstream failure
that is correctly surfaced is reported as a live gap, not a parser failure.

## Dead sources — do not re-add without re-testing

Verified failing keylessly from this Pi (2026-09-21):

`html.duckduckgo.com` (JS challenge) · `reddit.com/*.json` (403) ·
`index.commoncrawl.org` (504) ·
`api.gdeltproject.org` (429 even at 1 req/5s) · `lobste.rs`, `dblp.org`,
`www.mojeek.com` (bot walls) · `marginalia-search.com` (no keyless JSON API) ·
`libraries.io`, `urlhaus`, `api.hackertarget.com`, `eCosyste.ms`, `Tildes`,
`Kbin`, `Gutendex`, `ConceptNet`, `dictionaryapi.dev`, `openlibrary`/`DOAB`
search-API variants that time out · `Bluesky` public search (403) ·
`api.patentsview.org` (NXDOMAIN / Angular page) · `Lens.org` (403) ·
`ThreatMiner` (dead) · `Google Books` (429) · `grep.app` (429).

**Corrections (re-probed 2026-09-22) - these three are live, do not treat as dead:**

- **`patents.google.com/xhr/query`** returns 200 with real results (3/3 runs,
  `total_num_results` + publication numbers). Patents are **no longer a gap**. See
  `references/candidate-sources.md`.
- **`data.gov`** - the old path 404'd; the CKAN v2 endpoint
  (`catalog.data.gov/api/3/action/package_search`) returns 200.
- **`Regulations.gov`** - `DEMO_KEY` on the v4 documents API returns 200; the 400 was a
  wrong endpoint, not a key problem.

Verified candidate additions (patents, vendor advisory feeds, security news,
SearXNG `packages`/`it`/`news` categories, infra-attribution APIs) are catalogued in
`references/candidate-sources.md` with per-endpoint evidence.

## Verification

Positive control:
`python3 "$S" "residential proxy networks" --deep --limit 5` must produce an
**ACADEMIC** section containing *Beyond RTT: An Adversarially Robust Two-Tiered
Approach For Residential Proxy Detection* (via `SearXNG science` / Google
Scholar) and a **CODE** section with `TurboNodes/Turbo`. A **NEWS** section must
appear — if `## NEWS` is missing, RSS parsing has regressed. Expect ~60–80
on-topic findings in ~10–25s.

Note: assert on findings with `grep -A3` and the section headers, not with a
title-substring grep alone — the report indents bullet bodies, and a naive
`^\*\*` pattern silently matches nothing and reads as a failure.

Negative controls:
- `python3 "$S" "CVE-2021-44228" --deep` → `query shape: cve=['CVE-2021-44228']`,
  and the matching finding must list **CISA KEV** alongside **NVD** in its
  `sources:` line. Assert on `sources:` containing `CISA KEV` — do NOT grep for a
  standalone "CVE-… Apache/Log4j2" title, because KEV and NVD cite the same
  `nvd.nist.gov/vuln/detail/<id>` URL and are correctly merged into one row.
- `--json` needs a query: `python3 "$S" "x" --json`. With no query the script
  prints help and exits 2, which is intended, not a JSON failure.
- `python3 "$S" "residential proxy networks" --deep` must NOT place
  "Residential Painting Cost" or "Munchausen syndrome by proxy" in an on-topic
  lane — assert with `sed -n '/^## WEB/,/^## Unrelated/p'` then grep for
  `painting` (expect 0).
- `--lanes nope` must exit non-zero with `unknown lane(s)`.
- A free-text run must end with exactly one `## Sources (N unique — cite as [n])`
  header, and the block must contain **zero** rows matching `painting`/`munchausen`
  (off-topic rows stay out of the citation list). Assert with
  `sed -n '/^## Sources (/,$p' out.txt | grep -ci painting` → expect 0.
- `--max-sources 5` prints exactly 5 `[n]` entries plus a `more not shown` line;
  `--max-sources 0` prints all and no truncation line; `--no-sources` suppresses
  Sources blocks in both stdout and `--md` output.
- Round-trip: `--json compact > r.json && --render r.json` must print one
  `## Sources (N unique — cite as [n])` header and the same on-topic count as
  `--json` full reported. `--render` on a **full** dump must still work (it prints
  `note: full dump given; rendering its on-topic view only` to stderr).
- Assert `--json compact` omits `by_lane` and `full_text` but `--json` (bare) keeps them.

**Two controls in this file are drift-prone — a miss is not automatically a bug.**
Before "fixing" a red assertion, re-run the RAW path (`--json`) and check the
title is absent there too:

- ✶ *Beyond RTT* — the academic control. SearXNG's science engine still returns
  ~24 rows, but this specific NDSS paper stopped appearing (checked 2026-09-21);
  assert **the ACADEMIC section is non-empty and carries multi-source rows**, not
  this title.
- ✶ The KEV control — a `CVE-…` query can legitimately match **several** KEV
  entries, so `sources:.*CISA KEV` returning **2** lines is correct, not a merge
  bug. Assert **≥1**, not `==1`.

## Related

- `grounded-citations` — turn this output into `[n]`-cited prose. The `[n]` numbers
already come from this skill's Sources block, so cite against those and copy the URLs
out of it; never retype them. Use `sources.py add` for anything the block didn't
show (past `--max-sources`).
- `osint-recon` — domain/IP/ASN/email/username recon, deeper than this skill's
  security lane on infrastructure attribution.
- `arxiv` — paper metadata, BibTeX, citation-graph work once you have an id.
- `deep-research --lanes community,news` — for "what are people saying right now".
  Recency is now handled in-house (Bluesky `sort=latest` + `since`, the security
  news feeds, SearXNG `news`); the external `last30days` tool was removed.
- `local-web-search-backend` / `local-web-extract-backend` — the SearXNG and
  PiExtract services this depends on; check them first when lanes go quiet.
