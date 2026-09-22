# hermes-deep-research

One query, fanned across **91 configured sources in 10 lanes** in parallel,
merged, deduplicated and grouped — with per-source coverage accounting, so a
source that failed is reported as a gap rather than as "no results". **89 work
without credentials**; GitHub code search and Bluesky are optional.

Built as a [Hermes Agent](https://github.com/NousResearch/hermes-agent) skill,
but `scripts/deep_research.py` is **stdlib-only Python 3** and runs standalone.

## Why

A normal search gives you one page of one engine's opinion. For sourcing a paper
or a threat assessment you need the primary sources: the CVE record, the vendor
advisory that says whether a fix shipped, the paper, the exploit, the filing, the
patent. This runs ~90 of those at once and tells you which ones stayed silent.

The core sweep needs no API key. Two sources are optional and credentialed (see
[Optional credentials](#optional-credentials)); without them, those sources are
reported as not applicable rather than as failures.

## Quick start

```bash
python3 scripts/deep_research.py "residential proxy networks" --deep
python3 scripts/deep_research.py "CVE-2021-44228" --deep
python3 scripts/deep_research.py "CWE-89 SQL injection" --lanes security
python3 scripts/deep_research.py "topic" --quick          # 50 keyless + optional Bluesky
python3 scripts/deep_research.py --sources                # list the registry
```

As a Hermes skill, drop the directory into `~/.hermes/skills/research/` and it
loads automatically.

## Lanes

| Lane | N | What it reaches |
|---|---|---|
| `web` | 2 | SearXNG general + web |
| `academic` | 16 | Crossref, OpenAlex, arXiv, PubMed, Europe PMC, Zenodo, DataCite, DOAJ, OpenAIRE, HAL, OSF, Figshare, Unpaywall, OpenCitations, HF Papers, + SearXNG scientific publications (Google Scholar / Semantic Scholar) |
| `code` | 14 | GitHub, GitLab, Codeberg, npm, crates.io, Packagist, Maven, Docker Hub, HuggingFace, Software Heritage, SearXNG repos/IT/packages |
| `community` | 12 | Hacker News, Reddit, StackExchange, StackOverflow, ServerFault, SuperUser, Lemmy, Dev.to, Mastodon, Bluesky |
| `news` | 11 | SearXNG news, Bing/Google News, BleepingComputer, Krebs, The Record, The Hacker News, SecurityWeek, Dark Reading, Cisco advisories |
| `regulatory` | 7 | SEC EDGAR, Federal Register, Congress.gov, GovTrack, CourtListener, openFEC, ClinicalTrials.gov |
| `security` | 16 | CISA KEV, NVD, EPSS, CIRCL, OSV, CertSpotter CT, Shodan InternetDB, RIPEstat, AlienVault OTX, OpenPhish, ExploitDB, Red Hat CVE, Ubuntu CVE, SigmaHQ, MITRE CWE, MITRE CAPEC |
| `reference` | 10 | Wikipedia, Wikidata, Commons, OpenLibrary, Internet Archive, DBpedia, Datamuse, Nominatim |
| `archive` | 2 | Wayback CDX, urlscan.io |
| `patents` | 1 | Google Patents |

## Design notes

**Coverage gaps are output, not silence.** A source that errors is listed with
its error. A gap is *not* evidence of absence — that distinction is the whole
point when you are about to cite something.

**Cross-source duplicates are corroboration.** Rows describing the same item
(same normalized title or URL) merge into one finding naming every source that
carried it. A CVE found by both NVD and CISA KEV becomes one line reading
`sources: NVD, CISA KEV`.

**Query shapes are respected.** CVE-id APIs are only queried when the query
contains a `CVE-…`; MITRE's explicit CWE relationships are used to resolve
CAPEC patterns for an explicit `CWE-<n>` (the two ID namespaces are never
assumed to match); domain APIs need a domain; package APIs answer single tokens.
Misfits are reported as "not applicable" instead of failing.

**Every run ends with a numbered Sources block** (`[n]`-citeable) containing
on-topic rows only.

## Optional credentials

Two sources work better with a credential, and both degrade cleanly without one
(the source reports itself as *not applicable*; everything else still runs).

Set them in `~/.hermes/.env` (mode 0600) — the script reads that file directly,
because a shell does not inherit the variables Hermes loads into its own process:

```
# GitHub code search: a fine-grained token with read-only access is sufficient.
GITHUB_TOKEN=github_pat_xxxx

# Bluesky: the public AppView 403s search from many networks; auth fixes it.
# Use an APP PASSWORD (Settings -> App Passwords), not the account password.
# The identifier is the HANDLE (khermes.bsky.social), never an email form.
BSKY_HANDLE=yourhandle.bsky.social
BSKY_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx
```

`DEMO_KEY` is used for Congress.gov and openFEC — a public rate-limited
placeholder, not a secret.

## Verifying

```bash
bash scripts/verify_deep_research.sh
```

The verifier runs deterministic unit tests first, then live positive and
negative controls for the registry, CWE/CAPEC resolution, optional credentials,
Sources-block flags, JSON round-tripping, and lane validation. Run it after any
source change; live assertions can fail when an upstream endpoint drifts.
Transient upstream failures that the report correctly exposes are counted as
live gaps rather than deterministic test failures.

Bluesky auth can be checked on its own with `python3 scripts/bsky_probe.py`.

## Flags

| Flag | Purpose |
|---|---|
| `--deep` | all 10 lanes (default) |
| `--quick` | web+academic+community+news+reference only |
| `--lanes a,b` | pick lanes |
| `--limit N` | rows per source (default 5) |
| `--read N` | pull full text of the top N URLs (needs a local extractor on :3002) |
| `--md PATH` | write a markdown report incl. a Sources block |
| `--json [full\|compact]` | machine output; `compact` drops redundant fields |
| `--render PATH` | render a JSON run as text without re-searching |
| `--max-sources N` | cap the stdout Sources list (default 30; `0` = all) |
| `--live` | stream per-source progress to stderr |
| `--workers N` | concurrency (default 8) |

## Costs

A warm deep run is **8–25s**. Don't use `--deep` for a one-fact lookup — that is
roughly 90 HTTP requests for nothing; plain search is one call.

## Licence

MIT.
