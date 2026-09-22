#!/usr/bin/env python3
"""Route and fan out research across public sources reachable from this Pi.

One query -> ~60 sources in parallel -> deduped, citable findings grouped by
lane, with per-source coverage accounting (a source that failed is reported as
a gap, never as "no results").

Stdlib only. Optional credentials are loaded from the environment or Hermes env file.

    python3 deep_research.py "residential proxy networks" --deep
    python3 deep_research.py "residential proxy networks" --auto --plan
    python3 deep_research.py "CVE-2021-44228" --deep
    python3 deep_research.py "stegzero.com" --lanes security,archive,web
    python3 deep_research.py "topic" --read 3 --md report.md
    python3 deep_research.py --sources          # list the source registry
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import datetime as dt
import io
import json
import os
import re
import sys
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

SEARXNG = os.environ.get("SEARXNG_URL", "http://127.0.0.1:8080")
PIEXTRACT = os.environ.get("PIEXTRACT_URL", "http://127.0.0.1:3002")
UA = "HermesDeepResearch/1.0 (keyless research; +local)"
POLITE_MAILTO = os.environ.get("DEEP_RESEARCH_CONTACT", "kieranjg092@gmail.com")
TIMEOUT = 20
UA_SEC = "Hermes Research kieranjg092@gmail.com"  # SEC requires a contact UA
# Some endpoints (Google Patents) 503 a bare bot UA but answer a browser one.
# Applied per-source via register(..., headers={...}), never globally, so every
# other source keeps identifying itself honestly.
BROWSER_UA = ("Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

LANES = ("web", "academic", "code", "community", "news", "regulatory",
         "security", "reference", "archive", "patents")

# Deep = every lane. Quick = the ones that answer most questions.
QUICK_LANES = ("web", "academic", "community", "news", "reference")

OPENROUTER_DECISIONS_URL = os.environ.get(
    "OPENROUTER_DECISIONS_URL", "https://openrouter.ai/api/alpha/decisions"
)
JEV_MODEL = os.environ.get("JEV_MODEL", "typesafe/jev-1.13")
AUTO_THRESHOLD = 0.55


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------

def http(url, data=None, headers=None, timeout=TIMEOUT, retries=0, backoff=2.0):
    """Return (text, error). Never raises."""
    hdrs = {"User-Agent": UA, "Accept": "application/json, text/xml, text/html, */*"}
    hdrs.update(headers or {})
    last = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=data, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", "replace"), None
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "code", None)
            last = f"HTTP {code}" if code else f"{type(exc).__name__}: {exc}"
            if attempt < retries:
                time.sleep(backoff * (attempt + 1))
    return None, last


def jload(text):
    try:
        return json.loads(text)
    except Exception:  # noqa: BLE001
        return None


def xload(text):
    """Parse XML, tolerating the junk some feeds emit.

    Packet Storm's RSS is malformed enough that ElementTree refuses it outright,
    so the offending bytes are stripped before giving up.
    """
    try:
        return ET.fromstring(text)
    except Exception:  # noqa: BLE001
        cleaned = re.sub(r"&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)", "&amp;", text)
        cleaned = "".join(ch for ch in cleaned
                          if ch in "\t\n\r" or 0x20 <= ord(ch) <= 0x10FFFF)
        try:
            return ET.fromstring(cleaned)
        except Exception:  # noqa: BLE001
            return None


def _csv_rows(text):
    """Parse a CSV payload into a list of rows (empty on failure)."""
    try:
        return list(csv.reader(io.StringIO(text)))
    except Exception:  # noqa: BLE001
        return []


def as_list(value):
    """Normalize APIs that encode one item as an object and many as a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _dotenv_value(name, path=None):
    """Read one value from the environment or ``~/.hermes/.env``."""
    if os.environ.get(name):
        return os.environ[name]
    path = path or os.path.expanduser("~/.hermes/.env")
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith(name + "="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return None


def dig(obj, path, default=None):
    """Tiny dotted-path getter: dig(d, 'hits.total.value'). Accepts ints for lists."""
    cur = obj
    for part in path.split("."):
        if cur is None:
            return default
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return default
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return default
    return default if cur is None else cur


def clip(value, n=160):
    s = " ".join(str(value if value is not None else "").split())
    return s[: n - 3] + "..." if len(s) > n else s


def rss_items(text, limit):
    """Parse RSS/Atom into (title, meta, link) tuples.

    Note: ElementTree elements are NOT dicts, so ``dig()`` cannot walk them —
    every field is read with explicit ``find()`` calls.
    """
    root = xload(text)
    out = []
    if root is None:
        return out
    entries = list(root.iter("item")) + list(root.iter("{http://www.w3.org/2005/Atom}entry"))
    for item in entries:
        title_el = item.find("title")
        title = title_el.text if title_el is not None and title_el.text else ""
        link = ""
        link_el = item.find("link")
        if link_el is not None:
            link = link_el.get("href") or (link_el.text or "")
        date = ""
        for tag in ("pubDate", "published", "updated",
                    "{http://purl.org/dc/elements/1.1/}date"):
            el = item.find(tag)
            if el is not None and el.text:
                date = el.text
                break
        source = ""
        src_el = item.find("source")
        if src_el is not None and src_el.text:
            source = src_el.text
        meta = " ".join(x for x in (clip(date, 30), clip(source, 40)) if x)
        if title:
            out.append((clip(title, 150), meta, link))
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------------
# query classification
# ---------------------------------------------------------------------------

class Q:
    def __init__(self, raw):
        self.raw = raw
        self.enc = urllib.parse.quote(raw)
        self.plus = urllib.parse.quote_plus(raw)
        self.cves = re.findall(r"CVE-\d{4}-\d{4,7}", raw, flags=re.I)
        # CWE ids are their own namespace: CVE-2021-44228 must NOT be read as
        # CWE-44228, which is a 404. Only an explicit CWE-<n> maps.
        self.cwes = re.findall(r"CWE-(\d{1,5})", raw, flags=re.I)
        self.is_url = raw.startswith(("http://", "https://"))
        self.domain = None
        if self.is_url:
            self.domain = raw.split("//", 1)[-1].split("/")[0]
        elif re.match(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$", raw.strip(), flags=re.I):
            self.domain = raw.strip()
        stripped = raw.strip()
        host_value = self.domain or stripped
        self.ipv4 = host_value if re.fullmatch(
            r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}",
            host_value,
        ) else None
        if self.ipv4:
            self.domain = None
        self.asn = stripped.upper() if re.fullmatch(r"AS\d+", stripped, re.I) else None
        self.hash = stripped.lower() if re.fullmatch(
            r"(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", stripped, re.I
        ) else None
        self.doi = next(iter(re.findall(r"\b10\.\d{4,9}/\S+", raw, re.I)), None)
        self.arxiv = next(iter(re.findall(r"\b(?:arxiv:)?\d{4}\.\d{4,5}\b", raw, re.I)), None)
        self.nct = next(iter(re.findall(r"\bNCT\d{8}\b", raw, re.I)), None)
        self.patent = next(iter(re.findall(
            r"\b(?:US|EP|WO|GB|JP|CN)\s*\d{5,}[A-Z]?\d?\b", raw, re.I
        )), None)
        self.is_package = bool(re.match(r"^[@a-z0-9][\w.@/-]*$", raw.strip(), flags=re.I)) and " " not in raw
        # first token(s) that look like a product/vendor name for KEV-style match
        self.words = [w for w in re.split(r"\W+", re.sub(r"CVE-\d{4}-\d{4,7}", " ", raw, flags=re.I)) if len(w) > 3]

    def host(self):
        return self.domain or self.raw


# ---------------------------------------------------------------------------
# automatic lane routing
# ---------------------------------------------------------------------------

# Jev sees one state and answers these independent yes/no questions in one
# request. Web is deliberately absent: it is the small discovery baseline for
# every automatic run. Exact identifiers are handled by deterministic rules
# below and cannot be vetoed by the model.
AUTO_LANE_QUESTIONS = {
    "academic": (
        "Would scholarly papers, preprints, research datasets, citations, or "
        "scientific literature materially help answer `research_query`?"
    ),
    "code": (
        "Would source-code repositories, package registries, software artifacts, "
        "container images, or model registries materially help answer `research_query`?"
    ),
    "community": (
        "Would forums, technical Q&A, social posts, or first-hand community "
        "discussion materially help answer `research_query`?"
    ),
    "news": (
        "Would current or recent journalism, announcements, or news reporting "
        "materially help answer `research_query`?"
    ),
    "regulatory": (
        "Would laws, government records, corporate filings, court opinions, "
        "legislation, campaign data, or clinical-trial records materially help "
        "answer `research_query`?"
    ),
    "security": (
        "Would vulnerability, exploit, malware, threat-intelligence, defensive-rule, "
        "certificate, domain, IP, or network-security sources materially help answer "
        "`research_query`?"
    ),
    "reference": (
        "Would encyclopedic, bibliographic, geographic, catalogue, linked-data, or "
        "general reference sources materially help answer `research_query`?"
    ),
    "archive": (
        "Would historical website snapshots or prior scans of a specific domain or "
        "URL materially help answer `research_query`?"
    ),
    "patents": (
        "Would patents, inventions, assignees, or prior-art records materially help "
        "answer `research_query`?"
    ),
}

FALLBACK_LANE_TERMS = {
    "academic": ("paper", "study", "research", "literature", "evidence", "doi", "arxiv"),
    "code": ("code", "github", "repository", "package", "library", "npm", "pypi", "crate", "maven"),
    "community": ("forum", "reddit", "discussion", "community", "stackoverflow", "experience"),
    "news": ("news", "latest", "recent", "today", "current", "announcement", "announced"),
    "regulatory": ("law", "regulation", "regulatory", "filing", "court", "lawsuit", "bill", "clinical trial"),
    "security": ("cve", "vulnerability", "exploit", "malware", "phishing", "breach",
                 "threat", "attack", "proxy", "botnet", "command and control"),
    "reference": ("what is", "who is", "where is", "definition", "overview", "history"),
    "archive": ("archive", "archived", "historical website", "old website", "wayback"),
    "patents": ("patent", "invention", "inventor", "prior art"),
}


def hard_route_lanes(q):
    """Lanes forced by exact syntax; a statistical router cannot veto these."""
    forced = {"web"}
    reasons = {"web": "baseline discovery"}

    if q.cves or q.cwes or q.hash or q.ipv4 or q.asn:
        forced.add("security")
        reasons["security"] = "exact security/network identifier"
    if q.domain:
        forced.update(("security", "archive", "reference"))
        reasons.update({
            "security": "domain or URL pivot",
            "archive": "domain or URL history",
            "reference": "domain or URL context",
        })
    if q.doi or q.arxiv:
        forced.add("academic")
        reasons["academic"] = "exact scholarly identifier"
    if q.nct:
        forced.add("regulatory")
        reasons["regulatory"] = "clinical-trial identifier"
    if q.patent:
        forced.add("patents")
        reasons["patents"] = "patent identifier"

    low = q.raw.lower()
    package_words = ("package", "npm", "pypi", "crate", "maven", "rubygems", "nuget")
    explicit_identifier = q.doi or q.arxiv or q.nct or q.patent
    if (not explicit_identifier and any(word in low for word in package_words)) or (
            not explicit_identifier and q.is_package
            and (q.raw.startswith("@") or "/" in q.raw)):
        forced.update(("code", "security"))
        reasons["code"] = "package-shaped query"
        reasons.setdefault("security", "package vulnerability enrichment")
    return forced, reasons


def is_exact_identifier_query(q):
    """True when local syntax supplies the complete routing decision."""
    stripped = q.raw.strip()
    if q.domain or q.is_url or q.ipv4 or q.asn or q.hash:
        return True
    exact_patterns = (
        r"CVE-\d{4}-\d{4,7}",
        r"CWE-\d{1,5}",
        r"(?:doi:\s*)?10\.\d{4,9}/\S+",
        r"(?:arxiv:)?\d{4}\.\d{4,5}",
        r"NCT\d{8}",
        r"(?:US|EP|WO|GB|JP|CN)\s*\d{5,}[A-Z]?\d?",
    )
    if any(re.fullmatch(pattern, stripped, re.I) for pattern in exact_patterns):
        return True
    return bool(q.is_package and (stripped.startswith("@") or "/" in stripped))


def fallback_route_lanes(q):
    """Conservative local fallback used when Jev is unavailable."""
    forced, reasons = hard_route_lanes(q)
    low = q.raw.lower()
    matched = set()
    for lane, terms in FALLBACK_LANE_TERMS.items():
        if any(term in low for term in terms):
            matched.add(lane)
            reasons.setdefault(lane, "local keyword fallback")
    if not matched and forced == {"web"}:
        matched.update(QUICK_LANES)
        for lane in QUICK_LANES:
            reasons.setdefault(lane, "conservative quick-mode fallback")
    return forced | matched, reasons


def jev_lane_scores(q, api_key=None):
    """Return (probabilities, metadata, error) from OpenRouter Jev."""
    if api_key is None:
        api_key = _dotenv_value("OPENROUTER_API_KEY")
    if not api_key:
        return None, {}, "OPENROUTER_API_KEY is not configured"

    questions = {
        f"lane_{lane}": {
            "type": "noul",
            "instructions": question,
            "criteria": {
                "true": "This source lane is likely to produce material evidence.",
                "false": "This source lane is unlikely to improve the answer.",
            },
        }
        for lane, question in AUTO_LANE_QUESTIONS.items()
    }
    payload = {
        "model": JEV_MODEL,
        "state": {"research_query": q.raw},
        "questions": questions,
    }
    text, err = http(
        OPENROUTER_DECISIONS_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/Clevis22/hermes-deep-research",
            "X-OpenRouter-Title": "Hermes Deep Research Router",
        },
        timeout=20,
        retries=1,
    )
    if err:
        return None, {}, f"Jev routing failed: {err}"
    body = jload(text) or {}
    answers = body.get("answers") or {}
    scores = {}
    for lane in AUTO_LANE_QUESTIONS:
        value = dig(answers, f"lane_{lane}.noul")
        if not isinstance(value, (int, float)) or not 0 <= value <= 1:
            return None, {}, f"Jev routing returned no valid probability for {lane}"
        scores[lane] = round(float(value), 4)
    return scores, {
        "model": body.get("model") or JEV_MODEL,
        "usage": body.get("usage") or {},
    }, None


def auto_route(query, threshold=AUTO_THRESHOLD, api_key=None):
    """Choose lanes with hard identifier rules plus Jev's soft judgments."""
    q = query if isinstance(query, Q) else Q(query)
    forced, reasons = hard_route_lanes(q)
    if is_exact_identifier_query(q):
        ordered = [lane for lane in LANES if lane in forced]
        return {
            "mode": "auto-rules-exact",
            "selected_lanes": ordered,
            "forced_lanes": ordered,
            "reasons": {lane: reasons[lane] for lane in ordered},
            "probabilities": {},
            "threshold": threshold,
            "fallback": False,
            "note": "exact identifier routed locally; Jev was not called",
            "model": None,
            "usage": {},
        }
    scores, meta, err = jev_lane_scores(q, api_key=api_key)
    fallback = scores is None
    note = err

    if fallback:
        selected, fallback_reasons = fallback_route_lanes(q)
        reasons.update(fallback_reasons)
        mode = "auto-rules-fallback"
        scores = {}
    else:
        selected = set(forced)
        for lane, probability in scores.items():
            if probability >= threshold:
                selected.add(lane)
                reasons.setdefault(lane, f"Jev probability {probability:.2f}")

        # Natural-language queries get the two strongest semantic lanes even
        # when they sit just below the threshold. Exact identifiers already
        # have high-recall forced routes and do not need this widening.
        if forced == {"web"}:
            for lane, probability in sorted(scores.items(), key=lambda item: item[1], reverse=True)[:2]:
                selected.add(lane)
                reasons.setdefault(lane, f"top Jev probability {probability:.2f}")

        # A flat distribution near 0.5 means the router is unsure. Widen to the
        # existing quick set instead of silently dropping a useful lane.
        if scores and all(abs(probability - 0.5) < 0.12 for probability in scores.values()):
            selected.update(QUICK_LANES)
            for lane in QUICK_LANES:
                reasons.setdefault(lane, "low-confidence quick-mode widening")
            fallback = True
            note = "Jev probabilities were uniformly uncertain; widened to quick lanes"
        mode = "auto-jev"

    ordered = [lane for lane in LANES if lane in selected]
    return {
        "mode": mode,
        "selected_lanes": ordered,
        "forced_lanes": [lane for lane in LANES if lane in forced],
        "reasons": {lane: reasons[lane] for lane in ordered if lane in reasons},
        "probabilities": scores,
        "threshold": threshold,
        "fallback": fallback,
        "note": note,
        "model": meta.get("model"),
        "usage": meta.get("usage", {}),
    }


def format_route(route):
    """Human-readable, stable route explanation for reports and --plan."""
    lanes = ", ".join(route.get("selected_lanes") or [])
    text = [f"route: {route.get('mode')} -> {lanes or '(none)'}"]
    probabilities = route.get("probabilities") or {}
    if probabilities:
        ranked = sorted(probabilities.items(), key=lambda item: item[1], reverse=True)
        text.append("Jev: " + ", ".join(f"{lane}={value:.2f}" for lane, value in ranked))
    if route.get("note"):
        text.append(f"note: {route['note']}")
    return "\n".join(text)


# ---------------------------------------------------------------------------
# source registry
# ---------------------------------------------------------------------------
# Each entry: name, lane, builder(Q) -> url, kind, parser(payload, url, Q, limit)
# parsers return list of (title, meta, url)

def _searxng(cat=None, engines=None):
    def build(q):
        base = f"{SEARXNG}/search?q={q.enc}&format=json"
        if cat:
            base += f"&categories={urllib.parse.quote(cat)}"
        if engines:
            base += f"&engines={urllib.parse.quote(engines)}"
        return base

    def parse(text, url, q, limit):
        d = jload(text) or {}
        rows = [(clip(r.get("title"), 150),
                 clip((r.get("engine") or "") + " " + (r.get("publishedDate") or "")[:10], 60),
                 r.get("url") or "")
                for r in (d.get("results") or [])[:limit]]
        dead = [str(u[0] if isinstance(u, (list, tuple)) else u)
                for u in (d.get("unresponsive_engines") or [])]
        return rows, (f"unresponsive: {', '.join(dead)}" if dead else None)

    return build, parse


def _json_rows(build, parse):
    return build, parse


S = []  # registry


def register(name, lane, build, kind, parse, timeout=TIMEOUT, retries=0, limit_multiplier=1,
             headers=None, credential=None):
    S.append({"name": name, "lane": lane, "build": build, "kind": kind,
              "parse": parse, "timeout": timeout, "retries": retries,
              "limit_multiplier": limit_multiplier, "headers": headers,
              "credential": credential})


# --- WEB -------------------------------------------------------------------
_b, _p = _searxng()
register("SearXNG general", "web", _b, "json", _p, limit_multiplier=5)
_b, _p = _searxng("web")
register("SearXNG web", "web", _b, "json", _p, limit_multiplier=5)
_b, _p = _searxng("news")
register("SearXNG news", "news", _b, "json", _p, limit_multiplier=5)
_b, _p = _searxng("social media")
register("SearXNG social", "community", _b, "json", _p, limit_multiplier=5)
_b, _p = _searxng("repos")
register("SearXNG repos", "code", _b, "json", _p, limit_multiplier=5)
# These four categories are the single highest-value lane in the whole registry:
# they reach engines the standalone APIs cannot, notably Google Scholar and
# Semantic Scholar. Omitting 'scientific publications' once cost the NDSS
# residential-proxy-detection paper — do not drop it.
_b, _p = _searxng("scientific publications")
register("SearXNG science", "academic", _b, "json", _p, limit_multiplier=5)
_b, _p = _searxng("it")
register("SearXNG IT", "code", _b, "json", _p, limit_multiplier=5)
_b, _p = _searxng("q&a")
register("SearXNG Q&A", "community", _b, "json", _p, limit_multiplier=5)
_b, _p = _searxng("files")
register("SearXNG files", "reference", _b, "json", _p, limit_multiplier=5)
# One call, eight registries: crates.io, npm, Packagist, Hex, pkg.go.dev,
# pub.dev, lib.rs, Docker Hub. Measured 74 rows on a free-text query — cheaper
# than querying the registries one by one.
_b, _p = _searxng("packages")
register("SearXNG packages", "code", _b, "json", _p, limit_multiplier=5)


# --- ACADEMIC --------------------------------------------------------------
def _crossref(q):
    return ("https://api.crossref.org/works?rows=6&select=title,DOI,issued,container-title"
            f"&query.bibliographic={q.enc}&mailto={POLITE_MAILTO}")


def _crossref_parse(text, url, q, limit):
    rows = []
    for it in ((jload(text) or {}).get("message", {}).get("items") or [])[:limit]:
        year = (it.get("issued", {}).get("date-parts") or [[None]])[0][0]
        doi = it.get("DOI")
        rows.append((clip((it.get("title") or [""])[0], 150),
                     clip(f"{year} {(it.get('container-title') or [''])[0]}", 80),
                     f"https://doi.org/{doi}" if doi else url))
    return rows, None


register("Crossref", "academic", _crossref, "json", _crossref_parse)

register("OpenAlex", "academic",
         lambda q: (f"https://api.openalex.org/works?search={q.enc}&per-page=6&mailto={POLITE_MAILTO}"),
         "json",
         lambda t, u, q, l: ([(clip(w.get("title"), 150),
                               clip(f"{w.get('publication_year')} cited-by={w.get('cited_by_count')}", 60),
                               w.get("doi") or w.get("id") or u)
                              for w in ((jload(t) or {}).get("results") or [])[:l]], None),
         retries=1)

register("arXiv", "academic",
         lambda q: f"https://export.arxiv.org/api/query?search_query=all:{q.enc}&max_results=6&sortBy=relevance",
         "xml",
         lambda t, u, q, l: ([(clip(e.find("{http://www.w3.org/2005/Atom}title").text, 150),
                               clip(e.find("{http://www.w3.org/2005/Atom}published").text[:10], 40),
                               e.find("{http://www.w3.org/2005/Atom}id").text.strip())
                              for e in (xload(t).findall("{http://www.w3.org/2005/Atom}entry")[:l]
                                        if xload(t) is not None else [])], None))

register("PubMed", "academic",
         lambda q: ("https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi?db=pubmed&retmode=json"
                    f"&retmax=6&term={q.enc}"),
         "json",
         lambda t, u, q, l: ([
             (f"{dig(jload(t), 'esearchresult.count', '?')} indexed papers",
              f"ids {','.join(dig(jload(t), 'esearchresult.idlist', []) or [])}",
              f"https://pubmed.ncbi.nlm.nih.gov/?term={q.enc}")], None))

register("Europe PMC", "academic",
         lambda q: ("https://www.ebi.ac.uk/europepmc/webservices/rest/search?"
                    f"query={q.enc}&format=json&pageSize=6&resultType=lite"),
         "json",
         lambda t, u, q, l: ([(clip(dig(r, "title"), 150),
                               clip(f"{dig(r, 'pubYear', '')} {dig(r, 'journalTitle', '')} "
                                    f"cites={dig(r, 'citedByCount', '?')}", 80),
                               f"https://europepmc.org/article/{dig(r, 'source', 'MED')}/{dig(r, 'id')}")
                              for r in (dig(jload(t), "resultList.result", []) or [])[:l]], None))

register("Zenodo", "academic",
         lambda q: f"https://zenodo.org/api/records?q={q.enc}&size=6",
         "json",
         lambda t, u, q, l: ([(clip(dig(h, "metadata.title"), 150),
                               clip(str(dig(h, "metadata.publication_date", "")), 40),
                               dig(h, "links.self_html") or dig(h, "doi_url") or u)
                              for h in (dig(jload(t), "hits.hits", []) or [])[:l]], None))

register("DataCite", "academic",
         lambda q: f"https://api.datacite.org/dois?query={q.enc}&page%5Bsize%5D=6",
         "json",
         lambda t, u, q, l: ([(clip(dig(d, "attributes.titles.0.title"), 150),
                               clip(str(dig(d, "attributes.publisher", "")), 60),
                               dig(d, "attributes.url") or (f"https://doi.org/{dig(d, 'attributes.doi')}"
                                                            if dig(d, "attributes.doi") else u))
                              for d in (dig(jload(t), "data", []) or [])[:l]], None))

register("DOAJ", "academic",
         lambda q: f"https://doaj.org/api/search/articles/{q.enc}?pageSize=6",
         "json",
         lambda t, u, q, l: ([(clip(dig(r, "bibjson.title"), 150),
                               clip(f"{dig(r, 'bibjson.year', '')} {dig(r, 'bibjson.journal.title', '')}", 80),
                               f"https://doaj.org/article/{dig(r, 'id')}")
                              for r in (dig(jload(t), "results", []) or [])[:l]], None))

def _openaire_parse(text, url, q, limit):
    rows = []
    results = dig(jload(text), "response.results.result", []) or []
    for raw in as_list(results)[:limit]:
        item = dig(raw, "metadata.oaf:entity.oaf:result", {}) or {}
        titles = as_list(item.get("title"))
        title = next((dig(t, "$") for t in titles if dig(t, "$")), "")
        if not title:
            continue
        date = str(dig(item, "dateofacceptance.$", ""))[:10]
        creators = [str(dig(c, "$")) for c in as_list(item.get("creator")) if dig(c, "$")]
        meta = " ".join(x for x in (date, ", ".join(creators[:2])) if x)
        pids = as_list(item.get("pid"))
        doi = next((str(dig(p, "$")) for p in pids
                    if str(p.get("@classid", "")).lower() == "doi" and dig(p, "$")), None)
        link = f"https://doi.org/{doi}" if doi else ""
        if not link:
            instances = as_list(dig(item, "children.instance", []))
            link = next((dig(inst, "webresource.url.$") for inst in instances
                         if dig(inst, "webresource.url.$")), url)
        rows.append((clip(title, 150), clip(meta, 80), link))
    return rows, None


register("OpenAIRE", "academic",
         lambda q: f"https://api.openaire.eu/search/publications?keywords={q.enc}&format=json&size=6",
         "json", _openaire_parse)


register("HAL", "academic",
         lambda q: f"https://api.archives-ouvertes.fr/search/?q={q.enc}&wt=json&rows=6&fl=title_s,producedDateY_i,uri_s",
         "json",
         lambda t, u, q, l: ([(clip(dig(d, "title_s.0"), 150),
                               clip(str(dig(d, "producedDateY_i", "")), 40),
                               dig(d, "uri_s") or u)
                              for d in (dig(jload(t), "response.docs", []) or [])[:l]], None))

# NOTE: bioRxiv/medRxiv's public API returns *everything posted in a date range*
# and has no keyword search, so it can never answer a topical query — it was
# removed rather than left in to emit rows that only look like findings.

register("OSF", "academic",
         lambda q: f"https://api.osf.io/v2/nodes/?filter%5Btitle%5D={q.enc}&page%5Bsize%5D=6",
         "json",
         lambda t, u, q, l: ([(clip(dig(d, "attributes.title"), 150),
                               clip(str(dig(d, "attributes.date_created", ""))[:10], 40),
                               dig(d, "links.html") or u)
                              for d in (dig(jload(t), "data", []) or [])[:l]], None))

register("Figshare", "academic",
         lambda q: f"https://api.figshare.com/v2/articles?search_for={q.enc}&page_size=6",
         "json",
         lambda t, u, q, l: ([(clip(dig(a, 0) if False else re.sub("<[^>]+>", "", str(dig(a, "title") or "")), 150),
                               clip(str(dig(a, "published_date", ""))[:10], 40),
                               dig(a, "url_public_api") or f"https://doi.org/{dig(a, 'doi')}")
                              for a in (jload(t) or [])[:l]], None))

register("Unpaywall (OA PDF)", "academic",
         lambda q: (f"https://api.unpaywall.org/v2/{q.enc}?email={POLITE_MAILTO}"
                    if q.raw.lower().startswith("10.") else None),
         "json",
         lambda t, u, q, l: ([(
             clip(f"open access: {dig(jload(t), 'title')}", 150),
             clip(f"is_oa={dig(jload(t), 'is_oa')} {dig(jload(t), 'journal_name', '')}", 80),
             dig(jload(t), "best_oa_location.url_for_pdf") or u)], None))

register("OpenCitations", "academic",
         lambda q: f"https://opencitations.net/index/api/v2/citations/doi:{q.raw}" if q.raw.lower().startswith("10.") else None,
         "json",
         lambda t, u, q, l: ([(f"{len(jload(t) or [])} citing works (citation graph)", "", u)], None))

register("HF Papers", "academic",
         lambda q: f"https://huggingface.co/api/papers/search?q={q.enc}",
         "json",
         lambda t, u, q, l: ([(clip(dig(p, "paper.title"), 150),
                               clip(f"{dig(p, 'paper.publishedAt', '')[:10]} upvotes={dig(p, 'paper.upvotes', 0)}", 60),
                               f"https://huggingface.co/papers/{dig(p, 'paper.id')}")
                              for p in (jload(t) or [])[:l]], None))


# --- CODE ------------------------------------------------------------------
register("GitHub repos", "code",
         lambda q: f"https://api.github.com/search/repositories?q={q.enc}&per_page=6&sort=stars",
         "json",
         lambda t, u, q, l: ([(f"{dig(r, 'full_name')} ★{dig(r, 'stargazers_count')}",
                               clip(f"{dig(r, 'language')} {clip(dig(r, 'description'), 90)}", 110),
                               dig(r, "html_url") or u)
                              for r in (dig(jload(t), "items", []) or [])[:l]],
                             ("GitHub unauthenticated search is rate-limited to ~10 req/min"
                              if dig(jload(t), "message") else None)))

def _github_code_build(q):
    # GitHub's code-search API requires authentication. Without a token this
    # optional source is skipped instead of producing a guaranteed 401 gap.
    if not _dotenv_value("GITHUB_TOKEN"):
        return None
    return f"https://api.github.com/search/code?q={q.enc}&per_page=6"


def _github_code_headers():
    token = _dotenv_value("GITHUB_TOKEN")
    return {"Authorization": f"Bearer {token}"} if token else None


register("GitHub code", "code", _github_code_build,
         "json",
         lambda t, u, q, l: ([(clip(dig(i, "path"), 100), clip(dig(i, "repository.full_name"), 60),
                               dig(i, "html_url") or u)
                              for i in (dig(jload(t), "items", []) or [])[:l]],
                             None),
         headers=_github_code_headers, credential="GITHUB_TOKEN")

register("GitLab", "code",
         lambda q: f"https://gitlab.com/api/v4/projects?search={q.enc}&per_page=6&order_by=star_count",
         "json",
         lambda t, u, q, l: ([(clip(dig(p, "path_with_namespace"), 120),
                               clip(f"★{dig(p, 'star_count')} {clip(dig(p, 'description'), 80)}", 110),
                               dig(p, "web_url") or u)
                              for p in (jload(t) or [])[:l]], None))

register("Codeberg", "code",
         lambda q: f"https://codeberg.org/api/v1/repos/search?q={q.enc}&limit=6",
         "json",
         lambda t, u, q, l: ([(clip(dig(r, "full_name"), 120), clip(f"★{dig(r, 'stars_count')}", 40),
                               dig(r, "html_url") or u)
                              for r in (dig(jload(t), "data", []) or [])[:l]], None))

register("npm", "code",
         lambda q: f"https://registry.npmjs.org/-/v1/search?text={q.enc}&size=6",
         "json",
         lambda t, u, q, l: ([(f"{dig(o, 'package.name')}@{dig(o, 'package.version')}",
                               clip(clip(dig(o, "package.description"), 90), 110),
                               dig(o, "package.links.npm") or u)
                              for o in (dig(jload(t), "objects", []) or [])[:l]], None))

register("crates.io", "code",
         lambda q: f"https://crates.io/api/v1/crates?q={q.enc}&per_page=6",
         "json",
         lambda t, u, q, l: ([(clip(dig(c, "name"), 100), clip(dig(c, "description"), 100),
                               f"https://crates.io/crates/{dig(c, 'name')}")
                              for c in (dig(jload(t), "crates", []) or [])[:l]], None))

register("Packagist", "code",
         lambda q: f"https://packagist.org/search.json?q={q.enc}&per_page=6",
         "json",
         lambda t, u, q, l: ([(clip(dig(r, "name"), 100), clip(dig(r, "description"), 100),
                               dig(r, "repository") or f"https://packagist.org/packages/{dig(r, 'name')}")
                              for r in (dig(jload(t), "results", []) or [])[:l]], None))

register("Maven", "code",
         lambda q: f"https://search.maven.org/solrsearch/select?q={q.enc}&rows=6&wt=json",
         "json",
         lambda t, u, q, l: ([(f"{dig(d, 'g')}:{dig(d, 'a')}", clip(str(dig(d, 'latestVersion')), 40),
                               f"https://search.maven.org/artifact/{dig(d, 'g')}/{dig(d, 'a')}")
                              for d in (dig(jload(t), "response.docs", []) or [])[:l]], None))

register("Docker Hub", "code",
         lambda q: f"https://hub.docker.com/v2/search/repositories/?query={q.enc}&page_size=6",
         "json",
         lambda t, u, q, l: ([(clip(dig(r, "repo_name"), 100), clip(f"★{dig(r, 'star_count')} pulls={dig(r, 'pull_count')}", 60),
                               f"https://hub.docker.com/r/{dig(r, 'repo_name')}")
                              for r in (dig(jload(t), "results", []) or [])[:l]], None))

register("HuggingFace models", "code",
         lambda q: f"https://huggingface.co/api/models?search={q.enc}&limit=6&sort=downloads",
         "json",
         lambda t, u, q, l: ([(clip(dig(m, "id"), 110), clip(f"downloads={dig(m, 'downloads')} likes={dig(m, 'likes')}", 60),
                               f"https://huggingface.co/{dig(m, 'id')}")
                              for m in (jload(t) or [])[:l]], None))

register("Software Heritage", "code",
         lambda q: f"https://archive.softwareheritage.org/api/1/origin/search/{q.enc}/?limit=6",
         "json",
         lambda t, u, q, l: ([(clip(dig(o, "url"), 130), "", dig(o, "url") or u)
                              for o in (jload(t) or [])[:l]], None))


# --- COMMUNITY -------------------------------------------------------------
register("Hacker News", "community",
         lambda q: f"https://hn.algolia.com/api/v1/search?query={q.enc}&hitsPerPage=6&tags=story",
         "json",
         lambda t, u, q, l: ([(clip(h.get("title"), 150),
                               clip(f"points={h.get('points')} comments={h.get('num_comments')} {str(h.get('created_at'))[:10]}", 70),
                               h.get("url") or f"https://news.ycombinator.com/item?id={h.get('objectID')}")
                              for h in (dig(jload(t), "hits", []) or [])[:l]], None))

register("Reddit (pullpush)", "community",
         lambda q: f"https://api.pullpush.io/reddit/search/submission/?q={q.enc}&size=6&sort=desc",
         "json",
         lambda t, u, q, l: ([(clip(p.get("title"), 150),
                               clip(f"r/{p.get('subreddit')} score={p.get('score')} comments={p.get('num_comments')}", 70),
                               "https://reddit.com" + str(p.get("permalink", "")))
                              for p in (dig(jload(t), "data", []) or [])[:l]], None),
         retries=1, timeout=25)

register("StackExchange (security)", "community",
         lambda q: ("https://api.stackexchange.com/2.3/search/advanced?order=desc&sort=relevance"
                    f"&site=security&q={q.enc}&pagesize=6&filter=default"),
         "json",
         lambda t, u, q, l: ([(clip(i.get("title"), 150),
                               clip(f"score={i.get('score')} answers={i.get('answer_count')}", 50),
                               i.get("link") or u)
                              for i in (dig(jload(t), "items", []) or [])[:l]], None))


def _se_site(site, label):
    def build(q):
        return ("https://api.stackexchange.com/2.3/search/advanced?order=desc&sort=relevance"
                f"&site={site}&q={q.enc}&pagesize=6&filter=default")

    def parse(t, u, q, l):
        rows = [(clip(i.get("title"), 150),
                 clip(f"score={i.get('score')} answers={i.get('answer_count')}", 50),
                 i.get("link") or u)
                for i in (dig(jload(t), "items", []) or [])[:l]]
        return rows, None

    register(label, "community", build, "json", parse)


_se_site("stackoverflow", "StackOverflow")
_se_site("serverfault", "ServerFault")
_se_site("superuser", "SuperUser")

register("Lemmy", "community",
         lambda q: f"https://lemmy.world/api/v3/search?q={q.enc}&type_=Posts&limit=6",
         "json",
         lambda t, u, q, l: ([(clip(dig(p, "post.name"), 150),
                               clip(f"{dig(p, 'creator.name')} score={dig(p, 'counts.score')}", 70),
                               dig(p, "post.ap_id") or u)
                              for p in (dig(jload(t), "posts", []) or [])[:l]], None))

register("Dev.to", "community",
         lambda q: f"https://dev.to/api/articles?tag={q.raw.split()[0].lower()}&per_page=6",
         "json",
         lambda t, u, q, l: ([(clip(a.get("title"), 150),
                               clip(f"{a.get('user', {}).get('name')} reactions={a.get('public_reactions_count')}", 70),
                               a.get("url") or u)
                              for a in (jload(t) or [])[:l]], None))

register("Mastodon", "community",
         lambda q: f"https://mastodon.social/api/v2/search?q={q.enc}&limit=6&resolve=false",
         "json",
         lambda t, u, q, l: ([(clip(dig(s, "content"), 150), "mastodon post",
                               dig(s, "url") or u)
                              for s in (dig(jload(t), "statuses", []) or [])[:l]], None))


# Bluesky is one of two optional credentialed sources (with GitHub code search).
# The public AppView
# 403s search from this network, but an authenticated session searches fine.
# It is optional — with no BSKY_HANDLE/BSKY_APP_PASSWORD the source simply
# reports itself as not applicable and every other lane still runs keyless.
_BSKY = {"token": None, "tried": False}


def _bsky_token():
    if _BSKY["token"] or _BSKY["tried"]:
        return _BSKY["token"]
    _BSKY["tried"] = True
    handle = _dotenv_value("BSKY_HANDLE")
    password = _dotenv_value("BSKY_APP_PASSWORD")
    if not (handle and password):
        return None
    body = json.dumps({"identifier": handle, "password": password}).encode()
    req = urllib.request.Request(
        "https://bsky.social/xrpc/com.atproto.server.createSession",
        data=body, headers={"Content-Type": "application/json", "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            _BSKY["token"] = (json.loads(r.read().decode("utf-8", "replace")) or {}).get("accessJwt")
    except Exception:  # noqa: BLE001
        _BSKY["token"] = None
    return _BSKY["token"]


def _bsky_headers():
    tok = _bsky_token()
    return {"Authorization": "Bearer " + tok} if tok else None


def _bsky_build(q):
    # No session -> no URL -> the source is reported as skipped, not failed.
    if not _bsky_token():
        return None
    return ("https://bsky.social/xrpc/app.bsky.feed.searchPosts?"
            + urllib.parse.urlencode({"q": q.raw, "limit": "10", "sort": "latest"}))


def _bsky_parse(text, url, q, limit):
    rows = []
    for p in ((jload(text) or {}).get("posts") or [])[:limit]:
        rec = p.get("record") or {}
        body = " ".join((rec.get("text") or "").split())
        if not body:
            continue
        handle = dig(p, "author.handle") or ""
        rkey = (p.get("uri") or "").rsplit("/", 1)[-1]
        link = f"https://bsky.app/profile/{handle}/post/{rkey}" if (handle and rkey) else url
        rows.append((clip(body, 150),
                     clip(f"bluesky {dig(p, 'indexedAt', '')[:10]} "
                          f"likes={dig(p, 'likeCount')} replies={dig(p, 'replyCount')}", 70),
                     link))
    return rows, None


register("Bluesky", "community", _bsky_build, "json", _bsky_parse,
         timeout=25, headers=_bsky_headers,
         credential="BSKY_HANDLE + BSKY_APP_PASSWORD")


# --- NEWS ------------------------------------------------------------------
register("Bing News RSS", "news",
         lambda q: f"https://www.bing.com/news/search?q={q.plus}&format=RSS",
         "rss", lambda t, u, q, l: (rss_items(t, l), None))

register("Google News RSS", "news",
         lambda q: f"https://news.google.com/rss/search?q={q.plus}&hl=en-US&gl=US&ceid=US:en",
         "rss", lambda t, u, q, l: (rss_items(t, l), None))

register("Yahoo News RSS", "news",
         lambda q: f"https://news.search.yahoo.com/rss?p={q.plus}",
         "rss", lambda t, u, q, l: (rss_items(t, l), None))

# Security trade press. The news lane was three search wrappers with no
# editorial source; these are primary reporting. Krebs and Dark Reading serve
# RSS under a text/html content-type, which is why the parser sniffs the body.
for _n, _u in (
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    ("The Record", "https://therecord.media/feed"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("SecurityWeek", "https://www.securityweek.com/feed/"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml"),
    ("Cisco Security Advisories",
     "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"),
):
    register(_n, "news", (lambda u: (lambda q: u))(_u), "rss",
             lambda t, u, q, l: (rss_items(t, l), None))


# --- REGULATORY ------------------------------------------------------------
def _edgar(q):
    return ("https://efts.sec.gov/LATEST/search-index?q=" + urllib.parse.quote(f'"{q.raw}"')
            + "&forms=10-K,10-Q,8-K,S-1,20-F")


def _edgar_parse(t, u, q, l):
    hits = dig(jload(t), "hits", {}) or {}
    total = dig(hits, "total.value")
    rows = [(f"SEC EDGAR full-text: {total} filings contain the exact phrase",
             "coverage starts 2001", u)]
    for h in (hits.get("hits") or [])[:l]:
        src = h.get("_source", {})
        acc, _, doc = str(h.get("_id", "")).partition(":")
        link = (f"https://www.sec.gov/Archives/edgar/data/{acc.replace('-', '')}/{doc}"
                if acc else u)
        rows.append((clip(src.get("display_names"), 140), clip(src.get("file_date"), 40), link))
    return rows, None


register("SEC EDGAR full-text", "regulatory", _edgar, "json", _edgar_parse,
         timeout=30, retries=1)

register("Federal Register", "regulatory",
         lambda q: ("https://www.federalregister.gov/api/v1/documents.json?per_page=6"
                    f"&conditions%5Bterm%5D={q.enc}"
                    "&fields%5B%5D=title&fields%5B%5D=publication_date&fields%5B%5D=html_url"
                    "&fields%5B%5D=type"),
         "json",
         lambda t, u, q, l: ([(clip(r.get("title"), 150),
                               clip(f"{r.get('publication_date')} {r.get('type')}", 60),
                               r.get("html_url") or u)
                              for r in (dig(jload(t), "results", []) or [])[:l]],
                             (f"{dig(jload(t), 'count')} documents match" if dig(jload(t), "count") else None)))

register("Congress.gov", "regulatory",
         lambda q: f"https://api.congress.gov/v3/bill?api_key=DEMO_KEY&limit=6&query={q.enc}",
         "json",
         lambda t, u, q, l: ([(clip(f"{dig(b, 'type')}{dig(b, 'number')} {dig(b, 'title')}", 150),
                               clip(str(dig(b, "introducedDate")), 40),
                               f"https://www.congress.gov/bill/{dig(b, 'congress')}th-congress/"
                               f"{str(dig(b, 'type', '')).lower()}-bill/{dig(b, 'number')}")
                              for b in (dig(jload(t), "bills", []) or [])[:l]], None))

register("GovTrack", "regulatory",
         lambda q: f"https://www.govtrack.us/api/v2/bill?q={q.enc}&limit=6",
         "json",
         lambda t, u, q, l: ([(clip(dig(o, "title_without_number"), 150),
                               clip(f"{dig(o, 'congress')} {dig(o, 'current_status_label')}", 70),
                               f"https://www.govtrack.us{dig(o, 'link', '')}")
                              for o in (dig(jload(t), "objects", []) or [])[:l]], None))

register("CourtListener", "regulatory",
         lambda q: f"https://www.courtlistener.com/api/rest/v4/search/?q={q.enc}&type=o",
         "json",
         lambda t, u, q, l: ([(clip(dig(r, "caseName"), 150),
                               clip(f"{dig(r, 'court')} {dig(r, 'dateFiled')}", 70),
                               f"https://www.courtlistener.com{dig(r, 'absolute_url', '')}")
                              for r in (dig(jload(t), "results", []) or [])[:l]],
                             (f"{dig(jload(t), 'count')} opinions match" if dig(jload(t), "count") else None)))

register("openFEC", "regulatory",
         lambda q: f"https://api.open.fec.gov/v1/candidates/?api_key=DEMO_KEY&per_page=6&q={q.enc}",
         "json",
         lambda t, u, q, l: ([(clip(dig(c, "name"), 120), clip(str(dig(c, "office_full")), 40), u)
                              for c in (dig(jload(t), "results", []) or [])[:l]], None))

register("ClinicalTrials.gov", "regulatory",
         lambda q: f"https://clinicaltrials.gov/api/v2/studies?query.term={q.enc}&pageSize=6",
         "json",
         lambda t, u, q, l: ([(clip(dig(s, "protocolSection.identificationModule.briefTitle"), 150),
                               clip(f"{dig(s, 'protocolSection.statusModule.overallStatus')} "
                                    f"{dig(s, 'protocolSection.identificationModule.nctId')}", 70),
                               f"https://clinicaltrials.gov/study/{dig(s, 'protocolSection.identificationModule.nctId')}")
                              for s in (dig(jload(t), "studies", []) or [])[:l]], None))

# NOTE: BLS / World Bank / Eurostat were removed — they serve *fixed series and
# metadata*, not search. They always answered with a row that read like a
# finding while carrying no query-relevant information.


# --- SECURITY --------------------------------------------------------------
def _kev_parse(t, u, q, l):
    d = jload(t) or {}
    ids = {c.upper() for c in q.cves}
    hits = [v for v in d.get("vulnerabilities", [])
            if v.get("cveID", "").upper() in ids
            or any(w.lower() in json.dumps(v).lower() for w in q.words)][:l]
    rows = [(f"CISA KEV catalog {d.get('catalogVersion')}: {len(hits)} match "
             f"of {d.get('count')} exploited CVEs", "matched on vendor/product text", u)]
    for v in hits:
        rows.append((f"{v.get('cveID')} {v.get('vendorProject')}/{v.get('product')}",
                     f"added {v.get('dateAdded')}",
                     f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}"))
    return rows, None


register("CISA KEV", "security",
         lambda q: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
         "json", _kev_parse, timeout=30, retries=1)


def _nvd(q):
    if q.cves:
        return f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={q.cves[0].upper()}"
    return ("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=6"
            f"&keywordSearch={q.enc}")


def _nvd_parse(t, u, q, l):
    d = jload(t) or {}
    rows = []
    if not q.cves:
        rows.append((f"NVD: {d.get('totalResults')} CVEs match",
                     "0 usually means the term is a nickname, not CVE text", u))
    for v in (d.get("vulnerabilities") or [])[:l]:
        c = v.get("cve", {})
        desc = (dig(c, "descriptions.0.value") or "")
        rows.append((f"{c.get('id')} {clip(desc, 100)}",
                     f"published {str(c.get('published'))[:10]}",
                     f"https://nvd.nist.gov/vuln/detail/{c.get('id')}"))
    return rows, None


register("NVD", "security", _nvd, "json", _nvd_parse, timeout=30, retries=1)

register("EPSS", "security",
         lambda q: ("https://api.first.org/data/v1/epss?cve=" + ",".join(q.cves)) if q.cves else None,
         "json",
         lambda t, u, q, l: ([(f"EPSS {dig(d, 'cve')} exploit probability {dig(d, 'epss')} "
                               f"(percentile {dig(d, 'percentile')})", "", u)
                              for d in (dig(jload(t), "data", []) or [])[:l]], None))

register("CIRCL CVE", "security",
         lambda q: f"https://cve.circl.lu/api/cve/{q.cves[0].upper()}" if q.cves else None,
         "json",
         lambda t, u, q, l: ([(clip(f"{dig(jload(t), 'id') or q.cves[0]} "
                                    f"{dig(jload(t), 'summary') or '(no summary in CIRCL record)'}", 160),
                               clip(f"CVSS {dig(jload(t), 'cvss', 'n/a')}", 50), u)], None))

register("OSV", "security",
         lambda q: (f"https://api.osv.dev/v1/vulns/{q.raw}" if re.match(r"^(GHSA|CVE|PYSEC|RUSTSEC)-", q.raw, re.I)
                    else None),
         "json",
         lambda t, u, q, l: ([(clip(f"{dig(jload(t), 'id') or q.raw} "
                                    f"{dig(jload(t), 'summary') or '(advisory record, no summary)'}", 160),
                               clip(str(dig(jload(t), "published", "")), 40), u)], None))

register("CertSpotter CT", "security",
         lambda q: (f"https://api.certspotter.com/v1/issuances?domain={q.domain}"
                    "&include_subdomains=true&expand=dns_names") if q.domain else None,
         "json",
         lambda t, u, q, l: ([(
             f"CT: {len(jload(t) or [])} certificates for {q.domain}",
             clip(", ".join(sorted({n for c in (jload(t) or [])[:8] for n in (c.get('dns_names') or [])})), 200),
             u)], None))

register("Shodan InternetDB", "security",
         lambda q: f"https://internetdb.shodan.io/{q.raw.strip()}" if re.match(r"^\d+\.\d+\.\d+\.\d+$", q.raw.strip()) else None,
         "json",
         lambda t, u, q, l: ([(f"InternetDB {dig(jload(t), 'ip')}: ports {dig(jload(t), 'ports')}",
                               clip(f"hostnames {dig(jload(t), 'hostnames')} vulns {len(dig(jload(t), 'vulns', []) or [])}", 120),
                               u)], None))

register("RIPEstat", "security",
         lambda q: (f"https://stat.ripe.net/data/prefix-overview/data.json?resource={q.raw.strip()}"
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$|^AS\d+$", q.raw.strip(), re.I) else None),
         "json",
         lambda t, u, q, l: ([(f"RIPEstat {dig(jload(t), 'data.resource')}: "
                               f"{len(dig(jload(t), 'data.asns', []) or [])} origin ASN(s)",
                               clip(f"abuse contacts {dig(jload(t), 'data.abuse_contacts')}", 120), u)], None))

register("AlienVault OTX", "security",
         lambda q: f"https://otx.alienvault.com/api/v1/indicators/domain/{q.domain}/general" if q.domain else None,
         "json",
         lambda t, u, q, l: ([(f"OTX {q.domain}: {dig(jload(t), 'pulse_info.count')} threat pulses",
                               clip(f"reputation={dig(jload(t), 'reputation')} "
                                    f"malware={len(dig(jload(t), 'malware', []) or [])}", 100), u)], None),
         timeout=25)

def _openphish_build(q):
    """The bulk feed is useful only when there is a concrete domain to match."""
    return "https://openphish.com/feed.txt" if q.domain else None


def _openphish_parse(text, _url, q, limit):
    rows = []
    target = (q.domain or "").lower().rstrip(".")
    for candidate in text.splitlines():
        candidate = candidate.strip()
        if not candidate:
            continue
        try:
            hostname = (urllib.parse.urlparse(candidate).hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if target and (hostname == target or hostname.endswith(f".{target}")):
            rows.append((f"OpenPhish match for {target}", hostname, candidate))
            if len(rows) >= limit:
                break
    return rows, None


register("OpenPhish feed", "security", _openphish_build, "text", _openphish_parse)

register("ExploitDB", "security",
         lambda q: "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
         "text", lambda t, u, q, l: ([(clip(r[2], 150),
                                       clip(f"{r[5]}/{r[6]} {r[3]}", 60),
                                       f"https://www.exploit-db.com/exploits/{r[0]}")
                                      for r in _csv_rows(t)
                                      if len(r) > 6 and q.words
                                      and any(w.lower() in (r[2] or "").lower() for w in q.words)][:l],
                                     None))

# Vendor / distro advisory feeds. These are the tier the security lane lacked:
# NVD and CISA KEV describe a vulnerability, these say whether YOUR distro
# shipped a fix. Each keys differently, so each has its own builder.
def _redhat_build(q):
    """Red Hat answers per-CVE or per-package.

    `keyword=` and the `?cve=` list form both return HTTP 400 — the only
    working lookups are the per-CVE path and `package=`.
    """
    if q.cves:
        return ("https://access.redhat.com/hydra/rest/securitydata/cve/"
                f"{q.cves[0]}.json")
    if q.is_package:
        return ("https://access.redhat.com/hydra/rest/securitydata/cve.json"
                f"?package={q.enc}&per_page=6")
    return None


def _redhat_parse(text, url, q, limit):
    d = jload(text)
    # Red Hat sometimes returns the record double-encoded: the body is a JSON
    # *string* whose content is the escaped JSON object. Decoding once yields a
    # str, so decode again rather than silently reporting zero rows.
    if isinstance(d, str):
        d = jload(d)
    rows = []
    if isinstance(d, dict):  # single-CVE record
        cve = dig(d, "CVE") or (q.cves[0] if q.cves else "")
        summary = dig(d, "bugzilla.description") or dig(d, "details") or ""
        rows.append((clip(f"{cve} Red Hat: {dig(d, 'threat_severity') or ''}", 90),
                     clip(f"{dig(d, 'public_date', '')[:10]} "
                          f"cvss3={dig(d, 'cvss3.cvss3_base_score') or ''} {summary}", 160),
                     f"https://access.redhat.com/security/cve/{cve}"))
    elif isinstance(d, list):  # package listing
        rows = [(clip(f"{dig(it, 'CVE')} {dig(it, 'severity') or ''}", 70),
                 clip(f"{dig(it, 'public_date', '')[:10]} "
                      f"{dig(it, 'bugzilla_description') or ''}", 150),
                 f"https://access.redhat.com/security/cve/{dig(it, 'CVE')}")
                for it in d[:limit] if dig(it, "CVE")]
    return rows[:limit], None


register("Red Hat CVE", "security", _redhat_build, "json", _redhat_parse)

register("Ubuntu CVE", "security",
         lambda q: ("https://ubuntu.com/security/cves.json?q="
                    + urllib.parse.quote(q.cves[0] if q.cves else q.raw.strip())
                    + "&limit=6"),
         "json",
         lambda t, u, q, l: ([(clip(f"{dig(it, 'id')} {dig(it, 'priority') or ''}", 70),
                               clip(f"{dig(it, 'published', '')[:10]} "
                                    f"{dig(it, 'description') or ''}", 150),
                               f"https://ubuntu.com/security/{dig(it, 'id')}")
                              for it in ((jload(t) or {}).get("cves") or [])[:l]
                              if dig(it, "id")], None),
         timeout=25)


# Detection-engineering sources. Nothing else in the registry answers "how is
# this technique actually detected" — these are the artefacts defenders write.
def _sigma_rows(text, q, limit):
    rows = []
    for rel in re.findall(r"^  - path: (\S+)", text, flags=re.M):
        if "/" not in rel:
            continue
        name = rel.rsplit("/", 1)[-1].removesuffix(".yml").replace("_", " ")
        hay = name + " " + rel
        if q.words and any(w.lower() in hay.lower() for w in q.words):
            rows.append((clip(f"SIGMA {name}", 140), clip(rel, 90),
                         f"https://github.com/SigmaHQ/sigma/blob/master/rules/{rel}"))
        if len(rows) >= limit:
            break
    return rows


register("SigmaHQ rules", "security",
         lambda q: ("https://raw.githubusercontent.com/SigmaHQ/sigma/master/"
                    "tests/thor.yml"),
         "text",
         lambda t, u, q, l: (_sigma_rows(t, q, l), None),
         timeout=25)
def _capec_parse(text, url, q, limit):
    """Resolve CWE-to-CAPEC relationships from MITRE's CWE record.

    CWE and CAPEC use independent ID namespaces: CWE-89 is SQL injection while
    CAPEC-89 is pharming. MITRE's ``RelatedAttackPatterns`` field is the
    authoritative mapping between them.
    """
    weakness = dig(jload(text), "Weaknesses.0", {}) or {}
    cwe = str(weakness.get("ID") or (q.cwes[0] if q.cwes else ""))
    name = weakness.get("Name") or ""
    ids = sorted({str(i) for i in as_list(weakness.get("RelatedAttackPatterns")) if i},
                 key=lambda value: (not value.isdigit(),
                                    int(value) if value.isdigit() else value))
    rows = [(f"CAPEC-{capec} related to CWE-{cwe}", clip(name, 120),
             f"https://capec.mitre.org/data/definitions/{capec}.html")
            for capec in ids[:limit]]
    note = None if rows else f"no CAPEC relationships listed for CWE-{cwe}"
    return rows, note


register("MITRE CAPEC", "security",
         lambda q: (f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{q.cwes[0]}"
                    if q.cwes else None),
         "json", _capec_parse, timeout=25)

register("MITRE CWE", "security",
         lambda q: (f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{q.cwes[0]}"
                    if q.cwes else None),
         "json",
         lambda t, u, q, l: ([(clip(f"CWE-{dig(it, 'ID')} {dig(it, 'Name') or ''}", 130),
                               clip(dig(it, "Description") or "", 150), u)
                              for it in ((jload(t) or {}).get("Weaknesses") or [])[:l]],
                             None),
         timeout=25)


# --- PATENTS ---------------------------------------------------------------
# Best-effort: Google's xhr endpoint answers a burst of requests then serves
# HTTP 503 for a while (measured: 3 clean runs, then 5/5 503 across both UAs).
# It is registered for the queries where a patent hit is worth a retry, and a
# 503 is reported as a normal coverage gap — never as "no patents exist".
def _gpat_build(q):
    return ("https://patents.google.com/xhr/query?url="
            + urllib.parse.quote(f"q={q.raw.strip()}&num=10") + "&exp=")


def _gpat_parse(text, url, q, limit):
    d = jload(text)
    if not d:
        return [], "Google Patents: non-JSON response (503 rate-limit)"
    res = dig(d, "results", {}) or {}
    rows = []
    for cl in (dig(res, "cluster", []) or []):
        for r in (dig(cl, "result", []) or []):
            p = dig(r, "patent", {}) or {}
            num = dig(p, "publication_number")
            if not num:
                continue
            rows.append((clip(f"{num}: {dig(p, 'title') or ''}", 150),
                         clip(f"{dig(p, 'priority_date') or dig(p, 'publication_date') or ''} "
                              f"{dig(p, 'assignee') or ''}", 70),
                         f"https://patents.google.com/patent/{num}"))
    return rows[:limit], f"Google Patents: {dig(res, 'total_num_results')} total matches"


register("Google Patents", "patents", _gpat_build, "json", _gpat_parse,
         timeout=25, retries=1, headers={"User-Agent": BROWSER_UA})


# --- REFERENCE -------------------------------------------------------------
register("Wikipedia", "reference",
         lambda q: "https://en.wikipedia.org/api/rest_v1/page/summary/"
                   + urllib.parse.quote(q.raw.replace(" ", "_")),
         "json",
         lambda t, u, q, l: ([(clip(dig(jload(t), "title"), 120),
                               clip(dig(jload(t), "description"), 100),
                               dig(jload(t), "content_urls.desktop.page") or u)], None))

register("Wikipedia search", "reference",
         lambda q: ("https://en.wikipedia.org/w/api.php?action=query&list=search&format=json&srlimit=6"
                    f"&srsearch={q.enc}"),
         "json",
         lambda t, u, q, l: ([(clip(dig(s, "title"), 120), clip(re.sub("<[^>]+>", "", str(dig(s, 'snippet'))), 120),
                               "https://en.wikipedia.org/wiki/" + urllib.parse.quote(str(dig(s, "title")).replace(" ", "_")))
                              for s in (dig(jload(t), "query.search", []) or [])[:l]], None))

register("Wikidata", "reference",
         lambda q: ("https://www.wikidata.org/w/api.php?action=wbsearchentities&format=json"
                    f"&language=en&limit=6&search={q.enc}"),
         "json",
         lambda t, u, q, l: ([(clip(f"{dig(s, 'label')} ({dig(s, 'id')})", 120),
                               clip(dig(s, "description"), 110),
                               dig(s, "concepturi") or u)
                              for s in (dig(jload(t), "search", []) or [])[:l]],
                             # wbsearchentities matches entity LABELS only — a
                             # topical phrase legitimately returns 0 and that is
                             # not a failure.
                             (None if dig(jload(t), "search") else
                              "no entity label matched this phrase (label-only search)")))

register("Wikipedia Commons", "reference",
         lambda q: ("https://commons.wikimedia.org/w/api.php?action=query&list=search&format=json"
                    f"&srlimit=6&srsearch={q.enc}"),
         "json",
         lambda t, u, q, l: ([(clip(dig(s, "title"), 120), "", u)
                              for s in (dig(jload(t), "query.search", []) or [])[:l]], None))

register("OpenLibrary", "reference",
         lambda q: f"https://openlibrary.org/search.json?q={q.enc}&limit=6&fields=title,author_name,first_publish_year,key",
         "json",
         lambda t, u, q, l: ([(clip(dig(d, "title"), 130),
                               clip(f"{', '.join(dig(d, 'author_name', ['?'])[:2])} {dig(d, 'first_publish_year', '')}", 90),
                               f"https://openlibrary.org{dig(d, 'key', '')}")
                              for d in (dig(jload(t), "docs", []) or [])[:l]],
                             (f"{dig(jload(t), 'numFound')} books match" if dig(jload(t), "numFound") else None)))

register("Internet Archive", "reference",
         lambda q: ("https://archive.org/advancedsearch.php?fl%5B%5D=identifier&fl%5B%5D=title"
                    f"&fl%5B%5D=year&rows=6&output=json&q={q.enc}"),
         "json",
         lambda t, u, q, l: ([(clip(dig(d, "title"), 130), clip(str(dig(d, "year", "")), 40),
                               f"https://archive.org/details/{dig(d, 'identifier')}")
                              for d in (dig(jload(t), "response.docs", []) or [])[:l]], None),
         timeout=30)

register("DBpedia", "reference",
         lambda q: "https://dbpedia.org/data/" + urllib.parse.quote(q.raw.replace(" ", "_")) + ".json",
         "json",
         lambda t, u, q, l: ([(f"DBpedia resource for {clip(q.raw, 60)}",
                               f"{len(jload(t) or {})} linked-data resources", u)], None))

register("Datamuse", "reference",
         lambda q: f"https://api.datamuse.com/words?ml={q.enc}&max=6",
         "json",
         lambda t, u, q, l: ([(clip(w.get("word"), 60), "related term", u) for w in (jload(t) or [])[:l]], None))

register("Nominatim", "reference",
         lambda q: f"https://nominatim.openstreetmap.org/search?q={q.enc}&format=jsonv2&limit=6",
         "json",
         lambda t, u, q, l: ([(clip(dig(p, "display_name"), 150),
                               clip(f"{dig(p, 'type')} {dig(p, 'lat')},{dig(p, 'lon')}", 60),
                               f"https://www.openstreetmap.org/{dig(p, 'osm_type')}/{dig(p, 'osm_id')}")
                              for p in (jload(t) or [])[:l]], None))


# --- ARCHIVE ---------------------------------------------------------------
def _wayback(q):
    target = q.raw if q.is_url else (f"https://{q.domain}" if q.domain else None)
    if not target:
        return None
    return (f"http://web.archive.org/cdx/search/cdx?url={urllib.parse.quote(target)}"
            "&output=json&limit=6&collapse=timestamp:6&fl=timestamp,original,statuscode")


def _wayback_parse(t, u, q, l):
    rows = jload(t)
    if not rows or len(rows) < 2:
        return [("Wayback: no snapshots indexed", "", u)], None
    out = [(f"Wayback CDX: {len(rows) - 1} snapshots", "", u)]
    for r in rows[1:][:l]:
        ts = r[0]
        stamp = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
        out.append((f"snapshot {stamp}", f"HTTP {r[2]}",
                    f"https://web.archive.org/web/{ts}/{r[1]}"))
    return out, None


register("Wayback CDX", "archive", _wayback, "json", _wayback_parse, timeout=30, retries=1)

register("urlscan.io", "archive",
         lambda q: f"https://urlscan.io/api/v1/search/?q=domain:{urllib.parse.quote(q.domain)}&size=6" if q.domain else None,
         "json",
         lambda t, u, q, l: ([(clip(dig(r, "page.url"), 140),
                               clip(str(dig(r, "task.time", ""))[:10], 40),
                               dig(r, "result") or u)
                              for r in (dig(jload(t), "results", []) or [])[:l]],
                             (f"{dig(jload(t), 'total')} scans on record" if dig(jload(t), "total") is not None else None)))


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------

class Result:
    __slots__ = ("source", "lane", "title", "meta", "url", "error", "off_topic", "sources")

    def __init__(self, source, lane, title, meta, url, error=None, off_topic=False):
        self.source, self.lane = source, lane
        self.title, self.meta, self.url, self.error = title, meta, url, error
        self.off_topic = off_topic
        self.sources = [source] if source else []

    def as_dict(self):
        """__slots__ means vars() does not work — serialize explicitly."""
        return {k: getattr(self, k) for k in self.__slots__}


def norm_url(u):
    """Normalize for dedup: strip scheme, www, trailing slash, tracking params.

    Also unwraps redirect wrappers (Bing/Yahoo news ``apiclick``, Google News
    ``rss/articles``) so the same story arriving via search + RSS collapses to
    one finding instead of two.
    """
    if not u:
        return ""
    if "bing.com/news/apiclick" in u or "news.yahoo.com" in u:
        inner = urllib.parse.parse_qs(urllib.parse.urlparse(u).query).get("url")
        if inner:
            u = inner[0]
    u = re.sub(r"^https?://", "", u.strip().lower())
    u = re.sub(r"^www\.", "", u)
    u = u.split("#")[0]
    u = re.sub(r"[?&](utm_[^&]*|fbclid=[^&]*|ref=[^&]*|tid=[^&]*|aid=[^&]*"
               r"|c=[^&]*|mkt=[^&]*|oc=[^&]*)", "", u)
    return u.rstrip("/")


def dedup_key(r):
    """URL + title, both normalized.

    URL alone is wrong: an independent source often cites the same landing page
    (a CISA KEV entry and the NVD record share
    nvd.nist.gov/vuln/detail/<id>), and collapsing them silently deletes
    corroboration. Same URL *and* same title is a genuine duplicate.
    """
    return f"{norm_url(r.url)}|{re.sub(r'[^a-z0-9]+', '', r.title.lower())[:70]}"


def clean_title(title):
    """Strip placeholder fragments left when an API field is absent."""
    if not title:
        return ""
    t = " ".join(str(title).split())
    t = re.sub(r"\bNone\b", "", t).strip(" -–—|:")
    return t


def run_one(src, q, limit):
    """Return (rows, note, applicable).

    ``applicable=False`` means the source does not fit this query shape (a
    domain-only or CVE-only API given free text) and was skipped on purpose.
    ``note`` is informational and is NOT a failure. A real failure is reported
    as rows=[] with note starting "ERR:".
    """
    build = src["build"]
    try:
        url = build(q)
    except Exception as exc:  # noqa: BLE001
        return [], f"ERR: {src['name']}: build failed: {exc}", True
    if not url:
        return [], None, False
    # A source may supply headers as a plain dict or as a zero-arg callable, so
    # an authenticated source (Bluesky) can mint its token at request time.
    hdrs = src.get("headers")
    if callable(hdrs):
        try:
            hdrs = hdrs()
        except Exception:  # noqa: BLE001
            hdrs = None
    text, err = http(url, timeout=src["timeout"], retries=src["retries"],
                     headers=hdrs)
    if err:
        return [], f"ERR: {src['name']}: {err}", True
    try:
        # SearXNG fans out to many engines at once, so one request already
        # carries far more results than a single API — take more of them.
        eff_limit = limit * src.get("limit_multiplier", 1)
        rows, note = src["parse"](text, url, q, eff_limit)
    except Exception as exc:  # noqa: BLE001
        return [], f"ERR: {src['name']}: parse failed: {type(exc).__name__}: {exc}", True
    out = []
    for r in rows:
        if r and clean_title(r[0]):
            out.append(Result(src["name"], src["lane"], clean_title(r[0]), r[1], r[2]))
    # Same source often returns one row per engine for the same paper (a
    # Crossref hit and a Google Scholar hit for one DOI). Collapse repeats
    # inside the source only — cross-source repeats are corroboration and are
    # kept deliberately.
    seen_t, deduped = set(), []
    for r in out:
        tkey = re.sub(r"[^a-z0-9]+", "", r.title.lower())[:80]
        if tkey and tkey in seen_t:
            continue
        seen_t.add(tkey)
        deduped.append(r)
    return deduped, (f"{src['name']}: {note}" if note else None), True


_RELEVANCE_STOP = {"com", "org", "net", "www", "http", "https", "the", "and",
                   "for", "with", "from", "that", "this", "new", "how", "what"}


def relevant(title, meta, q):
    """Tag rows whose only link to the query is a generic shared word.

    Rows are NEVER dropped for this — deep research means maximum coverage, so
    an uncertain row is flagged ``off_topic`` and parked in its own section;
    only the explicit "0 matches" count rows are suppressed outright.
    """
    if not title:
        return False
    low_meta = (meta or "").lower()
    if "0 match" in low_meta or "0 match" in title.lower() or "no snapshots" in title.lower():
        return False  # informational count row asserting emptiness
    n = len(q.words)
    if n < 2:
        return True  # single-token lookups ('log4j') are exact by nature
    need = 1 if n == 2 else 2
    hay = title.lower() + " " + low_meta
    terms = [w.lower() for w in q.words if w.lower() not in _RELEVANCE_STOP]
    if not terms:
        return True
    return sum(1 for term in terms if term in hay) >= min(need, len(terms))


def research(query, lanes=None, limit=5, workers=8, on_progress=None):
    q = Q(query)
    wanted = set(lanes or LANES)
    chosen = [s for s in S if s["lane"] in wanted]
    findings, errors, skipped, empty = [], [], [], []
    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(run_one, s, q, limit): s for s in chosen}
        done = 0
        for fut in concurrent.futures.as_completed(futs):
            src = futs[fut]
            done += 1
            try:
                rows, note, applicable = fut.result()
            except Exception as exc:  # noqa: BLE001
                rows, note, applicable = [], f"ERR: {src['name']}: {exc}", True
            if not applicable:
                skipped.append(src["name"])
            if rows:
                for r in rows:
                    if not relevant(r.title, r.meta, q):
                        r.off_topic = True
                findings.extend(rows)
            elif applicable and not (note or "").startswith("ERR:"):
                empty.append(src["name"])
            if note:
                (errors if note.startswith("ERR:") else errors).append(note)
            if on_progress:
                on_progress(done, len(chosen), src["name"], len(rows))
    # Merge rows that describe the same item (same normalized title, or same
    # normalized URL) into one finding that names every source which carried it.
    # Corroboration becomes visible instead of appearing as duplicate lines.
    by_title, merged, dupes = {}, [], 0
    for r in findings:
        tkey = re.sub(r"[^a-z0-9]+", "", r.title.lower())[:80]
        ukey = norm_url(r.url)
        hit = by_title.get(tkey) if tkey else None
        if hit is None and ukey:
            hit = next((m for m in merged if ukey and norm_url(m.url) == ukey), None)
        if hit is not None:
            dupes += 1
            for s in r.sources:
                if s not in hit.sources:
                    hit.sources.append(s)
            if not hit.meta and r.meta:
                hit.meta = r.meta
            # A duplicate is on-topic if any source supplied an on-topic form.
            hit.off_topic = hit.off_topic and r.off_topic
            continue
        if tkey:
            by_title[tkey] = r
        merged.append(r)
    unique = merged
    by_lane = {}
    unrelated = 0
    for r in unique:
        if r.off_topic:
            unrelated += 1
            continue
        by_lane.setdefault(r.lane, []).append(r)
    return {
        "query": query,
        "shape": {
            "cve": q.cves,
            "cwe": q.cwes,
            "domain": q.domain,
            "url": q.is_url,
            "ip": q.ipv4,
            "asn": q.asn,
            "hash": q.hash,
            "doi": q.doi,
            "arxiv": q.arxiv,
            "nct": q.nct,
            "patent": q.patent,
        },
        "elapsed_s": round(time.time() - t0, 1),
        "sources_queried": len(chosen),
        "sources_with_hits": len({source for r in unique if not r.off_topic
                                  for source in r.sources}),
        "findings": unique, "by_lane": by_lane, "errors": errors,
        "unrelated_matches": unrelated,
        "empty_sources": empty, "skipped_not_applicable": skipped,
        "duplicates_collapsed": dupes, "lanes": sorted(wanted),
    }


# ---------------------------------------------------------------------------
# full-text escalation (optional)
# ---------------------------------------------------------------------------

def read_url(url, chars=4000):
    """Fetch readable text via the local PiExtract service (SSRF-guarded)."""
    payload = json.dumps({"url": url, "formats": ["markdown"]}).encode()
    text, err = http(f"{PIEXTRACT}/v2/scrape", data=payload,
                     headers={"Content-Type": "application/json"}, timeout=45)
    if err:
        return None, err
    d = jload(text) or {}
    body = dig(d, "data.markdown") or dig(d, "markdown") or dig(d, "data.content") or ""
    if not body:
        return None, "no content returned"
    return clip(body, chars), None


# ---------------------------------------------------------------------------
# context hygiene: the run is not allowed to cost more than the finding
# ---------------------------------------------------------------------------

# A result row is the unit a reader quotes from. Everything else in a row is
# provenance already visible in the `sources` list, so the trimmed form keeps
# what is citable and drops the rest.
_ROW_KEYS = ("lane", "title", "url", "sources")


def rfield(r, name, default=None):
    """Read a row field from either a live ``Result`` or a loaded dict."""
    if hasattr(r, name):
        return getattr(r, name)
    try:
        return r.get(name, default)
    except AttributeError:
        return default


def trim_rows(rows):
    """Project result rows to the citable fields only."""
    out = []
    for r in rows:
        d = {k: rfield(r, k) for k in _ROW_KEYS}
        meta = rfield(r, "meta")
        if meta:
            d["meta"] = meta
        out.append(d)
    return out


def compact_payload(res, max_sources=0):
    """The small, analysis-ready view of a run.

    Everything here is derivable from the full payload or from the search output
    itself, and the expensive parts are deliberately absent:

    * ``by_lane`` is dropped — it is exactly ``regroup(on-topic findings)`` and
      is reproduced on demand by ``to_lanes()`` (verified on a live run: 13,095
      bytes of pure duplication).
    * off-topic rows appear as URL strings, not full bodies. They matched one
      generic word, and their bodies are what make a run look expensive.
    * ``full_text`` is not duplicated under a second key (``--read`` already
      stores it once).

    Analysis that needs real text should read it on demand rather than drag
    every result body into the conversation.
    """
    findings = res["findings"]
    on, off = [], []
    for r in findings:
        (off if rfield(r, "off_topic", False) else on).append(r)

    sources = [(t, u, s) for t, u, s in collect_sources(res)]
    shown = sources[:max_sources] if max_sources else sources

    payload = {
        "query": res["query"],
        "shape": res["shape"],
        "lanes": res["lanes"],
        "elapsed_s": res["elapsed_s"],
        "counts": {
            "sources_queried": res["sources_queried"],
            "sources_with_hits": res["sources_with_hits"],
            "on_topic": len(on),
            "off_topic_urls": len(off),
            "findings_raw": len(findings),
            "duplicates_collapsed": res["duplicates_collapsed"],
        },
        "on_topic": trim_rows(on),
        "unrelated_urls": [rfield(r, "url") for r in off if rfield(r, "url")],
        "sources": [{"n": i, "title": t, "url": u, "via": s}
                    for i, (t, u, s) in enumerate(shown, 1)],
        "sources_truncated": len(sources) - len(shown),
        "gaps": res["errors"],
        "empty_sources": res["empty_sources"],
        "skipped_not_applicable": res["skipped_not_applicable"],
    }
    if res.get("routing"):
        payload["routing"] = res["routing"]
    return payload


def to_lanes(payload):
    """Rebuild the lane grouping (what ``by_lane`` used to carry) from rows."""
    lanes = {}
    for r in payload.get("on_topic", []):
        lanes.setdefault(r["lane"], []).append(r)
    return lanes


def render_payload(payload, show_unrelated=True):
    """The compact payload as plain text — the agent-readable form."""
    c = payload["counts"]
    L = [f"# Deep research: {payload['query']}", ""]
    L.append(f"{c['on_topic']} on-topic findings · {c['sources_with_hits']} of "
             f"{c['sources_queried']} sources returned hits · "
             f"{c['duplicates_collapsed']} duplicates collapsed · {payload['elapsed_s']}s")
    if c["off_topic_urls"]:
        L.append(f"({c['off_topic_urls']} further rows matched only a generic word — "
                 f"URLs only in the JSON, not listed here)")
    shape = ", ".join(f"{k}={v}" for k, v in payload["shape"].items() if v)
    L.append(f"query shape: {shape or 'free text'}")
    if payload.get("routing"):
        L.extend(format_route(payload["routing"]).splitlines())
    L.append("")
    lanes = to_lanes(payload)
    for lane in LANES:
        rows = lanes.get(lane)
        if not rows:
            continue
        L.append(f"## {lane.upper()} ({len(rows)})")
        for r in rows:
            L.append(f"- **{r['title']}**")
            if r.get("meta"):
                L.append(f"  - {r['meta']}")
            if r.get("url"):
                L.append(f"  - {r['url']}")
            L.append(f"  - sources: {', '.join(r.get('sources') or [])}")
        L.append("")
    if payload.get("gaps"):
        L.append("## Coverage gaps and notes (a gap is not evidence of absence)")
        for e in payload["gaps"]:
            L.append(f"- {e}")
        L.append("")
    if payload.get("empty_sources"):
        L.append("## Sources that answered but returned nothing")
        L.append("- " + ", ".join(payload["empty_sources"]))
        L.append("")
    if payload.get("skipped_not_applicable"):
        L.append("## Sources not applicable to this query shape (skipped on purpose)")
        L.append("- " + ", ".join(payload["skipped_not_applicable"]))
        L.append("")
    if show_unrelated and payload.get("unrelated_urls"):
        L.append(f"## Unrelated matches ({len(payload['unrelated_urls'])}) — kept, not discarded")
        L.append("These matched one generic word of the query. Verify before citing.")
        for u in payload["unrelated_urls"]:
            L.append(f"- {u}")
        L.append("")
    if payload.get("sources"):
        L.append(f"## Sources ({len(payload['sources'])} unique — cite as [n])")
        L.append("")
        for s in payload["sources"]:
            L.append(f"[{s['n']}] {s['title']}")
            L.append(f"     {s['url']}")
            L.append(f"     via {s['via']}")
        if payload.get("sources_truncated"):
            L.append("")
            L.append(f"... {payload['sources_truncated']} more not shown "
                     f"(use --md for the full list)")
    return "\n".join(L)


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------

def text_report(res, show_errors=True, show_unrelated=False):
    L = []
    L.append(f"# Deep research: {res['query']}")
    L.append("")
    on_topic = len(res["findings"]) - res.get("unrelated_matches", 0)
    L.append(f"{on_topic} on-topic findings · {res['sources_with_hits']} of "
             f"{res['sources_queried']} sources returned hits · {res['duplicates_collapsed']} "
             f"duplicates collapsed · {res['elapsed_s']}s")
    if res.get("unrelated_matches"):
        L.append(f"({res['unrelated_matches']} further rows matched only a generic word — "
                 f"kept in the JSON, listed under 'Unrelated matches' at the end)")
    shape = ", ".join(f"{k}={v}" for k, v in res["shape"].items() if v)
    L.append(f"query shape: {shape or 'free text'}")
    if res.get("routing"):
        L.extend(format_route(res["routing"]).splitlines())
    L.append("")
    for lane in LANES:
        rows = res["by_lane"].get(lane)
        if not rows:
            continue
        L.append(f"## {lane.upper()} ({len(rows)})")
        for r in rows:
            L.append(f"- **{r.title}**")
            if r.meta:
                L.append(f"  - {r.meta}")
            if r.url:
                L.append(f"  - {r.url}")
            L.append(f"  - sources: {', '.join(r.sources)}")
        L.append("")
    if show_errors and res["errors"]:
        L.append("## Coverage gaps and notes (a gap is not evidence of absence)")
        for e in res["errors"]:
            L.append(f"- {e}")
        L.append("")
    if res.get("empty_sources"):
        L.append("## Sources that answered but returned nothing")
        L.append("- " + ", ".join(res["empty_sources"]))
        L.append("")
    if res["skipped_not_applicable"]:
        L.append("## Sources not applicable to this query shape (skipped on purpose)")
        L.append("- " + ", ".join(res["skipped_not_applicable"]))
        L.append("")
    if show_unrelated:
        off = [r for r in res["findings"] if r.off_topic]
        if off:
            L.append(f"## Unrelated matches ({len(off)}) — kept, not discarded")
            L.append("These matched one generic word of the query. Verify before citing.")
            for r in off:
                L.append(f"- {r.title} ({r.source}) {r.url}")
            L.append("")
    return "\n".join(L)


def collect_sources(res, include_off_topic=False):
    """Unique (title, url, source) rows across findings, deduped by normalized URL."""
    seen, out = set(), []
    for r in res["findings"]:
        if rfield(r, "off_topic", False) and not include_off_topic:
            continue
        u = rfield(r, "url")
        if not u:
            continue
        n = norm_url(u)
        if n in seen:
            continue
        seen.add(n)
        sources = rfield(r, "sources") or []
        out.append((rfield(r, "title"), u, ", ".join(sources) or rfield(r, "source")))
    return out


def markdown_sources_block(res, include_off_topic=False):
    """Render an on-topic Sources list for grounded citations."""
    return "\n".join(f"- [{t}]({u}) — {s}"
                     for t, u, s in collect_sources(res, include_off_topic))


def text_sources_block(res, max_sources=0):
    """Numbered plain-text Sources list, for terminal output the agent can cite from.

    On-topic rows only: the unrelated matches are already listed separately and are
    exactly the rows that must not end up in a reference list.
    """
    rows = collect_sources(res, include_off_topic=False)
    total = len(rows)
    if not total:
        return ""
    shown = rows[:max_sources] if max_sources else rows
    L = [f"## Sources ({total} unique — cite as [n])", ""]
    for i, (t, u, s) in enumerate(shown, 1):
        L.append(f"[{i}] {t}")
        L.append(f"     {u}")
        L.append(f"     via {s}")
    if total > len(shown):
        L.append("")
        L.append(f"... {total - len(shown)} more not shown "
                 f"(raise --max-sources, or use --md for the full list)")
    return "\n".join(L)


def markdown_report(res, include_sources=True):
    """Build a Markdown report with one on-topic citation block."""
    md = text_report(res)
    if include_sources:
        sources = markdown_sources_block(res)
        if sources:
            md += "\n\n## Sources\n\n" + sources + "\n"
    if res.get("full_text"):
        md += "\n## Full text\n\n"
        for ft in res["full_text"]:
            body = ft["text"] or "(failed: " + str(ft["error"]) + ")"
            md += f"### {ft['url']}\n\n{body}\n\n"
    return md


def main():
    ap = argparse.ArgumentParser(description="Deep research across all keyless sources")
    ap.add_argument("query", nargs="?")
    ap.add_argument("--deep", action="store_true", help="all lanes (default)")
    ap.add_argument("--quick", action="store_true", help="web+academic+community+news+reference")
    ap.add_argument("--auto", action="store_true",
                    help="route exact shapes locally and natural-language intent with Jev")
    ap.add_argument("--lanes", help="comma-separated: " + ",".join(LANES))
    ap.add_argument("--plan", action="store_true",
                    help="print the routing plan without querying research sources")
    ap.add_argument("--auto-threshold", type=float, default=AUTO_THRESHOLD, metavar="P",
                    help=f"Jev lane probability threshold (default {AUTO_THRESHOLD})")
    ap.add_argument("--limit", type=int, default=5, help="rows per source (default 5)")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--read", type=int, default=0, metavar="N",
                    help="also fetch full text of the top N unique URLs via PiExtract")
    ap.add_argument("--json", nargs="?", const="full", choices=["full", "compact"],
                    help="machine output; 'compact' drops the redundant by_lane, "
                         "off-topic bodies and duplicate full_text (much smaller)")
    ap.add_argument("--render", metavar="PATH",
                    help="render a JSON run (from --json full or compact) as text, no searching")
    ap.add_argument("--md", metavar="PATH", help="write a markdown report")
    ap.add_argument("--sources", action="store_true", help="list the source registry")
    ap.add_argument("--no-sources", action="store_true",
                    help="suppress the Sources block in stdout/--md output")
    ap.add_argument("--max-sources", type=int, default=30, metavar="N",
                    help="cap the stdout Sources list (default 30; 0 = all)")
    ap.add_argument("--no-unrelated", action="store_true",
                    help="omit the unrelated-matches section (stdout and --render)")
    ap.add_argument("--live", action="store_true", help="stream per-source progress to stderr")
    args = ap.parse_args()

    if args.sources:
        by_lane = {}
        for s in S:
            by_lane.setdefault(s["lane"], []).append(s["name"])
        total = 0
        for lane, names in by_lane.items():
            print(f"\n{lane.upper()} ({len(names)})")
            for n in names:
                print(f"  - {n}")
            total += len(names)
        credentialed = [s["name"] for s in S if s.get("credential")]
        print(f"\n{total} configured sources across {len(by_lane)} lanes: "
              f"{total - len(credentialed)} keyless, {len(credentialed)} optional "
              f"credentialed ({', '.join(credentialed)}).")
        return 0

    if args.render:
        try:
            with open(args.render, encoding="utf-8") as fh:
                payload = json.load(fh)
        except Exception as e:
            print(f"could not read {args.render}: {e}", file=sys.stderr)
            return 2
        if "on_topic" not in payload:
            # a --json full dump: project it and render that instead of re-searching
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            print("note: full dump given; rendering its on-topic view only",
                  file=sys.stderr)
            findings = payload.get("findings") or []
            for r in findings:
                r.setdefault("off_topic", False)
            payload = compact_payload(payload)
        print(render_payload(payload, show_unrelated=not args.no_unrelated))
        return 0

    if not args.query:
        ap.print_help()
        print("\nSources available: run with --sources")
        return 2

    if sum(bool(value) for value in (args.auto, args.quick, args.deep, args.lanes)) > 1:
        print("choose only one of --auto, --quick, --deep, or --lanes", file=sys.stderr)
        return 2
    if not 0 <= args.auto_threshold <= 1:
        print("--auto-threshold must be between 0 and 1", file=sys.stderr)
        return 2

    if args.auto:
        routing = auto_route(args.query, threshold=args.auto_threshold)
        lanes = tuple(routing["selected_lanes"])
    elif args.quick:
        lanes = QUICK_LANES
        routing = {
            "mode": "quick", "selected_lanes": list(lanes), "forced_lanes": [],
            "reasons": {}, "probabilities": {}, "fallback": False, "note": None,
        }
    elif args.lanes:
        lanes = tuple(l.strip() for l in args.lanes.split(",") if l.strip())
        routing = {
            "mode": "manual", "selected_lanes": list(lanes), "forced_lanes": [],
            "reasons": {}, "probabilities": {}, "fallback": False, "note": None,
        }
    else:
        lanes = LANES
        routing = {
            "mode": "deep", "selected_lanes": list(lanes), "forced_lanes": [],
            "reasons": {}, "probabilities": {}, "fallback": False, "note": None,
        }
    bad = [l for l in lanes if l not in LANES]
    if bad:
        print(f"unknown lane(s): {', '.join(bad)}. available: {', '.join(LANES)}", file=sys.stderr)
        return 2

    if args.plan:
        chosen = [source for source in S if source["lane"] in set(lanes)]
        print(f"# Research route: {args.query}\n")
        print(format_route(routing))
        print(f"configured sources in selected lanes: {len(chosen)} of {len(S)}")
        if routing.get("reasons"):
            print("reasons:")
            for lane in lanes:
                if lane in routing["reasons"]:
                    print(f"  - {lane}: {routing['reasons'][lane]}")
        return 0

    def prog(done, total, name, n):
        if args.live:
            print(f"  [{done}/{total}] {name}: {n} rows", file=sys.stderr, flush=True)

    res = research(args.query, lanes=lanes, limit=args.limit,
                   workers=args.workers, on_progress=prog)
    res["routing"] = routing

    if args.read:
        read_targets = [r.url for r in res["findings"] if r.url][: args.read]
        res["full_text"] = []
        for u in read_targets:
            body, err = read_url(u)
            res["full_text"].append({"url": u, "error": err, "text": body})
            if args.live:
                print(f"  read {'OK ' if body else 'FAIL'} {u}", file=sys.stderr, flush=True)

    if args.json:
        if args.json == "compact":
            payload = compact_payload(res, max_sources=args.max_sources)
            if res.get("full_text"):
                # --read output is the one thing that cannot be re-derived from the
                # search output, so compact keeps it (once), unlike the full dump.
                payload["full_text"] = res["full_text"]
            print(json.dumps(payload, indent=2))
        else:
            out = dict(res)
            out["findings"] = [r.as_dict() for r in res["findings"]]
            out["by_lane"] = {k: [r.as_dict() for r in v] for k, v in res["by_lane"].items()}
            print(json.dumps(out, indent=2))
    else:
        print(text_report(res, show_unrelated=not args.no_unrelated))
        if not args.no_sources:
            src = text_sources_block(res, max_sources=args.max_sources)
            if src:
                print()
                print(src)
        if res.get("full_text"):
            print("\n## Full text (via local PiExtract)\n")
            for ft in res["full_text"]:
                print(f"### {ft['url']}")
                print(ft["text"] if ft["text"] else f"(failed: {ft['error']})")
                print()

    if args.md:
        md = markdown_report(res, include_sources=not args.no_sources)
        os.makedirs(os.path.dirname(os.path.abspath(args.md)), exist_ok=True)
        with open(args.md, "w") as fh:
            fh.write(md)
        print(f"\n[report written to {args.md}]", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
