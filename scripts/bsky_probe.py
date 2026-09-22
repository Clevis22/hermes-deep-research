#!/usr/bin/env python3
"""Authenticate to Bluesky with the stored app password and measure what an
authenticated search actually returns (public AppView search 403s from this Pi).

Reads BSKY_HANDLE / BSKY_APP_PASSWORD from ~/.hermes/.env (or the environment).
Never prints the password.

    python3 bsky_probe.py                      # default query
    python3 bsky_probe.py "residential proxy"  # custom query
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ENV_PATH = os.path.expanduser("~/.hermes/.env")
XRPС_HOST = "https://bsky.social"
SESSION_CACHE = os.path.expanduser("~/.hermes/scripts/state/bsky_session.json")
UA = "HermesDeepResearch/1.0 (keyless research; +local)"


def load_env(path=ENV_PATH):
    out = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return out


def post_json(url, payload, token=None, timeout=25):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", UA)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace")), None
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:200]
        return e.code, None, body
    except Exception as exc:  # noqa: BLE001
        return "ERR", None, f"{type(exc).__name__}: {exc}"


def get_json(url, token=None, timeout=25):
    req = urllib.request.Request(url)
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace")), None
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:200]
        return e.code, None, body
    except Exception as exc:  # noqa: BLE001
        return "ERR", None, f"{type(exc).__name__}: {exc}"


def create_session(handle, password):
    st, d, err = post_json(f"{XRPС_HOST}/xrpc/com.atproto.server.createSession",
                           {"identifier": handle, "password": password})
    return st, d, err


def search(q, token, limit=5, sort="latest", since=None, until=None):
    params = {"q": q, "limit": str(limit), "sort": sort}
    if since:
        params["since"] = since
    if until:
        params["until"] = until
    url = (f"{XRPС_HOST}/xrpc/app.bsky.feed.searchPosts?"
           + urllib.parse.urlencode(params))
    return get_json(url, token)


def main():
    query = sys.argv[1] if len(sys.argv) > 1 else "residential proxy"
    env = load_env()
    handle = env.get("BSKY_HANDLE") or os.environ.get("BSKY_HANDLE")
    pw = env.get("BSKY_APP_PASSWORD") or os.environ.get("BSKY_APP_PASSWORD")
    if not (handle and pw):
        print("MISSING: BSKY_HANDLE / BSKY_APP_PASSWORD not set")
        return 2
    print(f"handle: {handle} | app password: set ({len(pw)} chars)")
    print("(password never printed; source: ~/.hermes/.env)\n")

    print("=== baseline: UNAUTHENTICATED search (expected to fail) ===")
    st, d, err = search(query, None, limit=2)
    print(f"  [{st}] {err if err else 'ok, posts=' + str(len(d.get('posts', [])))}")

    print("\n=== createSession ===")
    st, d, err = create_session(handle, pw)
    if err or not d:
        print(f"  [{st}] FAILED: {err}")
        return 1
    token = d.get("accessJwt")
    print(f"  [{st}] ok | did={d.get('did')} | handle={d.get('handle')}")
    print(f"  scopes/keys present: accessJwt={bool(token)} refreshJwt={bool(d.get('refreshJwt'))}")
    print(f"  active={d.get('active')} status={d.get('status')}")

    print(f"\n=== authenticated search: {query!r} ===")
    st, d, err = search(query, token, limit=5)
    if err or not d:
        print(f"  [{st}] FAILED: {err}")
        return 1
    posts = d.get("posts", [])
    print(f"  [{st}] {len(posts)} posts returned")
    for p in posts[:5]:
        rec = p.get("record", {})
        text = " ".join((rec.get("text") or "").split())[:95]
        print(f"    - {p.get('indexedAt','')[:10]} "
              f"likes={p.get('likeCount')} replies={p.get('replyCount')} "
              f"by {p.get('author',{}).get('handle')}")
        print(f"      {text}")

    print("\n=== recency window (since/until) ===")
    since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 30 * 86400))
    st, d, err = search(query, token, limit=3, since=since)
    print(f"  since 30d [{st}]: "
          + (f"{len(d.get('posts', []))} posts" if d else str(err)))

    os.makedirs(os.path.dirname(SESSION_CACHE), exist_ok=True)
    with open(SESSION_CACHE, "w", encoding="utf-8") as fh:
        json.dump({"did": d and d.get("did"), "handle": handle,
                   "has_jwt": bool(token), "checked": time.time()}, fh)
    os.chmod(SESSION_CACHE, 0o600)
    print(f"\nsession metadata cached (no secrets): {SESSION_CACHE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
