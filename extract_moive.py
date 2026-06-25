#!/usr/bin/env python3
"""
Local resolver/testing API for captured Frembed-style embed traffic.

This tool analyzes the live flow first. Saved capture data can be used as a
same-ID fallback for testing, but captured signed media URLs are not reused for
unrelated inputs.
"""

from __future__ import annotations

import argparse
import base64
import html
import json
import os
import re
import sys
import time
import traceback
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, quote, unquote, urljoin, urlparse, urlunparse


DEFAULT_TEST_URL = "https://frembed.one/embed/movie/218"
MEDIA_EXTENSIONS = (".m3u8", ".mpd", ".mp4", ".webm", ".mkv", ".ts")
MEDIA_RE = re.compile(
    r"https?://[^\s'\"<>\\]+?(?:\.m3u8|\.mpd|\.mp4|\.webm|\.mkv|\.ts)(?:\?[^\s'\"<>\\]*)?",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s'\"<>\\)]+", re.IGNORECASE)
IFRAME_RE = re.compile(r"<iframe[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)
ASSET_RE = re.compile(r"""(?:src|href|file|url)\s*[:=]\s*["']([^"']+)["']""", re.IGNORECASE)
TOKEN_KEYS = {"token", "t", "s", "e", "hash", "signature", "sig", "key", "auth", "expires"}


def now_ms() -> int:
    return int(time.time() * 1000)


def unique(values: Iterable[Any]) -> List[str]:
    seen = set()
    out = []
    for value in values:
        if isinstance(value, dict):
            value = value.get("url") or value.get("m3u8") or value.get("src") or value.get("href") or ""
        elif not isinstance(value, str):
            value = str(value) if value is not None else ""
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def normalize_url(url: str) -> str:
    return html.unescape(url or "").strip().strip("\"'<>")


def is_media_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in MEDIA_EXTENSIONS)


def classify_url(url: str) -> str:
    path = urlparse(url).path.lower()
    if path.endswith(".m3u8"):
        return "hls"
    if path.endswith(".mpd"):
        return "dash"
    if path.endswith((".mp4", ".webm", ".mkv")):
        return "video_file"
    if path.endswith(".ts"):
        return "segment"
    if "/embed" in path or "/e/" in path or "iframe" in path:
        return "embed_or_iframe"
    return "resource"


def redact_value(value: str, keep: int = 6) -> str:
    if not value:
        return value
    if len(value) <= keep * 2:
        return "***"
    return f"{value[:keep]}...{value[-keep:]}"


def discover_token_params(urls: Iterable[str]) -> List[Dict[str, str]]:
    found: List[Dict[str, str]] = []
    seen = set()
    for url in urls:
        parsed = urlparse(url)
        for key, values in parse_qs(parsed.query, keep_blank_values=True).items():
            if key.lower() not in TOKEN_KEYS:
                continue
            for value in values:
                sig = (parsed.netloc, key, value)
                if sig in seen:
                    continue
                seen.add(sig)
                found.append({"host": parsed.netloc, "name": key, "value": redact_value(value)})
    return found


def base_n(num: int, radix: int) -> str:
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    if num == 0:
        return "0"
    chars = []
    while num:
        num, rem = divmod(num, radix)
        chars.append(alphabet[rem])
    return "".join(reversed(chars))


def js_unescape(value: str) -> str:
    try:
        return bytes(value, "utf-8").decode("unicode_escape")
    except Exception:
        return value


def unpack_dean_edwards_packer(text: str) -> List[str]:
    """Decode common eval(function(p,a,c,k,e,d){...}(...)) packer blocks."""
    decoded: List[str] = []
    pattern = re.compile(
        r"eval\(function\(p,a,c,k,e,d\).*?\}\('(?P<payload>.*?)',(?P<radix>\d+),(?P<count>\d+),'(?P<keys>.*?)'\.split\('\|'\)\)\)",
        re.DOTALL,
    )
    for match in pattern.finditer(text):
        payload = js_unescape(match.group("payload"))
        radix = int(match.group("radix"))
        count = int(match.group("count"))
        keys = js_unescape(match.group("keys")).split("|")
        for index in range(count - 1, -1, -1):
            if index >= len(keys) or not keys[index]:
                continue
            payload = re.sub(r"\b" + re.escape(base_n(index, radix)) + r"\b", keys[index], payload)
        decoded.append(payload)
    return decoded


def maybe_base64_decode(text: str) -> str:
    stripped = text.strip()
    if len(stripped) < 40 or len(stripped) % 4:
        return text
    if not re.fullmatch(r"[A-Za-z0-9+/=\r\n]+", stripped):
        return text
    try:
        decoded = base64.b64decode(stripped, validate=True).decode("utf-8", errors="replace")
    except Exception:
        return text
    if "<html" in decoded.lower() or "{" in decoded or "http" in decoded:
        return decoded
    return text


def extract_urls(text: str, base_url: str = "") -> Dict[str, List[str]]:
    text = maybe_base64_decode(text or "")
    bodies = [text]
    bodies.extend(unpack_dean_edwards_packer(text))

    urls: List[str] = []
    iframes: List[str] = []
    for body in bodies:
        body = html.unescape(body)
        for match in URL_RE.finditer(body):
            urls.append(normalize_url(unquote(match.group(0))))
        for match in MEDIA_RE.finditer(body):
            urls.append(normalize_url(unquote(match.group(0))))
        for match in IFRAME_RE.finditer(body):
            iframes.append(urljoin(base_url, normalize_url(match.group(1))))
        for match in ASSET_RE.finditer(body):
            candidate = normalize_url(match.group(1))
            if candidate.startswith(("//", "/", "http")):
                urls.append(urljoin(base_url, candidate))

        # Some telemetry URLs include the media URL as mu=<encoded m3u8>.
        for mu in re.findall(r"[?&]mu=([^&\s'\"<>]+)", body):
            urls.append(normalize_url(unquote(mu)))

    urls = unique(urls + iframes)
    media = [u for u in urls if is_media_url(u)]
    embeds = [
        u
        for u in urls
        if not is_media_url(u)
        and ("/embed" in urlparse(u).path.lower() or "/e/" in urlparse(u).path.lower())
    ]
    return {
        "urls": urls,
        "media": unique(media),
        "iframes": unique(iframes),
        "embeds": unique(embeds),
    }


def parse_input_url(input_url: str) -> Dict[str, str]:
    parsed = urlparse(input_url)
    parts = [p for p in parsed.path.split("/") if p]
    kind = "movie"
    media_id = ""
    if "embed" in parts:
        idx = parts.index("embed")
        if len(parts) > idx + 1:
            kind = parts[idx + 1]
        if len(parts) > idx + 2:
            media_id = parts[idx + 2]
    elif parts:
        media_id = parts[-1]
    id_type = "imdb" if media_id.startswith("tt") else "tmdb"
    return {"kind": kind, "id": media_id, "id_type": id_type, "host": parsed.netloc}


@dataclass
class HttpStep:
    method: str
    url: str
    status: Optional[int] = None
    location: Optional[str] = None
    content_type: str = ""
    error: Optional[str] = None


@dataclass
class HttpResponse:
    url: str
    status: int
    headers: Dict[str, str]
    text: str
    content_type: str


class HttpClient:
    def __init__(self, timeout: int = 20):
        try:
            import requests  # type: ignore
        except Exception as exc:
            raise RuntimeError("The Python 'requests' package is required for live HTTP mode.") from exc
        self.requests = requests
        self.session = requests.Session()
        self.timeout = timeout
        self.session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        referer: str = "",
        json_body: Any = None,
        allow_redirects: bool = True,
        steps: Optional[List[Dict[str, Any]]] = None,
    ) -> HttpResponse:
        headers = {}
        if referer:
            headers["Referer"] = referer
        try:
            response = self.session.request(
                method,
                url,
                headers=headers,
                json=json_body,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
            )
            if steps is not None:
                for hist in response.history:
                    steps.append(
                        HttpStep(
                            method=hist.request.method,
                            url=hist.url,
                            status=hist.status_code,
                            location=hist.headers.get("location"),
                            content_type=hist.headers.get("content-type", ""),
                        ).__dict__
                    )
                steps.append(
                    HttpStep(
                        method=response.request.method,
                        url=response.url,
                        status=response.status_code,
                        location=response.headers.get("location"),
                        content_type=response.headers.get("content-type", ""),
                    ).__dict__
                )
            return HttpResponse(
                url=response.url,
                status=response.status_code,
                headers=dict(response.headers),
                text=response.text or "",
                content_type=response.headers.get("content-type", ""),
            )
        except Exception as exc:
            if steps is not None:
                steps.append(HttpStep(method=method, url=url, error=str(exc)).__dict__)
            raise


@dataclass
class ResolveResult:
    original_url: str
    resolved_redirect_url: str = ""
    ids: Dict[str, str] = field(default_factory=dict)
    source_servers: List[Dict[str, str]] = field(default_factory=list)
    iframe_urls: List[str] = field(default_factory=list)
    embed_urls: List[str] = field(default_factory=list)
    final_media_urls: List[Dict[str, str]] = field(default_factory=list)
    discovered_tokens_or_ids: List[Dict[str, str]] = field(default_factory=list)
    request_steps: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "ok"
    blocked: bool = False
    errors: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def add_urls(self, extracted: Dict[str, List[str]], *, include_media: bool = True) -> None:
        self.iframe_urls = unique(self.iframe_urls + extracted.get("iframes", []))
        self.embed_urls = unique(self.embed_urls + extracted.get("embeds", []))
        if not include_media:
            token_source = self.embed_urls + self.iframe_urls
            self.discovered_tokens_or_ids = discover_token_params(token_source)
            return
        existing_media = {item["url"] for item in self.final_media_urls}
        for url in extracted.get("media", []):
            if url in existing_media:
                continue
            self.final_media_urls.append({"url": url, "type": classify_url(url)})
            existing_media.add(url)
        token_source = [item["url"] for item in self.final_media_urls] + self.embed_urls + self.iframe_urls
        self.discovered_tokens_or_ids = discover_token_params(token_source)


class FrembedResolver:
    def __init__(self, timeout: int = 20):
        self.timeout = timeout

    def resolve(
        self,
        input_url: str,
        *,
        use_browser: bool = False,
        max_servers: int = 8,
    ) -> Dict[str, Any]:
        result = ResolveResult(original_url=input_url)
        parsed_input = parse_input_url(input_url)
        result.ids = parsed_input
        try:
            client = HttpClient(timeout=self.timeout)
            self._resolve_raw(client, input_url, parsed_input, result, max_servers=max_servers)
        except Exception as exc:
            result.errors.append(f"raw resolver error: {exc}")

        if use_browser and not result.final_media_urls:
            browser_data = observe_with_playwright(input_url, timeout_ms=max(15000, self.timeout * 1000))
            result.notes.extend(browser_data.get("notes", []))
            result.errors.extend(browser_data.get("errors", []))
            result.add_urls(
                {
                    "media": browser_data.get("media_urls", []),
                    "iframes": browser_data.get("iframe_urls", []),
                    "embeds": browser_data.get("embed_urls", []),
                    "urls": browser_data.get("all_urls", []),
                }
            )

        self._finalize_status(result)
        return result.__dict__

    def _resolve_raw(
        self,
        client: HttpClient,
        input_url: str,
        parsed_input: Dict[str, str],
        result: ResolveResult,
        *,
        max_servers: int,
    ) -> None:
        first = client.request("GET", input_url, steps=result.request_steps)
        result.resolved_redirect_url = first.url
        result.add_urls(extract_urls(first.text, first.url))

        base = f"{urlparse(first.url).scheme}://{urlparse(first.url).netloc}"
        film_id = parsed_input["id"]
        id_type = parsed_input["id_type"]
        kind = "movie" if parsed_input["kind"] not in {"tv", "series"} else parsed_input["kind"]

        if not film_id:
            result.errors.append("Could not infer media ID from input URL.")
            return

        film_api = f"{base}/api/films?id={quote(film_id)}&idType={id_type}"
        film_page = f"{base}/films?id={quote(film_id)}"
        film_resp = client.request("GET", film_api, referer=film_page, steps=result.request_steps)
        film_data = self._parse_jsonish(film_resp.text)
        if isinstance(film_data, dict):
            for key, value in film_data.items():
                if re.fullmatch(r"link\d+(?:vostfr|vo)?", key) and value:
                    result.source_servers.append({"name": key, "url": urljoin(base, str(value))})
            for key in ("tmdb", "imdb", "title", "year", "quality", "version"):
                if film_data.get(key) is not None:
                    result.ids[key] = str(film_data[key])
        else:
            result.notes.append("api/films did not return JSON; falling back to standard server slots.")

        if not result.source_servers:
            for n in range(1, 8):
                result.source_servers.append(
                    {
                        "name": f"link{n}",
                        "url": f"{base}/api/stream?type={kind}&tmdb={quote(film_id)}&server=link{n}",
                    }
                )

        for server in result.source_servers[:max_servers]:
            self._resolve_server_link(client, server, film_page, result)
            if result.final_media_urls:
                # Keep exploring a little, but avoid hammering every mirror after success.
                if len(result.embed_urls) >= 2:
                    break

    def _resolve_server_link(
        self, client: HttpClient, server: Dict[str, str], referer: str, result: ResolveResult
    ) -> None:
        url = server["url"]
        try:
            response = client.request("GET", url, referer=referer, allow_redirects=False, steps=result.request_steps)
        except Exception as exc:
            result.errors.append(f"{server['name']}: {exc}")
            return

        location = response.headers.get("location")
        if location:
            provider_url = urljoin(url, location)
            server["provider_url"] = provider_url
            result.embed_urls = unique(result.embed_urls + [provider_url])
            final = self._follow_provider_redirects(client, provider_url, referer, result)
            if final:
                self._inspect_provider_page(client, final, result)
            return

        result.add_urls(extract_urls(response.text, response.url))

    def _follow_provider_redirects(
        self, client: HttpClient, url: str, referer: str, result: ResolveResult, limit: int = 24
    ) -> Optional[HttpResponse]:
        current = url
        last_ref = referer
        for _ in range(limit):
            try:
                response = client.request("GET", current, referer=last_ref, allow_redirects=False, steps=result.request_steps)
            except Exception as exc:
                result.errors.append(f"provider redirect error for {current}: {exc}")
                return None
            location = response.headers.get("location")
            if response.status in (301, 302, 303, 307, 308) and location:
                nxt = urljoin(current, location)
                result.embed_urls = unique(result.embed_urls + [nxt])
                last_ref = current
                current = nxt
                continue
            return response
        result.errors.append(f"provider redirect chain exceeded {limit} hops")
        return None

    def _inspect_provider_page(self, client: HttpClient, response: HttpResponse, result: ResolveResult) -> None:
        text = response.text
        extracted = extract_urls(text, response.url)

        host = urlparse(response.url).netloc.lower()
        lowered = maybe_base64_decode(text).lower()
        protected_page = False
        if "need_captcha" in lowered or "captcha" in lowered:
            protected_page = True
            result.blocked = True
            result.notes.append(f"{host} indicates CAPTCHA or captcha-gated playback.")
        if "drm" in lowered and "widevine" in lowered:
            protected_page = True
            result.blocked = True
            result.notes.append(f"{host} appears to reference DRM-protected playback.")
        if response.status in {401, 403, 429, 503}:
            protected_page = True
            result.blocked = True
            result.notes.append(f"{host} returned HTTP {response.status}; raw Python may be blocked.")

        result.add_urls(extracted, include_media=not protected_page)
        if protected_page and extracted.get("media"):
            result.notes.append(
                f"Ignored {len(extracted['media'])} media-looking URL(s) from a protected provider page to avoid false positives."
            )
        if "voe" in lowered and not result.final_media_urls:
            result.notes.append(
                "VOE-style page uses runtime obfuscation/session scripts; raw extraction may need browser observation."
            )

        # Inspect linked same-origin scripts that are likely to bootstrap a player.
        for asset in extracted.get("urls", [])[:20]:
            if result.final_media_urls:
                break
            parsed = urlparse(asset)
            if parsed.netloc and parsed.netloc != urlparse(response.url).netloc:
                continue
            if not parsed.path.endswith(".js"):
                continue
            try:
                script_resp = client.request("GET", asset, referer=response.url, steps=result.request_steps)
                result.add_urls(extract_urls(script_resp.text, script_resp.url))
            except Exception:
                continue

    @staticmethod
    def _parse_jsonish(text: str) -> Any:
        text = maybe_base64_decode(text)
        try:
            return json.loads(text)
        except Exception:
            pass
        try:
            decoded = base64.b64decode(text.strip()).decode("utf-8", errors="replace")
            return json.loads(decoded)
        except Exception:
            return None

    @staticmethod
    def _finalize_status(result: ResolveResult) -> None:
        if result.final_media_urls:
            result.status = "resolved"
            return
        if result.blocked:
            result.status = "blocked_or_protected"
            return
        if result.errors:
            result.status = "partial_with_errors"
        else:
            result.status = "no_media_found"


def observe_with_playwright(url: str, timeout_ms: int = 20000) -> Dict[str, Any]:
    """Observe browser network traffic without bypassing CAPTCHA, auth, or DRM."""
    result = {"media_urls": [], "iframe_urls": [], "embed_urls": [], "all_urls": [], "notes": [], "errors": []}
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except Exception as exc:
        result["errors"].append(f"Playwright is not installed or not usable: {exc}")
        return result

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            def collect(candidate: str) -> None:
                candidate = normalize_url(unquote(candidate))
                if not candidate:
                    return
                result["all_urls"].append(candidate)
                if is_media_url(candidate):
                    result["media_urls"].append(candidate)
                elif "/embed" in urlparse(candidate).path.lower() or "/e/" in urlparse(candidate).path.lower():
                    result["embed_urls"].append(candidate)

            page.on("request", lambda req: collect(req.url))
            page.on("response", lambda resp: collect(resp.url))
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            page.wait_for_timeout(min(timeout_ms, 12000))
            for frame in page.frames:
                result["iframe_urls"].append(frame.url)
                collect(frame.url)
            browser.close()
    except Exception as exc:
        result["errors"].append(f"Playwright observation error: {exc}")
    result["media_urls"] = unique(result["media_urls"])
    result["iframe_urls"] = unique(result["iframe_urls"])
    result["embed_urls"] = unique(result["embed_urls"])
    result["all_urls"] = unique(result["all_urls"])
    if not result["media_urls"]:
        result["notes"].append("Browser observation completed without media URLs; page may require user action, CAPTCHA, login, or DRM.")
    return result


class ResolveHandler(BaseHTTPRequestHandler):
    resolver = FrembedResolver()

    def _send_json(self, payload: Dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/health"}:
            self._send_json(
                {
                    "ok": True,
                    "endpoint": "/resolve?url=https%3A%2F%2Ffrembed.one%2Fembed%2Fmovie%2F1318447",
                    "notes": "Use browser=1 for Playwright network observation if installed.",
                }
            )
            return
        if parsed.path != "/resolve":
            self._send_json({"error": "not found"}, status=404)
            return
        query = parse_qs(parsed.query)
        url = query.get("url", [DEFAULT_TEST_URL])[0]
        browser = query.get("browser", ["0"])[0] in {"1", "true", "yes"}
        try:
            payload = self.resolver.resolve(url, use_browser=browser)
            self._send_json(payload)
        except Exception as exc:
            self._send_json({"status": "error", "error": str(exc), "trace": traceback.format_exc()}, status=500)

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def serve(host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), ResolveHandler)
    print(f"Resolver API listening on http://{host}:{port}")
    print(f"Try: http://{host}:{port}/resolve?url={quote(DEFAULT_TEST_URL, safe='')}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Resolve Frembed-style embed URLs into provider/media resources.")
    parser.add_argument("--url", default=DEFAULT_TEST_URL, help="Input embed URL to resolve.")
    parser.add_argument("--browser", action="store_true", help="Use optional Playwright network observation fallback.")
    parser.add_argument("--serve", action="store_true", help="Start the local /resolve API server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--timeout", type=int, default=20)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.serve:
        ResolveHandler.resolver = FrembedResolver(timeout=args.timeout)
        serve(args.host, args.port)
        return 0
    resolver = FrembedResolver(timeout=args.timeout)
    result = resolver.resolve(args.url, use_browser=args.browser)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get("status") in {"resolved", "partial_with_errors", "no_media_found"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
