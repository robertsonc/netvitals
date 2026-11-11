"""A small JSON-over-HTTP client on urllib: timeouts on every call, bounded retries, clear errors."""
from __future__ import annotations

import base64
import json
import logging
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

LOG = logging.getLogger(__name__)
RETRY_STATUS = (429, 500, 502, 503, 504)


class HttpError(Exception):
    """A request that did not produce a usable answer. `status` is None for transport failures."""

    def __init__(self, message: str, status: Optional[int] = None, body: Any = None):
        super().__init__(message)
        self.status = status
        self.body = body


class Http:
    def __init__(self, base_url: str, *, headers: Optional[Dict[str, str]] = None, verify_tls: bool = True,
                 timeout: float = 15.0, basic: Optional[tuple] = None, query: Optional[Dict[str, str]] = None):
        self.base = base_url.rstrip("/")
        self.headers = dict(headers or {})
        self.timeout = timeout
        self.query = dict(query or {})
        if basic:
            raw = f"{basic[0]}:{basic[1]}".encode()
            self.headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
        self._ctx: Optional[ssl.SSLContext] = None
        if self.base.startswith("https://"):
            self._ctx = ssl.create_default_context()
            if not verify_tls:   # lab appliances with self-signed certificates; the operator opted out
                self._ctx.check_hostname = False
                self._ctx.verify_mode = ssl.CERT_NONE

    def request(self, method: str, path: str, body: Any = None, *, retries: int = 0,
                timeout: Optional[float] = None) -> Any:
        """Returns parsed JSON (or {} for an empty body). `retries` must only be non-zero for calls
        that are safe to repeat."""
        url = self.base + path
        if self.query:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(self.query)
        data = None if body is None else json.dumps(body).encode()
        headers = dict(self.headers)
        if data is not None:
            headers["Content-Type"] = "application/json"
        where = urllib.parse.urlsplit(self.base).netloc + path.split("?")[0]
        attempt = 0
        while True:
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=timeout or self.timeout, context=self._ctx) as resp:
                    raw = resp.read()
                if not raw.strip():
                    return {}
                try:
                    return json.loads(raw)
                except ValueError:
                    raise HttpError(f"{where} answered with something that is not JSON", resp.status)
            except urllib.error.HTTPError as exc:
                raw = exc.read()[:4000]
                try:
                    parsed: Any = json.loads(raw)
                except ValueError:
                    parsed = raw.decode("utf-8", "replace")
                if exc.code in RETRY_STATUS and attempt < retries:
                    attempt += 1
                    time.sleep(0.4 * 2 ** attempt)
                    continue
                detail = ""
                if isinstance(parsed, dict):
                    found = parsed.get("detail") or parsed.get("error") or parsed.get("message") or ""
                    if isinstance(found, dict):      # structured envelope: {"error": {"title", "detail", ...}}
                        found = found.get("detail") or found.get("title") or found.get("code") or ""
                    detail = str(found)
                raise HttpError(f"{where} answered HTTP {exc.code}" + (f": {detail}" if detail else ""),
                                exc.code, parsed)
            except ssl.SSLCertVerificationError as exc:
                raise HttpError(f"TLS certificate verification failed for {where}: {exc.verify_message}. "
                                "Add its CA to the trust store, or turn verification off for a lab.")
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
                if attempt < retries:
                    attempt += 1
                    time.sleep(0.4 * 2 ** attempt)
                    continue
                reason = getattr(exc, "reason", exc)
                raise HttpError(f"could not reach {where}: {reason}")
