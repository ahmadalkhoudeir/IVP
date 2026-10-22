"""HTTP-layer hardening applied to every response and every state-changing
request. Kept as one small middleware so it can't be forgotten on a new
route.

- Content-Security-Policy: scripts only from this origin (htmx is vendored
  in /static), no framing, no plugins. Inline style attributes are still
  allowed because the templates use them for layout.
- X-Frame-Options / frame-ancestors: blocks clickjacking of the approve
  buttons.
- Referrer-Policy same-origin: the holder-console URL carries the attempt
  id, which must not leak to other sites through the Referer header. NOT
  no-referrer: under the Fetch standard, no-referrer makes browsers send
  "Origin: null" on every POST, even same-origin ones, which the CSRF check
  below would then reject.
- Cache-Control no-store on dynamic pages: audit data and codes must not
  sit in a shared browser cache after logout.
- CSRF: a state-changing request must carry an Origin header (or, failing
  that, a Referer) naming this host. Following the OWASP CSRF Prevention
  Cheat Sheet, a missing header or "Origin: null" is not treated as
  same-origin: the request is rejected. Browsers send Origin on every
  form POST, so legitimate use is unaffected; SameSite=Lax session cookies
  are a second layer. Scripts and tests must send an Origin header.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; object-src 'none'; base-uri 'none'; "
        "frame-ancestors 'none'; form-action 'self'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def _is_trusted_source(request: Request) -> bool:
    origin = request.headers.get("origin")
    source = origin if origin and origin != "null" else request.headers.get("referer")
    if not source:
        return False
    return urlsplit(source).netloc == request.headers.get("host", "")


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:  # noqa: ANN001
        if request.method not in SAFE_METHODS and not _is_trusted_source(request):
            return PlainTextResponse(
                "Request rejected: missing or cross-site Origin (CSRF protection)",
                status_code=403,
            )
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if not request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response
