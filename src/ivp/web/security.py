"""HTTP-layer hardening applied to every response and every state-changing
request. Kept as one small middleware so it can't be forgotten on a new
route.

- Content-Security-Policy: scripts only from this origin (htmx is vendored
  in /static), no framing, no plugins. Inline style attributes are still
  allowed because the templates use them for layout.
- X-Frame-Options / frame-ancestors: blocks clickjacking of the approve
  buttons.
- Referrer-Policy no-referrer: the holder-console URL carries the attempt
  id, which must not leak to other sites through the Referer header.
- Cache-Control no-store on dynamic pages: audit data and codes must not
  sit in a shared browser cache after logout.
- Cross-site POST rejection: if a browser sends an Origin (or, failing
  that, a Referer) for a state-changing request, its host must be this
  host. Together with SameSite=Lax session cookies this blocks CSRF
  without per-form tokens. Requests carrying neither header (non-browser
  clients, the test client) are allowed, since a CSRF attack needs a
  browser and modern browsers send Origin on cross-site POSTs.
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
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def _is_cross_site(request: Request) -> bool:
    source = request.headers.get("origin") or request.headers.get("referer")
    if not source:
        return False
    if source == "null":
        return True
    return urlsplit(source).netloc != request.headers.get("host", "")


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:  # noqa: ANN001
        if request.method not in SAFE_METHODS and _is_cross_site(request):
            return PlainTextResponse("Cross-site request rejected", status_code=403)
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if not request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response
