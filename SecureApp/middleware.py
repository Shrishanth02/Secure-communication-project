"""Adds hardening HTTP response headers that Django does not set by default:
a Content-Security-Policy and a Permissions-Policy.

The CSP is strict: everything defaults to 'self', no external origins, no
plugins/objects, and the page may not be framed. Inline *style attributes*
(e.g. style="display:flex") and data: SVG icons are permitted because the
templates use them; there is NO inline or external JavaScript.
"""

CSP = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "style-src 'self' 'unsafe-inline'; "
    "script-src 'self'; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

PERMISSIONS_POLICY = "geolocation=(), microphone=(), camera=(), payment=()"


class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.setdefault('Content-Security-Policy', CSP)
        response.setdefault('Permissions-Policy', PERMISSIONS_POLICY)
        response.setdefault('Cross-Origin-Opener-Policy', 'same-origin')
        response.setdefault('X-Content-Type-Options', 'nosniff')
        return response
