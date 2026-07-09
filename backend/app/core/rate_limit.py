"""Application-wide rate limiting.

Wraps slowapi's Limiter with a single shared instance keyed on the client IP.
The real client IP is recovered from ProxyHeadersMiddleware (configured in
app.main), so limits apply per end-user rather than per nginx upstream.

Wire-up (in app.main):
    from app.core.rate_limit import limiter, register_rate_limiting
    register_rate_limiting(app)

Usage on a route (the endpoint MUST accept ``request: Request``)::

    from app.core.rate_limit import limiter
    from app.core.config import settings

    @router.post("/login")
    @limiter.limit(settings.RATE_LIMIT_LOGIN)
    def login(request: Request, ...):
        ...
"""

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.core.config import settings

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=settings.RATE_LIMIT_STORAGE_URI,
    enabled=settings.RATE_LIMIT_ENABLED,
    default_limits=[],
)


def register_rate_limiting(app) -> None:
    """Attach the limiter and its 429 handler to the FastAPI app."""
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
