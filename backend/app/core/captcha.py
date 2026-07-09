"""CAPTCHA verification for auth endpoints.

Provider-agnostic server-side verification of a CAPTCHA token. Supports
Cloudflare Turnstile (default), hCaptcha, and Google reCAPTCHA v2/v3 — all
expose the same ``POST secret+response -> {"success": bool}`` siteverify API.

Behavior:
  - When ``CAPTCHA_ENABLED`` is False (or no secret key is set), verification is
    skipped entirely so local/dev flows are unaffected.
  - When enabled, a missing or invalid token raises HTTP 400.

Usage (inside a route)::

    from app.core.captcha import verify_captcha
    verify_captcha(request.headers.get("x-captcha-token"), remote_ip=request.client.host)
"""

import logging
from typing import Optional

import httpx
from fastapi import HTTPException, status

from app.core.config import settings

logger = logging.getLogger(__name__)

_VERIFY_URLS = {
    "turnstile": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    "hcaptcha": "https://hcaptcha.com/siteverify",
    "recaptcha": "https://www.google.com/recaptcha/api/siteverify",
}


def captcha_enabled() -> bool:
    """True only when CAPTCHA is switched on AND a secret key is configured."""
    return bool(settings.CAPTCHA_ENABLED and settings.CAPTCHA_SECRET_KEY)


def verify_captcha(token: Optional[str], remote_ip: Optional[str] = None) -> None:
    """Validate a CAPTCHA token; raise HTTP 400 on any failure.

    No-op when CAPTCHA is disabled or unconfigured.
    """
    if not captcha_enabled():
        return

    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CAPTCHA verification required.",
        )

    provider = (settings.CAPTCHA_PROVIDER or "turnstile").lower()
    verify_url = _VERIFY_URLS.get(provider)
    if not verify_url:
        logger.error("Unknown CAPTCHA_PROVIDER '%s'; rejecting request.", provider)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CAPTCHA misconfigured.",
        )

    payload = {"secret": settings.CAPTCHA_SECRET_KEY, "response": token}
    if remote_ip:
        payload["remoteip"] = remote_ip

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(verify_url, data=payload)
        data = resp.json()
    except Exception as exc:
        # Fail closed: if we can't reach the verifier, don't let the request through.
        logger.warning("CAPTCHA verification call failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CAPTCHA verification unavailable. Please try again.",
        )

    if not data.get("success"):
        logger.info(
            "CAPTCHA rejected (provider=%s, errors=%s)",
            provider,
            data.get("error-codes"),
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CAPTCHA verification failed.",
        )
