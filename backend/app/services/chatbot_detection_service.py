"""Chatbot/live-chat detection for internet-facing web assets.

The detector intentionally avoids broad words like "chat" by themselves. Generic
chat bubbles only count when paired with message/send/input signals, which helps
avoid cookie banners, newsletter popups, and other non-chat widgets.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

import httpx

from app.services.wappalyzer_service import DetectedTechnology, slugify

logger = logging.getLogger(__name__)


@dataclass
class ChatbotDetection:
    name: str
    slug: str
    confidence: int
    category: str = "Live chat"
    source: str = "static_html"
    indicators: list[str] = field(default_factory=list)

    def to_detected_technology(self) -> DetectedTechnology:
        return DetectedTechnology(
            name=self.name,
            slug=self.slug,
            confidence=self.confidence,
            categories=[self.category],
            website=_CHAT_VENDOR_WEBSITES.get(self.slug),
            description="Detected chatbot or live-chat implementation.",
        )


@dataclass
class ChatbotDetectionResult:
    url: str
    detections: list[ChatbotDetection] = field(default_factory=list)
    rendered_checked: bool = False
    error: Optional[str] = None


_CHAT_VENDOR_WEBSITES = {
    "intercom": "https://intercom.com",
    "zendesk-chat": "https://zendesk.com",
    "drift": "https://drift.com",
    "crisp": "https://crisp.chat",
    "tawk-to": "https://tawk.to",
    "livechat": "https://livechat.com",
    "freshchat": "https://freshchat.com",
    "helpscout-beacon": "https://helpscout.com",
    "olark": "https://olark.com",
    "hubspot-chat": "https://hubspot.com",
    "salesforce-chat": "https://salesforce.com",
    "genesys-chat": "https://genesys.com",
}


# Vendor-specific patterns are high precision and can stand alone.
_VENDOR_PATTERNS: list[tuple[str, str, list[str]]] = [
    ("Intercom", "intercom", [r"intercom-app", r"widget\.intercom\.io", r"intercomSettings", r"\bIntercom\("]),
    ("Zendesk Chat", "zendesk-chat", [r"ZendeskChat", r"zopim", r"static\.zdassets\.com", r"zE\(['\"]webWidget"]),
    ("Drift", "drift", [r"drift-widget", r"js\.driftt\.com", r"drift\.load", r"drift\.com/widget"]),
    ("Crisp", "crisp", [r"crisp-chat", r"client\.crisp\.chat", r"\$crisp", r"crisp\.website"]),
    ("Tawk.to", "tawk-to", [r"tawkto", r"embed\.tawk\.to", r"Tawk_API", r"tawk\.to/chat"]),
    ("LiveChat", "livechat", [r"livechat-widget", r"cdn\.livechatinc\.com", r"LiveChatWidget", r"livechatinc\.com"]),
    ("Freshchat", "freshchat", [r"wchat\.freshchat\.com", r"freshchat", r"FreshworksWidget"]),
    ("HelpScout Beacon", "helpscout-beacon", [r"beacon-v2\.helpscout\.net", r"Beacon\(['\"]init", r"helpscout\.net"]),
    ("Olark", "olark", [r"static\.olark\.com", r"olark\.identify", r"olark\.com/jsclient"]),
    ("HubSpot Chat", "hubspot-chat", [r"HubSpotConversations", r"hs-chat", r"js\.hs-scripts\.com/.*/\.js"]),
    ("Salesforce Chat", "salesforce-chat", [r"embeddedservice_bootstrap", r"embeddedservice_liveagent", r"liveagent\.salesforce"]),
    ("Genesys Chat", "genesys-chat", [r"genesys", r"purecloud", r"Genesys\(['\"]command"]),
]


# These are not enough alone; they must appear with message/send indicators.
_GENERIC_WIDGET_PATTERNS = [
    r"chat-bubble",
    r"chat-button",
    r"chat-widget",
    r"support-chat",
    r"start-chat",
    r"livechat-widget",
    r"chat-launcher",
    r"chat-window",
]

_GENERIC_ACTION_PATTERNS = [
    r"send-message",
    r"message-input",
    r"chat-input",
    r"textarea[^>]+placeholder=['\"][^'\"]*(?:message|question|chat)",
    r"button[^>]+(?:send|message)",
    r"aria-label=['\"][^'\"]*(?:send message|open chat|start chat|chat)",
]

_COOKIE_OR_POPUP_NOISE = [
    r"cookie-consent",
    r"cookie-banner",
    r"accept-cookies",
    r"onetrust",
    r"privacy-policy",
]


class ChatbotDetectionService:
    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    ):
        self.timeout = timeout
        self.user_agent = user_agent

    async def detect_url(self, url: str, render: bool = False) -> ChatbotDetectionResult:
        result = ChatbotDetectionResult(url=url)
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": self.user_agent},
            ) as client:
                response = await client.get(url)
            result.detections.extend(self.detect_html(response.text, source="static_html"))
        except Exception as exc:
            result.error = str(exc)
            logger.debug("Static chatbot detection failed for %s: %s", url, exc)

        if render:
            rendered_html = await self._rendered_html(url)
            result.rendered_checked = rendered_html is not None
            if rendered_html:
                result.detections.extend(self.detect_html(rendered_html, source="rendered_dom"))

        result.detections = self._dedupe(result.detections)
        return result

    def detect_html(self, html: str, source: str = "static_html") -> list[ChatbotDetection]:
        if not html:
            return []

        detections: list[ChatbotDetection] = []

        for name, slug, patterns in _VENDOR_PATTERNS:
            matched = [p for p in patterns if re.search(p, html, re.IGNORECASE)]
            if matched:
                confidence = 95 if len(matched) > 1 else 90
                detections.append(ChatbotDetection(
                    name=name,
                    slug=slug,
                    confidence=confidence,
                    source=source,
                    indicators=matched[:5],
                ))

        widget_hits = [p for p in _GENERIC_WIDGET_PATTERNS if re.search(p, html, re.IGNORECASE)]
        action_hits = [p for p in _GENERIC_ACTION_PATTERNS if re.search(p, html, re.IGNORECASE)]
        noise_hits = [p for p in _COOKIE_OR_POPUP_NOISE if re.search(p, html, re.IGNORECASE)]

        if widget_hits and action_hits:
            confidence = 75
            if source == "rendered_dom":
                confidence += 10
            if noise_hits:
                confidence -= 15
            if confidence >= 65:
                detections.append(ChatbotDetection(
                    name="Custom Chat Widget",
                    slug="custom-chat-widget",
                    confidence=confidence,
                    source=source,
                    indicators=(widget_hits + action_hits)[:6],
                ))

        return detections

    async def _rendered_html(self, url: str) -> Optional[str]:
        try:
            from playwright.async_api import async_playwright
        except Exception:
            return None

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent=self.user_agent,
                    viewport={"width": 1365, "height": 900},
                )
                page = await context.new_page()
                await page.goto(url, wait_until="domcontentloaded", timeout=int(self.timeout * 1000))
                await asyncio.sleep(2)
                html = await page.content()
                await context.close()
                await browser.close()
                return html
        except Exception as exc:
            logger.debug("Rendered chatbot detection failed for %s: %s", url, exc)
            return None

    def _dedupe(self, detections: list[ChatbotDetection]) -> list[ChatbotDetection]:
        by_slug: dict[str, ChatbotDetection] = {}
        for detection in detections:
            existing = by_slug.get(detection.slug)
            if not existing or detection.confidence > existing.confidence:
                by_slug[detection.slug] = detection
        return list(by_slug.values())


def chatbot_detection_to_metadata(result: ChatbotDetectionResult) -> list[dict]:
    return [
        {
            "name": detection.name,
            "slug": detection.slug,
            "confidence": detection.confidence,
            "source": detection.source,
            "indicators": detection.indicators,
        }
        for detection in result.detections
    ]


def chatbot_detections_to_technologies(result: ChatbotDetectionResult) -> list[DetectedTechnology]:
    return [detection.to_detected_technology() for detection in result.detections]

