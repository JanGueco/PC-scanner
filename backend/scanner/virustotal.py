from __future__ import annotations

import threading
import time
from datetime import datetime, timezone

import httpx

from .tier2 import compute_sha256

VT_BASE_URL = "https://www.virustotal.com/api/v3/"
VT_TIMEOUT = 30.0
RATE_LIMIT_MAX = 4
RATE_LIMIT_WINDOW_SECONDS = 60.0


class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: float) -> None:
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._timestamps: list[float] = []
        self._lock = threading.Lock()

    def check(self) -> tuple[bool, int]:
        with self._lock:
            now = time.time()
            self._timestamps = [
                timestamp
                for timestamp in self._timestamps
                if now - timestamp < self._window_seconds
            ]
            if len(self._timestamps) >= self._max_requests:
                oldest = self._timestamps[0]
                retry_after = int(self._window_seconds - (now - oldest)) + 1
                return False, max(retry_after, 1)
            self._timestamps.append(now)
            return True, 0


_rate_limiter = RateLimiter(RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_SECONDS)


def check_rate_limit() -> tuple[bool, int]:
    return _rate_limiter.check()


def resolve_sha256(sha256: str, path: str | None) -> str | None:
    normalized = (sha256 or "").strip().lower()
    if normalized:
        return normalized
    if path:
        return compute_sha256(path)
    return None


def lookup_file(sha256: str, api_key: str) -> dict:
    url = f"{VT_BASE_URL}files/{sha256}"
    headers = {"x-apikey": api_key}

    with httpx.Client(timeout=VT_TIMEOUT) as client:
        response = client.get(url, headers=headers)

    if response.status_code == 404:
        return {
            "result": "undetected",
            "detections": 0,
            "total_engines": 0,
            "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
        }

    response.raise_for_status()
    payload = response.json()
    attributes = payload.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    total_engines = sum(int(value or 0) for value in stats.values())

    if malicious > 0:
        result = "malicious"
        detections = malicious
    elif suspicious > 0:
        result = "suspicious"
        detections = suspicious
    else:
        result = "clean"
        detections = 0

    permalink = attributes.get("link") or f"https://www.virustotal.com/gui/file/{sha256}"

    return {
        "result": result,
        "detections": detections,
        "total_engines": total_engines,
        "permalink": permalink,
    }


def run_deep_check(sha256: str, api_key: str) -> dict:
    lookup = lookup_file(sha256, api_key)
    return {
        "sha256": sha256,
        "result": lookup["result"],
        "detections": lookup["detections"],
        "total_engines": lookup["total_engines"],
        "permalink": lookup["permalink"],
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
