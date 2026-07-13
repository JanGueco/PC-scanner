from __future__ import annotations

import csv
import io
import json
import os
import threading
import time
import zipfile
from datetime import datetime, timezone

import httpx

from .models import get_app_data_dir

MB_CSV_URL = "https://bazaar.abuse.ch/export/csv/full/"
MB_CSV_V2_RECENT_URL = "https://mb-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"
MB_API_URL = "https://mb-api.abuse.ch/api/v1/"
MIN_EXPECTED_NAMES = 100
CACHE_MAX_AGE_SECONDS = 24 * 60 * 60


class NameCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._names: set[str] = set()
        self._last_refreshed: float | None = None
        self._warnings: list[str] = []
        self._initializing = False
        self._cache_path = os.path.join(get_app_data_dir(), "mb_filenames.json")
        self._meta_path = os.path.join(get_app_data_dir(), "mb_cache_meta.json")

    @property
    def initializing(self) -> bool:
        with self._lock:
            return self._initializing

    @property
    def warnings(self) -> list[str]:
        with self._lock:
            return list(self._warnings)

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._names)

    @property
    def age_hours(self) -> float | None:
        with self._lock:
            if self._last_refreshed is None:
                return None
            return (time.time() - self._last_refreshed) / 3600

    def initialize(self, auth_key: str) -> None:
        loaded = self._load_from_disk()
        if loaded and not self._is_stale() and not self._needs_repair():
            return
        self.refresh(auth_key)

    def initialize_async(self, auth_key: str) -> None:
        loaded = self._load_from_disk()
        if loaded and not self._is_stale() and not self._needs_repair():
            return

        def _run() -> None:
            with self._lock:
                self._initializing = True
            try:
                self.refresh(auth_key)
            finally:
                with self._lock:
                    self._initializing = False

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()

    def _is_stale(self) -> bool:
        with self._lock:
            if self._last_refreshed is None:
                return True
            return (time.time() - self._last_refreshed) >= CACHE_MAX_AGE_SECONDS

    def _needs_repair(self) -> bool:
        with self._lock:
            if len(self._names) >= 100:
                return False
            return any(
                "csv missing file_name" in warning.lower()
                or "csv unavailable" in warning.lower()
                for warning in self._warnings
            )

    def _load_from_disk(self) -> bool:
        if not os.path.exists(self._cache_path):
            return False
        try:
            with open(self._cache_path, encoding="utf-8") as f:
                names = json.load(f)
            with open(self._meta_path, encoding="utf-8") as f:
                meta = json.load(f)
            with self._lock:
                self._names = {n.lower() for n in names if isinstance(n, str)}
                self._last_refreshed = meta.get("last_refreshed")
                self._warnings = meta.get("warnings", [])
            return len(self._names) > 0
        except (OSError, json.JSONDecodeError, TypeError):
            return False

    def _save_to_disk(self) -> None:
        os.makedirs(os.path.dirname(self._cache_path), exist_ok=True)
        with self._lock:
            names = sorted(self._names)
            last_refreshed = self._last_refreshed
            warnings = list(self._warnings)
        with open(self._cache_path, "w", encoding="utf-8") as f:
            json.dump(names, f)
        with open(self._meta_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "last_refreshed": last_refreshed,
                    "refreshed_at": datetime.now(timezone.utc).isoformat(),
                    "warnings": warnings,
                },
                f,
                indent=2,
            )

    def refresh(self, auth_key: str) -> None:
        warnings: list[str] = []
        names: set[str] = set()

        if auth_key:
            try:
                names = self._fetch_csv(auth_key)
            except Exception as exc:
                warnings.append(f"MalwareBazaar CSV refresh failed: {exc}")
        else:
            warnings.append(
                "No MalwareBazaar Auth-Key configured. Using limited recent sample names only."
            )

        if not names and auth_key:
            try:
                names = self._fetch_recent(auth_key)
                warnings.append("CSV unavailable; loaded recent MalwareBazaar samples only.")
            except Exception as exc:
                warnings.append(f"MalwareBazaar recent fetch failed: {exc}")

        if not names and not auth_key:
            try:
                names = self._fetch_recent("")
            except Exception as exc:
                warnings.append(f"MalwareBazaar recent fetch failed: {exc}")

        with self._lock:
            if names:
                # VERIFIED - already optimized: malware names stored as set(), not rebuilt per scan
                self._names = names
                self._last_refreshed = time.time()
            elif not self._names:
                warnings.append("Name cache is empty. Tier 1 matching disabled.")
            else:
                warnings.append("Refresh failed; using stale name cache.")
            self._warnings = warnings

        if names or self._names:
            self._save_to_disk()

    def _decode_csv_payload(self, payload: bytes) -> str:
        if payload[:2] == b"PK":
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                csv_names = [name for name in archive.namelist() if name.lower().endswith(".csv")]
                if not csv_names:
                    raise ValueError("ZIP archive contains no CSV file")
                return archive.read(csv_names[0]).decode("utf-8", errors="replace")
        return payload.decode("utf-8", errors="replace")

    def _looks_like_data_first_row(self, line: str) -> bool:
        first_field = (line.split(",", 1)[0] if line else "").strip().strip('"')
        if not first_field:
            return False
        if len(first_field) == 64 and all(ch in "0123456789abcdef" for ch in first_field.lower()):
            return True
        return len(first_field) >= 10 and first_field[4:5] == "-" and first_field[7:8] == "-"

    def _parse_csv_text(self, text: str) -> set[str]:
        text = text.lstrip("\ufeff")
        lines = text.splitlines()
        header_idx = 0
        for i, line in enumerate(lines):
            stripped = line.lstrip("\ufeff").strip()
            if stripped and not stripped.startswith("#"):
                header_idx = i
                break

        body_lines = lines[header_idx:]
        if not body_lines:
            return set()

        if self._looks_like_data_first_row(body_lines[0]):
            schema = (
                "first_seen,sha256_hash,md5_hash,sha1_hash,signature,file_name,file_type,file_type_mime"
            )
            csv_text = schema + "\n" + "\n".join(body_lines)
        else:
            csv_text = "\n".join(body_lines)

        names: set[str] = set()
        reader = csv.DictReader(io.StringIO(csv_text))
        if not reader.fieldnames:
            return names

        fieldnames = [name.lstrip("\ufeff").strip() for name in reader.fieldnames]
        reader.fieldnames = fieldnames

        field = None
        for candidate in ("file_name", "filename", "File Name"):
            if candidate in fieldnames:
                field = candidate
                break
        if not field:
            for fn in fieldnames:
                if "file" in fn.lower() and "name" in fn.lower():
                    field = fn
                    break
        if not field:
            raise ValueError(f"CSV missing file_name column (found: {fieldnames[:8]})")

        for row in reader:
            value = (row.get(field) or "").strip().strip('"')
            if value:
                names.add(value.lower())
        return names

    def _fetch_csv(self, auth_key: str) -> set[str]:
        urls = [
            f"{MB_CSV_URL}?auth-key={auth_key}",
            MB_CSV_V2_RECENT_URL.format(auth_key=auth_key),
        ]
        last_error: Exception | None = None

        for url in urls:
            try:
                with httpx.Client(timeout=300.0, follow_redirects=True) as client:
                    response = client.get(url)
                    response.raise_for_status()
                text = self._decode_csv_payload(response.content)
                names = self._parse_csv_text(text)
                if len(names) >= MIN_EXPECTED_NAMES:
                    return names
                last_error = ValueError(
                    f"CSV from {url} contained too few filenames ({len(names)})"
                )
            except Exception as exc:
                last_error = exc

        if last_error:
            raise last_error
        return set()

    def _fetch_recent(self, auth_key: str) -> set[str]:
        headers = {"Auth-Key": auth_key} if auth_key else {}
        with httpx.Client(timeout=30.0) as client:
            response = client.post(
                MB_API_URL,
                data={"query": "get_recent", "selector": "time"},
                headers=headers,
            )
            response.raise_for_status()
            payload = response.json()

        if payload.get("query_status") != "ok":
            return set()

        names: set[str] = set()
        for item in payload.get("data", []):
            name = (item.get("file_name") or "").strip()
            if name:
                names.add(name.lower())
        return names

    def contains(self, filename: str) -> bool:
        import os

        # VERIFIED - already optimized: O(1) lookup against set() built on cache load/refresh
        basename = os.path.basename(filename).lower()
        with self._lock:
            return basename in self._names

    def get_names_frozen(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._names)
