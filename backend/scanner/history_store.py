from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone

from .models import HistoryEntry, ScanResultsResponse, ScanState, get_app_data_dir


class HistoryStore:
    MAX_ENTRIES = 50

    def __init__(self) -> None:
        self._path = os.path.join(get_app_data_dir(), "history.json")
        self._entries: list[HistoryEntry] = self._load()

    def _load(self) -> list[HistoryEntry]:
        if not os.path.exists(self._path):
            return []
        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
            return [HistoryEntry.model_validate(item) for item in data]
        except (OSError, json.JSONDecodeError, ValueError):
            return []

    def list_entries(self) -> list[HistoryEntry]:
        return [e.model_copy(deep=True) for e in self._entries]

    def get(self, entry_id: str) -> HistoryEntry | None:
        for entry in self._entries:
            if entry.id == entry_id:
                return entry.model_copy(deep=True)
        return None

    def add(self, results: ScanResultsResponse, scan_path: str, mode: str) -> HistoryEntry:
        entry = HistoryEntry(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            scan_path=scan_path,
            mode=mode,
            total_scanned=results.summary.total_scanned,
            duration_seconds=results.summary.duration_seconds,
            clean=results.summary.clean,
            suspicious=results.summary.suspicious,
            malicious=results.summary.malicious,
            skipped=results.summary.skipped,
            results=results,
        )
        self._entries.insert(0, entry)
        self._entries = self._entries[: self.MAX_ENTRIES]
        self._save()
        return entry

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump([e.model_dump() for e in self._entries], f, indent=2)
