from __future__ import annotations

import json
import os
from pathlib import Path

from .models import AppSettings, AppSettingsUpdate, ScanMode, get_app_data_dir


class SettingsStore:
    def __init__(self) -> None:
        self._path = os.path.join(get_app_data_dir(), "settings.json")
        self._settings = self._load()

    def _load(self) -> AppSettings:
        if not os.path.exists(self._path):
            return AppSettings()
        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
            if data.get("default_scan_mode") == "thorough":
                data["default_scan_mode"] = "background"
            return AppSettings.model_validate(data)
        except (OSError, json.JSONDecodeError, ValueError):
            return AppSettings()

    def get(self) -> AppSettings:
        return self._settings.model_copy(deep=True)

    def update(self, update: AppSettingsUpdate) -> AppSettings:
        payload = self._settings.model_dump()
        for key, value in update.model_dump(exclude_unset=True).items():
            if value is not None:
                payload[key] = value
        self._settings = AppSettings.model_validate(payload)
        self._save()
        return self.get()

    def _save(self) -> None:
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(self._settings.model_dump(), f, indent=2)

    @property
    def malwarebazaar_auth_key(self) -> str:
        env_key = os.environ.get("MALWAREBAZAAR_AUTH_KEY", "").strip()
        if env_key:
            return env_key
        return self._settings.malwarebazaar_auth_key.strip()
