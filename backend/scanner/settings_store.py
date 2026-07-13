from __future__ import annotations

import json
import os
from pathlib import Path

from .models import AppSettings, AppSettingsUpdate, EnvKeyStatus, ScanMode, get_app_data_dir

_ENV_FILE_PATH = Path(__file__).resolve().parent.parent / ".env"


def _parse_env_file() -> EnvKeyStatus:
    if not _ENV_FILE_PATH.is_file():
        return EnvKeyStatus()

    values: dict[str, str] = {}
    try:
        for line in _ENV_FILE_PATH.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        return EnvKeyStatus()

    return EnvKeyStatus(
        malwarebazaar=bool(values.get("MALWAREBAZAAR_AUTH_KEY", "")),
        virustotal=bool(values.get("VT_API_KEY", "")),
    )


class SettingsStore:
    def __init__(self) -> None:
        self._path = os.path.join(get_app_data_dir(), "settings.json")
        self._settings = self._load()

    def _load(self) -> AppSettings:
        if not os.path.exists(self._path):
            env_status = self.get_env_key_status()
            return AppSettings(
                api_key_source="env" if env_status.any_detected else "app",
            )
        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
            if data.get("default_scan_mode") == "thorough":
                data["default_scan_mode"] = "background"
            if "api_key_source" not in data:
                env_status = self.get_env_key_status()
                data["api_key_source"] = "env" if env_status.any_detected else "app"
            settings = AppSettings.model_validate(data)
            if settings.api_key_source == "env" and not self.get_env_key_status().any_detected:
                settings = settings.model_copy(update={"api_key_source": "app"})
            return settings
        except (OSError, json.JSONDecodeError, ValueError):
            env_status = self.get_env_key_status()
            return AppSettings(
                api_key_source="env" if env_status.any_detected else "app",
            )

    def get(self) -> AppSettings:
        return self._settings.model_copy(deep=True)

    def update(self, update: AppSettingsUpdate) -> AppSettings:
        payload = self._settings.model_dump()
        for key, value in update.model_dump(exclude_unset=True).items():
            if value is not None:
                payload[key] = value
        if payload.get("api_key_source") == "env" and not self.get_env_key_status().any_detected:
            payload["api_key_source"] = "app"
        self._settings = AppSettings.model_validate(payload)
        self._save()
        return self.get()

    def _save(self) -> None:
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(self._settings.model_dump(), f, indent=2)

    @staticmethod
    def get_env_key_status() -> EnvKeyStatus:
        file_status = _parse_env_file()
        return EnvKeyStatus(
            malwarebazaar=file_status.malwarebazaar
            or bool(os.environ.get("MALWAREBAZAAR_AUTH_KEY", "").strip()),
            virustotal=file_status.virustotal or bool(os.environ.get("VT_API_KEY", "").strip()),
        )

    @property
    def malwarebazaar_auth_key(self) -> str:
        if self._settings.api_key_source == "env":
            return os.environ.get("MALWAREBAZAAR_AUTH_KEY", "").strip()
        return self._settings.malwarebazaar_auth_key.strip()

    @property
    def virustotal_api_key(self) -> str:
        if self._settings.api_key_source == "env":
            return os.environ.get("VT_API_KEY", "").strip()
        return self._settings.virustotal_api_key.strip()
