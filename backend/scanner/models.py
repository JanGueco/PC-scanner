from __future__ import annotations

import os
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class ScanMode(str, Enum):
    FAST = "fast"
    BACKGROUND = "background"


class ScanState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    ERROR = "error"


class ThreatStatus(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class MatchType(str, Enum):
    NAME = "name"
    SHA256 = "sha256"


class ScanRequest(BaseModel):
    path: str
    mode: ScanMode = ScanMode.FAST

    @field_validator("mode", mode="before")
    @classmethod
    def migrate_thorough_mode(cls, value: object) -> object:
        if value == "thorough":
            return "background"
        return value


class FlaggedFile(BaseModel):
    file_name: str
    path: str
    status: Literal["suspicious", "malicious"]
    match_type: Literal["name", "sha256"]
    sha256: str | None = None
    database: str | None = None


class ScanStatusResponse(BaseModel):
    state: ScanState
    current: int = 0
    total: int = 0
    file_path: str = ""
    clean: int = 0
    suspicious: int = 0
    malicious: int = 0
    skipped: int = 0
    workers: int = 0
    message: str = ""


class ScanSummary(BaseModel):
    total_scanned: int = 0
    duration_seconds: float = 0.0
    clean: int = 0
    suspicious: int = 0
    malicious: int = 0
    skipped: int = 0
    scan_path: str = ""
    mode: ScanMode = ScanMode.FAST


class ScanResultsResponse(BaseModel):
    summary: ScanSummary
    flagged_files: list[FlaggedFile] = Field(default_factory=list)


class AppSettings(BaseModel):
    default_scan_path: str = "C:\\"
    default_scan_mode: ScanMode = ScanMode.FAST
    malwarebazaar_auth_key: str = ""
    virustotal_api_key: str = ""


class AppSettingsUpdate(BaseModel):
    default_scan_path: str | None = None
    default_scan_mode: ScanMode | None = None
    malwarebazaar_auth_key: str | None = None
    virustotal_api_key: str | None = None


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"] = "ok"
    cache_age_hours: float | None = None
    cache_count: int = 0
    warnings: list[str] = Field(default_factory=list)


class HistoryEntry(BaseModel):
    id: str
    timestamp: str
    scan_path: str
    mode: ScanMode
    total_scanned: int
    duration_seconds: float
    clean: int
    suspicious: int
    malicious: int
    skipped: int
    results: ScanResultsResponse


def get_app_data_dir() -> str:
    appdata = os.environ.get("APPDATA")
    if appdata:
        base = os.path.join(appdata, "NullScan")
    else:
        base = os.path.join(os.path.expanduser("~"), ".nullscan")
    os.makedirs(base, exist_ok=True)
    return base
