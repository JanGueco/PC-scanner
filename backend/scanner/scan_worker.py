from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal

from .scan_enumeration import is_scannable_extension
from .tier2 import Tier2Verifier

_malware_names: frozenset[str] = frozenset()
_verifier: Tier2Verifier | None = None


@dataclass(frozen=True)
class FileProcessResult:
    file_path: str
    outcome: Literal["clean", "suspicious", "malicious", "skipped_not_file", "skipped_extension", "error"]
    file_name: str = ""
    status: Literal["suspicious", "malicious"] | None = None
    match_type: Literal["name", "sha256"] | None = None
    sha256: str | None = None
    database: str | None = None


def init_scan_worker(malware_names: frozenset[str], auth_key: str) -> None:
    global _malware_names, _verifier
    _malware_names = malware_names
    _verifier = Tier2Verifier(auth_key)


def shutdown_scan_worker() -> None:
    global _verifier
    if _verifier:
        _verifier.close()
        _verifier = None


def _name_hit(file_path: str) -> bool:
    basename = os.path.basename(file_path).lower()
    return basename in _malware_names


def process_scan_file(file_path: str) -> FileProcessResult:
    if not os.path.isfile(file_path):
        return FileProcessResult(file_path=file_path, outcome="skipped_not_file")

    if not is_scannable_extension(file_path):
        return FileProcessResult(file_path=file_path, outcome="skipped_extension")

    try:
        if not _name_hit(file_path):
            return FileProcessResult(file_path=file_path, outcome="clean")

        if not _verifier:
            return FileProcessResult(file_path=file_path, outcome="error")

        status, match_type, sha256, database = _verifier.verify(file_path)
        if status == "clean":
            return FileProcessResult(file_path=file_path, outcome="clean")

        threat_status: Literal["suspicious", "malicious"] = (
            "malicious" if status == "malicious" else "suspicious"
        )
        return FileProcessResult(
            file_path=file_path,
            outcome=threat_status,
            file_name=os.path.basename(file_path),
            status=threat_status,
            match_type=match_type,  # type: ignore[arg-type]
            sha256=sha256,
            database=database,
        )
    except Exception:
        return FileProcessResult(file_path=file_path, outcome="error")
