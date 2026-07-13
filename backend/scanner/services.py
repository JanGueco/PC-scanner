from __future__ import annotations

import os
import re
from collections.abc import Callable

from .cache import NameCache
from .models import (
    ServiceEntry,
    ServiceScanEntry,
    ServiceSignatureInfo,
    ServicesScanResponse,
)
from .signature_check import (
    clear_signature_cache,
    is_system_directory_path,
    verify_signature,
)
from .tier2 import Tier2Verifier


def _get_win32service():
    import win32service

    return win32service


def _parse_executable_path(path_name: str) -> str:
    if not path_name:
        return ""
    path_name = path_name.strip()
    if path_name.startswith('"'):
        match = re.match(r'^"([^"]+)"', path_name)
        if match:
            return match.group(1)
    return path_name.split()[0] if path_name else ""


def list_services() -> list[ServiceEntry]:
    win32service = _get_win32service()
    service_status_map = {
        win32service.SERVICE_RUNNING: "Running",
        win32service.SERVICE_STOPPED: "Stopped",
        win32service.SERVICE_PAUSED: "Paused",
    }
    start_type_map = {
        win32service.SERVICE_AUTO_START: "Automatic",
        win32service.SERVICE_DEMAND_START: "Manual",
        win32service.SERVICE_DISABLED: "Disabled",
    }
    entries: list[ServiceEntry] = []
    scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
    try:
        services = win32service.EnumServicesStatus(
            scm,
            win32service.SERVICE_WIN32,
            win32service.SERVICE_STATE_ALL,
        )
        for short_name, display_name, status in services:
            service_status = service_status_map.get(status[1], "Unknown")
            start_type = "Unknown"
            executable_path = ""
            try:
                handle = win32service.OpenService(
                    scm,
                    short_name,
                    win32service.SERVICE_QUERY_CONFIG,
                )
                try:
                    config = win32service.QueryServiceConfig(handle)
                    start_type = start_type_map.get(config[1], "Unknown")
                    executable_path = _parse_executable_path(config[3] or "")
                finally:
                    win32service.CloseServiceHandle(handle)
            except win32service.error:
                pass

            entries.append(
                ServiceEntry(
                    name=short_name,
                    display_name=display_name or short_name,
                    status=service_status,  # type: ignore[arg-type]
                    start_type=start_type,  # type: ignore[arg-type]
                    executable_path=executable_path,
                )
            )
    finally:
        win32service.CloseServiceHandle(scm)
    return entries


def _signature_info_from_result(result: dict) -> ServiceSignatureInfo:
    return ServiceSignatureInfo(
        signature_valid=result["signature_valid"],
        signer=result["signer"],
        signed_by_microsoft=result["signed_by_microsoft"],
        signature_status=result["status"],
        verification_error=result["verification_error"],
    )


def _run_tier1_tier2(
    exe_path: str,
    name_cache: NameCache,
    verifier: Tier2Verifier,
) -> tuple[bool, str | None, str | None, str | None, str | None]:
    if not name_cache.contains(exe_path):
        return False, None, None, None, None

    match_type = "name"
    status, tier_match, hash_val, db = verifier.verify(exe_path)
    if tier_match == "sha256":
        match_type = "sha256"

    if status == "malicious":
        return True, "malicious", hash_val, db, match_type
    if status == "clean":
        return False, None, hash_val, db, match_type
    return True, "review", hash_val, db, match_type


def scan_services(
    name_cache: NameCache,
    auth_key: str,
    *,
    on_progress: Callable[[int, int, str, int], None] | None = None,
) -> ServicesScanResponse:
    clear_signature_cache()
    services = list_services()
    verifier = Tier2Verifier(auth_key)
    scan_entries: list[ServiceScanEntry] = []
    flagged_count = 0
    trusted_count = 0
    total = len(services)

    try:
        for index, service in enumerate(services, start=1):
            flagged = False
            flag_label = None
            sha256: str | None = None
            database: str | None = None
            match_type: str | None = None
            signature: ServiceSignatureInfo | None = None

            exe_path = service.executable_path
            if exe_path and os.path.isfile(exe_path):
                sig_result = verify_signature(exe_path)
                signature = _signature_info_from_result(sig_result)

                if sig_result["verification_error"]:
                    flagged, flag_label, sha256, database, match_type = _run_tier1_tier2(
                        exe_path,
                        name_cache,
                        verifier,
                    )
                    if not flagged:
                        flag_label = "unverifiable"

                elif sig_result["signature_valid"] and sig_result["signed_by_microsoft"]:
                    trusted_count += 1

                elif sig_result["signature_valid"]:
                    flagged, tier_label, sha256, database, match_type = _run_tier1_tier2(
                        exe_path,
                        name_cache,
                        verifier,
                    )
                    flag_label = tier_label or "third_party"

                elif is_system_directory_path(exe_path):
                    flagged = True
                    flag_label = "suspicious_system"

                else:
                    flagged, flag_label, sha256, database, match_type = _run_tier1_tier2(
                        exe_path,
                        name_cache,
                        verifier,
                    )

            if flagged:
                flagged_count += 1

            scan_entries.append(
                ServiceScanEntry(
                    **service.model_dump(),
                    flagged=flagged,
                    flag_label=flag_label,  # type: ignore[arg-type]
                    sha256=sha256,
                    database=database,
                    match_type=match_type,  # type: ignore[arg-type]
                    signature=signature,
                )
            )

            if on_progress:
                on_progress(index, total, service.display_name, flagged_count)
    finally:
        verifier.close()

    return ServicesScanResponse(
        total=len(scan_entries),
        flagged=flagged_count,
        trusted=trusted_count,
        entries=scan_entries,
    )
