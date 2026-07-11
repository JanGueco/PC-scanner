from __future__ import annotations

import os
import re

from .cache import NameCache
from .models import ServiceEntry, ServiceScanEntry, ServicesScanResponse
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


def scan_services(name_cache: NameCache, auth_key: str) -> ServicesScanResponse:
    services = list_services()
    verifier = Tier2Verifier(auth_key)
    scan_entries: list[ServiceScanEntry] = []
    flagged_count = 0

    try:
        for service in services:
            flagged = False
            sha256: str | None = None
            database: str | None = None
            match_type: str | None = None

            exe_path = service.executable_path
            if exe_path and os.path.isfile(exe_path):
                if name_cache.contains(exe_path):
                    flagged = True
                    match_type = "name"
                    status, tier_match, hash_val, db = verifier.verify(exe_path)
                    if hash_val:
                        sha256 = hash_val
                    if db:
                        database = db
                    if tier_match == "sha256":
                        match_type = "sha256"
                    if status == "clean":
                        flagged = False

            if flagged:
                flagged_count += 1

            scan_entries.append(
                ServiceScanEntry(
                    **service.model_dump(),
                    flagged=flagged,
                    sha256=sha256,
                    database=database,
                    match_type=match_type,  # type: ignore[arg-type]
                )
            )
    finally:
        verifier.close()

    return ServicesScanResponse(
        total=len(scan_entries),
        flagged=flagged_count,
        entries=scan_entries,
    )
