from __future__ import annotations

import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from scanner.cache import NameCache
from scanner.engine import ScanEngine
from scanner.history_store import HistoryStore
from scanner.models import (
    AppSettings,
    AppSettingsUpdate,
    HealthResponse,
    HistoryEntry,
    ScanRequest,
    ScanResultsResponse,
    ScanState,
    ScanStatusResponse,
    ServiceEntry,
    ServicesScanResponse,
    StartupItem,
)
from scanner.services import list_services, scan_services
from scanner.settings_store import SettingsStore
from scanner.startup_items import list_startup_items

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

name_cache = NameCache()
settings_store = SettingsStore()
history_store = HistoryStore()
scan_engine = ScanEngine(name_cache, settings_store)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    auth_key = settings_store.malwarebazaar_auth_key
    name_cache.initialize_async(auth_key)
    yield


app = FastAPI(title="Maat API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:1420",
        "tauri://localhost",
        "https://tauri.localhost",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _mask_key(key: str) -> str:
    if not key:
        return ""
    if len(key) <= 8:
        return "*" * len(key)
    return key[:4] + "*" * (len(key) - 8) + key[-4:]


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    warnings = list(name_cache.warnings)
    if name_cache.initializing:
        warnings.append("Threat database is loading in the background.")
    if not settings_store.malwarebazaar_auth_key:
        warnings.append("MalwareBazaar Auth-Key not configured.")
    status = "ok" if name_cache.count > 0 else "degraded"
    return HealthResponse(
        status=status,
        cache_age_hours=name_cache.age_hours,
        cache_count=name_cache.count,
        warnings=warnings,
    )


@app.get("/settings", response_model=AppSettings)
def get_settings() -> AppSettings:
    settings = settings_store.get()
    return AppSettings(
        default_scan_path=settings.default_scan_path,
        default_scan_mode=settings.default_scan_mode,
        malwarebazaar_auth_key=_mask_key(settings.malwarebazaar_auth_key),
        virustotal_api_key=_mask_key(settings.virustotal_api_key),
    )


@app.put("/settings", response_model=AppSettings)
def update_settings(update: AppSettingsUpdate) -> AppSettings:
    previous_key = settings_store.malwarebazaar_auth_key
    payload = update.model_dump(exclude_unset=True)
    for key in ("malwarebazaar_auth_key", "virustotal_api_key"):
        if key in payload and "*" in (payload[key] or ""):
            payload.pop(key)
    settings_store.update(AppSettingsUpdate.model_validate(payload))
    new_key = settings_store.malwarebazaar_auth_key
    if new_key and new_key != previous_key:
        name_cache.refresh(new_key)
    settings = settings_store.get()
    return AppSettings(
        default_scan_path=settings.default_scan_path,
        default_scan_mode=settings.default_scan_mode,
        malwarebazaar_auth_key=_mask_key(settings.malwarebazaar_auth_key),
        virustotal_api_key=_mask_key(settings.virustotal_api_key),
    )


@app.post("/scan/start")
def start_scan(request: ScanRequest) -> dict:
    status = scan_engine.get_status()
    if status.state == ScanState.RUNNING:
        raise HTTPException(status_code=409, detail="Scan already running")
    if not os.path.isdir(request.path):
        raise HTTPException(status_code=400, detail="Invalid scan path")
    try:
        scan_engine.start(request)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"ok": True}


@app.get("/scan/status", response_model=ScanStatusResponse)
def scan_status() -> ScanStatusResponse:
    return scan_engine.get_status()


@app.post("/scan/stop")
def stop_scan() -> dict:
    scan_engine.stop()
    return {"ok": True}


@app.get("/scan/results", response_model=ScanResultsResponse)
def scan_results() -> ScanResultsResponse:
    results = scan_engine.get_results()
    if not results:
        raise HTTPException(status_code=404, detail="No scan results available")
    status = scan_engine.get_status()
    if status.state in (ScanState.COMPLETED, ScanState.CANCELLED) and not scan_engine.is_history_saved():
        history_store.add(
            results,
            scan_path=results.summary.scan_path,
            mode=results.summary.mode.value,
        )
        scan_engine.mark_history_saved()
    return results


@app.get("/history", response_model=list[HistoryEntry])
def get_history() -> list[HistoryEntry]:
    return history_store.list_entries()


@app.get("/history/{entry_id}", response_model=HistoryEntry)
def get_history_entry(entry_id: str) -> HistoryEntry:
    entry = history_store.get(entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="History entry not found")
    return entry


@app.get("/startup/list", response_model=list[StartupItem])
def startup_list() -> list[StartupItem]:
    return list_startup_items()


@app.get("/services/list", response_model=list[ServiceEntry])
def services_list() -> list[ServiceEntry]:
    try:
        return list_services()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to list services: {exc}") from exc


@app.post("/services/scan", response_model=ServicesScanResponse)
def services_scan() -> ServicesScanResponse:
    try:
        return scan_services(name_cache, settings_store.malwarebazaar_auth_key)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to scan services: {exc}") from exc


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8787"))
    uvicorn.run("main:app", host="127.0.0.1", port=port, reload=False)
