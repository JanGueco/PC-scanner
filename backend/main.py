from __future__ import annotations

import os
from contextlib import asynccontextmanager

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from scanner.cache import NameCache
from scanner.engine import ScanEngine
from scanner.history_store import HistoryStore
from scanner.models import (
    AppSettingsUpdate,
    AppSettingsView,
    DeepCheckRequest,
    DeepCheckResponse,
    HealthResponse,
    HistoryEntry,
    ScanRequest,
    ScanResultsResponse,
    ScanState,
    ScanStatusResponse,
    ServiceEntry,
    ServicesScanResponse,
    ServicesScanStatusResponse,
    StartupItem,
)
from scanner.services import list_services
from scanner.services_engine import ServicesEngine
from scanner.settings_store import SettingsStore
from scanner.startup_items import list_startup_items
from scanner.virustotal import check_rate_limit, resolve_sha256, run_deep_check

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

name_cache = NameCache()
settings_store = SettingsStore()
history_store = HistoryStore()
scan_engine = ScanEngine(name_cache, settings_store)
services_engine = ServicesEngine(name_cache, settings_store)


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


def _build_settings_view() -> AppSettingsView:
    settings = settings_store.get()
    return AppSettingsView(
        default_scan_path=settings.default_scan_path,
        default_scan_mode=settings.default_scan_mode,
        malwarebazaar_auth_key=_mask_key(settings_store.malwarebazaar_auth_key),
        virustotal_api_key=_mask_key(settings_store.virustotal_api_key),
        api_key_source=settings.api_key_source,
        env_keys_detected=settings_store.get_env_key_status(),
    )


@app.get("/settings", response_model=AppSettingsView)
def get_settings() -> AppSettingsView:
    return _build_settings_view()


@app.put("/settings", response_model=AppSettingsView)
def update_settings(update: AppSettingsUpdate) -> AppSettingsView:
    previous_key = settings_store.malwarebazaar_auth_key
    payload = update.model_dump(exclude_unset=True)
    for key in ("malwarebazaar_auth_key", "virustotal_api_key"):
        if key in payload and "*" in (payload[key] or ""):
            payload.pop(key)
    settings = settings_store.get()
    next_source = payload.get("api_key_source", settings.api_key_source)
    if next_source == "env":
        payload.pop("malwarebazaar_auth_key", None)
        payload.pop("virustotal_api_key", None)
    settings_store.update(AppSettingsUpdate.model_validate(payload))
    new_key = settings_store.malwarebazaar_auth_key
    if new_key and new_key != previous_key:
        name_cache.refresh(new_key)
    return _build_settings_view()


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


@app.post("/services/scan/start")
def services_scan_start() -> dict:
    try:
        services_engine.start()
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"ok": True}


@app.get("/services/scan/status", response_model=ServicesScanStatusResponse)
def services_scan_status() -> ServicesScanStatusResponse:
    return services_engine.get_status()


@app.get("/services/scan/results", response_model=ServicesScanResponse)
def services_scan_results() -> ServicesScanResponse:
    results = services_engine.get_results()
    if not results:
        raise HTTPException(status_code=404, detail="No services scan results available")
    return results


@app.post("/deepcheck", response_model=DeepCheckResponse)
def deepcheck(request: DeepCheckRequest):
    api_key = settings_store.virustotal_api_key
    if not api_key:
        return JSONResponse(status_code=400, content={"error": "no_api_key"})

    allowed, retry_after = check_rate_limit()
    if not allowed:
        return JSONResponse(
            status_code=429,
            content={"error": "rate_limited", "retry_after_seconds": retry_after},
        )

    sha256 = resolve_sha256(request.sha256, request.path)
    if not sha256:
        raise HTTPException(
            status_code=400,
            detail="Could not compute SHA256 for this item. The file may be missing or inaccessible.",
        )

    try:
        payload = run_deep_check(sha256, api_key)
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503,
            detail="Could not reach VirusTotal. Check your internet connection.",
        ) from exc

    return DeepCheckResponse(
        identifier=request.identifier,
        **payload,
    )


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8787"))
    uvicorn.run("main:app", host="127.0.0.1", port=port, reload=False)
