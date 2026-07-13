from __future__ import annotations

import threading
import time

from .cache import NameCache
from .models import ServicesScanResponse, ServicesScanState, ServicesScanStatusResponse
from .services import scan_services
from .settings_store import SettingsStore


class ServicesEngine:
    def __init__(self, name_cache: NameCache, settings_store: SettingsStore) -> None:
        self.name_cache = name_cache
        self.settings_store = settings_store
        self._lock = threading.Lock()
        self._scan_thread: threading.Thread | None = None

        self.state = ServicesScanState.IDLE
        self.current = 0
        self.total = 0
        self.service_name = ""
        self.flagged = 0
        self.message = ""
        self._results: ServicesScanResponse | None = None
        self._started_at: float | None = None

    def get_status(self) -> ServicesScanStatusResponse:
        with self._lock:
            return ServicesScanStatusResponse(
                state=self.state,
                current=self.current,
                total=self.total,
                service_name=self.service_name,
                flagged=self.flagged,
                message=self.message,
            )

    def get_results(self) -> ServicesScanResponse | None:
        with self._lock:
            if self._results:
                return self._results.model_copy(deep=True)
            return None

    def start(self) -> None:
        with self._lock:
            if self._scan_thread and self._scan_thread.is_alive():
                raise RuntimeError("Services scan already running")
            if self.state == ServicesScanState.RUNNING:
                raise RuntimeError("Services scan already running")

            self._reset_run_state()
            self.state = ServicesScanState.RUNNING
            self._started_at = time.time()

        thread = threading.Thread(target=self._run_scan, daemon=True)
        self._scan_thread = thread
        thread.start()

    def _reset_run_state(self) -> None:
        self.current = 0
        self.total = 0
        self.service_name = ""
        self.flagged = 0
        self.message = ""
        self._results = None
        self._started_at = None

    def _update_progress(self, current: int, total: int, service_name: str, flagged: int) -> None:
        with self._lock:
            self.current = current
            self.total = total
            self.service_name = service_name
            self.flagged = flagged

    def _run_scan(self) -> None:
        try:
            def on_progress(current: int, total: int, service_name: str, flagged: int) -> None:
                self._update_progress(current, total, service_name, flagged)

            results = scan_services(
                self.name_cache,
                self.settings_store.malwarebazaar_auth_key,
                on_progress=on_progress,
            )
            with self._lock:
                self._results = results
                self.current = results.total
                self.total = results.total
                self.flagged = results.flagged
                self.state = ServicesScanState.COMPLETED
                self.message = ""
        except Exception as exc:
            with self._lock:
                self.state = ServicesScanState.ERROR
                self.message = str(exc)
