from __future__ import annotations

import os
import threading
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait

from .cache import NameCache
from .models import (
    FlaggedFile,
    ScanMode,
    ScanRequest,
    ScanResultsResponse,
    ScanState,
    ScanStatusResponse,
    ScanSummary,
)
from .settings_store import SettingsStore
from .tier2 import Tier2Verifier


class ScanEngine:
    def __init__(self, name_cache: NameCache, settings_store: SettingsStore) -> None:
        self.name_cache = name_cache
        self.settings_store = settings_store
        self._lock = threading.Lock()
        self._cancel_event = threading.Event()
        self._executor: ThreadPoolExecutor | None = None
        self._verifier: Tier2Verifier | None = None

        self.state = ScanState.IDLE
        self.current = 0
        self.total = 0
        self.file_path = ""
        self.clean = 0
        self.suspicious = 0
        self.malicious = 0
        self.skipped = 0
        self.workers = 0
        self.message = ""
        self.flagged_files: list[FlaggedFile] = []
        self._results: ScanResultsResponse | None = None
        self._history_saved = False
        self._scan_path = ""
        self._mode = ScanMode.FAST
        self._started_at: float | None = None
        self._scan_thread: threading.Thread | None = None

    def get_status(self) -> ScanStatusResponse:
        with self._lock:
            return ScanStatusResponse(
                state=self.state,
                current=self.current,
                total=self.total,
                file_path=self.file_path,
                clean=self.clean,
                suspicious=self.suspicious,
                malicious=self.malicious,
                skipped=self.skipped,
                workers=self.workers,
                message=self.message,
            )

    def get_results(self) -> ScanResultsResponse | None:
        with self._lock:
            if self._results:
                return self._results.model_copy(deep=True)
            return None

    def mark_history_saved(self) -> None:
        with self._lock:
            self._history_saved = True

    def is_history_saved(self) -> bool:
        with self._lock:
            return self._history_saved

    def start(self, request: ScanRequest) -> None:
        with self._lock:
            if self._scan_thread and self._scan_thread.is_alive():
                raise RuntimeError("Scan already running")
            if self.state == ScanState.RUNNING:
                raise RuntimeError("Scan already running")

            self._reset_run_state()
            self.state = ScanState.RUNNING
            self._scan_path = request.path
            self._mode = request.mode
            self._started_at = time.time()
            self.workers = (
                os.cpu_count() or 4
                if request.mode == ScanMode.FAST
                else 2
            )

        thread = threading.Thread(target=self._run_scan, args=(request,), daemon=True)
        self._scan_thread = thread
        thread.start()

    def stop(self) -> None:
        self._cancel_event.set()
        with self._lock:
            if self.state == ScanState.RUNNING:
                self.state = ScanState.CANCELLED
        executor = self._executor
        if executor:
            executor.shutdown(wait=False, cancel_futures=True)

    def _reset_run_state(self) -> None:
        self._cancel_event.clear()
        self.current = 0
        self.total = 0
        self.file_path = ""
        self.clean = 0
        self.suspicious = 0
        self.malicious = 0
        self.skipped = 0
        self.message = ""
        self.flagged_files = []
        self._results = None
        self._history_saved = False
        self._executor = None
        if self._verifier:
            self._verifier.close()
        self._verifier = Tier2Verifier(self.settings_store.malwarebazaar_auth_key)

    def _enumerate_files(self, root: str) -> list[str]:
        files: list[str] = []
        for dirpath, dirnames, filenames in os.walk(root):
            if self._cancel_event.is_set():
                break
            dirnames[:] = [
                d for d in dirnames
                if not os.path.islink(os.path.join(dirpath, d))
            ]
            for name in filenames:
                full = os.path.join(dirpath, name)
                if os.path.islink(full):
                    continue
                files.append(full)
        return files

    def _run_scan(self, request: ScanRequest) -> None:
        try:
            if not os.path.isdir(request.path):
                raise ValueError(f"Scan path does not exist: {request.path}")

            files = self._enumerate_files(request.path)
            with self._lock:
                self.total = len(files)
                if self.total == 0:
                    self.state = ScanState.COMPLETED
                    self._finalize_results()
                    return

            max_workers = self.workers
            self._executor = ThreadPoolExecutor(max_workers=max_workers)
            pending: set[Future] = set()
            max_pending = max(max_workers * 4, 8)

            for file_path in files:
                if self._cancel_event.is_set():
                    break

                pending.add(self._executor.submit(self._process_file, file_path))

                if len(pending) >= max_pending:
                    done, pending = wait(pending, return_when=FIRST_COMPLETED)
                    self._resolve_futures(done)

            while pending and not self._cancel_event.is_set():
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                self._resolve_futures(done)

            if pending:
                self._resolve_futures(pending)

            with self._lock:
                if self._cancel_event.is_set():
                    self.state = ScanState.CANCELLED
                else:
                    self.state = ScanState.COMPLETED
                self._finalize_results()
        except Exception as exc:
            with self._lock:
                self.state = ScanState.ERROR
                self.message = str(exc)
        finally:
            if self._executor:
                self._executor.shutdown(wait=False, cancel_futures=True)
            if self._verifier:
                self._verifier.close()
                self._verifier = None
            self._scan_thread = None

    def _resolve_futures(self, futures: set[Future] | list[Future]) -> None:
        for future in futures:
            try:
                future.result()
            except Exception:
                with self._lock:
                    self.skipped += 1

    def _process_file(self, file_path: str) -> None:
        if self._cancel_event.is_set():
            return

        with self._lock:
            self.current += 1
            self.file_path = file_path

        if not os.path.isfile(file_path):
            with self._lock:
                self.skipped += 1
            return

        try:
            if not self.name_cache.contains(file_path):
                with self._lock:
                    self.clean += 1
                return
        except Exception:
            with self._lock:
                self.skipped += 1
            return

        if self._cancel_event.is_set() or not self._verifier:
            return

        status, match_type, sha256, database = self._verifier.verify(file_path)

        with self._lock:
            if status == "clean":
                self.clean += 1
                return
            if status == "malicious":
                self.malicious += 1
                threat_status = "malicious"
            else:
                self.suspicious += 1
                threat_status = "suspicious"

            self.flagged_files.append(
                FlaggedFile(
                    file_name=os.path.basename(file_path),
                    path=file_path,
                    status=threat_status,
                    match_type=match_type,
                    sha256=sha256,
                    database=database,
                )
            )

    def _finalize_results(self) -> None:
        duration = 0.0
        if self._started_at:
            duration = round(time.time() - self._started_at, 2)

        summary = ScanSummary(
            total_scanned=self.current,
            duration_seconds=duration,
            clean=self.clean,
            suspicious=self.suspicious,
            malicious=self.malicious,
            skipped=self.skipped,
            scan_path=self._scan_path,
            mode=self._mode,
        )
        self._results = ScanResultsResponse(
            summary=summary,
            flagged_files=list(self.flagged_files),
        )
