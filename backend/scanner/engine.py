from __future__ import annotations

import os
import threading
import time
from collections import deque
from concurrent.futures import FIRST_COMPLETED, Future, ProcessPoolExecutor, wait

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
from .scan_enumeration import iter_scan_batches
from .scan_worker import FileProcessResult, init_scan_worker, process_scan_file, shutdown_scan_worker
from .settings_store import SettingsStore


def _worker_count_for_mode(mode: ScanMode) -> int:
    cpu_count = os.cpu_count() or 4
    if mode == ScanMode.FAST:
        return cpu_count
    cpu_count = os.cpu_count() or 2
    if cpu_count <= 2:
        return 1
    return 2


class ScanEngine:
    def __init__(self, name_cache: NameCache, settings_store: SettingsStore) -> None:
        self.name_cache = name_cache
        self.settings_store = settings_store
        self._lock = threading.Lock()
        self._cancel_event = threading.Event()
        self._executor: ProcessPoolExecutor | None = None

        self.state = ScanState.IDLE
        self.current = 0
        self.total = 0
        self.file_path = ""
        self.clean = 0
        self.suspicious = 0
        self.malicious = 0
        self.skipped = 0
        self.skipped_dirs = 0
        self.skipped_files = 0
        self.workers = 0
        self.message = ""
        self.flagged_files: list[FlaggedFile] = []
        self._results: ScanResultsResponse | None = None
        self._history_saved = False
        self._scan_path = ""
        self._mode = ScanMode.FAST
        self._started_at: float | None = None
        self._scan_thread: threading.Thread | None = None
        self._progress_samples: deque[tuple[float, int]] = deque()

    def get_status(self) -> ScanStatusResponse:
        with self._lock:
            elapsed = 0.0
            if self._started_at and self.state == ScanState.RUNNING:
                elapsed = max(time.time() - self._started_at, 0.0)

            files_per_second = self._rolling_files_per_second()
            remaining_files = max(self.total - self.current, 0)
            estimated_remaining = 0.0
            if files_per_second > 0 and remaining_files > 0:
                estimated_remaining = remaining_files / files_per_second

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
                files_per_second=round(files_per_second, 1),
                elapsed_seconds=round(elapsed, 1),
                estimated_remaining=round(estimated_remaining, 1),
                skipped_dirs=self.skipped_dirs,
                skipped_files=self.skipped_files,
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
            self.workers = _worker_count_for_mode(request.mode)

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
        self.skipped_dirs = 0
        self.skipped_files = 0
        self.message = ""
        self.flagged_files = []
        self._results = None
        self._history_saved = False
        self._executor = None
        self._progress_samples.clear()

    def _rolling_files_per_second(self) -> float:
        if len(self._progress_samples) < 2:
            return 0.0
        oldest_time, oldest_count = self._progress_samples[0]
        newest_time, newest_count = self._progress_samples[-1]
        elapsed = newest_time - oldest_time
        if elapsed <= 0:
            return 0.0
        window = min(elapsed, 5.0)
        return (newest_count - oldest_count) / window

    def _record_progress(self) -> None:
        now = time.monotonic()
        self._progress_samples.append((now, self.current))
        while self._progress_samples and now - self._progress_samples[0][0] > 5.0:
            self._progress_samples.popleft()

    def _apply_result(self, result: FileProcessResult) -> None:
        with self._lock:
            self.current += 1
            self.file_path = result.file_path
            self._record_progress()

            if result.outcome == "clean":
                self.clean += 1
                return
            if result.outcome == "skipped_extension":
                self.skipped_files += 1
                return
            if result.outcome in ("skipped_not_file", "error"):
                self.skipped += 1
                return
            if result.outcome == "malicious":
                self.malicious += 1
                threat_status = "malicious"
            else:
                self.suspicious += 1
                threat_status = "suspicious"

            self.flagged_files.append(
                FlaggedFile(
                    file_name=result.file_name or os.path.basename(result.file_path),
                    path=result.file_path,
                    status=threat_status,
                    match_type=result.match_type or "name",
                    sha256=result.sha256,
                    database=result.database,
                )
            )

    def _run_scan(self, request: ScanRequest) -> None:
        executor: ProcessPoolExecutor | None = None
        try:
            if not os.path.isdir(request.path):
                raise ValueError(f"Scan path does not exist: {request.path}")

            malware_names = self.name_cache.get_names_frozen()
            auth_key = self.settings_store.malwarebazaar_auth_key
            max_workers = self.workers

            executor = ProcessPoolExecutor(
                max_workers=max_workers,
                initializer=init_scan_worker,
                initargs=(malware_names, auth_key),
            )
            self._executor = executor

            pending: set[Future] = set()
            max_pending = max(max_workers * 4, 8)
            discovered_any = False

            for batch, stats, _is_priority in iter_scan_batches(request.path):
                if self._cancel_event.is_set():
                    break

                with self._lock:
                    self.total += len(batch)
                    self.skipped_dirs = stats["skipped_dirs"]
                    self.skipped_files = stats["skipped_files"]

                if not batch:
                    continue

                discovered_any = True
                self._submit_batch(executor, batch, pending, max_pending)

            if not discovered_any:
                with self._lock:
                    self.state = ScanState.COMPLETED
                    self._finalize_results()
                return

            while pending and not self._cancel_event.is_set():
                done, not_done = wait(pending, return_when=FIRST_COMPLETED)
                pending.clear()
                pending.update(not_done)
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
            if executor:
                executor.shutdown(wait=False, cancel_futures=True)
            shutdown_scan_worker()
            self._executor = None
            self._scan_thread = None

    def _submit_batch(
        self,
        executor: ProcessPoolExecutor,
        batch: list[str],
        pending: set[Future],
        max_pending: int,
    ) -> None:
        for file_path in batch:
            if self._cancel_event.is_set():
                break

            pending.add(executor.submit(process_scan_file, file_path))

            if len(pending) >= max_pending:
                done, not_done = wait(pending, return_when=FIRST_COMPLETED)
                pending.clear()
                pending.update(not_done)
                self._resolve_futures(done)

    def _resolve_futures(self, futures: set[Future] | list[Future]) -> None:
        for future in futures:
            try:
                result = future.result()
                self._apply_result(result)
            except Exception:
                with self._lock:
                    self.current += 1
                    self.skipped += 1
                    self._record_progress()

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
            skipped=self.skipped + self.skipped_files,
            scan_path=self._scan_path,
            mode=self._mode,
        )
        self._results = ScanResultsResponse(
            summary=summary,
            flagged_files=list(self.flagged_files),
        )
