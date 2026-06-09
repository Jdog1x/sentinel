"""
sentinel/core/jobs.py
Bounded background job runner for scans.

The API used to launch each scan in a bare `threading.Thread(...).start()`, which
is unbounded: N API calls spawn N concurrent scans, each running nmap + network
probes, with nothing to stop a burst from exhausting the host. This module runs
scans on a fixed-size thread pool so concurrency is capped at
MAX_CONCURRENT_SCANS; additional requests queue and run as workers free up.

This is intentionally lightweight (in-process). For a multi-process or
horizontally-scaled deployment this is the seam where you'd swap in Celery/RQ/arq
backed by Redis without touching the call sites.
"""
from __future__ import annotations

import atexit
import logging
from concurrent.futures import ThreadPoolExecutor

from sentinel.core.config import config

log = logging.getLogger(__name__)

_executor = ThreadPoolExecutor(
    max_workers=max(1, config.max_concurrent_scans),
    thread_name_prefix="sentinel-scan",
)


def submit_scan(target: str, *, backend: str | None, fast: bool) -> None:
    """Queue a scan to run on the bounded worker pool."""
    _executor.submit(_run_scan_job, target, backend, fast)


def _run_scan_job(target: str, backend: str | None, fast: bool) -> None:
    # Imported lazily to avoid a circular import (scanner -> models -> config).
    from sentinel.core.scanner import ScanOrchestrator

    try:
        ScanOrchestrator(llm_backend=backend).run_scan(target, fast=fast)
    except Exception:  # pragma: no cover - defensive: never let a worker die silently
        log.exception("Scan job failed for target %s", target)


@atexit.register
def _shutdown() -> None:  # pragma: no cover
    _executor.shutdown(wait=False, cancel_futures=True)
