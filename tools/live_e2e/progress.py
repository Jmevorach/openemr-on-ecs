"""Human-facing progress output for long-running live E2E operations."""

from __future__ import annotations

import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator, TextIO


@dataclass
class ProgressReporter:
    """Emit phase and heartbeat messages to stderr without touching JSON stdout."""

    enabled: bool = True
    verbose: bool = False
    stream: TextIO = field(default_factory=lambda: sys.stderr)
    heartbeat_interval_seconds: float = 30.0
    _last_heartbeat_at: float = field(default=0.0, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def phase(self, name: str, detail: str = "") -> None:
        """Announce a major phase boundary."""

        suffix = f" — {detail}" if detail else ""
        self._emit(f"==> {name}{suffix}")

    def info(self, message: str) -> None:
        """Emit a status line whenever progress reporting is enabled."""

        self._emit(message)

    def detail(self, message: str) -> None:
        """Emit extra detail only when verbose mode is on."""

        if self.verbose:
            self._emit(message)

    def heartbeat(self, message: str, *, force: bool = False) -> None:
        """Rate-limited status for long polls; force bypasses the interval."""

        if not self.enabled:
            return
        now = time.monotonic()
        with self._lock:
            if not force and (now - self._last_heartbeat_at) < self.heartbeat_interval_seconds:
                return
            self._last_heartbeat_at = now
        self._emit(message)

    @contextmanager
    def pulse(self, message: str, *, interval_seconds: float | None = None) -> Iterator[None]:
        """Print elapsed-time heartbeats while a blocking operation runs."""

        if not self.enabled:
            yield
            return
        interval = self.heartbeat_interval_seconds if interval_seconds is None else interval_seconds
        if interval <= 0:
            yield
            return
        stop = threading.Event()
        started = time.monotonic()

        def _worker() -> None:
            while not stop.wait(interval):
                elapsed = time.monotonic() - started
                minutes, seconds = divmod(int(elapsed), 60)
                self.heartbeat(
                    f"{message} (elapsed {minutes}m{seconds:02d}s)",
                    force=True,
                )

        thread = threading.Thread(target=_worker, name="live-e2e-progress", daemon=True)
        thread.start()
        try:
            yield
        finally:
            stop.set()
            thread.join(timeout=1.0)
            elapsed = time.monotonic() - started
            minutes, seconds = divmod(int(elapsed), 60)
            self.detail(f"{message} finished in {minutes}m{seconds:02d}s")

    def _emit(self, message: str) -> None:
        if not self.enabled:
            return
        with self._lock:
            print(message, file=self.stream, flush=True)


NULL_PROGRESS = ProgressReporter(enabled=False)
"""Shared no-op reporter for tests and quiet callers."""
