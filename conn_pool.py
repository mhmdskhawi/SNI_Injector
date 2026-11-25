"""
Simple TLS connection pool for Direct-SNI → upstream proxy.

Not HTTP/2 multiplexing: one pooled idle SSL socket at a time is handed out
for a new CONNECT. After the tunneled session ends the socket is closed
(CONNECT makes the link single-use). Pooling here means *pre-warm / reuse of
half-open TLS sessions before CONNECT*, not mux.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable, Deque, Generic, Optional, Tuple, TypeVar

T = TypeVar("T")


class ConnectionPool(Generic[T]):
    def __init__(
        self,
        factory: Callable[[], T],
        *,
        max_idle: int = 4,
        max_age_sec: float = 60.0,
        close_fn: Optional[Callable[[T], None]] = None,
    ):
        self._factory = factory
        self._max_idle = max(0, max_idle)
        self._max_age = max_age_sec
        self._close_fn = close_fn or (lambda s: s.close())  # type: ignore[attr-defined]
        self._idle: Deque[Tuple[float, T]] = deque()
        self._lock = threading.Lock()
        self._created = 0
        self._reused = 0

    @property
    def stats(self) -> dict:
        with self._lock:
            return {
                "idle": len(self._idle),
                "created": self._created,
                "reused": self._reused,
            }

    def acquire(self) -> T:
        now = time.monotonic()
        with self._lock:
            while self._idle:
                ts, sock = self._idle.popleft()
                if now - ts <= self._max_age:
                    self._reused += 1
                    return sock
                self._safe_close(sock)
            self._created += 1
        return self._factory()

    def release(self, sock: T, *, reusable: bool) -> None:
        if not reusable:
            self._safe_close(sock)
            return
        now = time.monotonic()
        with self._lock:
            if len(self._idle) >= self._max_idle:
                self._safe_close(sock)
                return
            self._idle.append((now, sock))

    def close_all(self) -> None:
        with self._lock:
            while self._idle:
                _, sock = self._idle.popleft()
                self._safe_close(sock)

    def _safe_close(self, sock: T) -> None:
        try:
            self._close_fn(sock)
        except Exception:
            pass
