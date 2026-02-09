"""Logging helpers for the honeypot."""

from __future__ import annotations

import json
import logging
import os
import time
from logging.handlers import RotatingFileHandler
from typing import Any, Dict


LOG_PATH_DEFAULT = "/app/logs/honeypot.log"


class HoneypotLogger:
    """JSON-lines logger + simple alerting helpers. Each event is one JSON object on a single line."""

    def __init__(self, logger: logging.Logger):
        self._logger = logger
        self._failed_by_ip: Dict[str, list[float]] = {}

    def event(self, event_type: str, **fields: Any) -> None:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event_type,
            **fields,
        }
        self._logger.info(json.dumps(payload, separators=(",", ":"), ensure_ascii=False))

    def track_failed_login(self, src_ip: str, window_s: int = 60, threshold: int = 5) -> bool:
        """Returns True if the src_ip crosses the threshold failed logins within window_s."""
        now = time.time()
        arr = self._failed_by_ip.setdefault(src_ip, [])
        arr.append(now)

        cutoff = now - window_s
        while arr and arr[0] < cutoff:
            arr.pop(0)

        return len(arr) >= threshold


def create_logger(log_path: str = LOG_PATH_DEFAULT) -> HoneypotLogger:
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    logger = logging.getLogger("honeypot")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        #File handler (rotating)
        fh = RotatingFileHandler(log_path, maxBytes=2_000_000, backupCount=3)
        fh.setLevel(logging.INFO)

        #Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)

        fmt = logging.Formatter("%(asctime)s - %(message)s")
        fh.setFormatter(fmt)
        ch.setFormatter(fmt)

        logger.addHandler(fh)
        logger.addHandler(ch)

    return HoneypotLogger(logger)
