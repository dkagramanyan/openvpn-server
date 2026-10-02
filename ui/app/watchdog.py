"""Restart a web UI that no longer answers.

Docker marks a container whose health check fails as unhealthy but leaves it running. This
thread asks the UI's own /healthz - through the listening socket, the event loop and a worker
thread, the way a browser would - and ends the process after repeated failures; the
container's restart policy then starts a fresh one."""
from __future__ import annotations

import logging
import os
import threading
import urllib.request
from typing import Callable

log = logging.getLogger("openvpn-ui.watchdog")


# No proxy: Docker hands a configured HTTP proxy to every container, and a request for this
# container's own address sent there would fail and count against a healthy UI.
_direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def probe(url: str, timeout: float = 10.0) -> bool:
    try:
        with _direct.open(url, timeout=timeout) as res:
            return res.status == 200
    except Exception:
        return False


class Watchdog(threading.Thread):
    def __init__(self, check: Callable[[], bool], interval: float = 30.0, failures: int = 4, grace: float = 120.0,
                 die: Callable[[], None] = lambda: os._exit(1)) -> None:
        super().__init__(name="watchdog", daemon=True)
        self.check, self.interval, self.failures, self.grace, self.die = check, interval, failures, grace, die
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        failed = 0
        self._stop.wait(self.grace)             # the server is still starting
        while not self._stop.wait(self.interval):
            failed = 0 if self.check() else failed + 1
            if failed >= self.failures:
                log.critical("the UI has not answered %d health checks in a row - exiting for a restart", failed)
                self.die()
                return


def start() -> Watchdog | None:
    """Only under uvicorn in the container, which sets UVICORN_HOST; not in tests."""
    host = os.environ.get("UVICORN_HOST")
    if not host:
        return None
    host = {"0.0.0.0": "127.0.0.1", "::": "[::1]"}.get(host, f"[{host}]" if ":" in host else host)
    dog = Watchdog(lambda: probe(f"http://{host}:8080/healthz"))      # the port in the image's CMD
    dog.start()
    return dog
