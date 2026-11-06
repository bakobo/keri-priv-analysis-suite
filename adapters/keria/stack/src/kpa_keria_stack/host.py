"""One KERIA agency as a child process: its own HOME, stores, config, ports and log.

Each access boundary the scenario has (an issuing home, the citizens' wallet host, a verifier) runs
its own agency, so that what one party obtains is one host's stores and log and nothing else.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from . import errors

HOST = "127.0.0.1"
CONFIG_DT = "2022-01-20T12:57:59.823350+00:00"  # the dt KERIA's own sample configs carry
READY = b"The Agency is loaded and waiting for requests"
STAMP = "%Y-%m-%d %H:%M:%S"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def parse_log(text: str) -> list[tuple[float, str]]:
    """Every line of a KERIA log with the wall-clock time it was written.

    KERIA stamps its own lines to the second and keripy's lines carry no stamp, so a line without
    one takes the stamp of the latest stamped line before it, and lines before any stamp take the
    first stamp in the log.
    """
    lines = text.splitlines()
    stamps = [_stamp(line) for line in lines]
    known = [s for s in stamps if s is not None]
    last = known[0] if known else 0.0
    out = []
    for line, stamp in zip(lines, stamps, strict=True):
        last = stamp if stamp is not None else last
        out.append((last, line))
    return out


def _stamp(line: str) -> float | None:
    try:
        return datetime.strptime(line[:19], STAMP).timestamp()
    except ValueError:
        return None


class Host:
    """A KERIA agency in a child process, started by start() and stopped by stop()."""

    def __init__(self, name: str, root: Path, durls: list[str]):
        self.name = name
        self.root = Path(root) / name
        self.admin, self.http, self.boot = free_port(), free_port(), free_port()
        self.durls = list(durls)
        self.process: subprocess.Popen | None = None

    @property
    def data(self) -> Path:
        return self.root / "data"

    @property
    def log_path(self) -> Path:
        return self.root / "keria.log"

    @property
    def admin_url(self) -> str:
        return f"http://{HOST}:{self.admin}"

    @property
    def boot_url(self) -> str:
        return f"http://{HOST}:{self.boot}"

    @property
    def address(self) -> str:
        return f"{HOST}:{self.http}"

    def _write_config(self) -> Path:
        config = self.root / "config"
        where = config / "keri" / "cf"
        where.mkdir(parents=True, exist_ok=True)
        (where / "kpa.json").write_text(json.dumps({
            "dt": CONFIG_DT,
            "keria": {"dt": CONFIG_DT, "curls": [f"http://{HOST}:{self.http}/"]},
            "iurls": [], "durls": self.durls}))
        return config

    def start(self) -> None:
        config = self._write_config()
        self.data.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ, HOME=str(self.root))
        with self.log_path.open("wb") as log:
            self.process = subprocess.Popen(
                [sys.executable, "-u", "-m", "kpa_keria_stack.server", "--config-dir",
                 str(config), "--admin-port", str(self.admin), "--http-port", str(self.http),
                 "--boot-port", str(self.boot), "--data-dir", str(self.data)],
                env=env, stdout=log, stderr=subprocess.STDOUT)

    def wait_ready(self, timeout: float = 120.0) -> None:
        deadline = time.monotonic() + timeout
        while READY not in self.log_path.read_bytes():
            if self.process.poll() is not None:
                raise errors.HOST_EXITED(host=self.name, code=self.process.returncode,
                                         log=str(self.log_path))
            if time.monotonic() > deadline:
                raise errors.HOST_TIMEOUT(host=self.name, seconds=timeout, log=str(self.log_path))
            time.sleep(0.1)

    def stop(self) -> None:
        if self.process is None or self.process.poll() is not None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)

    def log(self) -> list[tuple[float, str]]:
        return parse_log(self.log_path.read_text(errors="replace"))
