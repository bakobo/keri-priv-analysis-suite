import subprocess
import sys
import time
from datetime import datetime

import pytest
from bakobo.errors import BakoboError

from kpa_keria_stack import host
from kpa_keria_stack.host import Host, free_port, parse_log


def stamp(text):
    return datetime.strptime(text, host.STAMP).timestamp()


def test_free_port_is_bindable():
    port = free_port()
    assert 1024 < port < 65536


def test_parse_log_carries_the_last_stamp_forward():
    text = ("keri: before any stamp\n"
            "2026-10-17 01:23:41 [keria] INFO first\n"
            "keri: unstamped\n"
            "2026-10-17 01:23:43 [keria] INFO second\n")
    first, second = stamp("2026-10-17 01:23:41"), stamp("2026-10-17 01:23:43")
    assert parse_log(text) == [(first, "keri: before any stamp"),
                               (first, "2026-10-17 01:23:41 [keria] INFO first"),
                               (first, "keri: unstamped"),
                               (second, "2026-10-17 01:23:43 [keria] INFO second")]


def test_parse_log_without_any_stamp_uses_zero():
    assert parse_log("keri: one\nkeri: two") == [(0.0, "keri: one"), (0.0, "keri: two")]
    assert parse_log("") == []


def test_host_paths_and_config(tmp_path):
    h = Host("home-0", tmp_path, ["http://127.0.0.1:1/oobi/x"])
    assert h.root == tmp_path / "home-0"
    assert h.data == h.root / "data" and h.log_path == h.root / "keria.log"
    assert h.admin_url.endswith(f":{h.admin}") and h.boot_url.endswith(f":{h.boot}")
    assert h.address == f"127.0.0.1:{h.http}"
    config = h._write_config()
    cf = (config / "keri" / "cf" / "kpa.json").read_text()
    assert f"http://127.0.0.1:{h.http}/" in cf and "oobi/x" in cf


class Fake(Host):
    """A host whose process is a stand-in, so failures can be staged without KERIA."""

    def __init__(self, tmp_path, code):
        super().__init__("fake", tmp_path, [])
        self.root.mkdir(parents=True)
        self.log_path.write_bytes(b"")
        self.process = subprocess.Popen([sys.executable, "-c", code])


def test_wait_ready_reports_an_exit(tmp_path):
    h = Fake(tmp_path, "raise SystemExit(3)")
    h.process.wait()
    with pytest.raises(BakoboError) as exc:
        h.wait_ready()
    assert exc.value.code == "e.env.keria.exited.r"


def test_wait_ready_times_out(tmp_path):
    h = Fake(tmp_path, "import time; time.sleep(30)")
    try:
        with pytest.raises(BakoboError) as exc:
            h.wait_ready(timeout=0.3)
        assert exc.value.code == "e.env.keria.timeout.r"
    finally:
        h.stop()
    assert h.process.poll() is not None


def test_wait_ready_returns_once_the_agency_says_so(tmp_path):
    h = Fake(tmp_path, "import time; time.sleep(30)")
    try:
        h.log_path.write_bytes(b"... " + host.READY + b"...\n")
        h.wait_ready(timeout=5)
    finally:
        h.stop()


def test_stop_without_a_process_or_after_exit(tmp_path):
    Host("idle", tmp_path, []).stop()
    h = Fake(tmp_path, "pass")
    h.process.wait()
    h.stop()


def test_stop_kills_a_process_that_ignores_terminate(tmp_path):
    h = Fake(tmp_path, "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                       "time.sleep(60)")
    time.sleep(0.5)  # let it install the handler
    real = h.process.wait
    calls = []

    def wait(timeout=None):
        calls.append(timeout)
        if len(calls) == 1:
            raise subprocess.TimeoutExpired(cmd="fake", timeout=timeout)
        return real(timeout=timeout)

    h.process.wait = wait
    h.stop()
    assert h.process.poll() is not None and len(calls) == 2


def test_log_reads_the_file(tmp_path):
    h = Host("x", tmp_path, [])
    h.root.mkdir(parents=True)
    h.log_path.write_text("2026-10-17 01:23:41 [keria] INFO hello\n")
    assert h.log() == [(stamp("2026-10-17 01:23:41"), "2026-10-17 01:23:41 [keria] INFO hello")]
