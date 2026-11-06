import argparse

import pytest
from hio.base import filing
from hio.help import ogling
from keri.db import dbing

from kpa_keria_stack import server


def test_config_logs_requests_at_info():
    args = argparse.Namespace(admin_port=1, http_port=2, boot_port=3, config_dir="/c")
    c = server.config(args)
    assert (c.adminPort, c.httpPort, c.bootPort, c.configDir) == (1, 2, 3, "/c")
    assert c.logRequests and c.logLevel == "INFO" and c.configFile == "kpa"


def test_contain_moves_every_default_store(monkeypatch, tmp_path):
    for cls in (dbing.LMDBer, filing.Filer, ogling.Ogler):
        monkeypatch.setattr(cls, "HeadDirPath", cls.HeadDirPath)
        monkeypatch.setattr(cls, "AltHeadDirPath", cls.AltHeadDirPath)
    monkeypatch.setattr(ogling.Ogler, "TempHeadDir", ogling.Ogler.TempHeadDir)
    server.contain(str(tmp_path))
    for cls in (dbing.LMDBer, filing.Filer, ogling.Ogler):
        assert cls.HeadDirPath == cls.AltHeadDirPath == str(tmp_path)
    assert ogling.Ogler.TempHeadDir == str(tmp_path)


def test_main_runs_the_agency_until_interrupted(monkeypatch, tmp_path):
    from keria.app import agenting

    seen = []
    monkeypatch.setattr(server, "contain", lambda d: seen.append(d))
    monkeypatch.setattr(server.signal, "signal", lambda sig, handler: seen.append(handler))

    def run(config, temp):
        seen.append(config.adminPort)
        raise KeyboardInterrupt

    monkeypatch.setattr(agenting, "runAgency", run)
    argv = ["--config-dir", "c", "--admin-port", "1", "--http-port", "2", "--boot-port", "3",
            "--data-dir", str(tmp_path)]
    assert server.main(argv) == 0
    assert seen == [str(tmp_path), server._stop, 1]
    monkeypatch.setattr(agenting, "runAgency", lambda config, temp: None)
    assert server.main(argv) == 0


def test_stop_interrupts():
    with pytest.raises(KeyboardInterrupt):
        server._stop(15, None)
