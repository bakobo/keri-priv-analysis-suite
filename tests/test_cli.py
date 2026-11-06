"""The kpa command line."""


from test_runner import small

from keri_priv_analysis import cli


def test_run_then_regenerate_the_report(tmp_path, capsys):
    scenario = tmp_path / "s.toml"
    scenario.write_text(small())
    assert cli.main(["run", str(scenario), "--out", str(tmp_path / "run")]) == 0
    first = (tmp_path / "run" / "report.md").read_bytes()
    (tmp_path / "run" / "report.md").unlink()
    assert cli.main(["report", str(tmp_path / "run")]) == 0
    assert (tmp_path / "run" / "report.md").read_bytes() == first
    assert "wrote" in capsys.readouterr().out


def test_check_reports_contract_problems(tmp_path, capsys, monkeypatch):
    scenario = tmp_path / "s.toml"
    scenario.write_text(small())
    assert cli.main(["check", str(scenario)]) == 0
    assert "generator: 0 contract problems" in capsys.readouterr().out
    monkeypatch.setattr(cli.contract, "check", lambda *a: ["one problem"])
    assert cli.main(["check", str(scenario)]) == 1
    assert "one problem" in capsys.readouterr().out


def test_a_coded_error_exits_2_with_its_code(tmp_path, capsys):
    scenario = tmp_path / "s.toml"
    scenario.write_text(small(**{"copies = 6": "copies = 0"}))
    assert cli.main(["run", str(scenario), "--out", str(tmp_path / "run")]) == 2
    assert "[e.input.range.scenario-parameter.f]" in capsys.readouterr().err
