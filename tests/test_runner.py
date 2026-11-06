"""The runner (docs/test-plan.md Part B item 8, and the run directory of 'Outputs')."""

import dataclasses
import json
from pathlib import Path

import pytest
from bakobo.errors import BakoboError

from keri_priv_analysis import runner
from keri_priv_analysis.generator import Generator
from keri_priv_analysis.model import Compartment, CompartmentSet, LogLine, Presentation

SMOKE = (Path(__file__).parent.parent / "scenarios" / "smoke.toml").read_text()


def small(**replacements) -> str:
    text = SMOKE.replace("size = 3500000", "size = 50000").replace("count = 300", "count = 10")
    for old, new in replacements.items():
        assert old in text, old
        text = text.replace(old, new)
    return text


@pytest.fixture(scope="module")
def smoke_run(tmp_path_factory):
    out = tmp_path_factory.mktemp("run") / "a"
    runner.run(small(), out)
    return out


def test_a_run_directory_holds_everything_a_number_is_recomputed_from(smoke_run):
    for name in ("scenario.toml", "compartments/index.json", "ground-truth.json",
                 "knowledge.json", "results.json", "report.md", "report.json"):
        assert (smoke_run / name).is_file(), name
    results = json.loads((smoke_run / "results.json").read_text())
    assert results["provenance"]["keripy"]["commit"] == "910dcb350e63d3129c91345429c1fa10f2dae5e5"
    assert results["provenance"]["population"]["size"] == 50000
    assert set(results["parties"]) == {"colluding-verifiers", "home-hacker",
                                       "verifiers-buy-stolen-home"}
    hacker = results["parties"]["home-hacker"]["attacks"]
    assert hacker["shared-registry"] == {"measured": False, "missing": ["verifier"]}


def test_the_same_scenario_and_seed_give_a_byte_identical_report(smoke_run, tmp_path):
    again = runner.run(small(), tmp_path / "b")
    for name in ("report.md", "report.json", "results.json"):
        assert (smoke_run / name).read_bytes() == (again / name).read_bytes(), name


def test_claims_are_judged_and_failures_name_their_attacks(smoke_run):
    claims = json.loads((smoke_run / "results.json").read_text())["claims"]
    flagged = next(c for c in claims if c["metric"] == "flagged_domains")
    assert flagged["verdict"] == "fail" and flagged["measured"] == 2
    assert "timestamp-clustering" in flagged["attacks"]


def test_live_adapter_can_name_the_owner_of_its_own_leak(monkeypatch, tmp_path):
    class OtherStack(Generator):
        def owners(self):
            return {"shared-registry": "this stack's registry operator"}

    monkeypatch.setattr(runner, "adapter_for", lambda name: OtherStack())
    out = runner.run(small(), tmp_path / "other")
    results = json.loads((out / "results.json").read_text())
    assert results["owners"]["shared-registry"] == "this stack's registry operator"
    assert results["owners"]["timestamp-clustering"] == runner.owners()[
        "timestamp-clustering"]


def test_a_run_never_overwrites_another(smoke_run):
    with pytest.raises(BakoboError) as raised:
        runner.run(small(), smoke_run)
    assert raised.value.code == "e.state.conflict.run-directory.f"


def test_an_adapter_that_is_not_installed_is_refused(tmp_path):
    with pytest.raises(BakoboError) as raised:
        runner.run(small(**{'adapter = "generator"': 'adapter = "keria"'}), tmp_path / "x")
    assert raised.value.code == "e.feature.unsupported.adapter.f"
    assert not (tmp_path / "x").exists()


def test_an_installed_adapter_is_found_by_entry_point(monkeypatch):
    class EntryPoint:
        name = "keria"

        def load(self):
            return Generator

    monkeypatch.setattr(runner.metadata, "entry_points", lambda group: [EntryPoint()])
    assert isinstance(runner.adapter_for("keria"), Generator)


def test_an_adapter_that_breaks_the_contract_is_refused_before_anything_is_scored(
        monkeypatch, tmp_path):
    class Leaky(Generator):
        def run(self, scenario, population):
            cs, truth, knowledge = super().run(scenario, population)
            return CompartmentSet(c for c in cs if c.name != "orchestrator"), truth, knowledge

    monkeypatch.setattr(runner, "adapter_for", lambda name: Leaky())
    with pytest.raises(BakoboError) as raised:
        runner.run(small(), tmp_path / "x")
    assert raised.value.code == "e.party.adapter-contract.f"
    assert "orchestrator" in str(raised.value)


def test_obtaining_a_compartment_keeps_what_existed_and_was_retained():
    p = Presentation(handle="h", verifier="v", time=50.0 * 86400, domain="d", disclosed={},
                     said="E", registry="E", issuer="E", holder="E", raw=b"")
    c = Compartment(name="verifier:v", status="present", presentations=[p],
                    logs=[LogLine(t * 86400.0, "a", "x") for t in (1, 20, 40, 60)],
                    records={"pool": [{"time": repr(10 * 86400.0)}, {"time": repr(45 * 86400.0)},
                                      {"said": "untimed"}]})
    got = runner.obtained(c, at=55 * 86400.0, retention_days=30.0)
    assert [line.time / 86400 for line in got.logs] == [40]
    assert got.presentations == [p]
    assert got.records["pool"] == [{"time": repr(45 * 86400.0)}, {"said": "untimed"}]
    absent = Compartment(name="orchestrator", status="absent")
    assert runner.obtained(absent, 1.0, 1.0) is absent


def test_every_metric_and_operator_is_judged(smoke_run):
    from keri_priv_analysis.scenario import METRICS, OPS, Claim
    from keri_priv_analysis.scoring import PartyScore
    s = PartyScore(threshold_bits=20.0, joins=0, direct_correct=0, certain_share=None,
                   precision=None, recall=None, bits=[1.0, 3.0], reidentified=0,
                   sensitive_exposed={}, identity_exposed=0, bound_joins=0, breach_bits=[],
                   breach_reidentified=0, increment=[0.5, 2.0])
    for metric in METRICS:
        for op in OPS:
            verdict, _value = runner._verdict(s, Claim("p", metric, op, 2.0))
            assert verdict in ("pass", "fail", "not-measured")
    assert runner._verdict(s, Claim("p", "precision", "<=", 0.5)) == ("not-measured", None)
    assert runner._verdict(s, Claim("p", "median_bits", "==", 2.0)) == ("pass", 2.0)
    empty = dataclasses.replace(s, bits=[], increment=[])
    assert runner._verdict(empty, Claim("p", "max_bits", "<", 1.0)) == ("pass", 0.0)
    assert runner._verdict(empty, Claim("p", "median_bits", ">", 1.0)) == ("fail", 0.0)
    assert runner._verdict(empty, Claim("p", "max_increment", ">=", 0.0)) == ("pass", 0.0)


def test_a_claim_no_attack_could_measure_is_not_measured_rather_than_passed(tmp_path):
    text = small(**{'compartments = ["public", "issuing-home:0"]': 'compartments = ["orchestrator"]',
                    'party = "verifiers-buy-stolen-home"\nmetric': 'party = "home-hacker"\nmetric'})
    out = runner.run(text, tmp_path / "r")
    claims = json.loads((out / "results.json").read_text())["claims"]
    assert claims[-1]["party"] == "home-hacker" and claims[-1]["verdict"] == "not-measured"


def test_every_attacks_joins_are_saved(smoke_run):
    saved = json.loads((smoke_run / "joins" / "colluding-verifiers" /
                        "timestamp-clustering.json").read_text())
    assert saved["joins"] and len(saved["joins"][0]) == 3


def test_a_party_holding_an_unexported_compartment_gets_no_verdict(monkeypatch, tmp_path):
    class Partial(Generator):
        def run(self, scenario, population):
            cs, truth, knowledge = super().run(scenario, population)
            return CompartmentSet(dataclasses.replace(c, status="not-measured", logs=[],
                                                      note="cannot export")
                                  if c.name == "orchestrator" else c for c in cs), truth, knowledge

    monkeypatch.setattr(runner, "adapter_for", lambda name: Partial())
    text = small(**{'compartments = ["public", "verifier:liquor-store", "verifier:pharmacy"]':
                    'compartments = ["public", "verifier:liquor-store", "verifier:pharmacy", '
                    '"orchestrator"]'})
    claims = json.loads((runner.run(text, tmp_path / "r") / "results.json").read_text())["claims"]
    first = claims[0]
    assert first["party"] == "colluding-verifiers" and first["verdict"] == "not-measured"
    assert first["measured"] == 0


def test_a_party_holding_an_absent_compartment_gets_no_protection_verdict(tmp_path):
    text = small(**{'compartments = ["public", "verifier:liquor-store", "verifier:pharmacy"]':
                    'compartments = ["public", "verifier:liquor-store", "verifier:pharmacy", '
                    '"orchestrator"]'})
    claims = json.loads((runner.run(text, tmp_path / "r") / "results.json").read_text())["claims"]
    assert claims[0]["party"] == "colluding-verifiers"
    assert claims[0]["verdict"] == "not-measured"
